## The operating system's trust anchors as a `Roots` store: the CA bundle
## file on Linux, the Keychain's system anchors on macOS, the ROOT and
## AuthRoot stores on Windows, where the system's chain engine also judges
## first (`systemVerifier`). `SSL_CERT_FILE` (a PEM bundle) and
## `SSL_CERT_DIR` (a hashed directory), when set, replace them, as with
## OpenSSL.

import std/envvars
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/config/config
import zal_tls/wire/consts

proc X509_STORE_load_locations(s: Roots; file: nil cstring; dir: nil cstring): cint {.importc, header: "<openssl/x509.h>".}
proc ERR_clear_error() {.importc, header: "<openssl/err.h>".}

when defined(macosx):
  {.passL: "-framework Security -framework CoreFoundation".}
  type
    CFArrayObj {.importc: "struct __CFArray", header: "<CoreFoundation/CoreFoundation.h>", incompleteStruct.} = object
    CFDataObj {.importc: "struct __CFData", header: "<CoreFoundation/CoreFoundation.h>", incompleteStruct.} = object
    CFArrayRef = nil ptr CFArrayObj
  proc SecTrustCopyAnchorCertificates(anchors: ptr CFArrayRef): int32 {.importc, header: "<Security/Security.h>".}
  proc CFArrayGetCount(a: ptr CFArrayObj): int {.importc, header: "<CoreFoundation/CoreFoundation.h>".}
  proc CFArrayGetValueAtIndex(a: ptr CFArrayObj; i: int): pointer {.importc, header: "<CoreFoundation/CoreFoundation.h>".}
  proc SecCertificateCopyData(c: pointer): nil ptr CFDataObj {.importc, header: "<Security/Security.h>".}
  proc CFDataGetBytePtr(d: ptr CFDataObj): Bytes {.importc, header: "<CoreFoundation/CoreFoundation.h>".}
  proc CFDataGetLength(d: ptr CFDataObj): int {.importc, header: "<CoreFoundation/CoreFoundation.h>".}
  proc CFRelease(p: pointer) {.importc, header: "<CoreFoundation/CoreFoundation.h>".}
elif defined(windows):
  {.passL: "-lcrypt32".}
  type
    CertContext = object        ## CERT_CONTEXT (declared here: no <wincrypt.h>, see crypto/awslc)
      encodingType: uint32
      pbCertEncoded: Bytes
      cbCertEncoded: uint32
      certInfo: pointer
      store: pointer
  proc CertOpenSystemStoreW(prov: uint; name: ptr uint16): nil pointer {.importc.}
  proc CertEnumCertificatesInStore(store: pointer; prev: nil ptr CertContext): nil ptr CertContext {.importc.}
  proc CertCloseStore(store: pointer; flags: uint32): int32 {.importc.}

  # The chain engine. Nested where the C structs are, so pointer fields keep
  # their alignment.
  type
    EnhkeyUsage = object
      count: uint32
      ids: ptr cstring
    UsageMatch = object
      kind: uint32
      usage: EnhkeyUsage
    ChainPara = object                ## CERT_CHAIN_PARA up to the revocation freshness
      size: uint32
      requestedUsage: UsageMatch
      issuancePolicy: UsageMatch
      urlRetrievalTimeoutMs: uint32
      checkRevocationFreshness: int32
      revocationFreshnessSeconds: uint32
    SslPolicyPara = object            ## SSL_EXTRA_CERT_CHAIN_POLICY_PARA
      size: uint32
      authType: uint32
      checks: uint32
      serverName: ptr uint16
    PolicyPara = object
      size: uint32
      flags: uint32
      extra: pointer
    PolicyStatus = object
      size: uint32
      error: uint32
      chainIndex: int32
      elementIndex: int32
      extra: nil pointer
  const
    X509Encoding = 1'u32
    ProvMemory = 2                    # CERT_STORE_PROV_MEMORY: an id passed as LPCSTR
    AddAlways = 4'u32
    PolicySsl = 4                     # CERT_CHAIN_POLICY_SSL, likewise
    UsageAnd = 0'u32
    AuthServer = 2'u32
    FetchTimeoutMs = 3000'u32         # AIA and root updates: a bound on blocking the lane
    ErrExpired = 0x800B0101'u32
    ErrUntrustedRoot = 0x800B0109'u32
    ErrChaining = 0x800B010A'u32
    ErrRevoked = 0x800B010C'u32
    ErrNameMismatch = 0x800B010F'u32
    ErrWrongUsage = 0x800B0110'u32
    ErrInvalidName = 0x800B0114'u32
    ErrSignature = 0x80096004'u32
  proc CertCreateCertificateContext(enc: uint32; der: Bytes; len: uint32): nil ptr CertContext {.importc.}
  proc CertFreeCertificateContext(c: ptr CertContext): int32 {.importc.}
  proc CertOpenStore(provider: pointer; enc: uint32; prov: nil pointer; flags: uint32;
                     para: nil pointer): nil pointer {.importc.}
  proc CertAddEncodedCertificateToStore(store: pointer; enc: uint32; der: Bytes; len: uint32;
                                        disposition: uint32; added: nil pointer): int32 {.importc.}
  proc CertGetCertificateChain(engine: nil pointer; c: ptr CertContext; time: nil pointer;
                               additional: nil pointer; para: ptr ChainPara; flags: uint32;
                               reserved: nil pointer; chain: ptr (nil pointer)): int32 {.importc.}
  proc CertVerifyCertificateChainPolicy(policy: pointer; chain: pointer; para: ptr PolicyPara;
                                        status: ptr PolicyStatus): int32 {.importc.}
  proc CertFreeCertificateChain(chain: pointer) {.importc.}

  proc systemVerdict(chain: ptr seq[seq[byte]]; host: string): uint32 =
    ## Windows' verdict on the chain for `host`: a Win32 error, 0 when good.
    result = ErrUntrustedRoot
    let leaf = CertCreateCertificateContext(X509Encoding, cast[Bytes](addr chain[][0][0]),
                                            uint32(chain[][0].len))
    if leaf == nil: return
    let extra = CertOpenStore(cast[pointer](ProvMemory), 0'u32, nil, 0'u32, nil)
    if extra != nil:
      for i in 1 ..< chain[].len:
        if chain[][i].len > 0:
          discard CertAddEncodedCertificateToStore(extra, X509Encoding,
            cast[Bytes](addr chain[][i][0]), uint32(chain[][i].len), AddAlways, nil)
    var serverAuth = cstring"1.3.6.1.5.5.7.3.1"
    var para = ChainPara(size: uint32(sizeof(ChainPara)),
      requestedUsage: UsageMatch(kind: UsageAnd, usage: EnhkeyUsage(count: 1, ids: addr serverAuth)),
      issuancePolicy: UsageMatch(kind: UsageAnd, usage: EnhkeyUsage(count: 0, ids: nil)),
      urlRetrievalTimeoutMs: FetchTimeoutMs, checkRevocationFreshness: 0,
      revocationFreshnessSeconds: 0)
    var ctx: nil pointer = nil
    if CertGetCertificateChain(nil, leaf, nil, extra, addr para, 0'u32, nil, addr ctx) != 0 and
       ctx != nil:
      var name = newSeq[uint16](host.len + 1)
      for i in 0 ..< host.len: name[i] = uint16(ord(host[i]))
      var ssl = SslPolicyPara(size: uint32(sizeof(SslPolicyPara)), authType: AuthServer,
                              checks: 0, serverName: addr name[0])
      var policy = PolicyPara(size: uint32(sizeof(PolicyPara)), flags: 0, extra: addr ssl)
      var status = PolicyStatus(size: uint32(sizeof(PolicyStatus)), error: 0, chainIndex: 0,
                                elementIndex: 0, extra: nil)
      if CertVerifyCertificateChainPolicy(cast[pointer](PolicySsl), ctx, addr policy, addr status) != 0:
        result = status.error
      CertFreeCertificateChain(ctx)
    if extra != nil: discard CertCloseStore(extra, 0)
    discard CertFreeCertificateContext(leaf)

  proc systemProc(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} =
    let roots = cast[nil Roots](ctx)
    if roots == nil: return alUnknownCa
    if chain[].len == 0 or chain[][0].len == 0: return alDecodeError
    if isIpLiteral(host): return webPkiVerify(roots, chain, host, 0)
    result = case systemVerdict(chain, host)
      of 0'u32: 0
      of ErrUntrustedRoot, ErrChaining: webPkiVerify(roots, chain, host, 0)
      of ErrExpired: alCertificateExpired
      of ErrRevoked: alCertificateRevoked
      of ErrNameMismatch, ErrInvalidName, ErrSignature: alBadCertificate
      of ErrWrongUsage: alUnsupportedCertificate
      else: alCertificateUnknown

  proc systemVerifier*(roots: Roots): CertVerifier =
    ## Windows' chain engine first: it has the roots Windows fetches on demand,
    ## finds intermediates a server left out and honours the Disallowed store.
    ## What it only lacks a root for is judged again over `roots`.
    CertVerifier(verify: systemProc, ctx: roots)
else:
  proc access(path: cstring; mode: cint): cint {.importc, header: "<unistd.h>".}
  const bundles = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                   "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                   "/etc/ssl/cert.pem"]

proc addDer(r: Roots; der: Bytes; len: int) =
  let c = certDer(der, len)
  if c != nil:
    discard addRoot(r, c)             # duplicates are refused and harmless
    release(c)

proc systemRoots*(): nil Roots =
  ## The system's trust anchors; nil when none could be loaded.
  let r = newRoots()
  if r == nil: return nil
  var file = getEnv("SSL_CERT_FILE")
  var dir = getEnv("SSL_CERT_DIR")
  if file.len > 0 or dir.len > 0:
    var loaded = false
    if file.len > 0 and X509_STORE_load_locations(r, file.toCString, nil) == 1: loaded = true
    if dir.len > 0 and X509_STORE_load_locations(r, nil, dir.toCString) == 1: loaded = true
    ERR_clear_error()
    if loaded: return r                    # a directory is read on demand: no count to check
    release(r)
    return nil
  when defined(macosx):
    var arr: CFArrayRef = nil
    if SecTrustCopyAnchorCertificates(addr arr) == 0 and arr != nil:
      for i in 0 ..< CFArrayGetCount(arr):
        let d = SecCertificateCopyData(CFArrayGetValueAtIndex(arr, i))
        if d != nil:
          addDer(r, CFDataGetBytePtr(d), CFDataGetLength(d))
          CFRelease(d)
      CFRelease(arr)
  elif defined(windows):
    # ROOT (the machine's and user's roots) and AuthRoot (third-party roots
    # Windows has fetched so far; it fetches more only for its own verifier).
    var root = [uint16(ord('R')), uint16(ord('O')), uint16(ord('O')), uint16(ord('T')), 0'u16]
    var auth = [uint16(ord('A')), uint16(ord('u')), uint16(ord('t')), uint16(ord('h')), uint16(ord('R')),
                uint16(ord('o')), uint16(ord('o')), uint16(ord('t')), 0'u16]
    for which in 0 ..< 2:
      let store = if which == 0: CertOpenSystemStoreW(0, addr root[0]) else: CertOpenSystemStoreW(0, addr auth[0])
      if store != nil:
        var c = CertEnumCertificatesInStore(store, nil)
        while c != nil:
          addDer(r, c.pbCertEncoded, int(c.cbCertEncoded))
          c = CertEnumCertificatesInStore(store, c)
        discard CertCloseStore(store, 0)
  else:
    for path in bundles:
      var p = path                          # toCString needs a mutable string
      if access(p.toCString, 4) == 0 and X509_STORE_load_locations(r, p.toCString, nil) == 1: break
    ERR_clear_error()
  if rootCount(r) == 0:
    release(r)
    return nil
  result = r
