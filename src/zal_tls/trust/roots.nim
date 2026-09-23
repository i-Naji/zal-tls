## The operating system's trust anchors as a `Roots` store: the CA bundle
## file on Linux, the Keychain's system anchors on macOS, the ROOT and
## AuthRoot stores on Windows. `SSL_CERT_FILE` (a PEM bundle) and
## `SSL_CERT_DIR` (a hashed directory), when set, replace them, as with
## OpenSSL.

import std/envvars
import zal_tls/common
import zal_tls/crypto/x509

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
