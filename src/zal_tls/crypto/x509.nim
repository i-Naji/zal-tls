## X.509 from AWS-LC: parse certificates (PEM, DER), verify a chain to a
## set of roots for a host name at a time.

import zal_tls/common
import zal_tls/crypto/[awslc, sig]

type
  X509Obj* {.importc: "X509", header: "<openssl/x509.h>", incompleteStruct.} = object
  X509StoreObj* {.importc: "X509_STORE", header: "<openssl/x509.h>", incompleteStruct.} = object
  StoreCtxObj {.importc: "X509_STORE_CTX", header: "<openssl/x509.h>", incompleteStruct.} = object
  StackObj {.importc: "struct stack_st_X509", header: "<openssl/x509.h>", incompleteStruct.} = object
  ParamObj {.importc: "X509_VERIFY_PARAM", header: "<openssl/x509.h>", incompleteStruct.} = object
  BioObj {.importc: "BIO", header: "<openssl/bio.h>", incompleteStruct.} = object
  ObjStackObj {.importc: "struct stack_st_X509_OBJECT", header: "<openssl/x509.h>", incompleteStruct.} = object
  ConstU8 {.importc: "const uint8_t", nodecl.} = object   # d2i's `const uint8_t **`

  Cert* = ptr X509Obj          ## owned: `release` it
  Roots* = ptr X509StoreObj    ## owned: `release` it

  VerifyResult* = enum
    vrOk, vrExpired, vrNotYetValid, vrUnknownIssuer, vrBadName, vrBadSignature, vrBadPurpose, vrOther

  CertPurpose* = enum
    cpServer   ## a TLS server's certificate (extended key usage serverAuth)
    cpClient   ## a TLS client's certificate (clientAuth)

const
  ErrIssuer = 2.cint                      # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
  ErrSignature = 7.cint                   # X509_V_ERR_CERT_SIGNATURE_FAILURE
  ErrNotYetValid = 9.cint                 # X509_V_ERR_CERT_NOT_YET_VALID
  ErrExpired = 10.cint                    # X509_V_ERR_CERT_HAS_EXPIRED
  ErrSelfSignedLeaf = 18.cint             # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
  ErrSelfSignedInChain = 19.cint          # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
  ErrIssuerLocal = 20.cint                # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
  ErrLeafSignature = 21.cint              # X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
  ErrPurpose = 26.cint                    # X509_V_ERR_INVALID_PURPOSE
  ErrHostname = 62.cint                   # X509_V_ERR_HOSTNAME_MISMATCH
  ErrIpAddress = 64.cint                  # X509_V_ERR_IP_ADDRESS_MISMATCH
  PurposeSslClient = 1.cint               # X509_PURPOSE_SSL_CLIENT
  PurposeSslServer = 2.cint               # X509_PURPOSE_SSL_SERVER
  NeverCheckSubject = 0x20.cuint          # X509_CHECK_FLAG_NEVER_CHECK_SUBJECT

proc BIO_new_mem_buf(buf: pointer; len: int): nil ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc BIO_free(b: nil ptr BioObj): cint {.importc, header: "<openssl/bio.h>".}
proc PEM_read_bio_X509(b: ptr BioObj; x: nil pointer; cb: nil pointer; u: nil pointer): nil ptr X509Obj {.importc, header: "<openssl/pem.h>".}
proc d2i_X509(x: nil pointer; inp: ptr ptr ConstU8; len: clong): nil ptr X509Obj {.importc, header: "<openssl/x509.h>".}
proc X509_free(c: nil ptr X509Obj) {.importc, header: "<openssl/x509.h>".}
proc X509_get_pubkey(c: ptr X509Obj): nil ptr PkeyObj {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_new(): nil ptr X509StoreObj {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_free(s: nil ptr X509StoreObj) {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_up_ref(s: ptr X509StoreObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_add_cert(s: ptr X509StoreObj; c: ptr X509Obj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_new(): nil ptr StoreCtxObj {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_free(c: nil ptr StoreCtxObj) {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_init(c: ptr StoreCtxObj; s: ptr X509StoreObj; leaf: ptr X509Obj;
                         chain: nil ptr StackObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_get0_param(c: ptr StoreCtxObj): ptr ParamObj {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_get_error(c: ptr StoreCtxObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_VERIFY_PARAM_set1_host(p: ptr ParamObj; name: pointer; len: csize_t): cint {.importc, header: "<openssl/x509.h>".}
proc X509_VERIFY_PARAM_set_time_posix(p: ptr ParamObj; t: int64) {.importc, header: "<openssl/x509.h>".}
proc X509_VERIFY_PARAM_set_hostflags(p: ptr ParamObj; flags: cuint) {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_CTX_set_purpose(c: ptr StoreCtxObj; purpose: cint): cint {.importc, header: "<openssl/x509.h>".}
proc ERR_clear_error() {.importc, header: "<openssl/err.h>".}
proc X509_verify_cert(c: ptr StoreCtxObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_VERIFY_PARAM_set1_ip_asc(p: ptr ParamObj; ip: cstring): cint {.importc, header: "<openssl/x509.h>".}
proc i2d_X509(c: ptr X509Obj; outp: nil ptr ptr uint8): cint {.importc, header: "<openssl/x509.h>".}
proc X509_check_private_key(c: ptr X509Obj; k: ptr PkeyObj): cint {.importc, header: "<openssl/x509.h>".}
proc X509_STORE_get0_objects(s: ptr X509StoreObj): ptr ObjStackObj {.importc, header: "<openssl/x509.h>".}
proc sk_X509_OBJECT_num(s: ptr ObjStackObj): csize_t {.importc, header: "<openssl/x509.h>".}
proc sk_X509_new_null(): nil ptr StackObj {.importc, header: "<openssl/x509.h>".}
proc sk_X509_push(s: ptr StackObj; c: ptr X509Obj): csize_t {.importc, header: "<openssl/x509.h>".}
proc sk_X509_free(s: nil ptr StackObj) {.importc, header: "<openssl/x509.h>".}

type NameObj {.importc: "X509_NAME", header: "<openssl/x509.h>", incompleteStruct.} = object
proc X509_get_subject_name(c: ptr X509Obj): nil ptr NameObj {.importc, header: "<openssl/x509.h>".}
proc i2d_X509_NAME(n: ptr NameObj; outp: nil ptr ptr uint8): cint {.importc, header: "<openssl/x509.h>".}

proc release*(c: nil Cert) = X509_free(c)
proc release*(r: nil Roots) = X509_STORE_free(r)

proc retain*(r: Roots): bool =
  ## Acquire an independent store reference, preserving the caller's ownership.
  X509_STORE_up_ref(r) == 1

proc certsPem*(pem: openArray[char]; outp: var seq[Cert]): int =
  ## Every certificate in a PEM text, appended to `outp`; how many.
  result = 0
  if pem.len == 0: return
  let b = BIO_new_mem_buf(unsafeAddr pem[0], pem.len)
  if b == nil: return
  while true:
    let c = PEM_read_bio_X509(b, nil, nil, nil)
    if c == nil: break
    outp.add c
    result = result + 1
  discard BIO_free(b)
  ERR_clear_error()          # the end of the text leaves "no start line" queued

proc certDer*(der: Bytes; len: int): nil Cert =
  ## Exactly one DER certificate: trailing bytes are refused.
  var p = cast[ptr ConstU8](der)
  let c = d2i_X509(nil, addr p, clong(len))
  if c != nil and cast[int](p) - cast[int](der) != len:
    X509_free(c)
    return nil
  result = c

type Asn1Time {.importc: "ASN1_TIME", header: "<openssl/asn1.h>", incompleteStruct.} = object
proc X509_get0_notAfter(c: ptr X509Obj): nil ptr Asn1Time {.importc, header: "<openssl/x509.h>".}
proc ASN1_TIME_to_posix(t: ptr Asn1Time; outp: ptr int64): cint {.importc, header: "<openssl/asn1.h>".}

proc notAfter*(c: Cert): int64 =
  ## The end of the certificate's validity (unix seconds); 0 when unreadable.
  result = 0
  let t = X509_get0_notAfter(c)
  if t != nil:
    var x = 0'i64
    if ASN1_TIME_to_posix(t, addr x) == 1: result = x

proc publicKey*(c: Cert): nil PublicKey =
  ## The certificate's public key (owned).
  result = X509_get_pubkey(c)

proc subjectDer*(c: Cert): seq[byte] =
  ## The certificate's subject name, DER (a CA's name for certificate_authorities).
  result = @[]
  let n = X509_get_subject_name(c)
  if n == nil: return
  let len = i2d_X509_NAME(n, nil)
  if len <= 0: return
  result = newSeq[byte](int(len))
  var p = cast[ptr uint8](addr result[0])
  if i2d_X509_NAME(n, addr p) != len: result = @[]

proc certDerOf*(c: Cert; outp: var seq[byte]) =
  ## The certificate's DER encoding (empty on failure).
  outp = @[]
  let n = i2d_X509(c, nil)
  if n <= 0: return
  outp = newSeq[byte](int(n))
  var p = cast[ptr uint8](addr outp[0])
  if i2d_X509(c, addr p) != n: outp = @[]

proc keyMatches*(c: Cert; k: ptr PkeyObj): bool =
  ## Is `k` the private key of the certificate's public key?
  result = X509_check_private_key(c, k) == 1
  ERR_clear_error()

proc isIpLiteral*(host: openArray[char]): bool =
  ## An IPv6 literal (has a ':') or dotted-decimal IPv4.
  if host.len == 0: return false
  var digitsOnly = true
  for ch in host:
    if ch == ':': return true
    if not (ch == '.' or (ch >= '0' and ch <= '9')): digitsOnly = false
  result = digitsOnly

proc newRoots*(): nil Roots = X509_STORE_new()

proc rootCount*(r: Roots): int =
  result = int(sk_X509_OBJECT_num(X509_STORE_get0_objects(r)))

proc addRoot*(r: Roots; c: Cert): bool =
  ## Trust `c` (the store keeps its own reference).
  result = X509_STORE_add_cert(r, c) == 1

proc verifyChain*(r: Roots; leaf: Cert; chain: openArray[Cert]; host: openArray[char];
                  atUnix: int64; purpose = cpServer): VerifyResult =
  ## The leaf, through `chain` (intermediates), to a root in `r`, for
  ## `purpose`, valid for `host` (matched against the DNS names only, never
  ## the subject's CN; an IP literal against the IP addresses; "" skips the
  ## name) at `atUnix` (0: now).
  result = vrOther
  let ctx = X509_STORE_CTX_new()
  let sk = sk_X509_new_null()
  if ctx == nil or sk == nil:
    X509_STORE_CTX_free(ctx)
    sk_X509_free(sk)
    return
  var pushed = true
  for c in chain:
    if sk_X509_push(sk, c) == 0: pushed = false
  if pushed and X509_STORE_CTX_init(ctx, r, leaf, sk) == 1:
    let p = X509_STORE_CTX_get0_param(ctx)
    let which = if purpose == cpServer: PurposeSslServer else: PurposeSslClient
    X509_VERIFY_PARAM_set_hostflags(p, NeverCheckSubject)
    # A name AWS-LC refuses to set (an embedded NUL) must not mean "no name check".
    var named = host.len == 0
    if not named and isIpLiteral(host):
      var z = newString(host.len)       # NUL-terminated copy for the C call
      for i in 0 ..< host.len: z[i] = host[i]
      named = X509_VERIFY_PARAM_set1_ip_asc(p, z.toCString) == 1
    elif not named:
      named = X509_VERIFY_PARAM_set1_host(p, unsafeAddr host[0], csize_t(host.len)) == 1
    if X509_STORE_CTX_set_purpose(ctx, which) == 1 and named:
      if atUnix != 0: X509_VERIFY_PARAM_set_time_posix(p, atUnix)
      if X509_verify_cert(ctx) == 1:
        result = vrOk
      else:
        result = case X509_STORE_CTX_get_error(ctx)
          of ErrExpired: vrExpired
          of ErrNotYetValid: vrNotYetValid
          of ErrIssuerLocal, ErrIssuer, ErrSelfSignedLeaf, ErrSelfSignedInChain, ErrLeafSignature:
            vrUnknownIssuer
          of ErrHostname, ErrIpAddress: vrBadName
          of ErrSignature: vrBadSignature
          of ErrPurpose: vrBadPurpose
          else: vrOther
  ERR_clear_error()
  X509_STORE_CTX_free(ctx)
  sk_X509_free(sk)
