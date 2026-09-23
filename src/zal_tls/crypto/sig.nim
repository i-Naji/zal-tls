## TLS 1.3 signatures from AWS-LC: ECDSA (P-256/SHA-256, P-384/SHA-384),
## RSA-PSS (SHA-256, SHA-384; RSAE keys) and Ed25519.

import zal_tls/common
import zal_tls/crypto/awslc

type
  PkeyObj* {.importc: "EVP_PKEY", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpMdCtxObj {.importc: "EVP_MD_CTX", header: "<openssl/digest.h>", incompleteStruct.} = object
  EvpPkeyCtxObj {.importc: "EVP_PKEY_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpMd {.importc: "EVP_MD", header: "<openssl/digest.h>", incompleteStruct.} = object
  EcKeyObj {.importc: "EC_KEY", header: "<openssl/ec_key.h>", incompleteStruct.} = object
  EcGroupObj {.importc: "EC_GROUP", header: "<openssl/ec.h>", incompleteStruct.} = object
  EcPointObj {.importc: "EC_POINT", header: "<openssl/ec.h>", incompleteStruct.} = object
  BioObj {.importc: "BIO", header: "<openssl/bio.h>", incompleteStruct.} = object

  SigScheme* = enum
    sigEcdsaP256Sha256, sigEcdsaP384Sha384, sigRsaPssSha256, sigRsaPssSha384, sigEd25519

  PublicKey* = ptr PkeyObj     ## owned: `release` it
  PrivateKey* = ptr PkeyObj    ## owned: `release` it
  PctxRef = nil ptr EvpPkeyCtxObj

const
  NidEd25519 = 949.cint                  # NID_ED25519
  NidP256 = 415.cint                     # NID_X9_62_prime256v1
  NidP384 = 715.cint                     # NID_secp384r1
  PkeyRsa = 6.cint                       # EVP_PKEY_RSA (rsaEncryption: the RSAE schemes)
  PkeyEc = 408.cint                      # EVP_PKEY_EC
  RsaPkcs1PssPadding = 6.cint            # RSA_PKCS1_PSS_PADDING
  SaltLenDigest = -1.cint                # RSA_PSS_SALTLEN_DIGEST

proc EVP_sha256(): ptr EvpMd {.importc, header: "<openssl/digest.h>".}
proc EVP_sha384(): ptr EvpMd {.importc, header: "<openssl/digest.h>".}
proc EVP_MD_CTX_new(): nil ptr EvpMdCtxObj {.importc, header: "<openssl/digest.h>".}
proc EVP_MD_CTX_free(c: nil ptr EvpMdCtxObj) {.importc, header: "<openssl/digest.h>".}
proc EVP_DigestVerifyInit(c: ptr EvpMdCtxObj; pctx: ptr PctxRef; md: nil ptr EvpMd; e: nil pointer;
                          k: ptr PkeyObj): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestVerify(c: ptr EvpMdCtxObj; sig: pointer; sigLen: csize_t; msg: pointer;
                      msgLen: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestSignInit(c: ptr EvpMdCtxObj; pctx: ptr PctxRef; md: nil ptr EvpMd; e: nil pointer;
                        k: ptr PkeyObj): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_DigestSign(c: ptr EvpMdCtxObj; sig: pointer; sigLen: ptr csize_t; msg: pointer;
                    msgLen: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_set_rsa_padding(c: ptr EvpPkeyCtxObj; pad: cint): cint {.importc, header: "<openssl/rsa.h>".}
proc EVP_PKEY_CTX_set_rsa_pss_saltlen(c: ptr EvpPkeyCtxObj; len: cint): cint {.importc, header: "<openssl/rsa.h>".}
proc EVP_PKEY_new_raw_public_key(typ: cint; e: nil pointer; key: pointer; len: csize_t): nil ptr PkeyObj {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_new(): nil ptr PkeyObj {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_assign_EC_KEY(k: ptr PkeyObj; ec: ptr EcKeyObj): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_free(k: nil ptr PkeyObj) {.importc, header: "<openssl/evp.h>".}
proc EC_KEY_new_by_curve_name(nid: cint): nil ptr EcKeyObj {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_free(k: nil ptr EcKeyObj) {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_get0_group(k: ptr EcKeyObj): ptr EcGroupObj {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_set_public_key(k: ptr EcKeyObj; p: ptr EcPointObj): cint {.importc, header: "<openssl/ec_key.h>".}
proc EC_POINT_new(g: ptr EcGroupObj): nil ptr EcPointObj {.importc, header: "<openssl/ec.h>".}
proc EC_POINT_free(p: nil ptr EcPointObj) {.importc, header: "<openssl/ec.h>".}
proc EC_POINT_oct2point(g: ptr EcGroupObj; p: ptr EcPointObj; buf: pointer; len: csize_t;
                        ctx: nil pointer): cint {.importc, header: "<openssl/ec.h>".}
proc BIO_new_mem_buf(buf: pointer; len: int): nil ptr BioObj {.importc, header: "<openssl/bio.h>".}
proc BIO_free(b: nil ptr BioObj): cint {.importc, header: "<openssl/bio.h>".}
proc EVP_PKEY_id(k: ptr PkeyObj): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_get0_EC_KEY(k: ptr PkeyObj): nil ptr EcKeyObj {.importc, header: "<openssl/evp.h>".}
proc EC_GROUP_get_curve_name(g: ptr EcGroupObj): cint {.importc, header: "<openssl/ec.h>".}
proc PEM_read_bio_PrivateKey(b: ptr BioObj; x: nil pointer; cb: nil pointer; u: nil pointer): nil ptr PkeyObj {.importc, header: "<openssl/pem.h>".}

proc code*(s: SigScheme): uint16 =
  ## The scheme's TLS SignatureScheme code.
  case s
  of sigEcdsaP256Sha256: 0x0403'u16
  of sigEcdsaP384Sha384: 0x0503'u16
  of sigRsaPssSha256: 0x0804'u16
  of sigRsaPssSha384: 0x0805'u16
  of sigEd25519: 0x0807'u16

proc release*(k: nil PublicKey) = EVP_PKEY_free(k)

proc publicKeyEd25519*(raw: Bytes): nil PublicKey =
  ## From the 32-byte raw public key.
  result = EVP_PKEY_new_raw_public_key(NidEd25519, nil, raw, 32)

proc publicKeyP256*(point: Bytes): nil PublicKey =
  ## From a 65-byte uncompressed point.
  result = nil
  let ec = EC_KEY_new_by_curve_name(NidP256)
  if ec == nil: return
  let g = EC_KEY_get0_group(ec)
  let p = EC_POINT_new(g)
  let k = EVP_PKEY_new()
  if p != nil and k != nil and EC_POINT_oct2point(g, p, point, 65, nil) == 1 and
     EC_KEY_set_public_key(ec, p) == 1 and EVP_PKEY_assign_EC_KEY(k, ec) == 1:
    result = k                       # it owns ec now
  else:
    EVP_PKEY_free(k)
    EC_KEY_free(ec)
  EC_POINT_free(p)

proc privateKeyPem*(pem: openArray[char]): nil PrivateKey =
  ## The first private key in a PEM text (PKCS#8, or a traditional EC or RSA key).
  result = nil
  if pem.len == 0: return
  let b = BIO_new_mem_buf(unsafeAddr pem[0], pem.len)
  if b == nil: return
  result = PEM_read_bio_PrivateKey(b, nil, nil, nil)
  discard BIO_free(b)

proc md(s: SigScheme): nil ptr EvpMd =
  ## The digest, or nil for Ed25519 (which hashes internally).
  result = nil
  case s
  of sigEcdsaP256Sha256, sigRsaPssSha256: result = EVP_sha256()
  of sigEcdsaP384Sha384, sigRsaPssSha384: result = EVP_sha384()
  of sigEd25519: discard

proc pss(s: SigScheme; pctx: PctxRef): bool =
  ## RSA-PSS parameters on a digest context; true for the other schemes.
  if s != sigRsaPssSha256 and s != sigRsaPssSha384: return true
  if pctx == nil: return false
  result = EVP_PKEY_CTX_set_rsa_padding(pctx, RsaPkcs1PssPadding) == 1 and
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, SaltLenDigest) == 1

proc curveOf(k: ptr PkeyObj): cint =
  let ec = EVP_PKEY_get0_EC_KEY(k)
  result = if ec == nil: 0.cint else: EC_GROUP_get_curve_name(EC_KEY_get0_group(ec))

proc matches*(s: SigScheme; k: ptr PkeyObj): bool =
  ## Does key `k` belong to scheme `s`? (TLS 1.3 ties each scheme to one
  ## key type and, for ECDSA, one curve.)
  let id = EVP_PKEY_id(k)
  result = case s
    of sigEcdsaP256Sha256: id == PkeyEc and curveOf(k) == NidP256
    of sigEcdsaP384Sha384: id == PkeyEc and curveOf(k) == NidP384
    of sigRsaPssSha256, sigRsaPssSha384: id == PkeyRsa
    of sigEd25519: id == NidEd25519

proc verify*(s: SigScheme; k: PublicKey; msg: Bytes; msgLen: int;
             sig: Bytes; sigLen: int): bool =
  result = false
  if not matches(s, k): return
  let c = EVP_MD_CTX_new()
  if c == nil: return
  var pctx: PctxRef = nil
  if EVP_DigestVerifyInit(c, addr pctx, md(s), nil, k) == 1 and pss(s, pctx):
    result = EVP_DigestVerify(c, sig, csize_t(sigLen), msg, csize_t(msgLen)) == 1
  EVP_MD_CTX_free(c)

proc sign*(s: SigScheme; k: PrivateKey; msg: Bytes; msgLen: int;
           sig: Bytes; sigCap: int; sigLen: var int): bool =
  ## The signature at sig[0 ..< sigLen] (at most `sigCap` bytes).
  result = false
  sigLen = 0
  if not matches(s, k): return
  let c = EVP_MD_CTX_new()
  if c == nil: return
  var pctx: PctxRef = nil
  var n = csize_t(sigCap)
  if EVP_DigestSignInit(c, addr pctx, md(s), nil, k) == 1 and pss(s, pctx) and
     EVP_DigestSign(c, sig, addr n, msg, csize_t(msgLen)) == 1:
    sigLen = int(n)
    result = true
  EVP_MD_CTX_free(c)
