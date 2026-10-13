## TLS 1.3 key exchange from AWS-LC: X25519, P-256 (secp256r1) and the
## X25519MLKEM768 hybrid. A client keeps a `KxKey` between its ClientHello
## and the ServerHello; a server answers in one call (`respond`).
##
## The hybrid's wire order (draft-ietf-tls-ecdhe-mlkem): client share =
## ML-KEM-768 encapsulation key (1184) ‖ X25519 public (32); server share =
## ML-KEM ciphertext (1088) ‖ X25519 public (32); secret = ML-KEM secret
## (32) ‖ X25519 secret (32).

import zal_tls/common
import zal_tls/crypto/awslc
import zal_tls/crypto/rand

type
  EcKeyObj {.importc: "EC_KEY", header: "<openssl/ec_key.h>", incompleteStruct.} = object
  EcGroupObj {.importc: "EC_GROUP", header: "<openssl/ec.h>", incompleteStruct.} = object
  EcPointObj {.importc: "EC_POINT", header: "<openssl/ec.h>", incompleteStruct.} = object
  BignumObj {.importc: "BIGNUM", header: "<openssl/bn.h>", incompleteStruct.} = object
  EvpPkeyObj {.importc: "EVP_PKEY", header: "<openssl/evp.h>", incompleteStruct.} = object
  EvpPkeyCtxObj {.importc: "EVP_PKEY_CTX", header: "<openssl/evp.h>", incompleteStruct.} = object
  PkeyRef = nil ptr EvpPkeyObj

  KxGroup* = enum
    kxX25519, kxSecp256r1, kxX25519MlKem768

  KxKey* = object
    ## A client's private share. `clear` wipes it.
    ## Owns C state: pass by `var` or pointer, never copy (c35).
    group*: KxGroup
    x: array[32, byte]               # X25519 private key (X25519, hybrid)
    ec: nil ptr EcKeyObj             # P-256 key
    kem: nil ptr EvpPkeyObj          # ML-KEM-768 decapsulation key (hybrid)

proc `=copy`(dst: var KxKey; src: KxKey) {.error.}

const
  NidP256 = 415.cint                 # NID_X9_62_prime256v1
  NidMlKem768 = 989.cint             # NID_MLKEM768
  EvpPkeyKem = 970.cint              # EVP_PKEY_KEM (NID_kem)
  PointUncompressed = 4.cint         # POINT_CONVERSION_UNCOMPRESSED
  MlKemPub = 1184
  MlKemCt = 1088

proc X25519_keypair(pub, priv: pointer) {.importc, header: "<openssl/curve25519.h>".}
proc X25519_public_from_private(pub, priv: pointer) {.importc, header: "<openssl/curve25519.h>".}
proc X25519(outp, priv, peer: pointer): cint {.importc, header: "<openssl/curve25519.h>".}
proc EC_KEY_new_by_curve_name(nid: cint): nil ptr EcKeyObj {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_free(k: nil ptr EcKeyObj) {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_generate_key(k: ptr EcKeyObj): cint {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_get0_group(k: ptr EcKeyObj): ptr EcGroupObj {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_get0_public_key(k: ptr EcKeyObj): nil ptr EcPointObj {.importc, header: "<openssl/ec_key.h>".}
proc EC_KEY_set_private_key(k: ptr EcKeyObj; priv: ptr BignumObj): cint {.importc, header: "<openssl/ec_key.h>".}
proc EC_POINT_new(g: ptr EcGroupObj): nil ptr EcPointObj {.importc, header: "<openssl/ec.h>".}
proc EC_POINT_free(p: nil ptr EcPointObj) {.importc, header: "<openssl/ec.h>".}
proc EC_POINT_oct2point(g: ptr EcGroupObj; p: ptr EcPointObj; buf: pointer; len: csize_t;
                        ctx: nil pointer): cint {.importc, header: "<openssl/ec.h>".}
proc EC_POINT_point2oct(g: ptr EcGroupObj; p: ptr EcPointObj; form: cint; buf: pointer; len: csize_t;
                        ctx: nil pointer): csize_t {.importc, header: "<openssl/ec.h>".}
proc ECDH_compute_key(outp: pointer; outLen: csize_t; peer: ptr EcPointObj; priv: ptr EcKeyObj;
                      kdf: nil pointer): cint {.importc, header: "<openssl/ecdh.h>".}
proc BN_bin2bn(inp: pointer; len: csize_t; ret: nil ptr BignumObj): nil ptr BignumObj {.importc, header: "<openssl/bn.h>".}
proc BN_clear_free(b: nil ptr BignumObj) {.importc, header: "<openssl/bn.h>".}
proc EVP_PKEY_CTX_new_id(id: cint; e: nil pointer): nil ptr EvpPkeyCtxObj {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_new(k: ptr EvpPkeyObj; e: nil pointer): nil ptr EvpPkeyCtxObj {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_free(c: nil ptr EvpPkeyCtxObj) {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_CTX_kem_set_params(c: ptr EvpPkeyCtxObj; nid: cint): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_keygen_init(c: ptr EvpPkeyCtxObj): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_keygen(c: ptr EvpPkeyCtxObj; k: ptr PkeyRef): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_free(k: nil ptr EvpPkeyObj) {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_get_raw_public_key(k: ptr EvpPkeyObj; outp: pointer; len: ptr csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_kem_new_raw_public_key(nid: cint; inp: pointer; len: csize_t): nil ptr EvpPkeyObj {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_encapsulate(c: ptr EvpPkeyCtxObj; ct: pointer; ctLen: ptr csize_t;
                          ss: pointer; ssLen: ptr csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EVP_PKEY_decapsulate(c: ptr EvpPkeyCtxObj; ss: pointer; ssLen: ptr csize_t;
                          ct: pointer; ctLen: csize_t): cint {.importc, header: "<openssl/evp.h>".}
proc EC_KEY_set_public_key(k: ptr EcKeyObj; p: ptr EcPointObj): cint {.importc, header: "<openssl/ec_key.h>".}
proc EC_POINT_mul(g: ptr EcGroupObj; r: ptr EcPointObj; n: ptr BignumObj; q: nil ptr EcPointObj;
                  m: nil ptr BignumObj; ctx: nil pointer): cint {.importc, header: "<openssl/ec.h>".}

proc clientShareLen*(g: KxGroup): int =
  case g
  of kxX25519: 32
  of kxSecp256r1: 65
  of kxX25519MlKem768: MlKemPub + 32

proc serverShareLen*(g: KxGroup): int =
  case g
  of kxX25519: 32
  of kxSecp256r1: 65
  of kxX25519MlKem768: MlKemCt + 32

proc secretLen*(g: KxGroup): int =
  case g
  of kxX25519, kxSecp256r1: 32
  of kxX25519MlKem768: 64

proc x25519Public*(priv, pub: Bytes) =
  X25519_public_from_private(pub, priv)

proc x25519*(priv, peer, secret: Bytes): bool =
  ## False for a low-order peer point (the all-zero secret).
  result = X25519(secret, priv, peer) == 1

proc ecdh(k: ptr EcKeyObj; peer: Bytes; secret: Bytes): bool =
  ## The shared x coordinate with `peer`, a 65-byte uncompressed point.
  result = false
  let g = EC_KEY_get0_group(k)
  let p = EC_POINT_new(g)
  if p == nil: return
  if EC_POINT_oct2point(g, p, peer, 65, nil) == 1:
    result = ECDH_compute_key(secret, 32, p, k, nil) == 32
  EC_POINT_free(p)

proc p256Shared*(priv: Bytes; peer: Bytes;
                 secret: Bytes): bool =
  ## The P-256 shared secret of a raw 32-byte private scalar and a 65-byte
  ## uncompressed point (test vectors).
  result = false
  let k = EC_KEY_new_by_curve_name(NidP256)
  if k == nil: return
  let bn = BN_bin2bn(priv, 32, nil)
  if bn != nil and EC_KEY_set_private_key(k, bn) == 1:
    result = ecdh(k, peer, secret)
  BN_clear_free(bn)
  EC_KEY_free(k)

proc clear*(k: var KxKey) =
  ## Wipe the private share. Safe to call twice.
  wipeBytes(addr k.x[0], k.x.len)
  EC_KEY_free(k.ec)
  k.ec = nil
  EVP_PKEY_free(k.kem)
  k.kem = nil

proc generate*(k: var KxKey; g: KxGroup; share: Bytes): bool =
  ## A fresh private share; its public part (`clientShareLen(g)` bytes) at `share`.
  clear(k)
  k.group = g
  result = false
  case g
  of kxX25519:
    X25519_keypair(share, addr k.x[0])
    result = true
  of kxSecp256r1:
    let ec = EC_KEY_new_by_curve_name(NidP256)
    if ec == nil: return
    k.ec = ec
    if EC_KEY_generate_key(ec) != 1: return
    let pub = EC_KEY_get0_public_key(ec)
    if pub == nil: return
    result = EC_POINT_point2oct(EC_KEY_get0_group(ec), pub, PointUncompressed, share, 65, nil) == 65
  of kxX25519MlKem768:
    let c = EVP_PKEY_CTX_new_id(EvpPkeyKem, nil)
    if c == nil: return
    var key: PkeyRef = nil
    if EVP_PKEY_CTX_kem_set_params(c, NidMlKem768) == 1 and EVP_PKEY_keygen_init(c) == 1 and
       EVP_PKEY_keygen(c, addr key) == 1 and key != nil:
      k.kem = key
      var n = csize_t(MlKemPub)
      if EVP_PKEY_get_raw_public_key(key, share, addr n) == 1 and n == csize_t(MlKemPub):
        X25519_keypair(addr share[MlKemPub], addr k.x[0])
        result = true
    EVP_PKEY_CTX_free(c)

proc complete*(k: var KxKey; peer: Bytes; peerLen: int;
               secret: Bytes): bool =
  ## The shared secret (`secretLen`) from the server's share.
  result = false
  if peerLen != serverShareLen(k.group): return
  case k.group
  of kxX25519:
    result = X25519(secret, addr k.x[0], peer) == 1
  of kxSecp256r1:
    let ec = k.ec
    if ec == nil: return
    result = ecdh(ec, peer, secret)
  of kxX25519MlKem768:
    let kem = k.kem
    if kem == nil: return
    let c = EVP_PKEY_CTX_new(kem, nil)
    if c == nil: return
    var n = csize_t(32)
    if EVP_PKEY_decapsulate(c, secret, addr n, peer, csize_t(MlKemCt)) == 1 and n == 32:
      result = X25519(addr secret[32], addr k.x[0], addr peer[MlKemCt]) == 1
    EVP_PKEY_CTX_free(c)
  if not result: wipeBytes(secret, secretLen(k.group))

proc respond*(g: KxGroup; peer: Bytes; peerLen: int;
              share, secret: Bytes): bool =
  ## Server: from the client's share, our share (`serverShareLen`) and the
  ## shared secret (`secretLen`), in one step.
  result = false
  if peerLen != clientShareLen(g): return
  var k = default(KxKey)
  case g
  of kxX25519, kxSecp256r1:
    # A P-256 server share has the client share's form (65-byte point).
    if generate(k, g, share): result = complete(k, peer, peerLen, secret)
  of kxX25519MlKem768:
    let pk = EVP_PKEY_kem_new_raw_public_key(NidMlKem768, peer, csize_t(MlKemPub))
    if pk == nil: return
    let c = EVP_PKEY_CTX_new(pk, nil)
    if c != nil:
      var ctLen = csize_t(MlKemCt)
      var ssLen = csize_t(32)
      if EVP_PKEY_encapsulate(c, share, addr ctLen, secret, addr ssLen) == 1 and
         ctLen == csize_t(MlKemCt) and ssLen == 32:
        X25519_keypair(addr share[MlKemCt], addr k.x[0])
        result = X25519(addr secret[32], addr k.x[0], addr peer[MlKemPub]) == 1
      EVP_PKEY_CTX_free(c)
    EVP_PKEY_free(pk)
  if not result: wipeBytes(secret, secretLen(g))
  clear(k)

proc setPrivate*(k: var KxKey; g: KxGroup; priv: Bytes;
                 share: Bytes): bool =
  ## A given private share (X25519 or P-256: 32 bytes) and its public part
  ## at `share`. For byte-exact tests (RFC 8448); never for real traffic.
  clear(k)
  k.group = g
  result = false
  case g
  of kxX25519:
    copyMem(addr k.x[0], priv, 32)
    X25519_public_from_private(share, addr k.x[0])
    result = true
  of kxSecp256r1:
    let ec = EC_KEY_new_by_curve_name(NidP256)
    if ec == nil: return
    k.ec = ec
    let bn = BN_bin2bn(priv, 32, nil)
    if bn == nil: return
    let grp = EC_KEY_get0_group(ec)
    let pub = EC_POINT_new(grp)
    if pub != nil and EC_KEY_set_private_key(ec, bn) == 1 and
       EC_POINT_mul(grp, pub, bn, nil, nil, nil) == 1 and EC_KEY_set_public_key(ec, pub) == 1:
      result = EC_POINT_point2oct(grp, pub, PointUncompressed, share, 65, nil) == 65
    EC_POINT_free(pub)
    BN_clear_free(bn)
  of kxX25519MlKem768:
    discard                          # ML-KEM keys come from a seed: not needed by the vectors

proc respondWith*(g: KxGroup; priv: Bytes; peer: Bytes;
                  peerLen: int; share, secret: Bytes): bool =
  ## `respond` with a given private share (X25519 or P-256): tests only.
  var k = default(KxKey)
  result = peerLen == clientShareLen(g) and setPrivate(k, g, priv, share) and
    complete(k, peer, peerLen, secret)
  clear(k)
