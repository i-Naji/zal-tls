## HPKE (RFC 9180) base mode from AWS-LC: DHKEM(X25519, HKDF-SHA256),
## HKDF-SHA256, AES-128-GCM, the suite ECH uses first.

import zal_tls/common
import zal_tls/crypto/awslc

type
  HpkeCtxC {.importc: "EVP_HPKE_CTX", header: "<openssl/hpke.h>".} = object
  HpkeKeyC {.importc: "EVP_HPKE_KEY", header: "<openssl/hpke.h>".} = object
  HpkeKem {.importc: "EVP_HPKE_KEM", header: "<openssl/hpke.h>", incompleteStruct.} = object
  HpkeKdf {.importc: "EVP_HPKE_KDF", header: "<openssl/hpke.h>", incompleteStruct.} = object
  HpkeAead {.importc: "EVP_HPKE_AEAD", header: "<openssl/hpke.h>", incompleteStruct.} = object

  HpkeCtx* = object
    ## One HPKE context (a sender's or a recipient's). `clear` wipes it.
    ## Owns C state: pass by `var` or pointer, never copy (c35).
    ctx: HpkeCtxC
    live: bool

proc `=copy`(dst: var HpkeCtx; src: HpkeCtx) {.error.}

const HpkeEncLen* = 32

proc EVP_hpke_x25519_hkdf_sha256(): ptr HpkeKem {.importc, header: "<openssl/hpke.h>".}
proc EVP_hpke_hkdf_sha256(): ptr HpkeKdf {.importc, header: "<openssl/hpke.h>".}
proc EVP_hpke_aes_128_gcm(): ptr HpkeAead {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_zero(c: ptr HpkeCtxC) {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_cleanup(c: ptr HpkeCtxC) {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_KEY_zero(k: ptr HpkeKeyC) {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_KEY_cleanup(k: ptr HpkeKeyC) {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_KEY_init(k: ptr HpkeKeyC; kem: ptr HpkeKem; priv: pointer; len: csize_t): cint {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_setup_sender(c: ptr HpkeCtxC; enc: pointer; encLen: ptr csize_t; maxEnc: csize_t;
    kem: ptr HpkeKem; kdf: ptr HpkeKdf; aead: ptr HpkeAead; peer: pointer; peerLen: csize_t;
    info: pointer; infoLen: csize_t): cint {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_setup_sender_with_seed_for_testing(c: ptr HpkeCtxC; enc: pointer; encLen: ptr csize_t;
    maxEnc: csize_t; kem: ptr HpkeKem; kdf: ptr HpkeKdf; aead: ptr HpkeAead; peer: pointer;
    peerLen: csize_t; info: pointer; infoLen: csize_t; seed: pointer; seedLen: csize_t): cint {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_setup_recipient(c: ptr HpkeCtxC; key: ptr HpkeKeyC; kdf: ptr HpkeKdf;
    aead: ptr HpkeAead; enc: pointer; encLen: csize_t; info: pointer; infoLen: csize_t): cint {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_seal(c: ptr HpkeCtxC; outp: pointer; outLen: ptr csize_t; maxOut: csize_t;
    inp: pointer; inLen: csize_t; ad: pointer; adLen: csize_t): cint {.importc, header: "<openssl/hpke.h>".}
proc EVP_HPKE_CTX_open(c: ptr HpkeCtxC; outp: pointer; outLen: ptr csize_t; maxOut: csize_t;
    inp: pointer; inLen: csize_t; ad: pointer; adLen: csize_t): cint {.importc, header: "<openssl/hpke.h>".}

proc clear*(h: var HpkeCtx) =
  ## Wipe the context. Safe to call twice.
  if h.live: EVP_HPKE_CTX_cleanup(addr h.ctx)
  h.live = false

proc setupSender*(h: var HpkeCtx; peerPub: Bytes; info: Bytes;
                  infoLen: int; enc: Bytes): bool =
  ## A sender to `peerPub` (32 bytes); the encapsulated key (HpkeEncLen) at `enc`.
  clear(h)
  EVP_HPKE_CTX_zero(addr h.ctx)
  var n: csize_t = 0
  h.live = EVP_HPKE_CTX_setup_sender(addr h.ctx, enc, addr n, csize_t(HpkeEncLen), EVP_hpke_x25519_hkdf_sha256(),
      EVP_hpke_hkdf_sha256(), EVP_hpke_aes_128_gcm(), peerPub, 32, info, csize_t(infoLen)) == 1
  result = h.live and n == csize_t(HpkeEncLen)

proc setupSenderSeeded*(h: var HpkeCtx; peerPub, info: Bytes; infoLen: int;
                        seed: Bytes; seedLen: int; enc: Bytes): bool =
  ## Tests only: the ephemeral key from `seed` (the RFC's skEm).
  clear(h)
  EVP_HPKE_CTX_zero(addr h.ctx)
  var n: csize_t = 0
  h.live = EVP_HPKE_CTX_setup_sender_with_seed_for_testing(addr h.ctx, enc, addr n, csize_t(HpkeEncLen),
      EVP_hpke_x25519_hkdf_sha256(), EVP_hpke_hkdf_sha256(), EVP_hpke_aes_128_gcm(), peerPub, 32,
      info, csize_t(infoLen), seed, csize_t(seedLen)) == 1
  result = h.live and n == csize_t(HpkeEncLen)

proc setupRecipient*(h: var HpkeCtx; priv, enc, info: Bytes; infoLen: int): bool =
  ## A recipient with private key `priv` (32 bytes) for the sender's `enc`.
  clear(h)
  EVP_HPKE_CTX_zero(addr h.ctx)
  var key = default(HpkeKeyC)
  EVP_HPKE_KEY_zero(addr key)
  if EVP_HPKE_KEY_init(addr key, EVP_hpke_x25519_hkdf_sha256(), priv, 32) == 1:
    h.live = EVP_HPKE_CTX_setup_recipient(addr h.ctx, addr key, EVP_hpke_hkdf_sha256(),
        EVP_hpke_aes_128_gcm(), enc, csize_t(HpkeEncLen), info, csize_t(infoLen)) == 1
  EVP_HPKE_KEY_cleanup(addr key)
  result = h.live

proc seal*(h: var HpkeCtx; pt: Bytes; ptLen: int; aad: Bytes;
           aadLen: int; ct: Bytes; ctCap: int; ctLen: var int): bool =
  var n: csize_t = 0
  result = h.live and EVP_HPKE_CTX_seal(addr h.ctx, ct, addr n, csize_t(ctCap), pt, csize_t(ptLen),
                                        aad, csize_t(aadLen)) == 1
  ctLen = int(n)

proc open*(h: var HpkeCtx; ct: Bytes; ctLen: int; aad: Bytes;
           aadLen: int; pt: Bytes; ptCap: int; ptLen: var int): bool =
  var n: csize_t = 0
  result = h.live and EVP_HPKE_CTX_open(addr h.ctx, pt, addr n, csize_t(ptCap), ct, csize_t(ctLen),
                                        aad, csize_t(aadLen)) == 1
  ptLen = int(n)
