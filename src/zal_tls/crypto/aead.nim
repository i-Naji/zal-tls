## AEAD from AWS-LC (EVP_AEAD): AES-128-GCM, AES-256-GCM and
## ChaCha20-Poly1305, sealed and opened in place with the 16-byte tag at a
## place the caller chooses (a TLS record keeps it after the ciphertext).

import zal_tls/common
import zal_tls/crypto/awslc
import zal_tls/crypto/rand

type
  EvpAead {.importc: "EVP_AEAD", header: "<openssl/aead.h>", incompleteStruct.} = object
  EvpAeadCtx {.importc: "EVP_AEAD_CTX", header: "<openssl/aead.h>".} = object

  AeadAlg* = enum
    aeadAes128Gcm, aeadAes256Gcm, aeadChaCha20Poly1305

  Aead* = object
    ## One key. Embeddable; call `clear` before it goes away.
    ## Owns C state: pass by `var` or pointer, never copy (c35).
    ctx: EvpAeadCtx
    alg*: AeadAlg
    live: bool

proc `=copy`(dst: var Aead; src: Aead) {.error.}

const
  AeadTagLen* = 16
  AeadNonceLen* = 12

proc EVP_aead_aes_128_gcm(): ptr EvpAead {.importc, header: "<openssl/aead.h>".}
proc EVP_aead_aes_256_gcm(): ptr EvpAead {.importc, header: "<openssl/aead.h>".}
proc EVP_aead_chacha20_poly1305(): ptr EvpAead {.importc, header: "<openssl/aead.h>".}
proc EVP_AEAD_CTX_init(ctx: ptr EvpAeadCtx; aead: ptr EvpAead; key: pointer; keyLen: csize_t;
                       tagLen: csize_t; impl: nil pointer): cint {.importc, header: "<openssl/aead.h>".}
proc EVP_AEAD_CTX_cleanup(ctx: ptr EvpAeadCtx) {.importc, header: "<openssl/aead.h>".}
proc EVP_AEAD_CTX_seal_scatter(ctx: ptr EvpAeadCtx; outp, outTag: pointer; outTagLen: ptr csize_t;
                               maxOutTagLen: csize_t; nonce: pointer; nonceLen: csize_t;
                               inp: pointer; inLen: csize_t; extraIn: nil pointer; extraInLen: csize_t;
                               ad: nil pointer; adLen: csize_t): cint {.importc, header: "<openssl/aead.h>".}
proc EVP_AEAD_CTX_open_gather(ctx: ptr EvpAeadCtx; outp: pointer; nonce: pointer; nonceLen: csize_t;
                              inp: pointer; inLen: csize_t; inTag: pointer; inTagLen: csize_t;
                              ad: nil pointer; adLen: csize_t): cint {.importc, header: "<openssl/aead.h>".}

proc keyLen*(alg: AeadAlg): int =
  case alg
  of aeadAes128Gcm: 16
  of aeadAes256Gcm, aeadChaCha20Poly1305: 32

proc clear*(a: var Aead) =
  ## Wipe the key. Safe to call twice.
  if a.live: EVP_AEAD_CTX_cleanup(addr a.ctx)
  wipeBytes(addr a.ctx, sizeof(a.ctx))
  a.live = false

proc init*(a: var Aead; alg: AeadAlg; key: Bytes; keyLen: int): bool =
  ## False for a key of the wrong length.
  clear(a)
  a.alg = alg
  if keyLen != keyLen(alg): return false
  let impl = case alg
    of aeadAes128Gcm: EVP_aead_aes_128_gcm()
    of aeadAes256Gcm: EVP_aead_aes_256_gcm()
    of aeadChaCha20Poly1305: EVP_aead_chacha20_poly1305()
  a.live = EVP_AEAD_CTX_init(addr a.ctx, impl, key, csize_t(keyLen), csize_t(AeadTagLen), nil) == 1
  result = a.live
  if not result: wipeBytes(addr a.ctx, sizeof(a.ctx))

proc sealInPlace*(a: var Aead; nonce, buf: Bytes; len: int;
                  tag: Bytes; ad: nil Bytes; adLen: int): bool =
  ## Encrypt buf[0 ..< len] in place; the tag goes to tag[0 ..< AeadTagLen].
  ## Invalid dimensions cause no writes; all pointers borrow live storage.
  if not a.live or len < 0 or adLen < 0: return false
  if adLen > 0 and ad == nil: return false
  var tagLen: csize_t = 0
  result = EVP_AEAD_CTX_seal_scatter(addr a.ctx, buf, tag, addr tagLen, csize_t(AeadTagLen),
                              nonce, csize_t(AeadNonceLen), buf, csize_t(len), nil, 0,
                              ad, csize_t(adLen)) == 1 and
    tagLen == csize_t(AeadTagLen)

proc openInPlace*(a: var Aead; nonce, buf: Bytes; len: int;
                  tag: Bytes; ad: nil Bytes; adLen: int): bool =
  ## Decrypt buf[0 ..< len] in place when the tag checks. False otherwise;
  ## valid output is wiped on authentication failure. Invalid dimensions cause
  ## no writes; all pointers borrow live storage.
  if not a.live or len < 0 or adLen < 0: return false
  if adLen > 0 and ad == nil: return false
  result = EVP_AEAD_CTX_open_gather(addr a.ctx, buf, nonce, csize_t(AeadNonceLen), buf, csize_t(len),
                             tag, csize_t(AeadTagLen), ad, csize_t(adLen)) == 1
