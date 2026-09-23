## SHA-256 and SHA-384 from AWS-LC, allocation free. A `Hash` is plain
## data: a copy is a snapshot (the handshake transcript needs them).

import zal_tls/common
import zal_tls/crypto/awslc

type
  Sha256Ctx {.importc: "SHA256_CTX", header: "<openssl/sha.h>".} = object
  Sha512Ctx {.importc: "SHA512_CTX", header: "<openssl/sha.h>".} = object

  HashAlg* = enum
    hashSha256, hashSha384

  Hash* = object
    alg*: HashAlg
    s256: Sha256Ctx
    s512: Sha512Ctx          # SHA-384 runs on SHA-512's state

proc SHA256_Init(c: ptr Sha256Ctx): cint {.importc, header: "<openssl/sha.h>".}
proc SHA256_Update(c: ptr Sha256Ctx; p: pointer; n: csize_t): cint {.importc, header: "<openssl/sha.h>".}
proc SHA256_Final(md: pointer; c: ptr Sha256Ctx): cint {.importc, header: "<openssl/sha.h>".}
proc SHA384_Init(c: ptr Sha512Ctx): cint {.importc, header: "<openssl/sha.h>".}
proc SHA384_Update(c: ptr Sha512Ctx; p: pointer; n: csize_t): cint {.importc, header: "<openssl/sha.h>".}
proc SHA384_Final(md: pointer; c: ptr Sha512Ctx): cint {.importc, header: "<openssl/sha.h>".}

proc digestLen*(alg: HashAlg): int =
  case alg
  of hashSha256: 32
  of hashSha384: 48

proc init*(h: var Hash; alg: HashAlg) =
  h.alg = alg
  case alg
  of hashSha256: discard SHA256_Init(addr h.s256)
  of hashSha384: discard SHA384_Init(addr h.s512)

proc update*(h: var Hash; p: Bytes; n: int): bool {.discardable.} =
  ## Negative lengths are rejected without advancing the hash. Empty input
  ## succeeds without touching the borrowed buffer.
  ## Explicitly discard unused results: the pinned compiler can drop an
  ## implicit discardable call when it is the last statement of a branch.
  if n < 0: return false
  if n == 0: return true
  case h.alg
  of hashSha256: result = SHA256_Update(addr h.s256, p, csize_t(n)) == 1
  of hashSha384: result = SHA384_Update(addr h.s512, p, csize_t(n)) == 1

proc final*(h: var Hash; outp: Bytes) =
  ## The digest (`digestLen` bytes); `h` must be `init` again before reuse.
  case h.alg
  of hashSha256: discard SHA256_Final(outp, addr h.s256)
  of hashSha384: discard SHA384_Final(outp, addr h.s512)

proc peek*(h: Hash; outp: Bytes) =
  ## The digest of what was hashed so far; `h` goes on.
  var c = h
  final(c, outp)
