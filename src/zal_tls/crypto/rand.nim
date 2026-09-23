## Random bytes from AWS-LC.

import zal_tls/common
import zal_tls/crypto/awslc

proc RAND_bytes(buf: pointer; n: csize_t): cint {.importc, header: "<openssl/rand.h>".}

proc OPENSSL_cleanse(p: pointer; n: csize_t) {.importc, header: "<openssl/mem.h>".}

proc wipeBytes*(p: pointer; n: int) =
  ## Zero `n` bytes in a way the compiler cannot drop (secrets).
  ## Nonpositive lengths cause no writes. Positive lengths require live storage.
  if n <= 0: return
  OPENSSL_cleanse(p, csize_t(n))

proc randomBytes*(p: Bytes; n: int): bool =
  ## Borrow n writable bytes. Invalid lengths are rejected without writes;
  ## entropy failure wipes the output. Empty requests do not ask for entropy.
  if n < 0: return false
  if n == 0: return true
  result = RAND_bytes(p, csize_t(n)) == 1
  if not result: wipeBytes(p, n)

proc CRYPTO_memcmp(a, b: pointer; n: csize_t): cint {.importc, header: "<openssl/mem.h>".}

proc ctEqual*(a, b: pointer; n: int): bool =
  ## Equal bytes, compared in constant time (Finished, binders).
  if n < 0: return false
  if n == 0: return true
  result = CRYPTO_memcmp(a, b, csize_t(n)) == 0

type Timespec {.importc: "struct timespec", header: "<time.h>".} = object
  tv_sec: int64
  tv_nsec: clong
proc timespec_get(ts: ptr Timespec; base: cint): cint {.importc, header: "<time.h>".}

proc unixMs*(): int64 =
  ## Wall-clock milliseconds since 1970 (C11 timespec_get: POSIX and Windows).
  var ts = default(Timespec)
  discard timespec_get(addr ts, 1)          # TIME_UTC
  result = ts.tv_sec * 1000 + int64(ts.tv_nsec) div 1_000_000

type EntropySource* = nil proc (p: Bytes; n: int): bool {.nimcall.}
  ## Fill every byte or return false. Caller must fail the operation on failure.

proc randomFill*(source: EntropySource; p: Bytes; n: int): bool =
  if n < 0: return false
  if n == 0: return true
  if source != nil: result = source(p, n)
  else: return randomBytes(p, n)
  if not result: wipeBytes(p, n)
