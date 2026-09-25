## kTLS (Linux): after our handshake the kernel seals and opens the
## records; a socket then carries plaintext through read and write.
## Control records (a KeyUpdate, an alert) go through `ktlsSendRecord`
## and come back from `ktlsRecv` with their type (a plain read fails with
## EIO at one). A KeyUpdate needs new kernel keys (`ktlsKeys` again: TLS
## 1.3 rekey; where the kernel lacks it the call fails and the connection
## must end). Elsewhere every proc answers `KtlsUnavailable`.

import zal_net/[errors, buffers]
import zal_tls/common
import zal_tls/crypto/aead
import zal_tls/keys/schedule
import zal_tls/crypto/rand

const
  KtlsUnavailable* = -95                 ## -EOPNOTSUPP: no kTLS on this system (the kernel's own
                                         ## refusals are -errno: -EINVAL for a suite it lacks)
  KtlsAgain* = -11                       ## nothing to read, or no room to send, yet (EAGAIN)

when defined(linux):
  {.compile: "nt_ktls.c".}
  proc ntUlp(fd: cint): cint {.importc: "nt_ktls_ulp".}
  proc ntSet(fd, tx, cipher: cint; key, iv: Bytes; seq: uint64): cint {.importc: "nt_ktls_set".}
  proc ntSend(fd, typ: cint; p: pointer; n: cint): cint {.importc: "nt_ktls_send".}
  proc ntRecv(fd: cint; p: pointer; n: cint; typ: ptr cint): cint {.importc: "nt_ktls_recv".}
  proc ntTxSeq(fd, cipher: cint): int64 {.importc: "nt_ktls_tx_seq".}

proc cipherOf(s: Suite): cint =
  case s
  of suiteAes128Gcm: 0.cint
  of suiteAes256Gcm: 1.cint
  of suiteChaCha20: 2.cint

proc ktlsAttach*(fd: cint): int =
  ## Put the kernel's TLS layer on a connected TCP socket (once): 0 or -errno.
  when defined(linux): result = int(ntUlp(fd))
  else: result = KtlsUnavailable

proc ktlsKeys*(fd: cint; tx: bool; suite: Suite; secret: Secret; seq: uint64): int =
  ## The kernel's keys for one direction from a traffic secret, from record
  ## `seq` on: 0 or -errno (after a first install: a TLS 1.3 rekey).
  when defined(linux):
    var key = default(array[32, byte])
    var iv = default(array[12, byte])
    if trafficKeys(suite, secret, ptrOf(key), ptrOf(iv)):
      let dir: cint = if tx: 1 else: 0
      result = int(ntSet(fd, dir, cipherOf(suite), ptrOf(key), ptrOf(iv), seq))
    else:
      result = -22
    wipeBytes(addr key[0], key.len)
    wipeBytes(addr iv[0], iv.len)
  else:
    result = KtlsUnavailable

proc ktlsSendRecord*(fd: cint; ctype: int; p: nil pointer; n: int): int =
  ## One record of `ctype` (22 handshake, 21 alert), non-blocking: the
  ## bytes taken, `KtlsAgain`, or -errno.
  if n < 0 or n > int(high(cint)): return InvalidInput
  if n == 0: return 0
  if p == nil: return InvalidInput
  when defined(linux): result = int(ntSend(fd, cint(ctype), p, cint(n)))
  else: result = KtlsUnavailable

proc ktlsRecv*(fd: cint; p: nil pointer; n: int; ctype: var int): int =
  ## Plaintext of the next record (up to n bytes) and its type, non-
  ## blocking: > 0, 0 at the end of the stream, `KtlsAgain`, or -errno.
  ctype = 0
  if n < 0 or n > int(high(cint)): return InvalidInput
  if n == 0: return 0
  if p == nil: return InvalidInput
  when defined(linux):
    var t: cint = 23
    result = int(ntRecv(fd, p, cint(n), addr t))
    ctype = int(t)
  else:
    ctype = 0
    result = KtlsUnavailable

proc ktlsTxSeq*(fd: cint; suite: Suite): int64 =
  ## The kernel's next send sequence number (its keys are for `suite`), or -errno.
  when defined(linux): result = ntTxSeq(fd, cipherOf(suite))
  else: result = KtlsUnavailable

proc ktlsSendRecord*(fd: cint; ctype: int; bytes: openArray[byte]): int =
  ## Immediate nonblocking syscall; the byte window is borrowed only for this call.
  result = ktlsSendRecord(fd, ctype, dataPtr(bytes), bytes.len)

proc ktlsRecv*(fd: cint; bytes: var openArray[byte]; ctype: var int): int =
  result = ktlsRecv(fd, dataPtr(bytes), bytes.len, ctype)
