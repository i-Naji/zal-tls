## Short-lived secret export for the kernel adapter. No secret escapes this call.
import zal_tls/private/core/conn
import zal_tls/keys/schedule
import zal_tls/raw/ktls

proc installKernelKeys*(c: var TlsConn; fd: cint; forWrite: bool): int =
  var secret = default(Secret)
  var sequence = 0'u64
  if not exportTrafficSecret(c, forWrite, secret, sequence): return -22
  result = ktlsKeys(fd, forWrite, suite(c), secret, sequence)
  wipe(secret)
