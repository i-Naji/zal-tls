## TLS diagnostic descriptions. I/O retains its allocation-free integer result.
import zal_net/errors as neterrors
import zal_net/net/failure

const
  TlsErrorBase* = -200_000
  TlsAlertBase* = -201_000
  TlsFailed* = TlsAlertBase     ## TlsFailed - alert: handshake or record failure
  TlsEof* = TlsErrorBase - 1    ## the peer closed during the handshake
  TlsTruncated* = TlsErrorBase - 2 ## transport ended without close_notify
  TlsEarlyNotSent* = TlsErrorBase - 3
    ## Connected, but rejected 0-RTT was not replayed because the negotiated
    ## application protocol differs from the ticket's protocol.
  TlsEchRejected* = TlsErrorBase - 4
    ## Authenticated ECH rejection by the public-name server. Retry configs
    ## remain available through echRetryConfigs until close. A received
    ## ech_required alert instead returns TlsFailed - alEchRequired.
  TlsClosed* = -32             ## EPIPE: send after shutdownWrite

proc tlsAlert*(code: int): int =
  if code <= TlsFailed and code > TlsFailed - 256:
    result = TlsFailed - code
  else:
    result = 0

proc describe*(code: int): string =
  let alert = tlsAlert(code)
  if code <= TlsFailed and code > TlsFailed - 256:
    return "TLS alert " & $alert
  case code
  of TlsEof: result = "peer closed during TLS handshake"
  of TlsTruncated: result = "TLS transport ended without close_notify"
  of TlsEarlyNotSent: result = "TLS early data was not sent"
  of TlsEchRejected: result = "TLS encrypted ClientHello rejected"
  else: result = neterrors.describe(code)

proc errorKind*(code: int): ErrorCode =
  if code <= TlsErrorBase and code >= TlsAlertBase - 255: ProtocolError
  else: failure.errorKind(code)

proc checkTls*(code: int) {.raises.} =
  if code < 0: raise errorKind(code)
