# TLS 1.3 for zal-net connections.
#
#   import zal_net, zal_tls
#
#   let config = newClientConfig(systemTrust())
#   var c = connect(config, "example.com", 443, dl = afterMs(5_000))
#   c.write "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
#
#   let serverConfig = newServerConfig(certPem, keyPem)
#   var s = accept(listener)
#   s.secure(serverConfig, afterMs(5_000))
#
# A secured connection is still a `Conn`: `read`, `readLine`, `write`,
# `flush`, deadlines and `serve` work as they do on a plain one.
#
# A configuration is built once and shared by every connection that uses
# it. A client configuration needs a trust source, and there is no default:
# `systemTrust()` for the machine's roots, `pemTrust(pem)` for your own.
#
# Protocol libraries that need the record layer, the relay framer, kTLS or a
# handshake they drive themselves import `zal_tls/raw`.
#
# Do not import this module as `tls`: Nimony confuses the alias with the
# re-exported module (zal-net tests/compiler c43/c44).

import zal_net/buffers
import zal_net/errors as neterrors
import zal_net/net/failure
import zal_tls/secure
import zal_tls/config/owned as configs
import zal_tls/errors

export secure
export configs.TrustSource, configs.pemTrust, configs.systemTrust, configs.storeTrust

type
  ClientConfig* = configs.ClientConfigRef
  ServerConfig* = configs.ServerConfigRef

proc newClientConfig*(trust: TrustSource; alpn: seq[string] = @[]): ClientConfig {.raises.} =
  ## What a client needs for every connection it makes: whom to trust and
  ## which protocols to offer. Raises when the trust source cannot be loaded.
  let built = configs.tryNewClientConfig(trust, alpn)
  checkTls(built.code)
  let value = built.value
  if value == nil: failIo(neterrors.ResourceClosed)
  result = value

proc newServerConfig*(certPem, keyPem: string; alpn: seq[string] = @[]): ServerConfig {.raises.} =
  ## A server's certificate chain and key, both as PEM text. Raises when
  ## either does not parse or they do not belong together.
  let built = configs.tryNewServerConfig(certPem, keyPem, alpn)
  checkTls(built.code)
  let value = built.value
  if value == nil: failIo(neterrors.ResourceClosed)
  result = value

proc connect*(config: ClientConfig; host: string; port: uint16; serverName = "";
              dl: Deadline = never; stop: nil CancelToken = nil): Conn {.passive, raises.} =
  ## Connect and run the handshake, all within `dl`. The certificate is
  ## checked against `serverName`, or against `host` when that is empty.
  result = connect(host, port, dl, stop)
  secure(result, config, (if serverName.len > 0: serverName else: host), dl)

proc connect*(config: ClientConfig; host: string; port: uint16; request: openArray[byte];
              serverName = ""; dl: Deadline = never;
              stop: nil CancelToken = nil): Conn {.passive, raises.} =
  ## Connect and send `request` before returning. With a resumable session
  ## and `earlyData` on the configuration it goes as 0-RTT, which an attacker
  ## can replay: idempotent requests only.
  result = connect(host, port, dl, stop)
  let code = trySecure(result, config, (if serverName.len > 0: serverName else: host),
                       dl, dataPtr(request), request.len)
  checkTls(code)
