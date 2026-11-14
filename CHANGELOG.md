# Changelog

## Unreleased

- Initial standard-runtime package.
- Use the zal-net checkpoint for Nimony `0a48dbd4`.
- Use Nimony `d5fc40e3` and synchronize the retained TLS writer gate.
- Use the zal-net checkpoint for Nimony `aa01546a`.
- Use the zal-net checkpoint for Nimony `d5396682`.
- Use bounded passive resumptions and completion draining from zal-net.
- Retry kTLS attach after a failed key install and read connection state under its lock.
- Scope tickets per built server configuration and wipe key-exchange secrets on failure.
- Use the zal-net checkpoint for Nimony `2593bf85`.
- Let Windows' chain engine judge chains against the system trust first.
- Plug zal-tls into `std/streamio` as a `TlsEngine` (`zal_tls/engine`).
- `connect` can send the first request, as 0-RTT when a ticket allows.
- Add a standing deadline to TLS streams (`deadline`, `renew`).
- A TLS stream dropped without close still sends close_notify when the socket takes it at once.
- Use the zal-net checkpoint for Nimony `c923e3c9`.
- TLS owners close with `retire` and half-close with `halfClose`; `close` and `shutdownWrite` are the raising forms of the TLS stream.
- scripts/test.sh and scripts/test.ps1 pass zal-net to the compiler as an absolute path.
- Use the zal-net checkpoint for Nimony `0da5a6b7`; the tests import net/tcp as `tcp` again.
- Use the zal-net checkpoint for Nimony `941d128a`.
- Use the zal-net checkpoint for Nimony `288097b1`.
- Use the zal-net checkpoint for Nimony `ee549766`.
- Use the zal-net checkpoint for Nimony `abeb5082`.
- Use the zal-net checkpoint for Nimony `4ba90a78`.
- A writer no longer retries forever when a key update is owed on a failed or closed connection.
- `import zal_tls` puts TLS on zal-net's `Conn`: `connect` returns a secured `Conn`, and `secure` secures one that is connected or accepted. The `TlsStream` application type and the `foundation` owner tier are gone.
- `secure` works on a `Conn` that already has a layer, so TLS runs inside another tunnel or over a layer of the program's own.
- The result-returning configuration constructors in `config/owned` are `tryNewClientConfig` and `tryNewServerConfig`.
- The stream tests run on a secured `Conn`; `tests/interop.sh` and its Go peer are removed, because the programs it drove are not in this repository.

### Moving from the old API

| Old | New |
| --- | --- |
| `tls.connect(config, host, port, serverName = n, deadline = d)` returning a `TlsStream` | `connect(config, host, port, n, d)` returning a `Conn` |
| `tls.connect(config, host, port, request, ...)` | `connect(config, host, port, request, ...)` |
| `wrapOwned(config, tcpStream, ...)`, `wrapBorrowed(config, stream, ...)` | `secure(c, config, serverName, dl)` or `secure(c, serverConfig, dl)` on a `Conn` |
| `stream.read(buf, deadline = d)`, `stream.write(buf, deadline = d)` | `c.read(buf, d)`, `c.write(buf, d)`, and the rest of the `Conn` operations |
| `stream.close()`, `stream.shutdownWrite()` | `close c` or the end of its scope; `c.shutdownWrite()` |
| `deadline(stream)`, `renew(stream, d)` | `renew(c, d)` |
| `negotiatedProtocol(stream)` | `negotiatedProtocol(c)`; also `isSecure`, `resumed`, `earlyBytes` |
| `lastReadFailure`, `lastWriteFailure` | the raised `ErrorCode` |
| a `cancel` token per call | the connection's token, `cancelToken(c)`, or the `stop` token given to `connect` |
| `zal_tls/foundation` (`TlsConnRef`, `connectTlsConn`, `takeTlsClient`, `borrowTlsServer`, `retire`, `halfClose`), `net/tlsview` (`tlsTransport`), `net/scoped` (`withTls`) | a secured `Conn`, or `TlsStream` from `zal_tls/raw` |
| `wrapClient`, `wrapServer`, `takeClient`, `takeServer` over a `Transport` in `raw/stream` | `secure` over a layer installed on a `Conn`, or `unsafeWrapClient` and `unsafeWrapServer` over a `StreamView` |
| `newClientConfig`, `newServerConfig` in `config/owned`, returning a result | `tryNewClientConfig`, `tryNewServerConfig`; the raising pair comes from `zal_tls` |
