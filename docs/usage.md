# Usage

## Building and testing

Place zal-net beside this checkout, or set `ZAL_NET_DIR`.
Build AWS-LC with `scripts/awslc-setup.sh`; `ci/aws-lc.ref` pins its source.
Use the same unchanged Nimony revision as zal-net.

```sh
NIMONY=../zal-net/build/toolchain/bin/nimony scripts/test.sh
NIMONY=../zal-net/build/toolchain/bin/nimony SUITE=full scripts/test.sh
```

`scripts/test.sh` builds zal-net's `tools/tester.nim` and runs it; that file
describes the rules. Tests live in `tests/<category>/t*.nim`.
`TESTS="tests/stream wire/tbytes"` picks categories or tests, `SUITE=stress`
runs the heap and fuzz cases, `SUITE=platform` the kTLS cases, `WORKERS="1 4"`
runs every program at both worker counts.

`AWSLC` selects an existing AWS-LC installation. Windows uses the PowerShell
setup and test scripts. `scripts/test-ktls.sh` requires native Linux kTLS.
Generated output stays under ignored `build/` directories.

## TLS on a Conn

`import zal_net, zal_tls` gives a program TLS on zal-net's `Conn`:

- `newClientConfig(trust, alpn)` and `newServerConfig(certPem, keyPem, alpn)`
  build a configuration once for every connection that uses it. They raise
  `ValueError` for PEM that does not parse, a key that does not match its
  certificate, a trust source without certificates, or an empty protocol
  name. A client needs a trust source and there is no default: `systemTrust()`,
  `pemTrust(pem)` or `storeTrust(roots)`.
- `connect(config, host, port, serverName, dl, stop)` connects and runs the
  handshake within `dl`. `connect(config, host, port, request, ...)` also
  sends `request`, as 0-RTT when the configuration holds a ticket that
  allows it.
- `secure(c, config, serverName, dl)` runs the client handshake on a
  connected `Conn`, `secure(c, serverConfig, dl)` the server handshake on an
  accepted one. `trySecure` returns the failure as a code, for callers that
  cannot raise.

After the handshake the connection's own operations read and write
plaintext: `read`, `readLine`, `fill`, `peek`, `consume`, `write`, `flush`,
`shutdownWrite`, `renew` and `close`. Under `serve`, a handler calls
`secure` first and is written as for a plain connection after that.
`isSecure`, `negotiatedProtocol` (ALPN), `resumed` and, on a server,
`earlyBytes` describe the session.

A failed handshake raises `ProtocolError` for a TLS failure, `TimeoutError`
at the deadline or `AbortedOperation` when the token was cancelled, and
leaves the connection closed. A read or write deadline that passes leaves
the connection usable, as long as no record was cut in half. Cancelling
`cancelToken(c)`, or the `stop` token passed to `connect`, ends the
connection's waits with `AbortedOperation` and shuts the socket down: the
peer reads a cut stream, not close_notify.

`shutdownWrite` sends close_notify after the records already written. A
connection that is closed or goes out of scope without it still sends
close_notify when the socket takes it at once, so the peer can tell a
finished stream from a cut one. When TLS sits on another layer (TLS inside
TLS, or a layer of your own) only `shutdownWrite` sends it.

`secure` on a connection that already has a layer keeps that layer
underneath and sends its records through it: that is TLS inside a tunnel,
or TLS over a layer of your own installed with zal-net's `install`.
`examples/customstream.nim` counts the bytes that cross the socket that way.

The configurations from `zal_tls` keep no session store and no ticketer, so
they neither resume nor take 0-RTT. To turn that on, set the fields of the
raw configuration through `unsafeBorrowConfig` (`zal_tls/config/owned`)
before the first connection, as `tests/stream/tconnresume.nim` does.
0-RTT can be replayed by an attacker: send only idempotent requests that way.

## The raw tier

`zal_tls/raw` is the `TlsStream` the `Conn` layer is built on: `connectTls`
and `acceptTls` over a socket, `takeClient` over a connected one,
`unsafeWrapClient` and `unsafeWrapServer` over a `StreamView` that must
outlive the stream. `zal_tls/record` and `zal_tls/handshake` are the
protocol state machines without sockets, `zal_tls/raw/relay` the relay
framer, `zal_tls/raw/ktls` and `zal_tls/raw/splice` the Linux kTLS paths.
Configurations there are the raw `ClientConfig` and `ServerConfig` objects,
whose resources the caller keeps alive.

One reader and one writer may use a raw stream at once. Writes and control
records keep record order. Locks cover bounded state changes and are
released before waits. A partial record that fails makes the stream
unusable; do not replay it. QUIC mode is a handshake API, not a QUIC
transport. Certificate verification is enabled.

Platform availability is checked by native tests. AWS-LC is a separate dependency
with its own licenses; it is not vendored here.

## The std/streamio engine

The `std/streamio` engine keeps at most two records of unprocessed network
input. Its default output queues follow the standard stream's draining policy.
The current standard driver consumes a whole write before draining ciphertext
and does not retry partial receive input.

A custom driver can set `newTlsEngine(config, pendingLimit=65536)` to bound
each output queue. Retry the suffix reported by `used`, drain `appOut` and
`recordsOut` between calls, and drain records before calling `close`.
A zero `used` means the queues need draining. The limit must fit one maximum
record plus control output; 64 KiB is sufficient. Do not enable this limit
when passing the engine to the current `std/streamio` driver.
