# zal-tls

TLS 1.3 for Nimony, built on zal-net and AWS-LC.
Includes certificate verification, mTLS, resumption, ECH, QUIC handshake mode
and Linux kTLS adapters.

```nim
import std/syncio
import zal_net
import zal_tls

proc main() {.passive.} =
  try:
    let config = newClientConfig(systemTrust())
    var c = connect(config, "example.com", 443, dl = afterMs(5000))
    c.renew afterMs(5000)
    c.write "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
    echo c.readLine()
  except ErrorCode as error:
    echo error

discard runMain(main())
```

`connect` returns a zal-net `Conn` with TLS on it, and `secure` puts TLS on
a `Conn` you already have, accepted ones included. `examples/tlsecho.nim` is
a server. `zal_tls/raw` has the stream, record layer, relay framer and kTLS
underneath, and `zal_tls/engine` plugs the same TLS into `std/streamio` as
its `TlsEngine`. On Windows `systemTrust()` lets the system's chain engine
judge first.

Use the compiler pinned by zal-net and `--mm:atomicArc`. `-d:useMimalloc` is optional.
See [usage](docs/usage.md). MIT license.
