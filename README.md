# zal-tls

TLS 1.3 for Nimony, built on zal-net and AWS-LC.
Includes certificate verification, mTLS, resumption, ECH, QUIC handshake mode
and Linux kTLS adapters.

```nim
import std/syncio
import zal_net/rt
import zal_tls as tls

proc main() {.passive.} =
  try:
    let config = tls.newClientConfig(tls.systemTrust())
    let stream = tls.connect(config, "example.com", 443, deadline=afterMs(5000))
    defer: stream.close()
  except ErrorCode as error:
    echo error

discard runMain(main())
```

`zal_tls/engine` plugs the same TLS into `std/streamio` as its `TlsEngine`.
On Windows `systemTrust()` lets the system's chain engine judge first.

Use the compiler pinned by zal-net and `--mm:atomicArc`. `-d:useMimalloc` is optional.
See [build and ownership](docs/usage.md). MIT license.
