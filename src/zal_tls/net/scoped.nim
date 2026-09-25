## Optional scoped TLS ownership, drained in the caller's passive frame.
import zal_tls/foundation/stream

template withTls*(owner: TlsConnRef; body: untyped) =
  block:
    let held = owner
    defer: discard close(held)
    body
