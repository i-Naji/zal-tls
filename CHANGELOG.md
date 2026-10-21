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
