## Explicit manual TLS configurations and address-stable record streams.
## Configuration/key/trust owners outlive every borrowing stream. Numeric I/O
## preserves native errors. Handshake, relay, kTLS and splice remain explicit.
import zal_tls/config/config
import zal_tls/crypto/x509
import zal_tls/raw/stream
export config
export stream except setBackgroundLease, KernelCopyStats, copyToKernel, copyFromKernel, KernelRelayStats, relayKernel
export Cert, Roots, newRoots, addRoot, certsPem, release
