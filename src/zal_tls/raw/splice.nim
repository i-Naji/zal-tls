## Explicit opt-in kTLS application-payload pumping. The destination must have
## completed its handshake and successfully enabled kTLS TX with useKtls().
## Raw owners remain borrowed for the entire operation. On the custom runtime
## they stay on their owning loop; std owns placement. Both relay pumps join
## before the caller may close or move either owner.
import zal_tls/raw/stream
export KernelCopyStats, copyToKernel, copyFromKernel, KernelRelayStats, relayKernel
