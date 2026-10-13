## Application TLS over retained configurations and transports. Client
## builders require an explicit trust source; import zal_tls/raw for manual
## owners. Do not import this module as `tls`: Nimony confuses the alias with
## the re-exported module (zal-net tests/compiler c43/c44).
import zal_tls/private/application
export application
