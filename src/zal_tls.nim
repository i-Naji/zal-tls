## Application TLS: retained configurations/transports and enum-error byte I/O.
## Client builders require an explicit trust source. Borrowed and transferring
## wrapping have distinct contracts. Import zal_tls/raw for manual owners.
## Keep the implementation's module name distinct from the customary `tls`
## import alias: the pin confuses a re-exported namesake module with that alias.
## zal-net compiler guards c43/c44 reproduce the failure and working form.
import zal_tls/private/application
export application
