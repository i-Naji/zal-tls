## Advanced ClientHello inspection and construction. Builders preserve the
## required TLS extensions and transcript inputs; normal verification is unchanged.
import zal_tls/core/hello
import zal_tls/private/core/client
export hello, writeDefaultHello
