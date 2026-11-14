import std/[assertions, syncio]
import zal_net/errors as neterrors
import zal_tls/errors as tlserrors

assert tlserrors.tlsAlert(TlsFailed - 80) == 80
assert tlserrors.tlsAlert(TlsFailed - 256) == 0
assert tlserrors.tlsAlert(TlsTruncated) == 0
assert tlserrors.describe(TlsFailed - 80) == "TLS alert 80"
assert tlserrors.describe(TlsTruncated) == "TLS transport ended without close_notify"
assert tlserrors.describe(InvalidInput) == neterrors.describe(InvalidInput)
assert tlserrors.describe(-9) == "OS error 9"
echo "PASS TLS alert range, truncation and qualified net-error delegation"
