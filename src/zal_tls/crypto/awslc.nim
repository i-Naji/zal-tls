## Every crypto module imports this: the C side must be AWS-LC. Its headers
## keep OpenSSL's directory name (`openssl/*.h`, as BoringSSL does) so the
## names read the same; this guard makes the compile fail if the include
## path finds another library's `openssl/` first.

{.emit: """
#include <openssl/opensslv.h>
#ifndef OPENSSL_IS_AWSLC
#error "zal-tls is built on AWS-LC: put its include directory (AWSLC/include) first"
#endif
""".}

when defined(windows):
  # <windows.h> would include <wincrypt.h>, whose X509_NAME, PKCS7_SIGNER_INFO
  # ... macros break the OpenSSL headers in any C file that sees both (a
  # program using zal-net and zal-tls). trust/roots declares the few
  # CryptoAPI procs it calls itself.
  {.passC: "-DNOCRYPT".}
