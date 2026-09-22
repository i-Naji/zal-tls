version       = "0.1.0"
author        = "Naji"
description   = "TLS 1.3 for Nimony on zal-net: our own protocol code on AWS-LC's libcrypto"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "c", "h"]

requires "zal_net"
