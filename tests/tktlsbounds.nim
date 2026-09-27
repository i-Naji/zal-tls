## ABI int-length guards run without a socket or crypto state.
import std/[assertions, syncio]
import zal_net/errors
import zal_tls/raw/ktls
var kind = 23
assert ktlsSendRecord(-1, 21, nil, -1) == InvalidInput
assert ktlsRecv(-1, nil, -1, kind) == InvalidInput and kind == 0
when sizeof(int) > sizeof(cint):
  let oversized = int(high(cint)) + 1
  assert ktlsSendRecord(-1, 21, nil, oversized) == InvalidInput
  kind = 23
  assert ktlsRecv(-1, nil, oversized, kind) == InvalidInput and kind == 0
assert ktlsSendRecord(-1, 21, nil, 0) == 0
kind = 23
assert ktlsRecv(-1, nil, 0, kind) == 0 and kind == 0
echo "PASS kTLS signed lengths, ABI overflow and empty windows"
