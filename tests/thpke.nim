import std/[syncio, assertions]
import zal_tls/crypto/[hpke, rand]
import hexutil

# RFC 9180 A.1.1 (as in AWS-LC's crypto/hpke/hpke_test_vectors.txt): base mode.
var info = hex("4f6465206f6e2061204772656369616e2055726e")
var skR = hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
var pkR = hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
var skE = hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
var aad = hex("436f756e742d30")
var pt = hex("4265617574792069732074727574682c20747275746820626561757479")
const Ct0 = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
var enc = newSeq[byte](HpkeEncLen)
var ct = newSeq[byte](pt.len + 16)
var back = newSeq[byte](pt.len)
var s = default(HpkeCtx)
assert setupSenderSeeded(s, ua(pkR), ua(info), info.len, ua(skE), skE.len, ua(enc))
assert toHex(enc) == "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
var n = 0
assert seal(s, ua(pt), pt.len, ua(aad), aad.len, ua(ct), ct.len, n) and n == ct.len
assert toHex(ct) == Ct0
var r = default(HpkeCtx)
assert setupRecipient(r, ua(skR), ua(enc), ua(info), info.len)
var m = 0
assert open(r, ua(ct), ct.len, ua(aad), aad.len, ua(back), back.len, m) and m == pt.len
assert back == pt
ct[0] = ct[0] xor 1
var r2 = default(HpkeCtx)
assert setupRecipient(r2, ua(skR), ua(enc), ua(info), info.len)
assert not open(r2, ua(ct), ct.len, ua(aad), aad.len, ua(back), back.len, m)
clear(s)
clear(r)
clear(r2)
echo "PASS hpke: RFC 9180 A.1.1 enc and first ciphertext, recipient opens, tamper refused"

var a = newSeq[byte](32)
var b = newSeq[byte](32)
assert randomBytes(ua(a), 32) and randomBytes(ua(b), 32) and a != b
echo "PASS rand"
