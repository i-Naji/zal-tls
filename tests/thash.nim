import std/[syncio, assertions]
import zal_tls/crypto/[hash, hkdf]
import hexutil

var abc = hex("616263")
var d = newSeq[byte](48)

var h = default(Hash)
init(h, hashSha256)
discard update(h, ua(abc), 3)
var early = newSeq[byte](32)
peek(h, ua(early))                                   # a snapshot; h goes on
final(h, ua(d))
assert toHex(d.toOpenArray(0, 31)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
assert toHex(early) == toHex(d.toOpenArray(0, 31))
init(h, hashSha384)
discard update(h, ua(abc), 3)
final(h, ua(d))
assert toHex(d) == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
echo "PASS hash: SHA-256 and SHA-384 of \"abc\", peek equals final"

# RFC 4231 test case 2.
var jefe = hex("4a656665")
var msg = hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")
var mac = newSeq[byte](32)
assert hmac(hashSha256, ua(jefe), jefe.len, ua(msg), msg.len, ua(mac))
assert toHex(mac) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
echo "PASS hmac: RFC 4231 test case 2"

# RFC 5869 test cases 1 and 3.
var ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
var salt = hex("000102030405060708090a0b0c")
var info = hex("f0f1f2f3f4f5f6f7f8f9")
var prk = newSeq[byte](32)
var okm = newSeq[byte](42)
assert hkdfExtract(hashSha256, ua(salt), salt.len, ua(ikm), ikm.len, ua(prk))
assert toHex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
assert hkdfExpand(hashSha256, ua(prk), prk.len, ua(info), info.len, ua(okm), okm.len)
assert toHex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
var none = newSeq[byte](1)                          # a valid pointer for empty inputs
assert hkdfExtract(hashSha256, ua(none), 0, ua(ikm), ikm.len, ua(prk))
assert toHex(prk) == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
assert hkdfExpand(hashSha256, ua(prk), prk.len, ua(none), 0, ua(okm), okm.len)
assert toHex(okm) == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
echo "PASS hkdf: RFC 5869 test cases 1 and 3"
