import std/[syncio, assertions]
import zal_tls/crypto/aead
import hexutil

proc roundTrip(alg: AeadAlg; key, nonce, ad, pt, ct, tag: string; label: string) =
  var k = hex(key)
  var n = hex(nonce)
  var a = hex(ad)
  var buf = hex(pt)
  var t = newSeq[byte](AeadTagLen)
  var c = default(Aead)
  assert init(c, alg, ua(k), k.len)
  assert sealInPlace(c, ua(n), ua(buf), buf.len, ua(t), ua(a), a.len)
  assert toHex(buf) == ct, label & " ciphertext"
  assert toHex(t) == tag, label & " tag"
  assert openInPlace(c, ua(n), ua(buf), buf.len, ua(t), ua(a), a.len)
  assert toHex(buf) == pt, label & " round trip"
  # A flipped bit in the tag: refused.
  assert sealInPlace(c, ua(n), ua(buf), buf.len, ua(t), ua(a), a.len)
  t[0] = t[0] xor 1
  assert not openInPlace(c, ua(n), ua(buf), buf.len, ua(t), ua(a), a.len), label & " bad tag"
  clear(c)
  clear(c)                                    # idempotent

const
  GcmP = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
  GcmA = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
  GcmN = "cafebabefacedbaddecaf888"

# GCM specification test cases 4 (AES-128) and 16 (AES-256).
roundTrip(aeadAes128Gcm, "feffe9928665731c6d6a8f9467308308", GcmN, GcmA, GcmP,
  "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  "5bc94fbc3221a5db94fae95ae7121a47", "aes-128-gcm")
roundTrip(aeadAes256Gcm, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", GcmN, GcmA, GcmP,
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
  "76fc6ece0f4e1768cddf8853bb2d551b", "aes-256-gcm")
# RFC 8439 section 2.8.2.
roundTrip(aeadChaCha20Poly1305, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  "070000004041424344454647", "50515253c0c1c2c3c4c5c6c7",
  "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
  "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  "1ae10b594f09e26a7e902ecbd0600691", "chacha20-poly1305")

# A key of the wrong length is refused.
var shortKey = hex("00112233")
var c = default(Aead)
assert not init(c, aeadAes128Gcm, ua(shortKey), shortKey.len)
echo "PASS aead: GCM test cases 4 and 16, RFC 8439 2.8.2, tamper refused, wrong key length refused"
