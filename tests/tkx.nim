import std/[syncio, assertions]
import zal_tls/crypto/kx
import hexutil

# RFC 7748 section 6.1.
var aPriv = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
var bPriv = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
var aPub = newSeq[byte](32)
var bPub = newSeq[byte](32)
var s1 = newSeq[byte](32)
var s2 = newSeq[byte](32)
x25519Public(ua(aPriv), ua(aPub))
x25519Public(ua(bPriv), ua(bPub))
assert toHex(aPub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert toHex(bPub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
assert x25519(ua(aPriv), ua(bPub), ua(s1)) and x25519(ua(bPriv), ua(aPub), ua(s2))
assert toHex(s1) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" and s1 == s2
var zero = newSeq[byte](32)
assert not x25519(ua(aPriv), ua(zero), ua(s1))       # low-order point refused
echo "PASS x25519: RFC 7748 6.1, low-order point refused"

# RFC 5903 section 8.1 (256-bit random ECP group).
var i = hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
var gr = hex("04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB")
var ps = newSeq[byte](32)
assert p256Shared(ua(i), ua(gr), ua(ps))
assert toHex(ps) == "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de"
echo "PASS p-256: RFC 5903 8.1"

# Each group, client and server, agree; short shares refused.
for g in [kxX25519, kxSecp256r1, kxX25519MlKem768]:
  var k = default(KxKey)
  var cShare = newSeq[byte](clientShareLen(g))
  var sShare = newSeq[byte](serverShareLen(g))
  var cSecret = newSeq[byte](secretLen(g))
  var sSecret = newSeq[byte](secretLen(g))
  assert generate(k, g, ua(cShare))
  assert respond(g, ua(cShare), cShare.len, ua(sShare), ua(sSecret))
  assert complete(k, ua(sShare), sShare.len, ua(cSecret))
  assert cSecret == sSecret
  assert not respond(g, ua(cShare), cShare.len - 1, ua(sShare), ua(sSecret))
  assert not complete(k, ua(sShare), sShare.len - 1, ua(cSecret))
  clear(k)
  clear(k)
echo "PASS kx: X25519, P-256 and X25519MLKEM768 agree; short shares refused"
