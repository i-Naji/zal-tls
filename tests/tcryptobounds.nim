## Signed-size guards leave borrowed output and hash state unchanged.
import std/[assertions, syncio]
import zal_tls/common
import zal_tls/crypto/[aead, hash, hkdf, rand]

var key = default(array[32, byte])
var nonce = default(array[AeadNonceLen, byte])
var body = default(array[32, byte])
var tag = default(array[AeadTagLen, byte])
var output = default(array[48, byte])

when defined(tlsTestEntropy):
  {.compile: "crypto_rand_probe.c".}
  proc armEntropyFailure() {.importc: "tls_arm_entropy_failure", cdecl.}
  proc nativeEntropyCalls(): cint {.importc: "tls_entropy_calls", cdecl.}

proc resetOutput() =
  for b in body.mitems: b = 0x5a
  for b in tag.mitems: b = 0x6b
  for b in output.mitems: b = 0x7c

proc unchanged() =
  for b in body: assert b == 0x5a
  for b in tag: assert b == 0x6b
  for b in output: assert b == 0x7c

var entropyCalls = 0
proc failEntropy(p: Bytes; n: int): bool {.nimcall.} =
  entropyCalls = entropyCalls + 1
  for i in 0 ..< n: p[i] = 0x42
  result = false

resetOutput()
for length in [-1, low(int)]:
  assert not randomBytes(ptrOf(body), length)
  assert not randomFill(failEntropy, ptrOf(body), length)
  assert not ctEqual(ptrOf(body), ptrOf(output), length)
  wipeBytes(ptrOf(body), length)
  unchanged()
assert randomFill(failEntropy, ptrOf(body), 0)
assert randomBytes(ptrOf(body), 0)
assert ctEqual(ptrOf(body), ptrOf(output), 0)
assert entropyCalls == 0
unchanged()
assert not randomFill(failEntropy, ptrOf(body), 16)
assert entropyCalls == 1
for i in 0 ..< 16: assert body[i] == 0
for i in 16 ..< body.len: assert body[i] == 0x5a
echo "PASS random, wipe and comparison signed bounds; empty entropy bypass and bounded failure wipe"

when defined(tlsTestEntropy):
  for useProvider in [false, true]:
    resetOutput()
    armEntropyFailure()
    assert not randomBytes(ptrOf(body), -1)
    assert randomBytes(ptrOf(body), 0)
    assert nativeEntropyCalls() == 0
    let ok = if useProvider: randomFill(nil, ptrOf(body), 16)
             else: randomBytes(ptrOf(body), 16)
    assert not ok and nativeEntropyCalls() == 1
    for i in 0 ..< 16: assert body[i] == 0
    for i in 16 ..< body.len: assert body[i] == 0x5a
    assert randomBytes(ptrOf(body), body.len)
    assert nativeEntropyCalls() == 2
  echo "PASS direct AWS-LC entropy failure: partial output wiped, bounds preserved and provider recovers"

for algorithm in [hashSha256, hashSha384]:
  resetOutput()
  for length in [-1, low(int)]:
    assert not hmac(algorithm, ptrOf(key), length, ptrOf(body), body.len, ptrOf(output))
    assert not hmac(algorithm, ptrOf(key), key.len, ptrOf(body), length, ptrOf(output))
    assert not hkdfExtract(algorithm, ptrOf(key), length, ptrOf(body), body.len, ptrOf(output))
    assert not hkdfExtract(algorithm, ptrOf(key), key.len, ptrOf(body), length, ptrOf(output))
    assert not hkdfExpand(algorithm, ptrOf(key), length, ptrOf(body), body.len, ptrOf(output), 32)
    assert not hkdfExpand(algorithm, ptrOf(key), key.len, ptrOf(body), length, ptrOf(output), 32)
    assert not hkdfExpand(algorithm, ptrOf(key), key.len, ptrOf(body), body.len, ptrOf(output), length)
    unchanged()
  assert not hkdfExpand(algorithm, ptrOf(key), key.len, ptrOf(body), body.len,
                       ptrOf(output), 255 * digestLen(algorithm) + 1)
  assert not hkdfExpand(algorithm, ptrOf(key), key.len, ptrOf(body), body.len, ptrOf(output), high(int))
  assert hkdfExpand(algorithm, ptrOf(key), 0, ptrOf(body), 0, ptrOf(output), 0)
  unchanged()
  var first, second = default(Hash)
  init(first, algorithm)
  init(second, algorithm)
  assert not update(first, ptrOf(body), -1)
  assert not update(first, ptrOf(body), low(int))
  assert update(first, ptrOf(body), 0)
  assert update(first, ptrOf(body), body.len)
  assert update(second, ptrOf(body), body.len)
  var expected = default(array[48, byte])
  final(first, ptrOf(output))
  final(second, ptrOf(expected))
  assert ctEqual(ptrOf(output), ptrOf(expected), digestLen(algorithm))
echo "PASS HMAC/HKDF signed bounds, HKDF output limit and rejected hash updates preserve state"

for algorithm in [aeadAes128Gcm, aeadAes256Gcm, aeadChaCha20Poly1305]:
  resetOutput()
  var owner = default(Aead)
  assert init(owner, algorithm, ptrOf(key), keyLen(algorithm))
  for length in [-1, low(int)]:
    assert not sealInPlace(owner, ptrOf(nonce), ptrOf(body), length, ptrOf(tag), nil, 0)
    assert not openInPlace(owner, ptrOf(nonce), ptrOf(body), length, ptrOf(tag), nil, 0)
    assert not sealInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), ptrOf(key), length)
    assert not openInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), ptrOf(key), length)
    unchanged()
  assert not sealInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 1)
  assert not openInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 1)
  unchanged()
  assert sealInPlace(owner, ptrOf(nonce), ptrOf(body), 0, ptrOf(tag), nil, 0)
  assert openInPlace(owner, ptrOf(nonce), ptrOf(body), 0, ptrOf(tag), nil, 0)
  assert sealInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  tag[0] = tag[0] xor 1
  assert not openInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  for b in body: assert b == 0
  clear(owner)
  clear(owner)
  resetOutput()
  assert not sealInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  assert not openInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  unchanged()
  assert init(owner, algorithm, ptrOf(key), keyLen(algorithm))
  assert sealInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  assert openInPlace(owner, ptrOf(nonce), ptrOf(body), body.len, ptrOf(tag), nil, 0)
  clear(owner)
echo "PASS all AEAD signed bounds, nil associated-data rejection, empty records, authentication wipe and owner reuse"
