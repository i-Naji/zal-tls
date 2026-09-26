import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509]
import zal_tls/keys/schedule
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import hexutil, loophelp

# Our client against our server through memory: every suite x group x
# signature scheme; data both ways, key updates, close; HelloRetryRequest,
# ALPN, SNI; records delivered one byte at a time and all at once.

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

proc certified(chainFile, keyFile: string): CertifiedKey =
  result = default(CertifiedKey)
  let err = loadCertifiedKey(slurpText(chainFile) & slurpText("tests/data/inter.pem"), slurpText(keyFile), result)
  expect(err == "", chainFile & ": " & err)

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
var ckP256 = certified("tests/data/leaf.pem", "tests/data/leaf.key")
var ckP384 = certified("tests/data/leaf-p384.pem", "tests/data/p384.key")
var ckRsa = certified("tests/data/leaf-rsa.pem", "tests/data/rsa.key")
var ckEd = certified("tests/data/leaf-ed25519.pem", "tests/data/ed25519.key")
var ckOther = certified("tests/data/other.pem", "tests/data/other.key")
expect(ckRsa.schemes == @[sigRsaPssSha256, sigRsaPssSha384] and ckEd.schemes == @[sigEd25519], "schemes")

proc connect(a, b: var Side; ab, ba: var seq[byte]; cc: ptr ClientConfig; sc: ptr ServerConfig;
             name: string; chunk: int) =
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, name), "initClient")
  expect(initServer(b.c, sc), "initServer")
  run(a, b, ab, ba, chunk)

proc traffic(a, b: var Side; ab, ba: var seq[byte]; chunk, seed: int) =
  ## 64 KiB each way, a key update each way, 64 KiB again, then close.
  let up = pattern(65536, seed)
  let down = pattern(65536, seed + 1)
  expect(sendApp(a, ab, up, 16384) and sendApp(b, ba, down, 16384), "seal")
  run(a, b, ab, ba, chunk)
  expect(b.app == up and a.app == down, "64 KiB each way")
  var buf = newSeq[byte](64)
  var n = keyUpdate(a.c, true, bytesOf(buf), buf.len)
  expect(n > 0, "client key update")
  for i in 0 ..< n: ab.add buf[i]
  run(a, b, ab, ba, chunk)                      # the server answers with its own
  n = keyUpdate(b.c, false, bytesOf(buf), buf.len)
  expect(n > 0, "server key update")
  for i in 0 ..< n: ba.add buf[i]
  a.app = @[]
  b.app = @[]
  expect(sendApp(a, ab, down, 16384) and sendApp(b, ba, up, 16384), "seal after update")
  run(a, b, ab, ba, chunk)
  expect(b.app == down and a.app == up, "data after key updates")
  n = close(a.c, bytesOf(buf), buf.len)
  for i in 0 ..< n: ab.add buf[i]
  run(a, b, ab, ba, chunk)
  expect(b.peerClosed, "server saw close_notify")
  n = close(b.c, bytesOf(buf), buf.len)
  for i in 0 ..< n: ba.add buf[i]
  run(a, b, ab, ba, chunk)
  expect(a.peerClosed and a.failed < 0 and b.failed < 0, "both closed cleanly")

var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]

# The matrix.
var count = 0
for s in AllSuites:
  for g in [kxX25519, kxSecp256r1, kxX25519MlKem768]:
    for k in 0 ..< 5:
      var cc = defaultClientConfig(roots)
      cc.suites = @[s]
      cc.groups = @[g]
      cc.shareGroups = @[g]
      var sc = defaultServerConfig()
      case k
      of 0:
        cc.sigSchemes = @[sigEcdsaP256Sha256]
        sc.resolver = singleCert(addr ckP256)
      of 1:
        cc.sigSchemes = @[sigEcdsaP384Sha384]
        sc.resolver = singleCert(addr ckP384)
      of 2:
        cc.sigSchemes = @[sigRsaPssSha256]
        sc.resolver = singleCert(addr ckRsa)
      of 3:
        cc.sigSchemes = @[sigRsaPssSha384]
        sc.resolver = singleCert(addr ckRsa)
      else:
        cc.sigSchemes = @[sigEd25519]
        sc.resolver = singleCert(addr ckEd)
      connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1 shl 30)
      if not (a.ready and b.ready): echo "suite ", s, " group ", g, " scheme ", k, ": ", a.reason, " / ", b.reason
      expect(a.ready and b.ready and suite(a.c) == s and suite(b.c) == s and not a.c.retried, "handshake")
      traffic(a, b, ab, ba, 1 shl 30, count)
      release(a.c)
      release(b.c)
      count = count + 1
echo "PASS loop: ", count, " handshakes (3 suites x 3 groups x 5 schemes), data, key updates, close"

# HelloRetryRequest: the client shares x25519, the server takes only P-256.
var cc = defaultClientConfig(roots)
cc.groups = @[kxX25519, kxSecp256r1]
var sc = defaultServerConfig()
sc.groups = @[kxSecp256r1]
sc.resolver = singleCert(addr ckP256)
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1 shl 30)
expect(a.ready and b.ready and a.c.retried and b.c.retried, "HRR handshake")
traffic(a, b, ab, ba, 1 shl 30, 7)
release(a.c)
release(b.c)
echo "PASS HelloRetryRequest"

# ALPN: agreed; refused.
cc = defaultClientConfig(roots)
cc.alpn = @["h2", "http/1.1"]
sc = defaultServerConfig()
sc.alpn = @["http/1.1"]
sc.resolver = singleCert(addr ckP256)
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1 shl 30)
expect(a.ready and b.ready and alpn(a.c) == "http/1.1" and alpn(b.c) == "http/1.1", "ALPN agreed")
release(a.c)
release(b.c)
cc.alpn = @["h2"]
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1 shl 30)
expect(b.failed == 120 and a.failed == 120, "ALPN refused")
release(a.c)
release(b.c)
echo "PASS ALPN"

# SNI: two certificates.
var table = @[SniEntry(name: "test.example", ck: addr ckP256), SniEntry(name: "*.wild.example", ck: addr ckOther)]
sc = defaultServerConfig()
sc.resolver = sniCerts(addr table)
cc = defaultClientConfig(roots)
connect(a, b, ab, ba, addr cc, addr sc, "a.wild.example", 1 shl 30)
expect(a.ready and b.ready and serverName(b.c) == "a.wild.example", "SNI other")
expect(peerLeafDer(a.c) == ckOther.chain[0], "the wildcard certificate")
release(a.c)
release(b.c)
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1 shl 30)
expect(a.ready and b.ready and peerLeafDer(a.c) == ckP256.chain[0], "SNI test.example")
release(a.c)
release(b.c)
echo "PASS SNI"

# Delivery: one byte at a time, and everything coalesced.
sc = defaultServerConfig()
sc.resolver = singleCert(addr ckRsa)
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 1)
expect(a.ready and b.ready, "byte-at-a-time handshake")
traffic(a, b, ab, ba, 1, 11)
release(a.c)
release(b.c)
connect(a, b, ab, ba, addr cc, addr sc, "test.example", 7)
expect(a.ready and b.ready, "7-byte chunks")
traffic(a, b, ab, ba, 3001, 12)
release(a.c)
release(b.c)
echo "PASS delivery: 1-byte, 7-byte and coalesced"
release(ckP256)
release(ckP384)
release(ckRsa)
release(ckEd)
release(ckOther)
release(roots)
release(rootCerts[0])
