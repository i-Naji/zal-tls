import std/[syncio, assertions, envvars]
import zal_tls/crypto/[kx, sig, x509]
import zal_tls/config/config
import zal_tls/trust/roots
import zal_tls/wire/[consts, messages]
import hexutil, rfc8448

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

# setPrivate: RFC 8448's client x25519 private key gives its public key.
var cPriv = hex(trace(Simple, "{client} create an ephemeral x25519", "private key"))
var cPub = hex(trace(Simple, "{client} create an ephemeral x25519", "public key"))
var sPriv = hex(trace(Simple, "{server} create an ephemeral x25519", "private key"))
var sPub = hex(trace(Simple, "{server} create an ephemeral x25519", "public key"))
var k = default(KxKey)
var share = newSeq[byte](65)
assert setPrivate(k, kxX25519, ua(cPriv), ua(share))
assert toHex(share.toOpenArray(0, 31)) == toHex(cPub)
# respondWith: the server's key gives its public key and the same secret.
var sShare = newSeq[byte](32)
var sSecret = newSeq[byte](32)
assert respondWith(kxX25519, ua(sPriv), ua(cPub), 32, ua(sShare), ua(sSecret))
assert toHex(sShare) == toHex(sPub)
var cSecret = newSeq[byte](32)
assert complete(k, ua(sPub), 32, ua(cSecret)) and toHex(cSecret) == toHex(sSecret)
clear(k)
# P-256 (RFC 8448 5, the second ClientHello's share) both ways.
var pPriv = hex(trace(Hrr, "{client} create an ephemeral P-256", "private key"))
var pPub = hex(trace(Hrr, "{client} create an ephemeral P-256", "public key"))
var psPriv = hex(trace(Hrr, "{server} create an ephemeral P-256", "private key"))
var psPub = hex(trace(Hrr, "{server} create an ephemeral P-256", "public key"))
assert setPrivate(k, kxSecp256r1, ua(pPriv), ua(share)) and toHex(share) == toHex(pPub)
var psShare = newSeq[byte](65)
var psSecret = newSeq[byte](32)
assert respondWith(kxSecp256r1, ua(psPriv), ua(pPub), 65, ua(psShare), ua(psSecret))
assert toHex(psShare) == toHex(psPub)
assert complete(k, ua(psPub), 65, ua(cSecret)) and toHex(cSecret) == toHex(psSecret)
clear(k)
echo "PASS kx: fixed private keys (RFC 8448 x25519 and P-256)"

# A certified key: the chain, the key, its schemes; a key of another certificate is refused.
var ck = default(CertifiedKey)
assert loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == ""
assert ck.chain.len == 2 and ck.schemes == @[sigEcdsaP256Sha256] and ck.key != nil
var der: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/leaf.pem"), der) == 1
var leafDer: seq[byte] = @[]
certDerOf(der[0], leafDer)
assert leafDer == ck.chain[0]
release(der[0])
var bad = default(CertifiedKey)
assert loadCertifiedKey(slurpText("tests/data/leaf.pem"), slurpText("tests/data/rsa.key"), bad) != ""
assert loadCertifiedKey("", slurpText("tests/data/leaf.key"), bad) != ""
echo "PASS certified key: chain, key match, schemes"

# The web PKI verifier over the test root; alerts for a wrong name, expiry, unknown CA.
var rootCerts: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1
let r = newRoots()
if r == nil: quit "tconfig: no store"
assert addRoot(r, rootCerts[0]) and rootCount(r) == 1
const Y2030 = 1893456000'i64
const Y2040 = 2208988800'i64
assert webPkiVerify(r, addr ck.chain, "test.example", Y2030) == 0
assert webPkiVerify(r, addr ck.chain, "Test.Example", Y2030) == 0
assert webPkiVerify(r, addr ck.chain, "other.example", Y2030) == alBadCertificate
assert webPkiVerify(r, addr ck.chain, "127.0.0.1", Y2030) == alBadCertificate
assert webPkiVerify(r, addr ck.chain, "test.example", Y2040) == alCertificateExpired
var leafOnly = @[ck.chain[0]]
assert webPkiVerify(r, addr leafOnly, "test.example", Y2030) == alUnknownCa
var junk = @[@[1'u8, 2, 3]]
assert webPkiVerify(r, addr junk, "test.example", Y2030) == alBadCertificate
let v = webPkiVerifier(r)
assert v.verify != nil and v.verify(v.ctx, addr ck.chain, "test.example") == 0   # now: 2026-09 is inside
echo "PASS web PKI verifier: accept, name, time, issuer"

# Resolvers: one certificate; SNI with exact and wildcard names.
var hv = default(HelloView)
let one = singleCert(addr ck)
assert one.resolve(one.ctx, addr hv) == addr ck
var ck2 = default(CertifiedKey)
var table = @[SniEntry(name: "a.example", ck: addr ck), SniEntry(name: "*.b.example", ck: addr ck2)]
let sni = sniCerts(addr table)
hv.serverName = "x.b.example"
assert sni.resolve(sni.ctx, addr hv) == addr ck2
hv.serverName = "A.EXAMPLE"
assert sni.resolve(sni.ctx, addr hv) == addr ck
hv.serverName = "b.example"                        # a wildcard needs one more label
assert sni.resolve(sni.ctx, addr hv) == addr ck
hv.serverName = "y.x.b.example"                    # ... exactly one
assert sni.resolve(sni.ctx, addr hv) == addr ck
echo "PASS resolvers: single, SNI exact and wildcard"

# The system's roots.
let sys = systemRoots()
if sys != nil: echo "system roots: ", rootCount(sys)
# Windows keeps a small ROOT store and fetches more on demand; elsewhere the bundle has 100+.
expect(sys != nil and rootCount(sys) > (when defined(windows): 10 else: 50), "system roots")
echo "PASS system roots"
release(sys)
# SSL_CERT_FILE replaces the system's roots, as with OpenSSL.
proc setEnv(k, v: string) =
  try: putEnv(k, v)
  except: quit "putEnv"
proc unsetEnv(k: string) =
  try: delEnv(k)
  except: quit "delEnv"
setEnv("SSL_CERT_FILE", "tests/data/root.pem")
let fromFile = systemRoots()
expect(fromFile != nil and rootCount(fromFile) == 1, "SSL_CERT_FILE")
release(fromFile)
setEnv("SSL_CERT_FILE", "tests/data/nothing-here.pem")
expect(systemRoots() == nil, "SSL_CERT_FILE that does not load: no roots, not the system's")
unsetEnv("SSL_CERT_FILE")
echo "PASS SSL_CERT_FILE"
release(r)
release(rootCerts[0])
release(ck)

# Client certificates: the web PKI with the clientAuth purpose over the
# client roots; the one-certificate resolver; a CA's name for
# certificate_authorities.
block:
  var croots: seq[Cert] = @[]
  expect(certsPem(slurpText("tests/data/cauth-root.pem"), croots) == 1, "client root")
  let cr = newRoots()
  if cr == nil: quit "no store"
  expect(addRoot(cr, croots[0]), "client store")
  proc chainOf(path: string): seq[seq[byte]] =
    var cs: seq[Cert] = @[]
    discard certsPem(slurpText(path), cs)
    result = @[]
    for c in cs:
      var d: seq[byte] = @[]
      certDerOf(c, d)
      result.add d
      release(c)
  var good = chainOf("tests/data/cauth.pem")
  var expired = chainOf("tests/data/cauth-expired.pem")
  var serverOnly = chainOf("tests/data/cauth-server.pem")
  var otherCa = chainOf("tests/data/leaf.pem")
  for d in chainOf("tests/data/inter.pem"): otherCa.add d
  var none: seq[seq[byte]] = @[]
  expect(webPkiVerifyClient(cr, addr good, 0) == 0, "a client certificate")
  expect(webPkiVerifyClient(cr, addr expired, 0) == alCertificateExpired, "expired")
  expect(webPkiVerifyClient(cr, addr serverOnly, 0) == alUnsupportedCertificate, "server purpose only")
  expect(webPkiVerifyClient(cr, addr otherCa, 0) == alUnknownCa, "another CA")
  expect(webPkiVerifyClient(cr, addr none, 0) == alDecodeError, "no certificate")
  let name = subjectDer(croots[0])
  expect(name.len > 10 and name[0] == 0x30, "the CA's subject, DER")
  var ck = default(CertifiedKey)
  expect(loadCertifiedKey(slurpText("tests/data/cauth.pem"), slurpText("tests/data/cauth.key"), ck) == "", "client key")
  let res = singleClientCert(addr ck)
  var req = default(CertRequestView)
  req.schemes = @[0x0804, 0x0403]
  expect(res.resolve(res.ctx, addr req) == addr ck, "a scheme fits: presented")
  req.schemes = @[0x0804]
  expect(res.resolve(res.ctx, addr req) == nil, "no scheme fits: none")
  release(ck)
  release(croots[0])
  release(cr)
echo "PASS client certificates: clientAuth purpose, expiry, CA; the resolver; CA names"
