import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages]
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import hexutil, loophelp

# Client certificates, our client against our server through memory:
# ignored, requested, required; the client's identity on the server; bad
# chains (another CA, expired, not for clients), bad CertificateVerify
# (tampered, the server's context, a scheme not asked for) refused;
# certificate_required; resumption keeps the identity, and a server that
# requires one does not resume a ticket without it; no CertificateRequest
# when resumed; one after the handshake refused.

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
var cauthRoot: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/cauth-root.pem"), cauthRoot) == 1, "client root")
let clientRoots = newRoots()
if clientRoots == nil: quit "no store"
expect(addRoot(clientRoots, cauthRoot[0]), "add client root")
var ck = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == "", "leaf")
var ckClient = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/cauth.pem"), slurpText("tests/data/cauth.key"), ckClient) == "", "client")
var ckExpired = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/cauth-expired.pem"), slurpText("tests/data/cauth.key"), ckExpired) == "", "expired")
var ckServerOnly = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/cauth-server.pem"), slurpText("tests/data/cauth.key"), ckServerOnly) == "", "server-only")
var ckOtherCa = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ckOtherCa) == "", "another CA")

var ticketer = default(KeyedTicketer)
assert initKeyedTicketer(ticketer)
var store = default(MemoryStore)
initMemoryStore(store)
let sessions = memoryStore(addr store)
var cHsLog = default(Secret)

proc keyLog(ctx: nil pointer; label: string; clientRandom: Bytes; secret: Secret) {.nimcall.} =
  if label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET": cHsLog = secret

proc clientConfig(cert: nil ptr CertifiedKey): ClientConfig =
  result = defaultClientConfig(roots)
  result.suites = @[suiteAes128Gcm]
  result.keyLog = KeyLog(log: keyLog, ctx: nil)
  let c = cert
  if c != nil: result.clientCert = singleClientCert(c)

proc serverConfig(auth: ClientAuth): ServerConfig =
  result = defaultServerConfig()
  result.resolver = singleCert(addr ck)
  result.clientAuth = auth
  result.clientRoots = clientRoots

var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]

proc connect(cc: ptr ClientConfig; sc: ptr ServerConfig) =
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, "test.example") and initServer(b.c, sc), "init")
  run(a, b, ab, ba, 1 shl 20)

proc done() =
  release(a.c)
  release(b.c)

var clientDer: seq[byte] = ckClient.chain[0]

# 1. Ignored, requested, required.
var cWith = clientConfig(addr ckClient)
var cWithout = clientConfig(nil)
var sIgnore = serverConfig(caIgnore)
var sRequest = serverConfig(caRequest)
var sRequire = serverConfig(caRequire)
connect(addr cWith, addr sIgnore)
expect(a.ready and b.ready and peerLeafDer(b.c).len == 0, "ignored: no certificate asked, none sent")
done()
connect(addr cWithout, addr sRequest)
expect(a.ready and b.ready and peerLeafDer(b.c).len == 0, "requested, none: no identity")
done()
connect(addr cWith, addr sRequest)
expect(a.ready and b.ready and peerLeafDer(b.c) == clientDer, "requested: the client's certificate")
done()
connect(addr cWith, addr sRequire)
expect(a.ready and b.ready and peerLeafDer(b.c) == clientDer, "required: the client's certificate")
let up = pattern(20000, 1)
expect(sendApp(a, ab, up, 16384), "seal")
run(a, b, ab, ba, 1 shl 20)
expect(b.app == up, "traffic after client authentication")
done()
connect(addr cWithout, addr sRequire)
expect(b.failed == alCertificateRequired and a.failed == alCertificateRequired, "required, none: certificate_required")
done()
echo "PASS client certificates ignored, requested, required; the identity on the server"

# 2. Bad chains: refused, required or only requested.
var cExpired = clientConfig(addr ckExpired)
var cServerOnly = clientConfig(addr ckServerOnly)
var cOtherCa = clientConfig(addr ckOtherCa)
connect(addr cExpired, addr sRequire)
expect(b.failed == alCertificateExpired, "expired: " & $b.failed)
done()
connect(addr cServerOnly, addr sRequire)
expect(b.failed == alUnsupportedCertificate, "not for clients: " & $b.failed)
done()
connect(addr cOtherCa, addr sRequire)
expect(b.failed == alUnknownCa, "another CA: " & $b.failed)
done()
connect(addr cExpired, addr sRequest)
expect(b.failed == alCertificateExpired, "a bad certificate is refused when only requested too")
done()
echo "PASS client certificates: another CA, expired, not for clients refused"

# 3. Bad CertificateVerify: tampered, the server's context, a scheme not asked for.
proc badSig(ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int; outSig: Bytes; cap: int;
            sigLen: var int): bool {.nimcall.} =
  let k = ckClient.key
  if k == nil: return false
  result = sign(scheme, k, msg, n, outSig, cap, sigLen)
  outSig[sigLen - 1] = outSig[sigLen - 1] xor 1

proc serverContext(ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int; outSig: Bytes; cap: int;
                   sigLen: var int): bool {.nimcall.} =
  ## Signs the server's context string over the same transcript.
  let k = ckClient.key
  if k == nil: return false
  var m = newSeq[byte](n)
  copyMem(addr m[0], msg, n)
  let s = "TLS 1.3, server"
  for i in 0 ..< s.len: m[64 + i] = byte(s[i])
  result = sign(scheme, k, bytesOf(m), n, outSig, cap, sigLen)

var cTampered = clientConfig(addr ckClient)
cTampered.signer = SignHook(sign: badSig, ctx: nil)
connect(addr cTampered, addr sRequire)
expect(b.failed == alDecryptError, "a tampered CertificateVerify: " & $b.failed)
expect(peerLeafDer(b.c).len == 0, "no identity from a certificate whose key was not proven")
done()
var cServerCtx = clientConfig(addr ckClient)
cServerCtx.signer = SignHook(sign: serverContext, ctx: nil)
connect(addr cServerCtx, addr sRequire)
expect(b.failed == alDecryptError, "the server's context: " & $b.failed)
done()
block:
  # The client's flight re-sealed with another scheme in its CertificateVerify.
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, addr cWith, "test.example") and initServer(b.c, addr sRequire), "init")
  discard turn(a, ab)
  feed(b, ab, 1 shl 30)
  while turn(b, ba): discard
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, ab): discard
  expect(a.ready, "the client is done")
  var pos = 0
  var fixed: seq[byte] = @[]
  var p = default(Protection)
  expect(install(p, suiteAes128Gcm, cHsLog), "the client's keys")
  var q = default(Protection)
  expect(install(q, suiteAes128Gcm, cHsLog), "... for sealing")
  var changed = false
  while pos < ab.len:
    let n = recordLen(bytesOf(ab), pos, ab.len - pos)
    expect(n > 0, "a record")
    if int(ab[pos]) != ctApplicationData:
      for i in pos ..< pos + n: fixed.add ab[i]
    else:
      var ct = 0
      var off = 0
      var len = 0
      expect(openRecord(p, bytesOf(ab), pos, n, ct, off, len) == 0, "open")
      var pay = newSeq[byte](len)
      for i in 0 ..< len: pay[i] = ab[off + i]
      var i = 0
      while i + 4 <= pay.len:                    # the CertificateVerify's scheme -> ed25519
        let ml = (int(pay[i + 1]) shl 16) or (int(pay[i + 2]) shl 8) or int(pay[i + 3])
        if pay[i] == 15:
          pay[i + 4] = 8
          pay[i + 5] = 7
          changed = true
        i = i + 4 + ml
      var rec = newSeq[byte](5 + pay.len + 17)
      for j in 0 ..< pay.len: rec[5 + j] = pay[j]
      let m = sealRecord(q, bytesOf(rec), 0, pay.len, ct, 0)
      for j in 0 ..< m: fixed.add rec[j]
    pos = pos + n
  clear(p)
  clear(q)
  expect(changed, "a CertificateVerify found")
  feed(b, fixed, 1 shl 30)
  while turn(b, ba): discard
  expect(b.failed == alIllegalParameter, "a scheme the key cannot make: " & $b.failed)
  done()
echo "PASS client CertificateVerify: tampered, the server's context, a wrong scheme refused"

# 4. Resumption: the identity comes back; a server that requires one does
#    not resume a ticket without it; no CertificateRequest when resumed.
var sRequireT = serverConfig(caRequire)
sRequireT.ticketer = keyedTicketer(addr ticketer)
var sRequestT = serverConfig(caRequest)
sRequestT.ticketer = keyedTicketer(addr ticketer)
var cWithT = clientConfig(addr ckClient)
cWithT.sessions = sessions
var cWithoutT = clientConfig(nil)
cWithoutT.sessions = sessions
connect(addr cWithT, addr sRequireT)                # tickets with the client's certificate
expect(a.ready and b.ready and not b.c.resumed, "full handshake")
done()
connect(addr cWithT, addr sRequireT)
expect(a.ready and b.ready and b.c.resumed and peerLeafDer(b.c) == clientDer, "resumed with the client's identity")
done()
clear(store)
connect(addr cWithoutT, addr sRequestT)             # tickets without an identity
expect(a.ready and b.ready and peerLeafDer(b.c).len == 0, "no identity")
done()
connect(addr cWithT, addr sRequireT)                # such a ticket: no resumption; asked, answered
expect(a.ready and b.ready and not b.c.resumed and peerLeafDer(b.c) == clientDer,
       "a ticket without an identity is not resumed where one is required")
done()
echo "PASS resumption keeps the client's identity; a required one is never skipped"

# 5. A CertificateRequest after the handshake: our client refuses it.
connect(addr cWithout, addr sIgnore)
block:
  var msg = newSeq[byte](64)
  var w = initWriter(bytesOf(msg), 5, msg.len - 5)
  writeCertificateRequest(w, nil, 0, @[0x0403], @[])
  var rec = newSeq[byte](5 + (w.pos - 5) + 17)
  for i in 5 ..< w.pos: rec[i] = msg[i]
  let m = sealRecord(b.c.wr, bytesOf(rec), 0, w.pos - 5, ctHandshake, 0)
  var q2: seq[byte] = @[]
  for i in 0 ..< m: q2.add rec[i]
  feed(a, q2, 1 shl 30)
  var sink: seq[byte] = @[]
  while turn(a, sink): discard
  expect(a.failed == alUnexpectedMessage, "a post-handshake CertificateRequest: " & $a.failed)
done()
echo "PASS a CertificateRequest after the handshake refused (no post-handshake auth)"

# ---------------------------------------------------------- the review's cases

proc emptyStore() = clear(store)

proc loadCk(pem: string): CertifiedKey =
  result = default(CertifiedKey)
  expect(loadCertifiedKey(slurpText(pem), slurpText("tests/data/cauth.key"), result) == "", pem)

# I1. An identity whose certificate expired meanwhile is not resumed (the
#     server's clock); a resumption check can refuse one (revoked).
var gSrvNow = 1790726400000'i64                   # 2026-09-30
proc srvNow(): int64 {.nimcall.} = gSrvNow
var ckShort = loadCk("tests/data/cauth-short.pem")  # until 2026-10-01
var sShort = serverConfig(caRequire)
sShort.ticketer = keyedTicketer(addr ticketer)
sShort.clock = srvNow
sShort.ticketLifetime = 604800
var cShort = clientConfig(addr ckShort)
cShort.sessions = sessions
emptyStore()
connect(addr cShort, addr sShort)
expect(a.ready and b.ready and not b.c.resumed, "a full handshake on 2026-09-30")
done()
gSrvNow = 1790899200000                           # 2026-10-02: expired
connect(addr cShort, addr sShort)
expect(not b.c.resumed and b.failed == alCertificateExpired, "an expired identity not resumed: " & $b.failed)
done()
var gRevoked = false
proc stillGood(ctx: nil pointer; leaf: ptr seq[byte]; serverName: string): bool {.nimcall.} = not gRevoked
var sRev = serverConfig(caRequire)
sRev.ticketer = keyedTicketer(addr ticketer)
sRev.resumeCheck = ResumeCheck(check: stillGood, ctx: nil)
var cRev = clientConfig(addr ckClient)
cRev.sessions = sessions
emptyStore()
connect(addr cRev, addr sRev)
done()
connect(addr cRev, addr sRev)
expect(b.c.resumed, "resumed while the check agrees")
done()
gRevoked = true
connect(addr cRev, addr sRev)
expect(a.ready and b.ready and not b.c.resumed, "the check refuses: a full handshake")
done()
echo "PASS review I1: expired identities and a resumption check"

# I2. A ticket resumes only on the configuration that issued it (or those
#     sharing its ticketScope): not on a stricter one sharing the ticketer.
proc acceptAny(ctx: nil pointer; chain: ptr seq[seq[byte]]; serverName: string): int {.nimcall.} = 0
var sLax = serverConfig(caRequest)
sLax.clientVerifier = ClientCertVerifier(verify: acceptAny, ctx: nil)
sLax.ticketer = keyedTicketer(addr ticketer)
var sStrict = serverConfig(caRequire)
sStrict.ticketer = keyedTicketer(addr ticketer)
var cOther = clientConfig(addr ckOtherCa)
cOther.sessions = sessions
emptyStore()
connect(addr cOther, addr sLax)
expect(a.ready and b.ready and peerLeafDer(b.c).len > 0, "the lax one takes it")
done()
connect(addr cOther, addr sStrict)
expect(not b.c.resumed and b.failed == alUnknownCa, "the strict one does not resume it: " & $b.failed)
done()
var sScopeA = serverConfig(caRequire)
sScopeA.ticketer = keyedTicketer(addr ticketer)
sScopeA.ticketScope = "cluster"
var sScopeB = sScopeA
emptyStore()
connect(addr cRev, addr sScopeA)
done()
connect(addr cRev, addr sScopeB)
expect(b.c.resumed, "configurations sharing a ticketScope resume each other's tickets")
done()
echo "PASS review I2: tickets bound to their configuration (or scope)"

# I3. A client certificate of 6.7 KB is kept in tickets; one too big for
#     them means no tickets (never an identity lost on resumption).
var ckBig = loadCk("tests/data/cauth-big.pem")
var ckHuge = loadCk("tests/data/cauth-huge.pem")
var sReqT2 = serverConfig(caRequest)
sReqT2.ticketer = keyedTicketer(addr ticketer)
var cBig = clientConfig(addr ckBig)
cBig.sessions = sessions
emptyStore()
connect(addr cBig, addr sReqT2)
done()
connect(addr cBig, addr sReqT2)
expect(b.c.resumed and peerLeafDer(b.c) == ckBig.chain[0], "a 6.7 KB identity resumed")
done()
var cHuge = clientConfig(addr ckHuge)
cHuge.sessions = sessions
proc storedTickets(): int =
  result = 0
  var held: seq[SessionTicket] = @[]
  var tk = default(SessionTicket)
  let tf = sessions.take
  let pf = sessions.put
  if tf == nil or pf == nil: return
  for key in ["test.example", sessionKey(addr cHuge, "test.example")]:
    while tf(addr store, key, unixMs(), tk):
      held.add tk
      tk = default(SessionTicket)
  result = held.len
  for i in 0 ..< held.len: pf(addr store, addr held[i])

emptyStore()
connect(addr cHuge, addr sReqT2)
expect(a.ready and b.ready and peerLeafDer(b.c) == ckHuge.chain[0], "a 10 KB identity")
done()
expect(storedTickets() == 0, "no tickets for an identity they cannot carry")
echo "PASS review I3: big identities kept, too big ones get no tickets"

# I4. A client offers a ticket only with the client certificate it was got with.
# The short-lived identity above belongs to the controlled-clock expiry test.
# Use a distinct long-lived identity here so this check survives 2026-10-01.
var cB = clientConfig(addr ckBig)
cB.sessions = sessions
var cNone = clientConfig(nil)
cNone.sessions = sessions
emptyStore()
connect(addr cRev, addr sReqT2)                  # tickets for ckClient
done()
connect(addr cB, addr sReqT2)
expect(a.ready and not b.c.resumed and peerLeafDer(b.c) == ckBig.chain[0], "another certificate: not resumed")
done()
connect(addr cNone, addr sReqT2)
expect(a.ready and not b.c.resumed and peerLeafDer(b.c).len == 0, "no certificate: not resumed")
done()
connect(addr cRev, addr sReqT2)
expect(b.c.resumed and peerLeafDer(b.c) == clientDer, "the same certificate: resumed")
done()
echo "PASS review I4: tickets offered with the certificate they were got with"

# M1. A client that refuses our ServerHello: its plaintext alert read while
#     we wait for its certificate.
block:
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, addr cWith, "test.example") and initServer(b.c, addr sRequest), "init")
  discard turn(a, ab)
  feed(b, ab, 1 shl 30)
  while turn(b, ba): discard
  ba[5 + 4 + 2 + 32 + 1] = ba[5 + 4 + 2 + 32 + 1] xor 1   # the echoed session id
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, ab): discard
  expect(a.failed == alIllegalParameter, "the client refuses: " & $a.failed)
  feed(b, ab, 1 shl 30)
  var sink: seq[byte] = @[]
  while turn(b, sink): discard
  expect(b.failed == alIllegalParameter and b.reason.len >= 9 and b.reason[0 ..< 9] == "peer sent", "the server reads why: " & b.reason)
  done()
echo "PASS review M1: a plaintext alert while waiting for the client's certificate"

# M3. A CertificateVerify with a scheme we did not ask for; a chain of 11;
#     a context in the client's Certificate.
proc tamperedFlight(cc: ptr ClientConfig; sc: ptr ServerConfig; edit: proc (pay: var seq[byte]): bool {.nimcall.}): int =
  ## The client's flight re-sealed after `edit`; the server's alert.
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, "test.example") and initServer(b.c, sc), "init")
  discard turn(a, ab)
  feed(b, ab, 1 shl 30)
  while turn(b, ba): discard
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, ab): discard
  expect(a.ready, "the client is done")
  var fixed: seq[byte] = @[]
  var p = default(Protection)
  var q = default(Protection)
  expect(install(p, suiteAes128Gcm, cHsLog) and install(q, suiteAes128Gcm, cHsLog), "the client's keys")
  var changed = false
  var pos = 0
  while pos < ab.len:
    let n = recordLen(bytesOf(ab), pos, ab.len - pos)
    expect(n > 0, "a record")
    if int(ab[pos]) != ctApplicationData:
      for i in pos ..< pos + n: fixed.add ab[i]
    else:
      var ct = 0
      var off = 0
      var len = 0
      expect(openRecord(p, bytesOf(ab), pos, n, ct, off, len) == 0, "open")
      var pay = newSeq[byte](len)
      for i in 0 ..< len: pay[i] = ab[off + i]
      if edit(pay): changed = true
      var rec = newSeq[byte](5 + pay.len + 17)
      for j in 0 ..< pay.len: rec[5 + j] = pay[j]
      let m = sealRecord(q, bytesOf(rec), 0, pay.len, ct, 0)
      for j in 0 ..< m: fixed.add rec[j]
    pos = pos + n
  clear(p)
  clear(q)
  expect(changed, "edited")
  feed(b, fixed, 1 shl 30)
  while turn(b, ba): discard
  result = b.failed
  done()

proc toEd25519(pay: var seq[byte]): bool =
  result = false
  var i = 0
  while i + 4 <= pay.len:
    let ml = (int(pay[i + 1]) shl 16) or (int(pay[i + 2]) shl 8) or int(pay[i + 3])
    if pay[i] == 15:
      pay[i + 4] = 8
      pay[i + 5] = 7
      result = true
    i = i + 4 + ml

proc withContext(pay: var seq[byte]): bool =
  ## The Certificate's request context: one byte instead of none.
  result = false
  if pay.len < 5 or pay[0] != 11 or pay[4] != 0: return
  var np: seq[byte] = @[pay[0], 0, 0, 0, 1, 42]
  for i in 5 ..< pay.len: np.add pay[i]
  let certLen = (int(pay[1]) shl 16) or (int(pay[2]) shl 8) or int(pay[3])
  let nl = certLen + 1
  np[1] = byte(nl shr 16)
  np[2] = byte((nl shr 8) and 0xff)
  np[3] = byte(nl and 0xff)
  pay = np
  result = true

var sNoEd = serverConfig(caRequire)
sNoEd.sigSchemes = @[sigEcdsaP256Sha256, sigEcdsaP384Sha384, sigRsaPssSha256]
expect(tamperedFlight(addr cWith, addr sNoEd, toEd25519) == alIllegalParameter, "a scheme not asked for")
expect(tamperedFlight(addr cWith, addr sRequire, withContext) == alIllegalParameter, "a context in the client's Certificate")
var ckLong = ckClient
for i in 0 ..< 10: ckLong.chain.add ckClient.chain[0]
var cLong = clientConfig(addr ckLong)
connect(addr cLong, addr sRequire)
expect(b.failed == alBadCertificate, "a chain of 11: " & $b.failed)
done()
echo "PASS review M3: a scheme not asked for, a context, a chain of 11"

# M4. Configurations that could never work are refused at initServer.
var bad1 = serverConfig(caRequire)
bad1.clientRoots = nil
var t1 = default(TlsConn)
expect(not initServer(t1, addr bad1), "client certificates asked for with nothing to check them")
var bad2 = serverConfig(caRequest)
bad2.clientCaNames = @[newSeq[byte](0)]
expect(not initServer(t1, addr bad2), "an empty CA name")
var bad3 = serverConfig(caRequest)
for i in 0 ..< 70: bad3.clientCaNames.add newSeq[byte](1000)
expect(not initServer(t1, addr bad3), "CA names over 64 KiB")
echo "PASS review M4: impossible client-certificate settings refused at initServer"
