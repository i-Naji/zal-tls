{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages]
import hexutil, loophelp

# Resumption and 0-RTT, our client against our server through memory:
# tickets issued and stored, resumed handshakes (no certificate), early data
# accepted once and refused on replay, after a HelloRetryRequest, for
# another ALPN; the ticket key's rotation; tampered tickets and binders.

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
var ck = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == "", "leaf")

var ticketer = default(KeyedTicketer)
assert initKeyedTicketer(ticketer)
var replay = default(MemoryReplay)
initMemoryReplay(replay)
var store = default(MemoryStore)
initMemoryStore(store)
let sessions = memoryStore(addr store)

proc clientConfig(): ClientConfig =
  result = defaultClientConfig(roots)
  result.sessions = sessions
  result.earlyData = true

proc serverConfig(): ServerConfig =
  result = defaultServerConfig()
  result.resolver = singleCert(addr ck)
  result.ticketScope = "tresume"                 # these configurations resume each other's tickets
  result.ticketer = keyedTicketer(addr ticketer)
  result.maxEarlyData = 16384
  result.antiReplay = memoryReplay(addr replay)

var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]

proc start(cc: ptr ClientConfig; sc: ptr ServerConfig) =
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, "test.example") and initServer(b.c, sc), "init")

proc done() =
  release(a.c)
  release(b.c)

proc tickets(): int =
  ## How many tickets the store holds for test.example (left there).
  result = 0
  var held: seq[SessionTicket] = @[]
  let tf = sessions.take
  let pf = sessions.put
  if tf == nil or pf == nil: return
  var tk = default(SessionTicket)
  while tf(addr store, "test.example", unixMs(), tk):
    held.add tk
    tk = default(SessionTicket)
  result = held.len
  var i = held.len - 1
  while i >= 0:
    pf(addr store, addr held[i])
    i = i - 1

proc withEarly(cc: ptr ClientConfig; sc: ptr ServerConfig; data: seq[byte]; sent: var seq[byte]) =
  ## A connection that sends `data` as 0-RTT right after its ClientHello;
  ## `sent` is what went to the server before it answered (hello, early records).
  start(cc, sc)
  discard turn(a, ab)                            # the ClientHello
  var buf = newSeq[byte](5 + data.len + 17)
  for i in 0 ..< data.len: buf[5 + i] = data[i]
  let n = sealEarly(a.c, bytesOf(buf), 0, data.len)
  if n > 0:
    for i in 0 ..< n: ab.add buf[i]
  sent = ab
  run(a, b, ab, ba, 1 shl 20)

var cc = clientConfig()
var sc = serverConfig()
var ccNoEarly = clientConfig()
ccNoEarly.earlyData = false

# 1. A full handshake issues tickets (two), stored by the client.
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and not a.c.resumed and not b.c.resumed, "full handshake")
expect(peerLeafDer(a.c).len > 0, "a certificate the first time")
expect(tickets() == 2, "two tickets stored")
done()
echo "PASS tickets issued after the handshake and stored"

# 2. The next connection resumes: no certificate; traffic both ways.
start(addr ccNoEarly, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and a.c.resumed and b.c.resumed, "resumed")
expect(peerLeafDer(a.c) == ck.chain[0], "the server's certificate from the first handshake, when resumed")
expect(not a.c.earlyAccepted and not a.c.earlyRejected, "no early data offered: none refused")
let up = pattern(40000, 1)
let down = pattern(30000, 2)
expect(sendApp(a, ab, up, 16384) and sendApp(b, ba, down, 16384), "seal")
run(a, b, ab, ba, 1 shl 20)
expect(b.app == up and a.app == down, "traffic after resumption")
done()
echo "PASS resumed: no certificate, traffic both ways"

# 3. 0-RTT accepted, delivered first (as stEarlyData); then a replay of the
#    same hello and early records: resumable, the data never delivered twice.
var early = pattern(1000, 3)
var sent: seq[byte] = @[]
withEarly(addr cc, addr sc, early, sent)
expect(a.ready and b.ready and a.c.resumed and a.c.earlyAccepted and not a.c.earlyRejected, "0-RTT accepted")
expect(b.app == early, "early data delivered")
done()
initSide(b)
expect(initServer(b.c, addr sc), "init replay")
var q = sent
feed(b, q, 1 shl 20)
var sink: seq[byte] = @[]
while turn(b, sink): discard
expect(b.app.len == 0 and b.failed < 0, "a replay: early data skipped")
release(b.c)
echo "PASS 0-RTT accepted once; a replay's early data skipped"

# 4. 0-RTT refused after a HelloRetryRequest (the PSK still resumes, its
#    binder over message_hash + HRR + the second hello).
var scHrr = serverConfig()
scHrr.groups = @[kxSecp256r1]                    # the client shares X25519MLKEM768 and X25519
withEarly(addr cc, addr scHrr, early, sent)
if not (a.ready and b.ready and a.c.retried and a.c.resumed and b.c.resumed):
  echo "HRR: ", a.ready, b.ready, a.c.retried, a.c.resumed, b.c.resumed, " ", a.failed, " ", a.reason, " / ", b.failed, " ", b.reason
expect(a.ready and b.ready and a.c.retried and a.c.resumed and b.c.resumed, "resumed after HRR")
expect(a.c.earlyRejected and not a.c.earlyAccepted and b.app.len == 0, "0-RTT refused after HRR")
done()
echo "PASS 0-RTT refused after a HelloRetryRequest; resumed with the second hello's binder"

# 5. 0-RTT refused for another ALPN than the ticket's.
var ccAlpn = clientConfig()
ccAlpn.alpn = @["h2", "http/1.1"]
var scAlpn = serverConfig()
scAlpn.alpn = @["h2", "http/1.1"]
start(addr ccAlpn, addr scAlpn)                  # a ticket for h2
run(a, b, ab, ba, 1 shl 20)
expect(alpn(a.c) == "h2", "h2")
done()
scAlpn.alpn = @["http/1.1"]
withEarly(addr ccAlpn, addr scAlpn, early, sent)
expect(a.ready and b.ready and a.c.resumed and a.c.earlyRejected and b.app.len == 0, "0-RTT refused: other ALPN")
expect(alpn(a.c) == "http/1.1", "http/1.1")
done()
echo "PASS 0-RTT refused for another ALPN"

# 6. Early data over the ticket's limit: the server aborts (unexpected_message)
#    and delivers nothing past the limit.
start(addr cc, addr sc)                          # fresh tickets without ALPN (5 left h2 ones)
run(a, b, ab, ba, 1 shl 20)
done()
block:
  var tk = default(SessionTicket)
  let tf = sessions.take
  let pf = sessions.put
  expect(tf != nil and pf != nil and tf(addr store, "test.example", unixMs(), tk), "a ticket")
  var other = default(SessionTicket)
  while tf(addr store, "test.example", unixMs(), other): discard   # only this one left
  tk.maxEarlyData = 1'u32 shl 20                 # the client believes more than the server said
  pf(addr store, addr tk)
start(addr cc, addr sc)
discard turn(a, ab)
var over = pattern(16384, 4)
for k in 0 ..< 2:
  var buf = newSeq[byte](5 + over.len + 17)
  for i in 0 ..< over.len: buf[5 + i] = over[i]
  let sn = sealEarly(a.c, bytesOf(buf), 0, over.len)
  if sn != buf.len: echo "k=", k, " sn=", sn, " earlyWrite=", a.c.earlyWrite, " state=", a.c.state
  expect(sn == buf.len, "early record")
  for x in buf: ab.add x
run(a, b, ab, ba, 1 shl 20)
expect(b.failed == 10 and b.app.len <= 16384, "over max_early_data: unexpected_message")
done()
echo "PASS early data over the limit aborts"

# 7. The ticket key: a ticket from before one rotation still resumes, not
#    after two; a tampered ticket gives a full handshake.
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)                      # fresh tickets under the current key
done()
assert rotate(ticketer)
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and a.c.resumed, "one rotation: resumed")
done()
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)                      # tickets under the new key...
done()
assert rotate(ticketer)
assert rotate(ticketer)                                 # ... two rotations ago
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and not a.c.resumed and not b.c.resumed, "two rotations: full handshake")
done()
block:
  var tk = default(SessionTicket)
  let tf = sessions.take
  let pf = sessions.put
  expect(tf != nil and pf != nil and tf(addr store, "test.example", unixMs(), tk), "a ticket")
  var other = default(SessionTicket)
  while tf(addr store, "test.example", unixMs(), other): discard   # only this one left
  tk.ticket[tk.ticket.len div 2] = tk.ticket[tk.ticket.len div 2] xor 1
  pf(addr store, addr tk)
start(addr cc, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and not a.c.resumed, "tampered ticket: full handshake")
done()
echo "PASS ticket key rotation (one kept), tampered tickets refused"

# 8. A binder that does not match (someone else's hello): decrypt_error.
start(addr ccNoEarly, addr sc)
discard turn(a, ab)                              # the ClientHello record: the binder ends it
ab[ab.len - 1] = ab[ab.len - 1] xor 1
run(a, b, ab, ba, 1 shl 20)
expect(b.failed == 51, "wrong binder: decrypt_error")
done()
# An expired ticket (the server's clock): a full handshake.
var scLate = serverConfig()
scLate.clock = proc (): int64 {.nimcall.} = unixMs() + 7201 * 1000
start(addr ccNoEarly, addr scLate)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and not a.c.resumed, "expired ticket: full handshake")
done()
echo "PASS a wrong binder refused; an expired ticket not resumed"

# 9. A ticket split across three records (and nothing else): stored by the
#    client, not data; the next connection resumes with it.
var scManual = serverConfig()
scManual.ticketsAfter = 0
block:
  var tk = default(SessionTicket)
  let tf = sessions.take
  expect(tf != nil, "take")
  while tf(addr store, "test.example", unixMs(), tk): discard   # the store empty
start(addr ccNoEarly, addr scManual)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and tickets() == 0, "no ticket sent")
block:
  var state = default(SessionState)   # not `st`: the seal hook's parameter leaks (c37)
  var nonce = [7'u8]
  state.suite = suite(b.c)
  state.psk = ticketPsk(hashOf(suite(b.c)), b.c.resumption, ptrOf(nonce), 1)
  state.serverName = "test.example"
  state.issuedMs = unixMs()
  state.authMs = state.issuedMs
  for ch in "tresume": state.scope.add byte(ch)
  state.lifetime = 600
  state.ageAdd = 12345
  var sealed: seq[byte] = @[]
  let sf = scManual.ticketer.seal
  expect(sf != nil and sf(scManual.ticketer.ctx, addr state, sealed), "seal a ticket")
  var msg = newSeq[byte](64 + sealed.len)
  var w = initWriter(bytesOf(msg), 0, msg.len)
  writeNewSessionTicket(w, 600, 12345, ptrOf(nonce), 1, bytesOf(sealed), sealed.len, 0)
  expect(w.ok, "ticket message")
  let n = w.pos
  var at0 = 0
  for cut in [5, n div 2, n]:
    let k = cut - at0
    var rec = newSeq[byte](5 + k + 1 + 16)
    for i in 0 ..< k: rec[5 + i] = msg[at0 + i]
    expect(sealRecord(b.c.wr, bytesOf(rec), 0, k, ctHandshake, 0) == rec.len, "seal a piece")
    for x in rec: ba.add x
    at0 = cut
  run(a, b, ab, ba, 7)                           # delivered in 7-byte pieces too
  expect(a.app.len == 0 and a.failed < 0, "the ticket is no data")
  expect(tickets() == 1, "the ticket stored")
done()
start(addr ccNoEarly, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and a.c.resumed, "resumed with the split ticket")
done()
echo "PASS a ticket split across records: stored, not data, and it resumes"

# 9. The age window is strict (|drift| < earlyWindowMs): with the replay
#    memory kept for twice the window, a hello is never taken twice.
var gClientNow = 5_000_000'i64
var gServerNow = 5_000_000'i64
proc clientNow(): int64 {.nimcall.} = gClientNow
proc serverNow(): int64 {.nimcall.} = gServerNow
var cClock = clientConfig()
cClock.clock = clientNow
var sClock = serverConfig()
sClock.clock = serverNow
sClock.earlyWindowMs = 10_000
proc freshTicket() =
  var tk = default(SessionTicket)
  let tf = sessions.take
  if tf != nil:
    while tf(addr store, "test.example", unixMs() + 1_000_000_000, tk): discard   # (all of them)
  start(addr cClock, addr sClock)
  run(a, b, ab, ba, 1 shl 20)
  done()
freshTicket()
gClientNow = 5_000_000 + 10_000                   # the client's age is the window ahead
withEarly(addr cClock, addr sClock, early, sent)
expect(a.ready and a.c.resumed and a.c.earlyRejected and b.app.len == 0, "a drift of exactly the window: refused")
done()
gClientNow = 5_000_000
freshTicket()
gClientNow = 5_000_000 + 9_999
withEarly(addr cClock, addr sClock, early, sent)
expect(a.ready and a.c.earlyAccepted and b.app == early, "within the window: taken")
done()
for later in [9_998'i64, 9_999, 10_000, 19_999, 20_000, 20_001]:
  gServerNow = 5_000_000 + later
  initSide(b)
  expect(initServer(b.c, addr sClock), "init replay")
  var q = sent
  feed(b, q, 1 shl 20)
  var sink: seq[byte] = @[]
  while turn(b, sink): discard
  expect(b.app.len == 0, "a replay " & $later & " ms later: not taken")
  release(b.c)
echo "PASS the age window is strict; a replay is never taken, at any time"

# 10. Refused 0-RTT is skipped as far as the server lets tickets carry
#     (maxEarlyData), not a fixed amount: 80 KiB under a ticket that no
#     longer opens (two key rotations), then a full handshake.
var sBig = serverConfig()
sBig.maxEarlyData = 1'u32 shl 20
start(addr cc, addr sBig)                        # a ticket allowing 1 MiB
run(a, b, ab, ba, 1 shl 20)
done()
assert rotate(ticketer)
assert rotate(ticketer)
start(addr cc, addr sBig)
discard turn(a, ab)
var chunk = pattern(16384, 9)
for k in 0 ..< 5:
  var buf = newSeq[byte](5 + chunk.len + 17)
  for i in 0 ..< chunk.len: buf[5 + i] = chunk[i]
  expect(sealEarly(a.c, bytesOf(buf), 0, chunk.len) == buf.len, "early record " & $k)
  for x in buf: ab.add x
run(a, b, ab, ba, 1 shl 20)
expect(b.failed < 0 and a.ready and b.ready and not a.c.resumed and a.c.earlyRejected and b.app.len == 0,
       "80 KiB of refused 0-RTT skipped: " & $b.failed & " " & b.reason)
done()
echo "PASS refused 0-RTT skipped up to the server's maxEarlyData"

# 11. A ticket promising more 0-RTT than the server now takes: refused (and
#     skipped), not taken nor fatal.
var sLow = serverConfig()                        # tickets promise 16384
start(addr cc, addr sLow)
run(a, b, ab, ba, 1 shl 20)
done()
sLow.maxEarlyData = 100                          # ... the server now takes 100
withEarly(addr cc, addr sLow, early, sent)       # 1000 bytes
expect(b.failed < 0 and a.ready and a.c.resumed and a.c.earlyRejected and b.app.len == 0,
       "a ticket over the current limit: 0-RTT refused")
done()
echo "PASS 0-RTT refused where a ticket promises more than the server now takes"

# 12. A client that offered 0-RTT and fails before EncryptedExtensions:
#     its alert goes under the handshake keys, which a server that refused
#     the 0-RTT reads (it would skip one under the early keys).
start(addr cc, addr sLow)                        # a ticket promising 100
run(a, b, ab, ba, 1 shl 20)
done()
sLow.maxEarlyData = 50                           # ... refused from now on
block:
  start(addr cc, addr sLow)
  discard turn(a, ab)
  var e1 = newSeq[byte](5 + 10 + 17)
  expect(sealEarly(a.c, bytesOf(e1), 0, 10) == e1.len, "early")
  for x in e1: ab.add x
  feed(b, ab, 1 shl 30)
  while turn(b, ba): discard
  ba[ba.len - 1] = ba[ba.len - 1] xor 1          # the server's flight, spoiled at its end
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, ab): discard
  expect(a.failed == alBadRecordMac, "the client fails: " & $a.failed)
  feed(b, ab, 1 shl 30)
  var sink: seq[byte] = @[]
  while turn(b, sink): discard
  expect(b.failed == alBadRecordMac and b.reason.len > 0, "the server reads the client's alert: " & $b.failed)
  done()
echo "PASS a client that offered 0-RTT: its alert before EncryptedExtensions is read"

# 13. Resumption chains end: a ticket reissued on a resumed connection
#     keeps the first handshake's time; past resumeWithin, a full one.
var sChain = serverConfig()
sChain.clock = serverNow
sChain.resumeWithin = 100                         # seconds
gServerNow = 7_000_000
freshTicket()
start(addr cc, addr sChain)
run(a, b, ab, ba, 1 shl 20)
expect(not b.c.resumed, "a full handshake")
done()
gServerNow = 7_000_000 + 50_000
start(addr cc, addr sChain)
run(a, b, ab, ba, 1 shl 20)
expect(b.c.resumed, "resumed 50 s later (a ticket issued then)")
done()
gServerNow = 7_000_000 + 101_000
start(addr cc, addr sChain)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and b.ready and not b.c.resumed, "101 s after the full handshake: a full one again")
done()
echo "PASS resumption chains end resumeWithin after the full handshake"

# 14. The newest ticket unusable (its suite no longer ours): the next is used.
start(addr ccNoEarly, addr sc)
run(a, b, ab, ba, 1 shl 20)                      # two fresh tickets
done()
var cOne = clientConfig()
cOne.earlyData = false
cOne.suites = @[suiteAes128Gcm]
block:
  var t1 = default(SessionTicket)
  var t2 = default(SessionTicket)
  let tf = sessions.take
  let pf = sessions.put
  expect(tf != nil and pf != nil and tf(addr store, "test.example", unixMs(), t1) and
         tf(addr store, "test.example", unixMs(), t2), "two tickets")
  pf(addr store, addr t2)
  t1.suite = suiteAes256Gcm                     # not in cOne's suites
  t1.issuedMs = t1.issuedMs + 1
  pf(addr store, addr t1)
start(addr cOne, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(a.ready and a.c.resumed, "the next ticket used")
done()
echo "PASS an unusable newest ticket: the next one is offered"

# 15. A binder whose length is not the ticket's hash: decrypt_error.
start(addr ccNoEarly, addr sc)
run(a, b, ab, ba, 1 shl 20)
done()
block:
  var tk15 = default(SessionTicket)   # not `t`: the hooks' parameter leaks (c37)
  let tf = sessions.take
  let pf = sessions.put
  expect(tf != nil and pf != nil and tf(addr store, "test.example", unixMs(), tk15), "a ticket")
  var other = default(SessionTicket)
  while tf(addr store, "test.example", unixMs(), other): discard
  tk15.suite = suiteAes256Gcm                       # the server's copy says AES-128 (SHA-256)
  tk15.psk.n = 48
  pf(addr store, addr tk15)
start(addr ccNoEarly, addr sc)
run(a, b, ab, ba, 1 shl 20)
expect(b.failed == alDecryptError, "a 48-byte binder for a SHA-256 ticket: " & $b.failed)
done()
echo "PASS a binder of the wrong length refused"
release(ck)
