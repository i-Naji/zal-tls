{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/kx
import zal_tls/keys/schedule
import zal_tls/wire/bytes
import zal_tls/config/config
import zal_tls/private/core/[conn, client]

import zal_tls/record/protect
import zal_tls/wire/consts
import hexutil, rfc8448

# RFC 8448 section 4 from the client's side, byte-exact: section 3's
# handshake stores the ticket (PSK from the resumption secret), section 4's
# ClientHello gets its binder from us, then early data, EndOfEarlyData and
# Finished are the RFC's records.
proc t3(step, label: string): string = trace(Simple, step, label)
proc t4(step, label: string): string = trace(Resumed, step, label)

var curCh: seq[byte] = @[]
var curPriv: seq[byte] = @[]
var seenParams = default(HelloParams)

proc rfcBuild(ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.} =
  seenParams = p[]
  putBytes(w, bytesOf(curCh), curCh.len)
  result = w.ok

proc rfcKey(ctx: nil pointer; g: KxGroup; k: var KxKey; share: Bytes): bool {.nimcall.} =
  result = setPrivate(k, g, bytesOf(curPriv), share)

proc acceptAll(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} = 0

proc fixedClock(): int64 {.nimcall.} = 1_000_000

var store = default(MemoryStore)
initMemoryStore(store)
var cfg = defaultClientConfig(nil)
cfg.builder = HelloBuilder(build: rfcBuild, ctx: nil)
cfg.kx = KxHook(generate: rfcKey, respond: nil, ctx: nil)
cfg.shareGroups = @[kxX25519]
cfg.verifier = CertVerifier(verify: acceptAll, ctx: nil)
cfg.sessions = memoryStore(addr store)
cfg.earlyData = true
cfg.clock = fixedClock
var outb = newSeq[byte](65536)

proc peekTicket(name: string; tkt: var SessionTicket): bool =
  ## The store's newest ticket for `name`, left in the store. (Not `t`:
  ## the hooks' parameter name leaks, Nimony bug c37.)
  result = false
  let tf = cfg.sessions.take
  let pf = cfg.sessions.put
  if tf == nil or pf == nil: return
  result = tf(cfg.sessions.ctx, name, 1_000_000, tkt)
  if result: pf(cfg.sessions.ctx, addr tkt)

var none = newSeq[byte](1)
var r = default(StepResult)

# 1. Section 3's handshake, then its NewSessionTicket: stored.
proc storeRfcTicket() =
  curCh = hex(t3("{client} construct a ClientHello", "ClientHello"))
  curPriv = hex(t3("{client} create an ephemeral x25519", "private key"))
  var c = default(TlsConn)
  expect(initClient(c, addr cfg, "server"), "init 1")
  expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 1")
  expect(seenParams.pskTicket.len == 0, "no ticket offered at first")
  var shRec = hex(nth(Simple, "{server} send handshake record", "complete record", 0))
  discard step(c, bytesOf(shRec), shRec.len, bytesOf(outb), outb.len, r)
  var flight = hex(nth(Simple, "{server} send handshake record", "complete record", 1))
  expect(step(c, bytesOf(flight), flight.len, bytesOf(outb), outb.len, r) == stSend, "finished 1")
  expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stReady, "ready 1")
  expect(not c.resumed, "full handshake first")
  var nst = hex(nth(Simple, "{server} send handshake record", "complete record", 2))
  expect(step(c, bytesOf(nst), nst.len, bytesOf(outb), outb.len, r) == stNeedInput and r.consumed == nst.len, "ticket")
  release(c)

storeRfcTicket()
var tk = default(SessionTicket)
expect(peekTicket("server", tk), "ticket stored")
expect(tk.ticket.len == 178 and tk.lifetime == 30 and tk.ageAdd == 0xfad6aac5'u32 and
       tk.maxEarlyData == 1024 and tk.suite == suiteAes128Gcm and tk.issuedMs == 1_000_000 and
       tk.alpn == "" and tk.serverName == "server", "ticket fields")
proc sec(s: Secret): string = toHex(s.b.toOpenArray(0, s.n - 1))
expect(sec(tk.psk) == t4("{client} extract secret \"early\"", "IKM"), "ticket PSK (RFC 8448 4)")
echo "PASS client: NewSessionTicket stored, PSK from the resumption secret"

# 2. Section 4: the RFC's ClientHello, our binder (equal to the RFC's).
curCh = hex(t4("{client} send handshake record", "payload"))
curPriv = hex(t4("{client} create an ephemeral x25519", "private key"))
# The builder writes the RFC's hello with a wrong binder: ours replaces it.
for i in curCh.len - 32 ..< curCh.len: curCh[i] = 0
var c2 = default(TlsConn)
expect(initClient(c2, addr cfg, "server"), "init 2")
expect(step(c2, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 2")
expect(seenParams.pskTicket == tk.ticket and seenParams.early and seenParams.pskBinderLen == 32, "ticket offered")
expect(seenParams.pskAge == 0xfad6aac5'u32, "obfuscated age: 0 ms + age_add")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Resumed, "{client} send handshake record", "complete record", 0),
       "ClientHello record with the RFC's binder")
expect(step(c2, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stNeedInput, "waiting for the server")
expect(not peekTicket("server", tk), "the ticket was used up")
# 3. Early data, byte-exact.
var early = hex(t4("{client} send application_data record", "payload"))
var ebuf = newSeq[byte](5 + early.len + 1 + 16)
copyMem(addr ebuf[5], addr early[0], early.len)
expect(sealEarly(c2, bytesOf(ebuf), 0, early.len) == ebuf.len, "sealEarly")
expect(toHex(ebuf) == nth(Resumed, "{client} send application_data record", "complete record", 0), "early data record")
# Over the ticket's limit (1024): refused.
var big = newSeq[byte](5 + 1100 + 17)
expect(sealEarly(c2, bytesOf(big), 0, 1100) == 0, "over max_early_data")
# 4. ServerHello, EE (early data accepted) + Finished: EndOfEarlyData and Finished.
var sh2 = hex(nth(Resumed, "{server} send handshake record", "complete record", 0))
expect(step(c2, bytesOf(sh2), sh2.len, bytesOf(outb), outb.len, r) == stNeedInput and r.consumed == sh2.len, "SH 2")
expect(c2.resumed, "resumed")
var fl2 = hex(nth(Resumed, "{server} send handshake record", "complete record", 1))
let st = step(c2, bytesOf(fl2), fl2.len, bytesOf(outb), outb.len, r)
if st != stSend: echo st, " ", r.alert, " ", r.reason
expect(st == stSend and r.consumed == fl2.len, "flight 2")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) ==
       nth(Resumed, "{client} send handshake record", "complete record", 1) &
       nth(Resumed, "{client} send handshake record", "complete record", 2), "EndOfEarlyData and Finished records")
expect(c2.earlyAccepted and not c2.earlyRejected, "early data accepted")
expect(step(c2, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stReady, "ready 2")
expect(sealEarly(c2, bytesOf(ebuf), 0, early.len) == 0, "no early data after the handshake")
echo "PASS client: RFC 8448 4 byte-exact (binder, early data, EndOfEarlyData, Finished)"
# 5. Application data both ways.
var app = hex(nth(Resumed, "{client} send application_data record", "payload", 1))
var abuf = newSeq[byte](5 + app.len + 17)
copyMem(addr abuf[5], addr app[0], app.len)
expect(sealApp(c2, bytesOf(abuf), 0, app.len) == abuf.len, "sealApp")
expect(toHex(abuf) == nth(Resumed, "{client} send application_data record", "complete record", 1), "app record")
var sapp = hex(t4("{server} send application_data record", "complete record"))
expect(step(c2, bytesOf(sapp), sapp.len, bytesOf(outb), outb.len, r) == stAppData, "server app data")
expect(toHex(sapp.toOpenArray(r.off, r.off + r.len - 1)) == t4("{server} send application_data record", "payload"), "server payload")
echo "PASS client: resumed traffic byte-exact"
release(c2)

# 6. A ServerHello selecting an identity we did not offer: illegal_parameter.
storeRfcTicket()
curCh = hex(t4("{client} send handshake record", "payload"))
curPriv = hex(t4("{client} create an ephemeral x25519", "private key"))
var c3 = default(TlsConn)
expect(initClient(c3, addr cfg, "server"), "init 3")
expect(step(c3, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 3")
var sh3 = hex(nth(Resumed, "{server} send handshake record", "complete record", 0))
var found = false
for i in 0 .. sh3.len - 6:                       # pre_shared_key: 00 29 00 02 00 00
  if not found and sh3[i] == 0 and sh3[i + 1] == 0x29 and sh3[i + 2] == 0 and sh3[i + 3] == 2:
    sh3[i + 5] = 1
    found = true
expect(found, "the ServerHello's pre_shared_key")
expect(step(c3, bytesOf(sh3), sh3.len, bytesOf(outb), outb.len, r) == stFailed and r.alert == 47, "selected identity 1")
release(c3)
# 7. A ticket that expired while stored is not offered (the store drops it).
storeRfcTicket()
var late = cfg
late.clock = proc (): int64 {.nimcall.} = 1_000_000 + 30_000
var c4 = default(TlsConn)
expect(initClient(c4, addr late, "server"), "init 4")
expect(step(c4, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 4")
expect(seenParams.pskTicket.len == 0 and not seenParams.early, "expired: no ticket")
release(c4)
echo "PASS client: a PSK we did not offer refused; an expired ticket not offered"

# 8. A resumed handshake asks for no certificate (4.3.2): the server's
#    flight with a CertificateRequest after EncryptedExtensions (re-sealed
#    with the RFC's handshake secret) is unexpected_message.
storeRfcTicket()
curCh = hex(t4("{client} send handshake record", "payload"))
curPriv = hex(t4("{client} create an ephemeral x25519", "private key"))
var c5 = default(TlsConn)
expect(initClient(c5, addr cfg, "server"), "init 5")
expect(step(c5, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 5")
var sh5 = hex(nth(Resumed, "{server} send handshake record", "complete record", 0))
expect(step(c5, bytesOf(sh5), sh5.len, bytesOf(outb), outb.len, r) == stNeedInput and c5.resumed, "resumed")
block:
  var sHs = default(Secret)
  var sx = hex(t4("{server} derive secret \"tls13 s hs traffic\"", "expanded"))
  sHs.n = 32
  for i in 0 ..< 32: sHs.b[i] = sx[i]
  var ee = hex(t4("{server} construct an EncryptedExtensions", "EncryptedExtensions"))
  var cr = @[13'u8, 0, 0, 11, 0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3]   # signature_algorithms: ecdsa_secp256r1_sha256
  var fin = hex(t4("{server} construct a Finished", "Finished"))
  var pay: seq[byte] = @[]
  for x in ee: pay.add x
  for x in cr: pay.add x
  for x in fin: pay.add x
  var rec = newSeq[byte](5 + pay.len + 17)
  for i in 0 ..< pay.len: rec[5 + i] = pay[i]
  var p = default(Protection)
  expect(install(p, suiteAes128Gcm, sHs), "the server's handshake keys")
  expect(sealRecord(p, bytesOf(rec), 0, pay.len, ctHandshake, 0) == rec.len, "sealed")
  clear(p)
  let st5 = step(c5, bytesOf(rec), rec.len, bytesOf(outb), outb.len, r)
  expect(st5 == stFailed and r.alert == alUnexpectedMessage, "a CertificateRequest when resumed: " & $r.alert)
release(c5)
echo "PASS client: no CertificateRequest on a resumed handshake"
