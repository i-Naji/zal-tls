{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/kx
import zal_tls/keys/schedule
import zal_tls/wire/bytes
import zal_tls/config/config
import zal_tls/private/core/[conn, client]

import hexutil, rfc8448

# RFC 8448 section 3, from the client's side, byte-exact: the builder sends
# the RFC's ClientHello, the key hook gives the RFC's x25519 key.
proc t(step, label: string): string = trace(Simple, step, label)
proc sec(s: Secret): string = toHex(s.b.toOpenArray(0, s.n - 1))

var rfcCh = hex(t("{client} construct a ClientHello", "ClientHello"))
var cPriv = hex(t("{client} create an ephemeral x25519", "private key"))
var chainLen = 0

proc rfcBuild(ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.} =
  putBytes(w, bytesOf(rfcCh), rfcCh.len)
  result = w.ok

proc rfcKey(ctx: nil pointer; g: KxGroup; k: var KxKey; share: Bytes): bool {.nimcall.} =
  result = setPrivate(k, g, bytesOf(cPriv), share)

proc acceptAll(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} =
  chainLen = chain[].len
  result = if host == "server": 0 else: 42

var cfg = defaultClientConfig(nil)
cfg.builder = HelloBuilder(build: rfcBuild, ctx: nil)
cfg.kx = KxHook(generate: rfcKey, respond: nil, ctx: nil)
cfg.shareGroups = @[kxX25519]                    # the RFC's client shares x25519 only
cfg.verifier = CertVerifier(verify: acceptAll, ctx: nil)
var c = default(TlsConn)
expect(initClient(c, addr cfg, "server"), "line 35")
var outb = newSeq[byte](65536)
var none = newSeq[byte](1)
var r = default(StepResult)

# 1. The ClientHello record (legacy_record_version 0x0301).
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "line 41")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Simple, "{client} send handshake record", "complete record", 0), "line 42")
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stNeedInput, "line 43")
# 2. ServerHello; the encrypted flight; our Finished, byte-exact.
var shRec = hex(nth(Simple, "{server} send handshake record", "complete record", 0))
expect(step(c, bytesOf(shRec), shRec.len, bytesOf(outb), outb.len, r) == stNeedInput and r.consumed == shRec.len, "line 46")
var flight = hex(nth(Simple, "{server} send handshake record", "complete record", 1))
let st2 = step(c, bytesOf(flight), flight.len, bytesOf(outb), outb.len, r)
if st2 != stSend: echo st2, " ", r.alert, " ", r.reason, " consumed ", r.consumed, "/", flight.len
expect(st2 == stSend and r.consumed == flight.len, "line 48")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Simple, "{client} send handshake record", "complete record", 1), "line 49")
expect(chainLen == 1, "line 50")
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stReady and r.consumed == 0, "line 51")
echo "PASS client: ClientHello and Finished records byte-exact (RFC 8448 3)"

# 3. The ticket: parsed, dropped.
var nst = hex(nth(Simple, "{server} send handshake record", "complete record", 2))
expect(step(c, bytesOf(nst), nst.len, bytesOf(outb), outb.len, r) == stNeedInput and r.consumed == nst.len, "line 56")
var tx = default(Secret)
var rx = default(Secret)
var txSeq = 0'u64
var rxSeq = 0'u64
expect(exportSecrets(c, tx, rx, txSeq, rxSeq), "line 61")
expect(sec(tx) == t("{server} derive secret \"tls13 c ap traffic\"", "expanded"), "line 62")
expect(sec(rx) == t("{server} derive secret \"tls13 s ap traffic\"", "expanded"), "line 63")
expect(txSeq == 0 and rxSeq == 1, "line 64")
# 4. Our application data record, byte-exact.
var app = hex(t("{client} send application_data record", "payload"))
var abuf = newSeq[byte](5 + app.len + 1 + 16)
copyMem(addr abuf[5], addr app[0], app.len)
expect(sealApp(c, bytesOf(abuf), 0, app.len) == abuf.len, "line 69")
expect(toHex(abuf) == t("{client} send application_data record", "complete record"), "line 70")
# 5. The server's, decrypted in place.
var sapp = hex(t("{server} send application_data record", "complete record"))
expect(step(c, bytesOf(sapp), sapp.len, bytesOf(outb), outb.len, r) == stAppData and r.consumed == sapp.len, "line 73")
expect(toHex(sapp.toOpenArray(r.off, r.off + r.len - 1)) == t("{server} send application_data record", "payload"), "line 74")
# 6. The server closes; our close_notify, byte-exact.
var salert = hex(t("{server} send alert record", "complete record"))
expect(step(c, bytesOf(salert), salert.len, bytesOf(outb), outb.len, r) == stPeerClosed, "line 77")
let n = close(c, bytesOf(outb), outb.len)
expect(n > 0 and toHex(outb.toOpenArray(0, n - 1)) == t("{client} send alert record", "complete record"), "line 79")
var cert = hex(t("{server} construct a Certificate", "Certificate"))
expect(peerLeafDer(c).len == cert.len - 13, "line 81")
echo "PASS client: traffic both ways, close_notify byte-exact, secrets exported"
release(c)
