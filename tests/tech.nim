{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[hash, hkdf, hpke, kx, x509]
import zal_tls/keys/schedule
import zal_tls/config/config
import zal_tls/wire/[bytes, consts, messages, ech]
import zal_tls/private/core/[conn, client, server]

import hexutil, rfc8448, loophelp

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

# ECH on the wire (RFC 9849): config lists, the extension's two forms, the
# inner hello encoded (session id emptied, extensions compressed, padding)
# and decoded against an outer hello; bad references refused.

# 1. ECHConfigList: two of ours around one of another version (skipped).
var pub1 = newSeq[byte](32)
var pub2 = newSeq[byte](32)
for i in 0 ..< 32:
  pub1[i] = byte(i)
  pub2[i] = byte(100 + i)
var lb = newSeq[byte](1024)
var w = initWriter(bytesOf(lb), 0, lb.len)
let lst = begin16(w)
writeEchConfig(w, 7, bytesOf(pub1), "public.example", 32)
put16(w, 0xfe0c)                                 # another version: skipped
let other = begin16(w)
for x in [1'u8, 2, 3]: put8(w, int(x))
finish16(w, other)
writeEchConfig(w, 9, bytesOf(pub2), "other.example", 0)
finish16(w, lst)
expect(w.ok, "written")
var configs: seq[EchConfigView] = @[]
expect(parseEchConfigList(bytesOf(lb), w.pos, configs) and configs.len == 2, "two configs")
expect(configs[0].configId == 7 and configs[0].kemId == 0x0020 and configs[0].publicName == "public.example" and
       configs[0].maxNameLen == 32 and configs[0].kdfs == @[1] and configs[0].aeads == @[1], "the first")
for i in 0 ..< 32: expect(lb[configs[0].pubAt + i] == byte(i), "its key")
expect(configs[1].configId == 9 and configs[1].publicName == "other.example", "the second")
expect(lb[configs[0].at] == 0xfe and lb[configs[0].at + 1] == 0x0d and
       configs[0].len == 4 + ((int(lb[configs[0].at + 2]) shl 8) or int(lb[configs[0].at + 3])), "its bytes (HPKE info)")
var bad = @[0'u8, 3, 0xfe, 0x0d, 0]
expect(not parseEchConfigList(bytesOf(bad), bad.len, configs), "a cut config refused")
echo "PASS ECHConfigList: ours parsed, another version skipped"

# 2. The extension: outer and inner forms.
var eb = newSeq[byte](256)
var we = initWriter(bytesOf(eb), 0, eb.len)
var enc = newSeq[byte](32)
for i in 0 ..< 32: enc[i] = byte(200 - i)
let payloadAt = writeEchOuter(we, 1, 1, 7, bytesOf(enc), 32, 48)
expect(we.ok and payloadAt > 0, "outer written")
var ev = default(EchExtView)
expect(parseEchExtension(bytesOf(eb), 4, we.pos - 4, ev) == 0 and ev.outer and ev.kdf == 1 and ev.aead == 1 and
       ev.configId == 7 and ev.encLen == 32 and ev.payloadLen == 48 and ev.payloadAt == payloadAt, "outer parsed")
var wi = initWriter(bytesOf(eb), 0, eb.len)
writeEchInner(wi)
expect(parseEchExtension(bytesOf(eb), 4, wi.pos - 4, ev) == 0 and not ev.outer, "inner parsed")
echo "PASS the encrypted_client_hello extension: outer and inner"

# 3. EncodedClientHelloInner: RFC 8448's ClientHello as the inner and the
#    outer both; key_share and supported_versions (contiguous) compressed.
var inner = hex(trace(Simple, "{client} construct a ClientHello", "ClientHello"))
var outer = inner
var encoded: seq[byte] = @[]
expect(encodeInner(bytesOf(inner), inner.len, @[extKeyShare, extSupportedVersions], 32, encoded), "encoded")
expect(encoded.len mod 32 == 0 and encoded.len < inner.len + 64, "padded to 32: " & $encoded.len)
var back: seq[byte] = @[]
expect(decodeInner(bytesOf(encoded), encoded.len, bytesOf(outer), outer.len, back) == 0, "decoded")
expect(back == inner, "the inner hello again")
# The session id comes from the outer hello.
var withSid: seq[byte] = @[]
for i in 0 ..< 38: withSid.add outer[i]
withSid.add 32
for i in 0 ..< 32: withSid.add byte(i)
for i in 39 ..< outer.len: withSid.add outer[i]
let ml = withSid.len - 4
withSid[1] = byte(ml shr 16)
withSid[2] = byte((ml shr 8) and 0xff)
withSid[3] = byte(ml and 0xff)
expect(decodeInner(bytesOf(encoded), encoded.len, bytesOf(withSid), withSid.len, back) == 0 and
       back.len == inner.len + 32 and back[38] == 32 and back[39] == 0, "the outer's session id")
echo "PASS EncodedClientHelloInner: compressed, padded, restored"

# 4. Bad references: a type the outer lacks, ECH itself, twice, out of order;
#    padding that is not zero.
proc refsCase(types: seq[int]; what: string) =
  var e2: seq[byte] = @[]
  expect(encodeInnerRaw(bytesOf(inner), inner.len, types, e2), "raw " & what)
  var b2: seq[byte] = @[]
  expect(decodeInner(bytesOf(e2), e2.len, bytesOf(outer), outer.len, b2) == alIllegalParameter, what)
refsCase(@[0x1234], "a type the outer lacks")
refsCase(@[extEch], "the ECH extension itself")
refsCase(@[extKeyShare, extKeyShare], "a type twice")
refsCase(@[extSupportedVersions, extKeyShare], "out of order")
var e3 = encoded
e3[e3.len - 1] = 1
var b3: seq[byte] = @[]
expect(decodeInner(bytesOf(e3), e3.len, bytesOf(outer), outer.len, b3) == alIllegalParameter, "padding not zero")
echo "PASS bad ech_outer_extensions and padding refused"

# 5. The acceptance confirmations (RFC 9849 7.2), against HKDF built here;
#    an ECH key whose published config seals to it (HPKE both ways).
block:
  var rnd = newSeq[byte](32)
  var th = newSeq[byte](32)
  for i in 0 ..< 32:
    rnd[i] = byte(i * 3)
    th[i] = byte(255 - i)
  for hrr in [false, true]:
    var got = default(array[8, byte])
    expect(echConfirmation(hashSha256, bytesOf(rnd), bytesOf(th), hrr, ptrOf(got)), "confirmation")
    var zeros = newSeq[byte](32)
    var prk = newSeq[byte](32)
    expect(hkdfExtract(hashSha256, bytesOf(zeros), 32, bytesOf(rnd), 32, bytesOf(prk)), "extract")
    let label = "tls13 " & (if hrr: "hrr ech accept confirmation" else: "ech accept confirmation")
    var info: seq[byte] = @[0'u8, 8, byte(label.len)]
    for ch in label: info.add byte(ch)
    info.add 32
    for x in th: info.add x
    var want = newSeq[byte](8)
    expect(hkdfExpand(hashSha256, bytesOf(prk), 32, bytesOf(info), info.len, bytesOf(want), 8), "expand")
    for i in 0 ..< 8: expect(got[i] == want[i], "confirmation byte " & $i & (if hrr: " (hrr)" else: ""))
  let key = newEchKey(42, "public.example")
  let lst = echConfigList(@[key])
  var cfgs: seq[EchConfigView] = @[]
  var lb2 = lst
  expect(parseEchConfigList(bytesOf(lb2), lb2.len, cfgs) and cfgs.len == 1 and cfgs[0].configId == 42 and
         cfgs[0].publicName == "public.example", "the key's config list")
  var info2: seq[byte] = @[]
  for ch in "tls ech": info2.add byte(ch)
  info2.add 0
  for i in 0 ..< cfgs[0].len: info2.add lb2[cfgs[0].at + i]
  var s = default(HpkeCtx)
  var r = default(HpkeCtx)
  var enc2 = newSeq[byte](HpkeEncLen)
  expect(setupSender(s, at(bytesOf(lb2), cfgs[0].pubAt), bytesOf(info2), info2.len, bytesOf(enc2)), "sender")
  var msg = @[1'u8, 2, 3, 4, 5]
  var aad = @[9'u8, 9]
  var ct = newSeq[byte](64)
  var ctLen = 0
  expect(seal(s, bytesOf(msg), msg.len, bytesOf(aad), aad.len, bytesOf(ct), ct.len, ctLen), "seal")
  var kp = key.priv
  expect(setupRecipient(r, ptrOf(kp), bytesOf(enc2), bytesOf(info2), info2.len), "recipient")
  var pt = newSeq[byte](64)
  var ptLen = 0
  expect(open(r, bytesOf(ct), ctLen, bytesOf(aad), aad.len, bytesOf(pt), pt.len, ptLen) and ptLen == 5 and
         pt[4] == 5, "opened with the key")
  clear(s)
  clear(r)
echo "PASS ECH confirmations; an ECH key and its config (HPKE both ways)"

# 6. The client: the outer hello shows the public name and no protocols;
#    the payload opens with the key to the inner hello (the real name, the
#    protocols, the inner mark, its own random, the same key shares).
proc recordMsg(q: seq[byte]): seq[byte] =
  ## The first record's payload (a plaintext handshake record).
  let n = (int(q[3]) shl 8) or int(q[4])
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = q[5 + i]

block:
  let key = newEchKey(5, "public.example")
  var cc = defaultClientConfig(nil)
  cc.echConfigs = echConfigList(@[key])
  cc.alpn = @["h2"]
  var c = default(TlsConn)
  expect(initClient(c, addr cc, "secret.example"), "init")
  var outb = newSeq[byte](65536)
  var none = newSeq[byte](1)
  var r = default(StepResult)
  expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  var q = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q[i] = outb[i]
  var outer = recordMsg(q)
  var v = default(HelloView)
  expect(parseClientHello(bytesOf(outer), outer.len, v) == 0 and v.serverName == "public.example" and
         v.alpn.len == 0 and v.echLen > 0, "the outer hello: the public name, no protocols")
  var ev = default(EchExtView)
  expect(parseEchExtension(bytesOf(outer), v.echAt, v.echLen, ev) == 0 and ev.outer and ev.configId == 5 and
         ev.encLen == 32, "its ECH extension")
  var aad = newSeq[byte](outer.len - 4)
  for i in 4 ..< outer.len: aad[i - 4] = outer[i]
  for i in 0 ..< ev.payloadLen: aad[ev.payloadAt - 4 + i] = 0
  var info: seq[byte] = @[]
  for ch in "tls ech": info.add byte(ch)
  info.add 0
  for x in key.config: info.add x
  var rc = default(HpkeCtx)
  var kp = key.priv
  expect(setupRecipient(rc, ptrOf(kp), at(bytesOf(outer), ev.encAt), bytesOf(info), info.len), "recipient")
  var encoded = newSeq[byte](ev.payloadLen)
  var encodedLen = 0
  expect(open(rc, at(bytesOf(outer), ev.payloadAt), ev.payloadLen, bytesOf(aad), aad.len,
              bytesOf(encoded), encoded.len, encodedLen), "the payload opens")
  clear(rc)
  var inner: seq[byte] = @[]
  expect(decodeInner(bytesOf(encoded), encodedLen, bytesOf(outer), outer.len, inner) == 0, "decoded")
  var vi = default(HelloView)
  expect(parseClientHello(bytesOf(inner), inner.len, vi) == 0 and vi.serverName == "secret.example" and
         vi.alpn == @["h2"], "the inner hello: the real name and protocols")
  var evi = default(EchExtView)
  expect(parseEchExtension(bytesOf(inner), vi.echAt, vi.echLen, evi) == 0 and not evi.outer, "the inner mark")
  var sameRandom = true
  for i in 0 ..< 32:
    if inner[vi.randomAt + i] != outer[v.randomAt + i]: sameRandom = false
  expect(not sameRandom and vi.shareGroups == v.shareGroups, "its own random, the same shares")
  release(c)
echo "PASS ECH client: the outer hello shows the public name; the inner opens with the key"

# 7. GREASE: without configs an outer-form extension (and the real name);
#    none when turned off.
block:
  var cc = defaultClientConfig(nil)
  var c = default(TlsConn)
  expect(initClient(c, addr cc, "real.example"), "init")
  var outb = newSeq[byte](65536)
  var none = newSeq[byte](1)
  var r = default(StepResult)
  expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  var q = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q[i] = outb[i]
  var ch = recordMsg(q)
  var v = default(HelloView)
  var ev = default(EchExtView)
  expect(parseClientHello(bytesOf(ch), ch.len, v) == 0 and v.serverName == "real.example" and v.echLen > 0 and
         parseEchExtension(bytesOf(ch), v.echAt, v.echLen, ev) == 0 and ev.outer and ev.encLen == 32 and
         ev.payloadLen >= 144, "GREASE ECH")
  release(c)
  cc.echGrease = false
  var c2 = default(TlsConn)
  expect(initClient(c2, addr cc, "real.example"), "init 2")
  expect(step(c2, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello 2")
  var q2 = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q2[i] = outb[i]
  var ch2 = recordMsg(q2)
  expect(parseClientHello(bytesOf(ch2), ch2.len, v) == 0 and v.echLen == 0, "no ECH when GREASE is off")
  release(c2)
echo "PASS ECH GREASE: an outer-form extension, or none"

# 8. Our client and server: ECH accepted (the server handshakes on the inner
#    hello: its name, its protocols); refused for an unknown config id, a
#    wrong key, a tampered payload (the client checks the public name, gets
#    the retry configs, ends in ech_required); through a HelloRetryRequest;
#    resumption and 0-RTT inside; GREASE ignored.
var roots0: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), roots0) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, roots0[0]), "add root")
var ck = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == "", "leaf")
var ckPublic = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/other.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/other.key"), ckPublic) == "", "the public name's")
var names = @[SniEntry(name: "test.example", ck: addr ck), SniEntry(name: "other.example", ck: addr ckPublic)]
let keyA = newEchKey(1, "other.example")
var keyA2 = newEchKey(1, "other.example")      # the same id, another key
let keyB = newEchKey(2, "other.example")
var ticketer = default(KeyedTicketer)
assert initKeyedTicketer(ticketer)
var replay = default(MemoryReplay)
initMemoryReplay(replay)
var store = default(MemoryStore)
initMemoryStore(store)
proc serverWith(keys: seq[EchKey]): ServerConfig =
  result = defaultServerConfig()
  result.resolver = sniCerts(addr names)
  result.alpn = @["h2", "http/1.1"]
  result.echKeys = keys
proc clientWith(list: seq[byte]): ClientConfig =
  result = defaultClientConfig(roots)
  result.alpn = @["h2"]
  result.echConfigs = list
var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]
proc begin(cc: ptr ClientConfig; sc: ptr ServerConfig) =
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, "test.example") and initServer(b.c, sc), "init")
proc finish() = run(a, b, ab, ba, 1 shl 20)
proc done() =
  release(a.c)
  release(b.c)

var sA = serverWith(@[keyA])
var cA = clientWith(echConfigList(@[keyA]))
begin(addr cA, addr sA)
finish()
expect(a.ready and b.ready and a.c.echAccepted and not a.c.echRejected, "accepted")
expect(serverName(b.c) == "test.example" and alpn(b.c) == "h2" and peerLeafDer(a.c) == ck.chain[0],
       "the inner hello: its name, its protocol, its certificate")
done()
echo "PASS ECH accepted: the server handshakes on the inner hello"

var sB = serverWith(@[keyB])
begin(addr cA, addr sB)                        # our config id is unknown there
finish()
expect(a.failed == alEchRequired and a.c.echRejected and not a.c.echAccepted, "unknown config: ech_required")
expect(echRetryConfigs(a.c) == echConfigList(@[keyB], true), "the retry configs")
done()
var sA2 = serverWith(@[keyA2])
begin(addr cA, addr sA2)                       # the same id, another key
finish()
expect(a.failed == alEchRequired and echRetryConfigs(a.c) == echConfigList(@[keyA2], true), "wrong key: ech_required")
done()
begin(addr cA, addr sA)
discard turn(a, ab)
ab[ab.len - 3] = ab[ab.len - 3] xor 1          # inside the outer hello's payload (its last extension)
finish()
expect(not a.c.echAccepted and not b.c.echAccepted and (a.failed >= 0 or b.failed >= 0), "tampered: never accepted")
done()
echo "PASS ECH refused: unknown config, wrong key, tampered payload; retry configs, ech_required"

var sHrr = serverWith(@[keyA])
sHrr.groups = @[kxSecp256r1]                   # the client shares X25519MLKEM768 and X25519
begin(addr cA, addr sHrr)
finish()
expect(a.ready and b.ready and a.c.retried and a.c.echAccepted and serverName(b.c) == "test.example",
       "accepted through a HelloRetryRequest")
done()
echo "PASS ECH through a HelloRetryRequest"

var sR = serverWith(@[keyA])
sR.ticketer = keyedTicketer(addr ticketer)
sR.antiReplay = memoryReplay(addr replay)
sR.maxEarlyData = 16384
var cR = clientWith(echConfigList(@[keyA]))
cR.sessions = memoryStore(addr store)
cR.earlyData = true
begin(addr cR, addr sR)
finish()
expect(a.ready and a.c.echAccepted and not a.c.resumed, "first: full, inside ECH")
done()
begin(addr cR, addr sR)
discard turn(a, ab)
var e = newSeq[byte](5 + 5 + 17)
for i in 0 ..< 5: e[5 + i] = byte(65 + i)
expect(sealEarly(a.c, bytesOf(e), 0, 5) == e.len, "0-RTT inside ECH")
for x in e: ab.add x
finish()
expect(a.ready and a.c.echAccepted and a.c.resumed and a.c.earlyAccepted and b.app.len == 5, "resumed with 0-RTT inside ECH")
done()
echo "PASS resumption and 0-RTT inside ECH"

var cG = clientWith(@[])                       # GREASE
begin(addr cG, addr sA)
finish()
expect(a.ready and b.ready and not a.c.echAccepted and not a.c.echRejected, "GREASE: ignored, a normal handshake")
done()
var sNone = serverWith(@[])
begin(addr cA, addr sNone)                     # a server without ECH keys
finish()
expect(a.failed == alEchRequired and echRetryConfigs(a.c).len == 0, "no ECH there: ech_required, no retry configs")
done()
echo "PASS GREASE ignored; a server without ECH"

# 9. The edges: refused at the first hello, then a retry (ech_required); a
#    second hello that does not open, or has no ECH, after an accepted
#    first (the server aborts, never the outer hello); a ServerHello
#    without the confirmation after an accepted retry; an inner mark in the
#    outer hello; an inner hello without its mark (illegal_parameter).
proc pass(s: var Side; inq, outq: var seq[byte]) =
  ## Feed s what it was sent and turn it until it has sent something.
  feed(s, inq, 1 shl 20)
  let before = outq.len
  var n = 0
  while outq.len == before and n < 16 and turn(s, outq): n = n + 1

proc helloAt(q: seq[byte]): int =
  ## Where the handshake record starts (after a ChangeCipherSpec).
  result = if q[0] == 20: 6 else: 0

var sHrrB = serverWith(@[keyB])
sHrrB.groups = @[kxSecp256r1]
begin(addr cA, addr sHrrB)
finish()
expect(a.c.retried and a.failed == alEchRequired and echRetryConfigs(a.c) == echConfigList(@[keyB], true),
       "refused, then a retry: ech_required, the retry configs")
done()

begin(addr cA, addr sHrr)
pass(a, ba, ab)
pass(b, ab, ba)
pass(a, ba, ab)                                  # the second hello
ab[ab.len - 3] = ab[ab.len - 3] xor 1            # its payload (its last extension)
finish()
expect(b.failed == alDecryptError and not b.ready and not a.ready, "a second hello that does not open: decrypt_error")
done()

begin(addr cA, addr sHrr)
pass(a, ba, ab)
pass(b, ab, ba)
pass(a, ba, ab)
block:
  let r2 = helloAt(ab)
  var rest: seq[byte] = @[]
  for i in r2 ..< ab.len: rest.add ab[i]
  var m = recordMsg(rest)
  var v2 = default(HelloView)
  expect(parseClientHello(bytesOf(m), m.len, v2) == 0 and v2.echLen > 0, "the second hello")
  ab[r2 + 5 + v2.echAt - 3] = 0x0e               # its ECH extension renamed: none
finish()
expect(b.failed == alMissingExtension and not a.ready, "a second hello without ECH: missing_extension")
done()

begin(addr cA, addr sHrr)
pass(a, ba, ab)
pass(b, ab, ba)
pass(a, ba, ab)
pass(b, ab, ba)                                  # the ServerHello
expect(ba[0] == 22 and ba[5] == 2, "a ServerHello")
ba[5 + 4 + 2 + 24] = ba[5 + 4 + 2 + 24] xor 1    # its confirmation
finish()
expect(a.failed == alIllegalParameter and not a.c.echAccepted, "no confirmation after an accepted retry")
done()

type Opened = object
  outer, encoded: seq[byte]
  encodedLen: int
  ev: EchExtView

proc echInfo(key: EchKey): seq[byte] =
  result = @[]
  for ch in "tls ech": result.add byte(ch)
  result.add 0
  for x in key.config: result.add x

proc echAad(outer: seq[byte]; ev: EchExtView): seq[byte] =
  result = newSeq[byte](outer.len - 4)
  for i in 4 ..< outer.len: result[i - 4] = outer[i]
  for i in 0 ..< ev.payloadLen: result[ev.payloadAt - 4 + i] = 0

proc openHello(cc: ptr ClientConfig; key: EchKey; o: var Opened) =
  ## Our client's outer hello, its payload opened with `key`.
  var c = default(TlsConn)
  expect(initClient(c, cc, "test.example"), "init")
  var outb = newSeq[byte](65536)
  var none = newSeq[byte](1)
  var r = default(StepResult)
  expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  var q = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q[i] = outb[i]
  release(c)
  o.outer = recordMsg(q)
  var v = default(HelloView)
  expect(parseClientHello(bytesOf(o.outer), o.outer.len, v) == 0 and
         parseEchExtension(bytesOf(o.outer), v.echAt, v.echLen, o.ev) == 0, "its ECH")
  var aad = echAad(o.outer, o.ev)
  var info = echInfo(key)
  var rc = default(HpkeCtx)
  var kp = key.priv
  expect(setupRecipient(rc, ptrOf(kp), at(bytesOf(o.outer), o.ev.encAt), bytesOf(info), info.len), "recipient")
  o.encoded = newSeq[byte](o.ev.payloadLen)
  expect(open(rc, at(bytesOf(o.outer), o.ev.payloadAt), o.ev.payloadLen, bytesOf(aad), aad.len,
              bytesOf(o.encoded), o.encoded.len, o.encodedLen), "opened")
  clear(rc)

proc reseal(o: var Opened; key: EchKey) =
  ## The (changed) encoding sealed again into the (changed) outer hello, a new enc in place.
  var cfgs: seq[EchConfigView] = @[]
  var lst = echConfigList(@[key])
  expect(parseEchConfigList(bytesOf(lst), lst.len, cfgs) and cfgs.len == 1, "the config")
  var info = echInfo(key)
  var sc = default(HpkeCtx)
  expect(setupSender(sc, at(bytesOf(lst), cfgs[0].pubAt), bytesOf(info), info.len,
                     at(bytesOf(o.outer), o.ev.encAt)), "sender")
  var aad = echAad(o.outer, o.ev)
  var sealed = newSeq[byte](o.ev.payloadLen)
  var n = 0
  expect(seal(sc, bytesOf(o.encoded), o.encodedLen, bytesOf(aad), aad.len, bytesOf(sealed), sealed.len, n) and
         n == o.ev.payloadLen, "sealed again")
  clear(sc)
  for i in 0 ..< n: o.outer[o.ev.payloadAt + i] = sealed[i]

proc find(q: seq[byte]; pat: openArray[byte]): int =
  result = -1
  for i in 0 .. q.len - pat.len:
    if result < 0:
      var same = true
      for j in 0 ..< pat.len:
        if q[i + j] != pat[j]: same = false
      if same: result = i

proc helloRecord(m: seq[byte]): seq[byte] =
  result = @[22'u8, 3, 1, byte(m.len shr 8), byte(m.len and 0xff)]
  for x in m: result.add x

proc serverSees(sc: ptr ServerConfig; hello: seq[byte]): int =
  ## The alert our server gives for this ClientHello (-1: none).
  initSide(b)
  ba = @[]
  expect(initServer(b.c, sc), "init server")
  var q = helloRecord(hello)
  pass(b, q, ba)
  result = b.failed
  release(b.c)

var op = default(Opened)
openHello(addr cA, keyA, op)
var innerHello: seq[byte] = @[]
expect(decodeInner(bytesOf(op.encoded), op.encodedLen, bytesOf(op.outer), op.outer.len, innerHello) == 0, "the inner hello")
expect(serverSees(addr sA, innerHello) == alIllegalParameter, "an inner mark in the outer hello: illegal_parameter")
let mark = find(op.encoded, [0xfe'u8, 0x0d, 0, 1, 1])   # the inner mark in the encoding: renamed away
expect(mark >= 0 and mark < op.encodedLen, "the mark")
op.encoded[mark + 1] = 0x0e
reseal(op, keyA)
expect(serverSees(addr sA, op.outer) == alIllegalParameter, "an inner hello without its mark: illegal_parameter")
openHello(addr cA, keyA, op)
let sv = find(op.outer, [0'u8, 0x2b, 0, 3, 2, 3, 4])  # supported_versions (the inner takes the outer's)
expect(sv >= 0, "supported_versions")
op.outer[sv + 6] = 3                             # TLS 1.2
reseal(op, keyA)
expect(serverSees(addr sA, op.outer) == alIllegalParameter, "an inner hello offering TLS 1.2: illegal_parameter")
# A retry that took ECH asks for no cookie: a client may compress the
# inner hello's cookie without putting it in the outer hello (Go 1.26
# does), and a stateful server needs none. Without ECH it still does.
proc retryCookie(sc: ptr ServerConfig): int =
  begin(addr cA, sc)
  pass(a, ba, ab)
  pass(b, ab, ba)
  var hrr = recordMsg(ba)
  var hv = default(ServerHelloView)
  expect(parseServerHello(bytesOf(hrr), hrr.len, hv) == 0 and hv.isHrr, "a HelloRetryRequest")
  result = hv.cookieLen
  done()
var sHrrNone = serverWith(@[])
sHrrNone.groups = @[kxSecp256r1]
expect(retryCookie(addr sHrr) == 0, "a retry that took ECH: no cookie")
expect(retryCookie(addr sHrrNone) > 0, "a retry without ECH: a cookie")
echo "PASS ECH edges: retries, a second hello, the confirmation, the inner mark, the inner's versions, no cookie"

# 10. Review fixes. Nothing a refusing server says counts before its
#     Finished (no retry configs, not "rejected"); configured ECH that
#     cannot be used refuses to start; the ECH extension in
#     EncryptedExtensions checked; public names and empty lists; keys
#     sharing an id; no second-hello ECH after a first without; keys and
#     retry configs checked; the outer hello's protocols; an unsolicited
#     ECH extension in a HelloRetryRequest.
var otherCa: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/cauth-root.pem"), otherCa) == 1, "another root")
let rootsX = newRoots()
if rootsX == nil: quit "no store"
expect(addRoot(rootsX, otherCa[0]), "add another root")
var cX = clientWith(echConfigList(@[keyA]))
cX.roots = rootsX                                # the refusing server does not authenticate
begin(addr cX, addr sB)
finish()
expect(a.failed >= 0 and a.failed != alEchRequired and not a.c.echRejected and echRetryConfigs(a.c).len == 0,
       "refused by a server that did not authenticate: no retry configs, not rejected, got " & $a.failed)
done()

proc refuseBuild(ctx: nil pointer; hp: ptr HelloParams; wr: var Writer): bool {.nimcall.} = false
var cBad = clientWith(keyA.config)               # one ECHConfig, not a list
var tc1 = default(TlsConn)
expect(not initClient(tc1, addr cBad, "test.example"), "echConfigs malformed: refused")
var noKem = echConfigList(@[keyA])
noKem[8] = 0x21                                  # the KEM: X448 (not ours)
cBad.echConfigs = noKem
expect(not initClient(tc1, addr cBad, "test.example"), "no usable config: refused")
cBad.echConfigs = echConfigList(@[keyA])
cBad.builder = HelloBuilder(build: refuseBuild)
expect(not initClient(tc1, addr cBad, "test.example"), "ECH with a HelloBuilder: refused")

proc eeWith(ext: seq[byte]): seq[byte] =
  result = newSeq[byte](64 + ext.len)
  var w = initWriter(bytesOf(result), 0, result.len)
  var e = ext
  writeEncryptedExtensions(w, "", false, false, bytesOf(e), e.len)
  result.setLen(w.pos)
var hsE = default(HandshakeState)
var goodList = echConfigList(@[keyA])
var eeGood = eeWith(goodList)
var eeShort = eeWith(@[0'u8])
var eeEmpty = eeWith(@[0'u8, 0])
expect(eeEch(addr hsE, false, bytesOf(eeGood), eeGood.len) == alUnsupportedExtension, "ECH in EE, none sent")
hsE.greaseOn = true
expect(eeEch(addr hsE, false, bytesOf(eeShort), eeShort.len) == alDecodeError, "GREASE: a malformed extension")
expect(eeEch(addr hsE, false, bytesOf(eeGood), eeGood.len) == 0 and hsE.echRetryPending.len == 0,
       "GREASE: retry configs checked, not kept")
hsE.greaseOn = false
hsE.echOffered = true
expect(eeEch(addr hsE, true, bytesOf(eeGood), eeGood.len) == alUnsupportedExtension, "accepted: no retry configs")
hsE.echRejected = true
expect(eeEch(addr hsE, false, bytesOf(eeEmpty), eeEmpty.len) == alDecodeError, "an empty list")
expect(eeEch(addr hsE, false, bytesOf(eeGood), eeGood.len) == 0 and hsE.echRetryPending.len == goodList.len,
       "refused: kept until the server's Finished")
free(hsE.echRetryPending)

proc namedList(names: seq[string]): seq[byte] =
  result = newSeq[byte](4096)
  var pubN = newSeq[byte](32)
  var w = initWriter(bytesOf(result), 0, result.len)
  let l = begin16(w)
  for n in names: writeEchConfig(w, 1, bytesOf(pubN), n, 32)
  finish16(w, l)
  result.setLen(w.pos)
var cfgsN: seq[EchConfigView] = @[]
var ln = namedList(@["1.2.3.4", "bad..example", "-x.example", "x-.example", "x.example.", ".x.example",
                     "a.0x1f", "a.123", "x_y.example", "ok-name.example", "a.b1"])
expect(parseEchConfigList(bytesOf(ln), ln.len, cfgsN) and cfgsN.len == 2 and
       cfgsN[0].publicName == "ok-name.example" and cfgsN[1].publicName == "a.b1",
       "public names: LDH labels, not an IPv4 address")
var emptyList = @[0'u8, 0]
expect(not parseEchConfigList(bytesOf(emptyList), 2, cfgsN), "an empty list: malformed")

var sAA = serverWith(@[keyA2, keyA])             # two keys with id 1: each tried
begin(addr cA, addr sAA)
finish()
expect(a.ready and a.c.echAccepted, "keys sharing an id: the one that opens")
done()

begin(addr cA, addr sHrr)
pass(a, ba, ab)
block:
  var m1 = recordMsg(ab)
  var v1 = default(HelloView)
  expect(parseClientHello(bytesOf(m1), m1.len, v1) == 0 and v1.echLen > 0, "the first hello")
  ab[5 + v1.echAt - 3] = 0x0e                    # its ECH renamed: a first hello without ECH
pass(b, ab, ba)
expect(not b.c.echAccepted and not b.c.echRejected and ba.len > 0, "a retry for a first hello without ECH")
pass(a, ba, ab)                                  # the second hello carries an ECH extension
pass(b, ab, ba)
expect(not b.c.echRejected, "its second hello's ECH: not looked at")
done()

begin(addr cA, addr sA)
pass(a, ba, ab)
block:
  var m1 = recordMsg(ab)
  var v1 = default(HelloView)
  expect(parseClientHello(bytesOf(m1), m1.len, v1) == 0 and v1.echLen > 0, "the hello")
  ab[5 + v1.echAt + 2] = 2                       # its KDF: HKDF-SHA384 (not ours)
pass(b, ab, ba)
expect(b.c.echRejected and not b.c.echAccepted, "an ECH extension for a suite we lack: refused (retry configs)")
done()

var noRetry = keyA
noRetry.retry = false
var tS = default(TlsConn)
var sNoRetry = serverWith(@[noRetry])
expect(not initServer(tS, addr sNoRetry), "ECH keys without retry configs: refused")
var sIpName = serverWith(@[newEchKey(3, "1.2.3.4")])
expect(not initServer(tS, addr sIpName), "a key for an IPv4 public name: refused")
var sBigId = serverWith(@[newEchKey(300, "other.example")])
expect(not initServer(tS, addr sBigId), "a config id over 255: refused")

block:
  var cc = clientWith(echConfigList(@[keyA]))
  cc.echOuterAlpn = @["h2", "http/1.1"]
  var tc = default(TlsConn)
  expect(initClient(tc, addr cc, "test.example"), "init")
  var outb = newSeq[byte](65536)
  var none = newSeq[byte](1)
  var r = default(StepResult)
  expect(step(tc, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  var q = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q[i] = outb[i]
  release(tc)
  var outer = recordMsg(q)
  var v = default(HelloView)
  expect(parseClientHello(bytesOf(outer), outer.len, v) == 0 and v.alpn == @["h2", "http/1.1"],
         "echOuterAlpn: the outer hello's protocols")
  begin(addr cc, addr sB)                        # refused: the server may pick one of those
  finish()
  expect(a.failed == alEchRequired and a.c.echRejected, "refused with outer protocols: ech_required")
  done()

proc hrrWithEch(grease: bool): int =
  ## A client that sent no ECH (or GREASE) answered by a HelloRetryRequest
  ## carrying an ECH extension: the alert (-1: it went on).
  var cc = defaultClientConfig(roots)
  cc.echGrease = grease
  var tc = default(TlsConn)
  expect(initClient(tc, addr cc, "test.example"), "init")
  var outb = newSeq[byte](65536)
  var none = newSeq[byte](1)
  var r = default(StepResult)
  expect(step(tc, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  var q = newSeq[byte](r.outLen)
  for i in 0 ..< r.outLen: q[i] = outb[i]
  var ch1 = recordMsg(q)
  var v = default(HelloView)
  expect(parseClientHello(bytesOf(ch1), ch1.len, v) == 0, "the hello")
  var hb = newSeq[byte](512)
  var w = initWriter(bytesOf(hb), 5, hb.len - 5)
  var hr = HrrRandom
  writeServerHello(w, ptrOf(hr), at(bytesOf(ch1), v.sessionIdAt), v.sessionIdLen, 0x1301,
                   groupCode(kxSecp256r1), ptrOf(hr), 0, 0, ptrOf(hr), 0, echConf = true)
  let n = w.pos - 5
  hb[0] = 22
  hb[1] = 3
  hb[2] = 3
  hb[3] = byte(n shr 8)
  hb[4] = byte(n and 0xff)
  let st = step(tc, bytesOf(hb), 5 + n, bytesOf(outb), outb.len, r)
  result = if st == stFailed: r.alert else: -1
  release(tc)
expect(hrrWithEch(false) == alUnsupportedExtension, "an ECH extension in a retry, none sent: unsupported_extension")
expect(hrrWithEch(true) == -1, "GREASE: a retry's ECH extension ignored")
echo "PASS review fixes: authenticated refusals, configs checked, keys sharing an id, outer protocols"
release(ck)
release(ckPublic)
