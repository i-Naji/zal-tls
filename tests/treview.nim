## Regressions from the phase 1 review, at the connection level: an empty
## server name, the handshake state freed on both sides, a ClientHello of
## thousands of extensions parsed in linear time, key update replies
## coalesced and owed to the writer, a TLS 1.2 ServerHello with
## extensions, no server data before the client's Finished, ALPN names
## checked.
import std/[syncio, assertions, monotimes]
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509]
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import zal_tls/wire/[bytes, consts, messages]
import hexutil, loophelp

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

# 1. No name, no verification: refused, not skipped.
var cc = defaultClientConfig(roots)
var c = default(TlsConn)
expect(not initClient(c, addr cc, ""), "initClient refuses an empty name")
expect(webPkiVerify(roots, addr ck.chain, "", 0) != 0, "the web PKI refuses an empty name")
echo "PASS an empty server name is refused"

# 2. Both sides free their handshake state once it is done.
var sc = defaultServerConfig()
sc.resolver = singleCert(addr ck)
var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]
initSide(a)
initSide(b)
expect(initClient(a.c, addr cc, "test.example") and initServer(b.c, addr sc), "init")
discard turn(a, ab)                          # ClientHello
feed(b, ab, 1 shl 30)
while turn(b, ba): discard                   # the server's flight, then it waits
# 13. The server seals nothing before the client's Finished.
var early = newSeq[byte](64)
expect(sealApp(b.c, bytesOf(early), 0, 8) == 0, "no server data before the client's Finished")
run(a, b, ab, ba, 1 shl 30)
expect(a.ready and b.ready, "handshake")
expect(a.c.hs == nil and b.c.hs == nil, "handshake state freed on both sides")
echo "PASS the handshake state is freed on both sides; no 0.5-RTT data"

# 5. Key update requests: one reply however many, sent by the writer first.
var buf = newSeq[byte](64)
for i in 0 ..< 5:
  let n = keyUpdate(a.c, true, bytesOf(buf), buf.len)
  expect(n > 0, "request")
  for j in 0 ..< n: ab.add buf[j]
feed(b, ab, 1 shl 30)
while turn(b, ba): discard
expect(ba.len == 0 and b.c.replyOwed, "the reader sends nothing; a reply is owed")
var ctl = newSeq[byte](64)
let r1 = takeControl(b.c, bytesOf(ctl), ctl.len)
expect(r1 > 0 and takeControl(b.c, bytesOf(ctl), ctl.len) == 0, "exactly one reply")
for j in 0 ..< r1: ba.add ctl[j]
let msg = pattern(1000, 3)
expect(sendApp(b, ba, msg, 1000), "data after the reply")
run(a, b, ab, ba, 1 shl 30)
expect(a.app == msg and a.failed < 0, "the client follows the reply, then reads the data")
release(a.c)
release(b.c)
echo "PASS five key update requests: one reply, from the writer, before its data"

# 3. A ClientHello of 16 000 empty extensions: linear, not quadratic.
initSide(a)
ab = @[]
expect(initClient(a.c, addr cc, "test.example"), "init")
discard turn(a, ab)
release(a.c)
var ch = newSeq[byte](ab.len - 5)
for i in 0 ..< ch.len: ch[i] = ab[5 + i]
var hv = default(HelloView)
expect(parseClientHello(bytesOf(ch), ch.len, hv) == 0, "our hello")
# Rebuild it with the extensions block replaced by thousands of unknown ones.
var r = initReader(bytesOf(ch), 4, ch.len - 4)
skip(r, 2 + 32)
discard vec8(r)
discard vec16(r)
discard vec8(r)
let extAt = r.pos
proc extensionHello(original: var seq[byte]; extAt, count: int): seq[byte] =
  result = newSeq[byte](extAt + 2 + count * 4)
  var w = initWriter(bytesOf(result), 0, result.len)
  put8(w, htClientHello)
  let m = begin24(w)
  putBytes(w, at(bytesOf(original), 4), extAt - 4)
  let e = begin16(w)
  for i in 0 ..< count:
    put16(w, 0x1000 + i)
    put16(w, 0)
  finish16(w, e)
  finish24(w, m)
  expect(w.ok and w.pos == result.len, "extension hello written")

proc parseCost(message: var seq[byte]; expected: int): int64 =
  # Warm the parser/allocator, then use the best of five samples to reduce
  # scheduling noise. Correctness is checked for every sample.
  var parsed = default(HelloView)
  expect(parseClientHello(bytesOf(message), message.len, parsed) == 0, "hello parses")
  result = high(int64)
  for sample in 0 ..< 5:
    let t0 = getMonoTime()
    let alert = parseClientHello(bytesOf(message), message.len, parsed)
    let elapsed = ticks(getMonoTime()) - ticks(t0)
    expect(alert == 0 and parsed.extOrder.len == expected, "every extension parsed")
    result = min(result, elapsed)

var small = extensionHello(ch, extAt, 512)
var big = extensionHello(ch, extAt, 16000)
let smallNs = parseCost(small, 512)
let bigNs = parseCost(big, 16000)
echo "  512 extensions in ", smallNs div 1000, " us; 16000 in ", bigNs div 1000, " us"
# About 32 times the input permits up to 4 times the linear normalized cost.
# A quadratic duplicate scan grows about 1024 times and fails this bound.
# An absolute deadline instead measures machine speed and sanitizer overhead.
expect(bigNs < max(1'i64, smallNs) * 128, "extension parsing scales with input")
echo "PASS 16000 extensions: bounded normalized parse cost"

# 6. A TLS 1.2 ServerHello carrying extensions: protocol_version, not unsupported_extension.
initSide(a)
ab = @[]
expect(initClient(a.c, addr cc, "test.example"), "init")
discard turn(a, ab)
var cv = default(HelloView)
var chm = newSeq[byte](ab.len - 5)
for i in 0 ..< chm.len: chm[i] = ab[5 + i]
expect(parseClientHello(bytesOf(chm), chm.len, cv) == 0, "parse")
var sh = newSeq[byte](200)
var sw = initWriter(bytesOf(sh), 5, sh.len - 5)
put8(sw, htServerHello)
let sm = begin24(sw)
put16(sw, Tls12)
for i in 0 ..< 32: put8(sw, i + 1)
let sid = begin8(sw)
for i in 0 ..< cv.sessionIdLen: put8(sw, int(chm[cv.sessionIdAt + i]))
finish8(sw, sid)
put16(sw, 0xc02f)                            # a TLS 1.2 suite
put8(sw, 0)
let sx = begin16(sw)
put16(sw, 0xff01)                            # renegotiation_info, as TLS 1.2 servers send
put16(sw, 1)
put8(sw, 0)
finish16(sw, sx)
finish24(sw, sm)
sh[0] = 22
sh[1] = 3
sh[2] = 3
sh[3] = byte((sw.pos - 5) shr 8)
sh[4] = byte((sw.pos - 5) and 0xff)
var rec = newSeq[byte](sw.pos)
for i in 0 ..< sw.pos: rec[i] = sh[i]
var sink: seq[byte] = @[]
feed(a, rec, 1 shl 30)
discard turn(a, sink)
expect(a.failed == alProtocolVersion, "TLS 1.2 with extensions: protocol_version, got " & $a.failed)
release(a.c)
echo "PASS a TLS 1.2 ServerHello with extensions: protocol_version"

# 14. ALPN names: 1 to 255 bytes.
var bad = defaultClientConfig(roots)
bad.alpn = @[""]
expect(not initClient(c, addr bad, "test.example"), "an empty ALPN name")
var long = ""
for i in 0 ..< 256: long.add 'a'
bad.alpn = @["h2", long]
expect(not initClient(c, addr bad, "test.example"), "an ALPN name of 256 bytes")
echo "PASS ALPN names checked"

release(ck)
release(roots)
release(rootCerts[0])
