{.feature: "assumeSync".}
## The TLS framer without sockets: a relay direction's buffer fed with a
## client's records, opened by the framer; spans sealed by the framer read
## back by the client; a key update request answered from the prefix; a
## padded record re-sealed with its gap closed; close_notify both ways.
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import zal_tls/record/protect
include zal_tls/raw/framer
import zal_net/relay
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
var cc = defaultClientConfig(roots)
var sc = defaultServerConfig()
sc.resolver = singleCert(addr ck)

# The handshake: our client against the traffic block's server connection.
let tp = newTraffic()
if tp == nil: quit "no traffic block"
let t = tp
var cli = default(TlsConn)
expect(initClient(cli, addr cc, "test.example") and initServer(t.conn, addr sc), "init")
var toSrv: seq[byte] = @[]
var toCli: seq[byte] = @[]
var outb = newSeq[byte](1 shl 17)

proc stepInto(c: var TlsConn; q: var seq[byte]; into: var seq[byte]; app: var seq[byte]): Step =
  ## One step on everything queued for c; what it sends goes to `into`.
  var r = default(StepResult)
  var inp = q
  if inp.len == 0: inp = @[0'u8]
  result = step(c, bytesOf(inp), q.len, bytesOf(outb), outb.len, r)
  for i in 0 ..< r.outLen: into.add outb[i]
  if result == stAppData:
    for i in r.off ..< r.off + r.len: app.add inp[i]
  dropFront(q, r.consumed)

var sink: seq[byte] = @[]
for i in 0 ..< 20:
  discard stepInto(cli, toCli, toSrv, sink)
  discard stepInto(t.conn, toSrv, toCli, sink)
expect(isReady(cli) and isReady(t.conn), "handshake")

let c = newConn(5000)
if c == nil: quit "no connection block"
useTls(addr c.a, addr c.b, t)                  # a: reads the client's records; b: writes to it
let d = addr c.a
let e = addr c.b
expect(ensurePayload(d) and ensurePayload(e), "explicit sans-I/O payload ownership")

proc feedDir(d: DirectionPtr; q: seq[byte]) =
  d.off = HeadRoom
  d.fill = HeadRoom + q.len
  for i in 0 ..< q.len: d.buf[HeadRoom + i] = q[i]

proc clientRecords(sizes: seq[int]; seed: int; pad = 0): seq[byte] =
  ## The client's application records of these sizes.
  result = @[]
  var k = 0
  for n in sizes:
    var rec = newSeq[byte](5 + n + 1 + pad + 16)
    let p = pattern(n, seed + k)
    for i in 0 ..< n: rec[5 + i] = p[i]
    let m = sealRecord(cli.wr, bytesOf(rec), 0, n, 23, pad)
    expect(m == rec.len, "client record")
    for x in rec: result.add x
    k = k + 1

proc emitted(e: DirectionPtr): seq[byte] =
  ## The prefix, then the sealed region.
  result = @[]
  for i in 0 ..< e.preLen: result.add e.pre[i]
  for i in e.wOff ..< e.wEnd: result.add e.buf[i]
  e.preLen = 0
  e.preAt = 0

# Open: three records, three spans in place.
feedDir(d, clientRecords(@[1000, 16384, 5], 1))
expect(tlsFramer.open(c, d) == 3 and d.bytes == 1000 + 16384 + 5, "three spans")
expect(d.spans[1].len == 16384 and d.buf[d.spans[1].off] == pattern(16384, 2)[0], "the payload in place")
expect(not tlsFramer.atBoundary(d), "no clean end before close_notify")
echo "PASS open: records into spans in place"

# Seal: spans laid out as a plain source lays them (slots), read by the client.
let stride = 5 + 16384 + 17
var sent: seq[byte] = @[]
for i in 0 ..< 2:
  let n = if i == 0: 16384 else: 777
  let p = pattern(n, 10 + i)
  for j in 0 ..< n: e.buf[HeadRoom + i * stride + j] = p[j]
  for x in p: sent.add x
  e.spans[i] = Span(off: HeadRoom + i * stride, len: n)
e.nspans = 2
expect(tlsFramer.seal(c, e), "seal")
toCli = emitted(e)
var got: seq[byte] = @[]
for i in 0 ..< 4: discard stepInto(cli, toCli, toSrv, got)
expect(got == sent, "the client reads the sealed spans")
echo "PASS seal: slots sealed in place into one region"

# A key update the client asks for: the read keys roll; the reply goes in
# the sink's prefix before the next data.
var ku = newSeq[byte](64)
let kn = keyUpdate(cli, true, bytesOf(ku), ku.len)
var kq: seq[byte] = @[]
for i in 0 ..< kn: kq.add ku[i]
for x in clientRecords(@[300], 20): kq.add x
feedDir(d, kq)
expect(tlsFramer.open(c, d) == 1 and d.spans[0].len == 300, "data after the key update, new keys")
expect(t.conn.replyOwed, "a reply owed")
let p = pattern(64, 30)
for j in 0 ..< 64: e.buf[HeadRoom + j] = p[j]
e.spans[0] = Span(off: HeadRoom, len: 64)
e.nspans = 1
expect(tlsFramer.seal(c, e) and e.preLen > 0 and not t.conn.replyOwed, "the reply in the prefix")
toCli = emitted(e)
got = @[]
for i in 0 ..< 4: discard stepInto(cli, toCli, toSrv, got)
expect(got == p, "the client follows the reply, then reads")
echo "PASS key update: read keys rolled, reply from the prefix before data"

# TLS to TLS on one buffer: padded records opened, re-sealed with the gaps closed.
feedDir(d, clientRecords(@[500, 600, 700], 40, pad = 33))
expect(tlsFramer.open(c, d) == 3, "padded spans")
e.nspans = d.nspans
var echoed: seq[byte] = @[]
for i in 0 ..< d.nspans:
  e.spans[i] = d.spans[i]
  for j in d.spans[i].off ..< d.spans[i].off + d.spans[i].len: echoed.add d.buf[j]
# The sink seals in the source's buffer here: copy the spans' bytes over.
for i in 0 ..< HeadRoom + 3 * (5 + 700 + 1 + 33 + 16): e.buf[i] = d.buf[i]
expect(tlsFramer.seal(c, e), "re-seal")
expect(e.wEnd - e.wOff == 3 * 22 + 500 + 600 + 700, "one region, the padding gone")
toCli = emitted(e)
got = @[]
for i in 0 ..< 4: discard stepInto(cli, toCli, toSrv, got)
expect(got == echoed, "the client reads the re-sealed records")
echo "PASS padded records re-sealed, gaps closed"

# close_notify: the client's ends the source; ours from the finish hook.
var cn = newSeq[byte](64)
let n = close(cli, bytesOf(cn), cn.len)
var cq: seq[byte] = @[]
for i in 0 ..< n: cq.add cn[i]
feedDir(d, cq)
expect(tlsFramer.open(c, d) == InEof and tlsFramer.atBoundary(d), "close_notify: the clean end")
e.wOff = 0
e.wEnd = 0
let fin = tlsFramer.finish
expect(fin != nil and fin(c, e) and e.preLen > 0, "finish: close_notify in the prefix")
toCli = emitted(e)
var st = stNeedInput
for i in 0 ..< 3:
  let s2 = stepInto(cli, toCli, toSrv, got)
  if s2 == stPeerClosed or s2 == stClosed: st = s2
expect(st == stPeerClosed or st == stClosed, "the client sees our close_notify")
echo "PASS close_notify both ways"

release(cli)
freeConn(c)                                    # the framers' close hooks free the traffic block
release(ck)
release(roots)
release(rootCerts[0])
