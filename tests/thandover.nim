import std/[syncio, assertions]
import zal_net/raw
import zal_net/relay
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/record/protect
import zal_tls/wire/consts
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

include zal_tls/raw/framer
import hexutil

# ktlsHandover, the switch of a relay's TLS side to the kernel, on the
# records a handshake's last read left buffered (any platform: the kernel
# is not needed to open them): more records than spans (the user-space
# framer takes the rest, none lost), a partial record, a KeyUpdate,
# close_notify and what follows it, a fatal alert, a corrupt record, a
# handshake message cut by data.

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var gCk = default(CertifiedKey)
var gServer = default(ServerConfig)
var gClient = default(ClientConfig)
var cin = newSeq[byte](65536)
var cinLen = 0
var sin = newSeq[byte](65536)
var sinLen = 0
var outb = newSeq[byte](65536)

proc drop(buf: var seq[byte]; len: var int; n: int) =
  if n <= 0: return
  let rest = len - n
  if rest > 0: moveMem(addr buf[0], addr buf[n], rest)
  len = rest

proc turn(x: var TlsConn; inb: var seq[byte]; inLen: var int; peer: var seq[byte]; peerLen: var int;
          ready: var bool) =
  var r = default(StepResult)
  while true:
    let st = step(x, bytesOf(inb), inLen, bytesOf(outb), outb.len, r)
    drop(inb, inLen, r.consumed)
    case st
    of stSend:
      copyMem(addr peer[peerLen], addr outb[0], r.outLen)
      peerLen = peerLen + r.outLen
    of stReady: ready = true
    of stNeedInput: return
    else:
      echo "handshake step: ", st, " ", r.reason
      quit 1

proc pair(c: var TlsConn): ptr TlsTraffic =
  ## A server traffic block and a client, handshake done.
  let t = newTraffic()
  if t == nil: quit "no traffic block"
  expect(initServer(t.conn, addr gServer), "server init")
  expect(initClient(c, addr gClient, "test.example"), "client init")
  cinLen = 0
  sinLen = 0
  var cReady = false
  var sReady = false
  var rounds = 0
  while (not cReady or not sReady) and rounds < 20:
    turn(c, cin, cinLen, sin, sinLen, cReady)
    turn(t.conn, sin, sinLen, cin, cinLen, sReady)
    rounds = rounds + 1
  expect(cReady and sReady and sinLen == 0, "handshake")
  result = t

proc put(d: DirectionPtr; rec: seq[byte]) =
  copyMem(bufAt(d, d.fill), addr rec[0], rec.len)
  d.fill = d.fill + rec.len

proc sealed(c: var TlsConn; typ: int; payload: seq[byte]): seq[byte] =
  ## One record of `typ` from the client, under its current keys.
  result = newSeq[byte](5 + payload.len + 1 + 16)
  for i in 0 ..< payload.len: result[5 + i] = payload[i]
  let n = sealRecord(c.wr, bytesOf(result), 0, payload.len, typ, 0)
  expect(n == result.len, "seal")

proc fresh(cn: Conn): DirectionPtr =
  result = addr cn.a
  expect(ensurePayload(result), "handover fixture payload")
  result.off = HeadRoom
  result.fill = HeadRoom
  result.nspans = 0
  result.bytes = 0

proc main() =
  let cn = newConn(5000)
  if cn == nil: quit "no conn"

  # 1. 70 small records: 64 become spans, the 6 others stay for user space.
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    const Records = 70
    for i in 0 ..< Records:
      var p = newSeq[byte](10)
      for k in 0 ..< 10: p[k] = byte(i)
      put(d, sealed(c, ctApplicationData, p))
    let before = d.fill
    expect(ktlsHandover(d, t) == HandoverFallback, "more records than spans: fallback")
    expect(d.nspans == MaxSpans and d.fill == before, "64 spans, the rest untouched")
    var seen = newSeq[int](Records)
    for i in 0 ..< d.nspans:
      for k in 0 ..< d.spans[i].len: seen[int(d.buf[d.spans[i].off + k])] += 1
    useTls(d, addr cn.b, t)
    d.nspans = 0
    d.bytes = 0
    discard tlsFramer.open(cn, d)
    for i in 0 ..< d.nspans:
      for k in 0 ..< d.spans[i].len: seen[int(d.buf[d.spans[i].off + k])] += 1
    for i in 0 ..< Records: expect(seen[i] == 10, "record " & $i & " delivered once")
    tlsFramer.closeSource(d)
    sinkState[nil TlsTrafficPtr](addr cn.b)[] = nil
    releaseTraffic(t)
    release(c)
  echo "PASS more records than spans: the rest goes to user space, none lost"

  # 2. A partial record: what it lacks; complete: at a boundary.
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    let rec = sealed(c, ctApplicationData, @[1'u8, 2, 3])
    copyMem(bufAt(d, d.fill), addr rec[0], 3)
    d.fill = d.fill + 3
    expect(ktlsHandover(d, t) == 2, "a partial header: 2 bytes more")
    copyMem(bufAt(d, d.fill), addr rec[3], 4)
    d.fill = d.fill + 4
    expect(ktlsHandover(d, t) == rec.len - 7, "a partial record: the rest")
    copyMem(bufAt(d, d.fill), addr rec[7], rec.len - 7)
    d.fill = d.fill + rec.len - 7
    expect(ktlsHandover(d, t) == 0 and d.nspans == 1 and d.bytes == 3, "complete: at a boundary")
    releaseTraffic(t)
    release(c)
  echo "PASS a partial record: read to its end, then the kernel"

  # 3. A KeyUpdate buffered: the read keys roll, a reply is owed, and the
  #    record after it opens under the new keys.
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    var ku = newSeq[byte](64)
    let n = keyUpdate(c, true, bytesOf(ku), ku.len)
    expect(n > 0, "key update")
    ku.setLen(n)
    put(d, ku)
    put(d, sealed(c, ctApplicationData, @[7'u8, 7]))
    expect(ktlsHandover(d, t) == 0 and d.nspans == 1 and d.bytes == 2, "after the KeyUpdate")
    expect(replyDue(t.conn) and not t.conn.keyChanged, "a reply owed; the kernel gets the new keys")
    releaseTraffic(t)
    release(c)
  echo "PASS a KeyUpdate at the switch: new read keys, reply owed"

  # 4. close_notify: the end; what follows it is ignored.
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    put(d, sealed(c, ctApplicationData, @[5'u8]))
    var cl = newSeq[byte](64)
    let n = close(c, bytesOf(cl), cl.len)
    cl.setLen(n)
    put(d, cl)
    put(d, @[23'u8, 3, 3, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
    expect(ktlsHandover(d, t) == 0 and t.peerClosed and d.off == d.fill, "close_notify ends it")
    expect(d.nspans == 1 and d.bytes == 1, "the data before it kept")
    releaseTraffic(t)
    release(c)
  echo "PASS close_notify at the switch: the end, nothing after it read"

  # 5. A fatal alert, a corrupt record, a handshake message cut by data: fail.
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    put(d, sealed(c, ctAlert, @[2'u8, 40]))
    expect(ktlsHandover(d, t) == HandoverFailed and t.conn.failAlert == 40, "a fatal alert fails")
    releaseTraffic(t)
    release(c)
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    var rec = sealed(c, ctApplicationData, @[1'u8, 2, 3, 4])
    rec[7] = rec[7] xor 1
    put(d, rec)
    expect(ktlsHandover(d, t) == HandoverFailed and t.conn.failAlert == alBadRecordMac, "a corrupt record fails")
    releaseTraffic(t)
    release(c)
  block:
    var c = default(TlsConn)
    let t = pair(c)
    let d = fresh(cn)
    put(d, sealed(c, ctHandshake, @[24'u8, 0, 0]))           # a KeyUpdate's first bytes...
    put(d, sealed(c, ctApplicationData, @[1'u8]))            # ... cut by data
    expect(ktlsHandover(d, t) == HandoverFailed and t.conn.failAlert == alUnexpectedMessage,
           "a handshake message cut by data fails")
    releaseTraffic(t)
    release(c)
  echo "PASS a fatal alert, a corrupt record, a cut handshake message: the switch fails"
  quit 0

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), gCk) == "", "leaf")
gServer = defaultServerConfig()
gServer.resolver = singleCert(addr gCk)
gClient = defaultClientConfig(roots)
main()
