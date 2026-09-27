import zal_net/net/endpointdial
## TLS on zal-net's framed relay, over real sockets: a terminator (TLS
## in, plain out to an echo server) and an originator (plain in, TLS out to
## the terminator). 4 MiB each way with half-close and close_notify; key
## updates every few records in both directions; a client whose Finished
## and first record arrive together; truncation (FIN without close_notify)
## fails the connection; every block goes back to the pool.
import std/[syncio, assertions, atomics]
import zal_net/raw
import zal_net/relay
import zal_net/net/endpoint, zal_net/raw/socket
import zal_tls/common
import zal_tls/crypto/[x509, rand]
import zal_tls/config/config
import zal_tls/private/core/[conn, client]

import zal_tls/raw/relay
include zal_tls/raw/stream
import hexutil

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

const Total = 4 * 1024 * 1024

var gCk = default(CertifiedKey)
var gServer = default(ServerConfig)
var gClient = default(ClientConfig)
var gEcho = default(Endpoint)
var gTerm = default(Endpoint)
var gKuEvery = 0'u64
var gKernel = false          ## the relays hand their TLS sides to the kernel (kTLS)
var gKernelUsed = 0          ## ... and it took them
var gToyUp = false           ## the terminator speaks a toy 18/16 record format to its upstream
var gHeader = 0              ## the terminator reads (and drops) a header of this many bytes first
var gResetTerm = false       ## the terminator resets right after the handshake
var gFirstSpan = 0           ## the originator reads this many plain bytes before its handshake
var gEchoReset = false       ## an echo connection ended with a reset (not a FIN)
var gTermResumed = 0         ## terminator connections that resumed ...
var gTermEarly = 0           ## ... and took 0-RTT
var gOrigResumed = 0         ## originator connections that resumed (tickets stored by the relay)
var gTermClientLeaf = 0      ## the client certificate's length the terminator last saw
var gTermEch = 0             ## terminator connections that took the client's ECH ...
var gTermName = ""           ## ... the name the terminator last saw
var gOrigTlsFailed = 0       ## originator connections whose handshake failed

# A toy record format with Shadowsocks 2022's geometry (18/16, 65535):
# [length:2][16 zero bytes][payload xor 0x5A][16 bytes: the length's low byte].
# TLS to it and back is relaid out (one copy per batch). The plain echo
# server sends the records back as they are.
proc toyOpen(c: Conn; d: DirectionPtr): int =
  d.nspans = 0
  d.bytes = 0
  while d.nspans < MaxSpans:
    let avail = d.fill - d.off
    if avail < 18: break
    let n = (int(d.buf[d.off]) shl 8) or int(d.buf[d.off + 1])
    if avail < 18 + n + 16: break
    let p = d.off + 18
    for k in 0 ..< n: d.buf[p + k] = d.buf[p + k] xor 0x5A
    if n > 0:
      d.spans[d.nspans] = Span(off: p, len: n)
      d.nspans = d.nspans + 1
      d.bytes = d.bytes + n
    d.off = p + n + 16
  result = d.nspans

proc toyBoundary(d: DirectionPtr): bool = true

proc toySeal(c: Conn; d: DirectionPtr): bool =
  var i = 0
  while i < d.nspans:
    let off = d.spans[i].off
    let n = d.spans[i].len
    let start = off - 18
    if n > 65535 or start < 0 or (i > 0 and start != d.wEnd): return false
    d.buf[start] = byte(n shr 8)
    d.buf[start + 1] = byte(n and 0xff)
    for k in 2 ..< 18: d.buf[start + k] = 0
    for k in 0 ..< n: d.buf[off + k] = d.buf[off + k] xor 0x5A
    for k in 0 ..< 16: d.buf[off + n + k] = byte(n and 0xff)
    if i == 0: d.wOff = start
    d.wEnd = off + n + 16
    i = i + 1
  result = true

proc toyClose(d: DirectionPtr) = discard

var gToy = FramerObj(geometry: Geometry(head: 18, tail: 16, maxRecord: 65535, headRoom: 0),
                     open: toyOpen, atBoundary: toyBoundary, seal: toySeal,
                     closeSource: toyClose, closeSink: toyClose)
var gEnds: int
var gLastEnd = ord(erEof)
var gEchoActive: int

proc hookEnd(c: Conn) =
  atomicStore(gLastEnd, ord(c.endReason), moRelease)
  discard atomicFetchAdd(gEnds, 1, moRelease)
var gHooks = ConnHooks(onBatch: nil, onEnd: hookEnd)

proc pattern(i: int): byte {.inline.} = byte((i * 29 + (i shr 10)) and 0xff)

proc matchesPattern(buf: openArray[byte]; offset: int): bool =
  ## Check every byte without allocating an assertion message per byte.
  ## That allocation flood can starve the loop and trigger peer idle timeouts
  ## under Linux sanitizers. One assertion below reports the whole buffer.
  for i in 0 ..< buf.len:
    if buf[i] != pattern(offset + i): return false
  result = true

# ------------------------------------------------------------------- echo

proc echoPlain(s: TcpStreamPtr): int {.passive.} =
  discard atomicFetchAdd(gEchoActive, 1, moAcquireRelease)
  var buf = default(array[32768, byte])
  while true:
    let n = recv(s, buf)
    if n <= 0:
      if n < 0: atomicStore(gEchoReset, true, moRelease)
      break
    if not writeAll(s, buf.toOpenArray(0, n - 1)): break
  shutdownWrite(s)
  discard atomicFetchSub(gEchoActive, 1, moRelease)
  result = 0

# ------------------------------------------------------------- terminator

proc termConn(fd: cint) {.passive.} =
  let c = newConn(5000)
  if c == nil:
    lingerRst(fd)
    return
  c.fd = fd
  c.hooks = addr gHooks
  var t: TlsSide = nil
  var ok = false
  tlsAccept(c, addr gServer, t, ok)
  let tt = t
  if not ok or tt == nil:
    failConn(c, "tls")
    return
  if gResetTerm:
    failConn(c, "reset on purpose")              # frees the TLS side (tlsAccept put it on c)
    return
  if resumed(tt): gTermResumed = gTermResumed + 1
  gTermClientLeaf = peerLeafDer(tt).len
  if echAccepted(tt): gTermEch = gTermEch + 1
  gTermName = serverName(tt)
  if earlyAccepted(tt): gTermEarly = gTermEarly + 1
  expect(setKeyUpdateInterval(tt, gKuEvery), "relay key update interval")
  if gHeader > 0:
    var po = 0
    var pl = 0
    var hok = false
    tlsReadPlain(c, tt, gHeader, po, pl, hok)
    if not hok:
      failConn(c, "header")
      return
    assert ensurePayload(addr c.a)
    for i in 0 ..< gHeader: expect(buf(addr c.a)[po + i] == pattern(i), "the header over TLS")
    restAsSpan(addr c.a, po + gHeader, pl - gHeader)
  dialEndpointInline(gEcho, true, 5000, c.up)
  if c.up < 0:
    failConn(c, "dial")                          # frees the TLS side too
    return
  c.a.dst = c.up
  c.b.src = c.up
  c.b.dst = c.fd
  if gToyUp:
    c.a.dstFramer = addr gToy                    # TLS in, toy records out, and back: relaid out
    c.b.srcFramer = addr gToy
  if gKernel:
    var ko = ktlsUser
    useKtls(c, addr c.a, addr c.b, tt, c.fd, ko)
    if ko == ktlsFailed:
      failConn(c, "ktls")
      return
    if ko == ktlsKernel: gKernelUsed = gKernelUsed + 1
  startPumps(c)

proc termLoop(fd: cint) {.passive.} =
  acceptEach(fd):
    startConn termConn(accepted)

# ------------------------------------------------------------- originator

proc origConn(fd: cint) {.passive.} =
  let c = newConn(5000)
  if c == nil:
    lingerRst(fd)
    return
  c.fd = fd
  c.a.src = fd
  c.hooks = addr gHooks
  if gFirstSpan > 0:
    # A request read before the handshake: its bytes become the first span
    # (longer than a TLS record: the relay splits it).
    var res = 0
    var filled = false
    let ad = addr c.a
    fillTo(c, ad, gFirstSpan, afterMs(5000), res, filled)
    if not filled:
      failConn(c, "request")
      return
    restAsSpan(addr c.a, c.a.off, c.a.fill - c.a.off)
    c.a.off = c.a.fill
  dialEndpointInline(gTerm, true, 5000, c.up)
  if c.up < 0:
    failConn(c, "dial")
    return
  var t: TlsSide = nil
  var ok = false
  tlsConnect(c, c.up, addr c.b, addr c.a, addr gClient, "test.example", t, ok)
  let tt = t
  if not ok or tt == nil:
    gOrigTlsFailed = gOrigTlsFailed + 1
    failConn(c, "tls")
    return
  expect(setKeyUpdateInterval(tt, gKuEvery), "relay key update interval")
  if resumed(tt): gOrigResumed = gOrigResumed + 1
  c.a.dst = c.up
  c.b.dst = c.fd
  if gKernel:
    var ko = ktlsUser
    useKtls(c, addr c.b, addr c.a, tt, c.up, ko)
    if ko == ktlsFailed:
      failConn(c, "ktls")
      return
    if ko == ktlsKernel: gKernelUsed = gKernelUsed + 1
  startPumps(c)

proc origLoop(fd: cint) {.passive.} =
  acceptEach(fd):
    startConn origConn(accepted)

# ------------------------------------------------------------------ tests

var gRequest = false         ## the TLS client asks for a key update halfway

proc tlsSender(s: TlsStreamPtr; done: ptr bool) {.passive.} =
  var buf = default(array[65536, byte])
  var sent = 0
  var asked = false
  while sent < Total:
    if gRequest and not asked and sent >= Total div 2:
      asked = true
      var rec = default(array[64, byte])
      let n = keyUpdate(s.conn, true, ptrOf(rec), rec.len)
      expect(n > 0 and writeAll(addr s.tcp, addr rec[0], n), "request a key update")
    let n = min(buf.len, Total - sent)
    for i in 0 ..< n: buf[i] = pattern(sent + i)
    var off = 0
    while off < n:
      let k = sendFrom(s, addr buf[off], n - off)
      expect(k > 0, "tls send")
      off = off + k
    sent = sent + n
  shutdownWrite(s)
  atomicStore(done[], true, moRelease)

proc plainSender(s: TcpStreamPtr; done: ptr bool) {.passive.} =
  var buf = default(array[65536, byte])
  var sent = 0
  while sent < Total:
    let n = min(buf.len, Total - sent)
    for i in 0 ..< n: buf[i] = pattern(sent + i)
    expect(writeAll(s, addr buf[0], n), "plain send")
    sent = sent + n
  shutdownWrite(s)
  atomicStore(done[], true, moRelease)

proc endCount(): int = atomicLoad(gEnds, moAcquire)

proc waitSender(done: ptr bool) {.passive.} =
  ## The sender borrows a stack owner until its final half-close returns.
  var spins = 0
  while not atomicLoad(done[], moAcquire) and spins < 500:
    parkUntil(afterMs(10))
    spins = spins + 1
  expect(atomicLoad(done[], moAcquire), "sender completed before its owner closes")

proc drainRelays() {.passive.} =
  ## No case may change borrowed configurations until its handlers are done.
  var spins = 0
  while (liveConnections() != 0 or atomicLoad(gEchoActive, moAcquire) != 0) and spins < 500:
    parkUntil(afterMs(10))
    spins = spins + 1
  atomicFence(moAcquire) # pair with the last live-connection release
  expect(liveConnections() == 0 and atomicLoad(gEchoActive, moAcquire) == 0,
         "previous relay and echo handlers drained")
  expect(liveTrafficBlocks() == 0 and liveAltBlocks() == 0,
         "previous TLS traffic and alt buffers released")

proc tlsRoundTrip(port: uint16; skip: int; label: string) {.passive.} =
  ## 4 MiB through a TLS client; the first `skip` bytes are not echoed.
  var s = default(TlsStream)
  expect(connectTls("127.0.0.1", port, addr gClient, addr s, "test.example") == 0, label & ": connect")
  s.conn.keyUpdateEvery = gKuEvery
  var tlsDone = false
  spawnTask tlsSender(addr s, addr tlsDone)
  var buf = default(array[65536, byte])
  var got = 0
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n == 0: break
    if n < 0: echo label, ": recv ", n, " alert ", tlsAlert(n)
    expect(n > 0, label & ": recv")
    expect(matchesPattern(buf.toOpenArray(0, n - 1), skip + got), label & ": data intact")
    got = got + n
  expect(got == Total - skip, label & ": " & $got & " bytes back")
  waitSender(addr tlsDone)
  close(addr s)
  drainRelays()

proc plainRoundTrip(port: uint16; label: string) {.passive.} =
  var p = connect(initSocketAddress(loopback4(), port))
  expect(p.isOpen, label & ": connect")
  var plainDone = false
  spawnTask plainSender(addr p, addr plainDone)
  var buf = default(array[65536, byte])
  var got = 0
  while true:
    let n = recvInto(addr p, addr buf[0], buf.len, never)
    if n <= 0: break
    expect(matchesPattern(buf.toOpenArray(0, n - 1), got), label & ": data intact")
    got = got + n
  expect(got == Total, label & ": " & $got & " bytes back")
  waitSender(addr plainDone)
  close(addr p)
  drainRelays()

var gLastEarlyAccepted = false

proc manySmallEarly(port: uint16; records, size: int): int {.passive.} =
  ## A client (by hand) whose 0-RTT is `records` records of `size` bytes;
  ## the bytes echoed back (0 when the 0-RTT was not taken).
  var raw = connect(initSocketAddress(loopback4(), port))
  expect(raw.isOpen, "connect")
  var c = default(TlsConn)
  expect(initClient(c, addr gClient, "test.example"), "init")
  var inb = newSeq[byte](1 shl 17)
  var inLen = 0
  var outb = newSeq[byte](65536)
  var r = default(StepResult)
  expect(step(c, bytesOf(inb), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
  expect(writeAll(addr raw, addr outb[0], r.outLen), "hello out")
  expect(c.earlyWrite, "a ticket with 0-RTT")
  var sent = 0
  for k in 0 ..< records:
    var rec = newSeq[byte](5 + size + 17)
    for i in 0 ..< size: rec[5 + i] = pattern(sent + i)
    expect(sealEarly(c, bytesOf(rec), 0, size) == rec.len, "an early record")
    expect(writeAll(addr raw, addr rec[0], rec.len), "early out")
    sent = sent + size
  var ready = false
  var echoed = 0
  var failed = false
  while not failed and (not ready or echoed < sent):
    let st = step(c, bytesOf(inb), inLen, bytesOf(outb), outb.len, r)
    if st == stAppData:
      for i in 0 ..< r.len: expect(inb[r.off + i] == pattern(echoed + i), "echo intact")
      echoed = echoed + r.len
    if r.consumed > 0:
      moveMem(addr inb[0], addr inb[r.consumed], inLen - r.consumed)
      inLen = inLen - r.consumed
    case st
    of stSend: expect(writeAll(addr raw, addr outb[0], r.outLen), "send")
    of stReady: ready = true
    of stNeedInput:
      let n = recvInto(addr raw, addr inb[inLen], inb.len - inLen, afterMs(5000))
      if n <= 0: failed = true
      else: inLen = inLen + n
    of stAppData: discard
    else: failed = true
  result = if c.earlyAccepted: echoed else: 0
  close(addr raw)
  release(c)
  drainRelays()

proc earlyRoundTrip(port: uint16; early, skip: int; label: string) {.passive.} =
  ## A TLS client whose first `early` bytes of the pattern go as 0-RTT (when
  ## it holds a ticket), the rest after; `skip` bytes are not echoed.
  var s = default(TlsStream)
  var first = newSeq[byte](early)
  for i in 0 ..< early: first[i] = pattern(i)
  expect(connectTls("127.0.0.1", port, addr gClient, addr s, "test.example",
                    earlyData = addr first[0], earlyLen = early) == 0, label & ": connect")
  var buf = newSeq[byte](20000)
  var sent = early
  var rest = 20000 - early
  for i in 0 ..< rest: buf[i] = pattern(sent + i)
  expect(sendFrom(addr s, addr buf[0], rest) == min(rest, 16384), label & ": send")
  sent = sent + min(rest, 16384)
  shutdownWrite(addr s)
  var got = 0
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0: break
    expect(matchesPattern(buf.toOpenArray(0, n - 1), skip + got), label & ": data intact")
    got = got + n
  expect(got == sent - skip, label & ": " & $got & " bytes back of " & $(sent - skip))
  gLastEarlyAccepted = s.conn.earlyAccepted
  close(addr s)
  drainRelays()

proc waitEnds(n: int) {.passive.} =
  var i = 0
  while endCount() < n and i < 500:
    parkUntil(afterMs(10))
    i = i + 1

proc rawHandshake(raw: TcpStreamPtr; c: var TlsConn) {.passive.} =
  ## Our client over a plain socket, driven by hand: the handshake, Finished sent.
  expect(initClient(c, addr gClient, "test.example"), "init")
  var inb = newSeq[byte](65536)
  var inLen = 0
  var outb = newSeq[byte](65536)
  var r = default(StepResult)
  var ready = false
  while not ready:
    let st = step(c, bytesOf(inb), inLen, bytesOf(outb), outb.len, r)
    if r.consumed > 0:
      moveMem(addr inb[0], addr inb[r.consumed], inLen - r.consumed)
      inLen = inLen - r.consumed
    case st
    of stSend: expect(writeAll(raw, addr outb[0], r.outLen), "send")
    of stNeedInput:
      let n = recvInto(raw, addr inb[inLen], inb.len - inLen, afterMs(5000))
      expect(n > 0, "server flight")
      inLen = inLen + n
    of stReady: ready = true
    else: expect(false, "handshake: " & $st)
  var r2 = default(StepResult)
  expect(step(c, bytesOf(inb), 0, bytesOf(outb), outb.len, r2) == stNeedInput, "idle")

proc main() {.passive.} =
  let base = liveConnections()
  var el = listenTcp(0, "127.0.0.1")
  expect(el.ok, "echo listen")
  serve(el, echoPlain)
  expect(parseHostPort("127.0.0.1:" & $port(el), gEcho), "echo endpoint")
  var tl = listenTcp(0, "127.0.0.1")
  expect(tl.ok, "terminator listen")
  spawnTask termLoop(nativeHandle(tl))
  expect(parseHostPort("127.0.0.1:" & $port(tl), gTerm), "terminator endpoint")
  var ol = listenTcp(0, "127.0.0.1")
  expect(ol.ok, "originator listen")
  spawnTask origLoop(nativeHandle(ol))

  for mode in 0 ..< 4:
   gKernel = mode >= 2
   gRequest = mode == 1 or mode == 3
   let every = if mode == 1 or mode == 3: 50'u64 else: 0'u64
   let before = gKernelUsed
   block:
    gKuEvery = every
    # A TLS client through the terminator to the echo server.
    var s = default(TlsStream)
    expect(connectTls("127.0.0.1", port(tl), addr gClient, addr s, "test.example") == 0, "connect")
    s.conn.keyUpdateEvery = every
    var tlsDone = false
    spawnTask tlsSender(addr s, addr tlsDone)
    var buf = default(array[65536, byte])
    var got = 0
    while true:
      let n = recvInto(addr s, addr buf[0], buf.len)
      if n == 0: break
      if n < 0: echo "recv ", n, " alert ", tlsAlert(n)
      expect(n > 0, "tls recv")
      for i in 0 ..< n: expect(buf[i] == pattern(got + i), "tls data intact")
      got = got + n
    expect(got == Total, "4 MiB back through the terminator")
    waitSender(addr tlsDone)
    close(addr s)
    echo "PASS terminator: 4 MiB each way, half-close, close_notify both ways",
         (if every > 0: ", key updates every 50 records both ways, one requested by the client" else: "")

    # A plain client through the originator (TLS out) and the terminator.
    var p = connect(initSocketAddress(loopback4(), port(ol)))
    expect(p.isOpen, "connect originator")
    var plainDone = false
    spawnTask plainSender(addr p, addr plainDone)
    got = 0
    while true:
      let n = recvInto(addr p, addr buf[0], buf.len, never)
      if n <= 0: break
      for i in 0 ..< n: expect(buf[i] == pattern(got + i), "plain data intact")
      got = got + n
    expect(got == Total, "4 MiB back through originator and terminator")
    waitSender(addr plainDone)
    close(addr p)
    drainRelays()
    echo "PASS originator -> terminator: 4 MiB each way over TLS between relays",
         (if every > 0: ", key updates every 50 records" else: "")
   if gKernel:
     when defined(linux):
       expect(gKernelUsed >= before + 3, "the kernel took the TLS sides: " & $(gKernelUsed - before))
       echo "PASS the same with kTLS on the relays' TLS sides", (if gRequest: ", a key update requested by the client" else: "")
     else:
       echo "PASS the same with kTLS asked for (not here: the user-space framer took over)"

  gKernel = false
  gRequest = false

  # TLS in, a Shadowsocks-shaped record format out and back (relayout both
  # ways), with key updates from the alt block.
  gToyUp = true
  gKuEvery = 50
  tlsRoundTrip(port(tl), 0, "TLS <-> toy 18/16 records")
  gToyUp = false
  gKuEvery = 0
  echo "PASS TLS <-> an 18/16 record format: relaid out both ways, key updates, close"

  # A header over TLS read first (tlsReadPlain): 20 000 bytes across records.
  gHeader = 20_000
  tlsRoundTrip(port(tl), 20_000, "header")
  gHeader = 0
  echo "PASS a 20 000-byte header read over TLS, the rest relayed"

  # A first span longer than a TLS record (a request read before the
  # handshake): split into records, all through.
  gFirstSpan = 40_000
  plainRoundTrip(port(ol), "first span")
  echo "PASS a 40 000-byte first span into a TLS sink: split, in order"
  # ... and the same with the TLS peer resetting: the split fails, cleanly.
  gResetTerm = true
  let endsR = endCount()
  var q = connect(initSocketAddress(loopback4(), port(ol)))
  var qb = default(array[65536, byte])
  for i in 0 ..< qb.len: qb[i] = pattern(i)
  discard writeAll(addr q, addr qb[0], qb.len)
  waitEnds(endsR + 1)
  expect(endCount() > endsR, "the originator's connection ended")
  close(addr q)
  drainRelays()
  gResetTerm = false
  gFirstSpan = 0
  echo "PASS a failed split (the TLS peer reset): no crash, the connection ends"

  # The client's Finished and its first record in one segment.
  gKuEvery = 0
  var raw = connect(initSocketAddress(loopback4(), port(tl)))
  var c = default(TlsConn)
  expect(initClient(c, addr gClient, "test.example"), "init")
  var inb = newSeq[byte](65536)
  var inLen = 0
  var outb = newSeq[byte](65536)
  var r = default(StepResult)
  var pending: seq[byte] = @[]
  var ready = false
  while not ready:
    let st = step(c, bytesOf(inb), inLen, bytesOf(outb), outb.len, r)
    if r.consumed > 0:
      moveMem(addr inb[0], addr inb[r.consumed], inLen - r.consumed)
      inLen = inLen - r.consumed
    case st
    of stSend:
      for i in 0 ..< r.outLen: pending.add outb[i]
    of stNeedInput:
      if pending.len > 0:
        expect(writeAll(addr raw, addr pending[0], pending.len), "hello")
        pending = @[]
      let n = recvInto(addr raw, addr inb[inLen], inb.len - inLen, afterMs(5000))
      expect(n > 0, "server flight")
      inLen = inLen + n
    of stReady: ready = true
    else: expect(false, "handshake: " & $st)
  var msg = newSeq[byte](5 + 5 + 17)
  for i in 0 ..< 5: msg[5 + i] = byte(ord("hello"[i]))
  let m = sealApp(c, bytesOf(msg), 0, 5)
  for i in 0 ..< m: pending.add msg[i]      # Finished (still pending) and data: one write
  expect(writeAll(addr raw, addr pending[0], pending.len), "Finished and data together")
  var echoed: seq[byte] = @[]
  while echoed.len < 5:
    let st = step(c, bytesOf(inb), inLen, bytesOf(outb), outb.len, r)
    if st == stAppData:
      for i in r.off ..< r.off + r.len: echoed.add inb[i]
    if r.consumed > 0:
      moveMem(addr inb[0], addr inb[r.consumed], inLen - r.consumed)
      inLen = inLen - r.consumed
    if st == stNeedInput:
      let n = recvInto(addr raw, addr inb[inLen], inb.len - inLen, afterMs(5000))
      expect(n > 0, "echo")
      inLen = inLen + n
    elif st == stFailed: expect(false, "failed: " & r.reason)
  expect(echoed.len == 5 and echoed[0] == byte('h') and echoed[4] == byte('o'), "hello echoed")
  echo "PASS the client's Finished and first record in one segment"

  # Truncation: FIN without close_notify ends the connection as an error,
  # and the upstream sees a reset, never a clean end.
  let before = endCount()
  atomicStore(gEchoReset, false, moRelease)
  shutdownWrite(addr raw)
  waitEnds(before + 1)
  expect(endCount() == before + 1 and atomicLoad(gLastEnd, moAcquire) == ord(erError), "truncation fails the connection")
  var spinsE = 0
  while not atomicLoad(gEchoReset, moAcquire) and spinsE < 200:
    parkUntil(afterMs(10))
    spinsE = spinsE + 1
  expect(atomicLoad(gEchoReset, moAcquire), "the upstream saw a clean end (a reset expected)")
  close(addr raw)
  release(c)
  drainRelays()
  echo "PASS truncation (FIN without close_notify) fails the connection"

  # A record header the kernel refuses (a plaintext alert where records are
  # encrypted): the terminator's TLS side fails at once, kernel or not; it
  # must not wait for more (the idle timeout is 5 s).
  gKernel = true
  var bad = connect(initSocketAddress(loopback4(), port(tl)))
  var bc = default(TlsConn)
  rawHandshake(addr bad, bc)
  parkUntil(afterMs(100))                        # the relay's switch to the kernel (on Linux)
  let beforeB = endCount()
  var hdr = [21'u8, 3, 3, 0, 2, 2, 40]
  expect(writeAll(addr bad, addr hdr[0], hdr.len), "a bad record")
  var spinsB = 0
  while endCount() == beforeB and spinsB < 200:
    parkUntil(afterMs(10))
    spinsB = spinsB + 1
  expect(endCount() == beforeB + 1 and atomicLoad(gLastEnd, moAcquire) == ord(erError), "a bad record fails the connection within 2 s")
  close(addr bad)
  release(bc)
  drainRelays()
  gKernel = false
  echo "PASS a record the kernel refuses fails the connection at once"

  # Resumption through the relays: tickets from the terminator, stored by
  # the originator's TLS side (its framer reads them); its next connection
  # resumes. 0-RTT into the terminator: relayed first, and read as the
  # start of a header.
  var ticketer = default(KeyedTicketer)
  assert initKeyedTicketer(ticketer)
  var replay = default(MemoryReplay)
  initMemoryReplay(replay)
  var store = default(MemoryStore)
  initMemoryStore(store)
  gServer.ticketer = keyedTicketer(addr ticketer)
  gServer.antiReplay = memoryReplay(addr replay)
  gServer.maxEarlyData = 16384
  gClient.sessions = memoryStore(addr store)
  gClient.earlyData = true
  let or0 = gOrigResumed
  plainRoundTrip(port(ol), "tickets 1")
  plainRoundTrip(port(ol), "tickets 2")
  expect(gOrigResumed == or0 + 1, "the originator resumed its second connection")
  echo "PASS tickets stored by a relay's TLS client side: its next connection resumes"
  earlyRoundTrip(port(tl), 1000, 0, "0-RTT 1")      # (tickets for the next, at least)
  let te0 = gTermEarly
  earlyRoundTrip(port(tl), 1000, 0, "0-RTT 2")
  expect(gLastEarlyAccepted and gTermEarly == te0 + 1, "0-RTT taken by the terminator")
  echo "PASS 0-RTT into a relay: relayed upstream first, in order"
  gHeader = 600
  earlyRoundTrip(port(tl), 1000, 600, "0-RTT header")
  expect(gLastEarlyAccepted and gTermEarly == te0 + 2, "0-RTT with a header")
  gHeader = 0
  echo "PASS 0-RTT carrying a header: tlsReadPlain starts with it"
  earlyRoundTrip(port(tl), 100, 0, "a ticket")      # (a fresh ticket for the next)
  let te1 = gTermEarly
  expect(manySmallEarly(port(tl), 100, 10) == 1000 and gTermEarly == te1 + 1,
         "100 small 0-RTT records through a relay")
  echo "PASS 0-RTT in many small records: one span, relayed first"
  gServer.maxEarlyData = 1'u32 shl 20
  earlyRoundTrip(port(tl), 100, 0, "a relay's ticket")
  block:
    var tk = default(SessionTicket)
    let tf = gClient.sessions.take
    expect(tf != nil and tf(gClient.sessions.ctx, "test.example", unixMs(), tk), "a ticket from the relay")
    expect(int(tk.maxEarlyData) == relayEarlyCap(), "a relay promises what its buffer holds: " & $tk.maxEarlyData)
  gServer.maxEarlyData = 16384
  echo "PASS a relay's tickets promise no more 0-RTT than it can hold"

  # A terminator that requires a client certificate; the originator presents one.
  var cauthRoots: seq[Cert] = @[]
  expect(certsPem(slurpText("tests/data/cauth-root.pem"), cauthRoots) == 1, "client root")
  let clientRoots = newRoots()
  if clientRoots == nil: quit "no store"
  expect(addRoot(clientRoots, cauthRoots[0]), "add client root")
  var ckc = default(CertifiedKey)
  expect(loadCertifiedKey(slurpText("tests/data/cauth.pem"), slurpText("tests/data/cauth.key"), ckc) == "", "client key")
  gServer.clientAuth = caRequire
  gServer.clientRoots = clientRoots
  gClient.clientCert = singleClientCert(addr ckc)
  gClient.sessions = SessionStore()               # a full handshake each time
  gTermClientLeaf = 0
  plainRoundTrip(port(ol), "mTLS between relays")
  expect(gTermClientLeaf == ckc.chain[0].len, "the terminator saw the originator's certificate")
  gServer.clientAuth = caIgnore
  gServer.clientRoots = nil
  gClient.clientCert = ClientCertResolver()
  # plainRoundTrip drained every handler before these fixture borrows end.
  release(ckc)
  release(clientRoots)
  for cert in cauthRoots: release(cert)
  cauthRoots = @[]
  expect(ckc.key == nil and ckc.chain.len == 0, "client fixture released")
  echo "PASS mTLS fixture key and roots released after relay drain"
  echo "PASS a terminator requiring a client certificate, an originator presenting one"

  # ECH between relays: the terminator opens the originator's inner hello;
  # a stale config fails the originator's handshake (ech_required), and
  # its client sees the connection end.
  # (The public name is one the terminator's certificate covers: a refusal
  # gets through the certificate check to ech_required.)
  let echKey = newEchKey(9, "test.example")
  gServer.echKeys = @[echKey]
  gClient.echConfigs = echConfigList(@[echKey])
  gTermEch = 0
  gTermName = ""
  plainRoundTrip(port(ol), "ECH between relays")
  expect(gTermEch == 1 and gTermName == "test.example", "the terminator took the inner hello")
  gClient.echConfigs = echConfigList(@[newEchKey(9, "test.example")])
  let failedBefore = gOrigTlsFailed
  var p = connect(initSocketAddress(loopback4(), port(ol)))
  # The originator can reject TLS and reset this socket before the client's
  # connect resumes (Linux SO_ERROR=ECONNRESET). Either connect or recv may
  # observe that rejection; neither may deliver application data.
  if p.isOpen:
    var one = default(array[16, byte])
    expect(recvInto(addr p, addr one[0], one.len, afterMs(5000)) <= 0,
           "a stale config ends the client connection without application data")
  close(addr p)
  drainRelays()
  expect(gOrigTlsFailed == failedBefore + 1,
         "a stale config fails exactly one originator TLS handshake")
  gServer.echKeys = @[]
  gClient.echConfigs = @[]
  echo "PASS ECH between relays; a stale config ends the connection"
  gServer.maxEarlyData = 0
  gClient.earlyData = false

  var spins = 0
  while liveConnections() > base and spins < 500:
    parkUntil(afterMs(10))
    spins = spins + 1
  expect(liveConnections() == base, "every block back: " & $liveConnections() & " vs " & $base)
  expect(liveTrafficBlocks() == 0 and liveAltBlocks() == 0,
         "TLS sides " & $liveTrafficBlocks() & ", alt blocks " & $liveAltBlocks())
  echo "PASS every connection block, TLS side and alt block returned"
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
initRuntime()
spawnTask main()
drainRuntime()
