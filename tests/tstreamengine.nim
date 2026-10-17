## zal-tls as a std/streamio engine: in memory against a zal-tls server,
## then over a socket through the std stream.
import std/[assertions, syncio, streamio]
import zal_net/rt, zal_net/rt/sync
import zal_net/net/tcp as tcp
import zal_tls as tls
import zal_tls/engine
import zal_tls/record as records
import zal_tls/config/owned
import zal_tls/common

proc text(path: string): string =
  try: result = readFile(path)
  except: result = ""

proc pattern(n: int): string =
  result = newString(n)
  for i in 0 ..< n: result[i] = char(i mod 251)

# ------------------------------------------------------------- in memory --

type Server = object
  c: records.TlsConn
  inb: seq[byte]
  inLen: int
  outb: seq[byte]
  app: string
  ready, peerClosed: bool

proc initServer(config: tls.ServerConfig): Server =
  result = Server(c: default(records.TlsConn), inb: newSeq[byte](1 shl 16), inLen: 0,
                  outb: newSeq[byte](1 shl 16), app: "", ready: false, peerClosed: false)
  assert records.initServer(addr result.c, unsafeBorrowConfig(config))

proc turn(s: var Server; input: string): string =
  ## Feed `input`, step until the server wants more; what it sends back.
  result = ""
  for ch in input:
    if s.inLen == s.inb.len: s.inb.setLen(s.inb.len * 2)
    s.inb[s.inLen] = byte(ch)
    inc s.inLen
  while true:
    var r = default(StepResult)
    let st = records.step(addr s.c, bytesOf(s.inb), s.inLen, bytesOf(s.outb), s.outb.len, r)
    for i in 0 ..< r.outLen: result.add char(s.outb[i])
    case st
    of stAppData, stEarlyData:
      for i in r.off ..< r.off + r.len: s.app.add char(s.inb[i])
    of stReady: s.ready = true
    of stPeerClosed, stClosed: s.peerClosed = true
    of stFailed: assert false, r.reason
    else: discard
    if r.consumed > 0:
      let rest = s.inLen - r.consumed
      if rest > 0: moveMem(addr s.inb[0], addr s.inb[r.consumed], rest)
      s.inLen = rest
    if st == stNeedInput or s.peerClosed: break
    if r.consumed == 0 and r.outLen == 0 and st != stReady: break

proc sealed(s: var Server; data: string): string =
  var buf = newSeq[byte](5 + data.len + 1 + 16)
  for i in 0 ..< data.len: buf[5 + i] = byte(data[i])
  let m = records.sealApp(addr s.c, bytesOf(buf), 0, data.len)
  assert m == buf.len
  result = ""
  for i in 0 ..< m: result.add char(buf[i])

proc handshake(e: ZalTlsEngine; s: var Server; name: string): bool {.raises.} =
  ## False when the engine refused the server.
  result = true
  e.start(name)
  var wire = ""
  var rounds = 0
  while not e.isConnected or not s.ready:
    assert rounds < 10
    e.recordsOut(wire)
    let back = turn(s, wire)
    wire = ""
    var used = 0
    try:
      e.recordsIn(back, used)
    except ErrorCode as error:
      assert error == ProtocolError
      return false
    assert used == back.len
    inc rounds

proc memory(client: tls.ClientConfig; config: tls.ServerConfig) {.raises.} =
  var s = initServer(config)
  let e = newTlsEngine(client)
  assert not e.isConnected
  assert handshake(e, s, "test.example")
  assert e.alpn == "test"
  var wire = ""
  var used = 0
  e.appIn("hello", used)
  assert used == 5
  e.recordsOut(wire)
  assert turn(s, wire).len == 0
  assert s.app == "hello"
  e.recordsIn(sealed(s, "world"), used)
  var plain = ""
  e.appOut(plain)
  assert plain == "world"
  let big = pattern(40_000)
  e.appIn(big, used)
  assert used == big.len
  wire = ""
  e.recordsOut(wire)
  assert wire.len > big.len + 2 * 22
  assert turn(s, wire).len == 0
  assert s.app == "hello" & big
  e.close()
  wire = ""
  e.recordsOut(wire)
  assert turn(s, wire).len == 0
  assert s.peerClosed
  var buf = newSeq[byte](64)
  let m = records.close(addr s.c, bytesOf(buf), buf.len)
  assert m > 0
  var notify = ""
  for i in 0 ..< m: notify.add char(buf[i])
  e.recordsIn(notify, used)
  assert e.isPeerClosed
  try:
    e.appIn("late", used)
    assert false
  except ErrorCode as error:
    assert error == BadOperation
  records.release(addr s.c)

proc bounded(client: tls.ClientConfig; config: tls.ServerConfig) {.raises.} =
  const Limit = 64 * 1024
  var s = initServer(config)
  defer: records.release(addr s.c)
  let e = newTlsEngine(client, pendingLimit=Limit)
  assert handshake(e, s, "test.example")
  let payload = pattern(1024 * 1024 + 7)
  var sent = 0
  while sent < payload.len:
    var used = 0
    e.appIn(payload.toOpenArray(sent, payload.len - 1), used)
    assert used > 0 and used <= Limit
    sent += used
    var wire = ""
    e.recordsOut(wire)
    assert wire.len <= Limit
    discard turn(s, wire)
  assert s.app == payload

  var wire = ""
  var offset = 0
  while offset < payload.len:
    let n = min(MaxPlaintext, payload.len - offset)
    wire.add sealed(s, payload.substr(offset, offset + n - 1))
    offset += n
  var received = ""
  offset = 0
  var rounds = 0
  while received.len < payload.len:
    var used = 0
    e.recordsIn(wire.toOpenArray(offset, wire.len - 1), used)
    if rounds == 0: assert used < wire.len
    offset += used
    var plain = ""
    e.appOut(plain)
    assert plain.len <= Limit
    assert used > 0 or plain.len > 0
    received.add plain
    var control = ""
    e.recordsOut(control)
    assert control.len <= Limit
    discard turn(s, control)
    inc rounds
  assert offset == wire.len and received == payload

  let small = sealed(s, "fragmented record")
  for ch in small:
    var used = 0
    let fragment = [ch]
    e.recordsIn(fragment, used)
    assert used == 1
  var plain = ""
  e.appOut(plain)
  assert plain == "fragmented record"

proc wrongName(client: tls.ClientConfig; config: tls.ServerConfig) {.raises.} =
  var s = initServer(config)
  let e = newTlsEngine(client)
  assert not handshake(e, s, "wrong.example")
  assert not e.isConnected
  assert e.alert != 0
  records.release(addr s.c)

# --------------------------------------------------------------- socket --

type Context = ref object
  config: nil tls.ServerConfig
  done: Event
  failure: ErrorCode
  got: int

proc serve(listener: sink tcp.TcpListener; ctx: sink Context) {.passive.} =
  try:
    var underlying: nil tcp.TcpStream = listener.accept(deadline=afterMs(5000))
    let config = ctx.config
    if config == nil:
      assert false
    else:
      let stream = tls.wrapOwned(config, underlying, deadline=afterMs(5000))
      defer: stream.close()
      var buf = newSeq[byte](16384)
      while true:
        let n = stream.read(buf, deadline=afterMs(5000))
        if n == 0: break
        stream.write(buf.toOpenArray(0, n - 1), deadline=afterMs(5000))
        ctx.got += n
      stream.shutdownWrite()
  except ErrorCode as error:
    ctx.failure = error
  setEvent(addr ctx.done)

proc socket(client: tls.ClientConfig; config: tls.ServerConfig) {.passive, raises.} =
  let ctx = Context()
  ctx.config = config
  let listener = tcp.listen(0, "127.0.0.1")
  defer: listener.close()
  assert trySpawnTask(serve(listener, ctx))
  let e = newTlsEngine(client, "test.example")
  var (r, w) = connect("127.0.0.1:" & $listener.port, tls = e)
  assert e.alpn == "test"
  w.write("I")
  w.flush()
  var one = default(array[1, char])
  assert r.read(one) == 1 and one[0] == 'I'
  let payload = pattern(65537)
  w.write(payload)
  w.flush()
  var back = ""
  var chunk = default(array[4096, char])
  while back.len < payload.len:
    let n = r.read(chunk)
    assert n > 0
    for i in 0 ..< n: back.add chunk[i]
  assert back == payload
  w.close()
  assert r.read(one) == 0
  assert wait(addr ctx.done, afterMs(5000)) == wrReady
  assert ctx.failure == Success
  assert ctx.got == payload.len + 1

proc main() {.passive.} =
  try:
    let client = tls.newClientConfig(pemTrust(text("tests/data/root.pem")), alpn = @["test"])
    let config = tls.newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                     text("tests/data/leaf.key"), alpn = @["test"])
    memory(client, config)
    bounded(client, config)
    wrongName(client, config)
    socket(client, config)
    echo "PASS std stream engine: in memory and over a socket"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
