{.feature: "assumeSync".}
## TLS on a user transport with deliberately fragmented reads and partial writes.
## Borrowing leaves the underlying owner open; transfer closes it exactly once.
import std/[syncio, assertions]
import zal_net/raw
import zal_net/net/transport
import zal_net/unsafe/streamview
import zal_net/rt/cancel
import zal_tls/raw/stream
import zal_tls/private/streamlease
import zal_tls/config/config
import zal_tls/crypto/x509
import hexutil

type SocketOwner = object
  tcp: TcpStream
  closes: int
  stopWriting: bool
  writeBudget: int
  blocked: Event
  flushEntered: Event

proc readPart(ctx: pointer; buf: pointer; count: int; until: Deadline;
              tok: nil CancelToken): int {.passive.} =
  let owner = cast[ptr SocketOwner](ctx)
  result = recvInto(addr owner.tcp, buf, min(count, 7), until, tok)
proc writePart(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.passive.} =
  let owner = cast[ptr SocketOwner](ctx)
  if owner.stopWriting and owner.writeBudget == 0:
    setEvent(addr owner.flushEntered)
    if wait(addr owner.blocked, until, tok) != wrReady:
      return (if cancelled(tok): ECancelled else: IoTimedOut)
  let limit = if owner.stopWriting: min(11, owner.writeBudget) else: 11
  result = sendFrom(addr owner.tcp, buf, min(count, limit), until, tok)
  if owner.stopWriting and result > 0: owner.writeBudget = owner.writeBudget - result
proc endWrite(ctx: pointer) =
  let owner = cast[ptr SocketOwner](ctx)
  shutdownWrite(addr owner.tcp)
proc stop(ctx: pointer) =
  let owner = cast[ptr SocketOwner](ctx)
  interrupt(addr owner.tcp)
proc finish(ctx: pointer): int {.passive.} =
  let owner = cast[ptr SocketOwner](ctx)
  owner.closes = owner.closes + 1
  close(addr owner.tcp)
  result = 0

proc disposeOwner(ctx: pointer): int =
  let owner = cast[ptr SocketOwner](ctx)
  if owner.tcp.isOpen:
    inc owner.closes
    close(addr owner.tcp)
  result = 0

proc transferCheck(ctx: pointer): int = 0

type SocketOwnerRef = ref object
  state: SocketOwner

proc retainedRead(ctx: pointer; buf: pointer; count: int; until: Deadline;
                  tok: nil CancelToken): int {.passive.} =
  let owner = cast[SocketOwnerRef](ctx)
  result = readPart(addr owner.state, buf, count, until, tok)
proc retainedWrite(ctx: pointer; buf: pointer; count: int; until: Deadline;
                   tok: nil CancelToken): int {.passive.} =
  let owner = cast[SocketOwnerRef](ctx)
  result = writePart(addr owner.state, buf, count, until, tok)
proc retainedEnd(ctx: pointer) =
  let owner = cast[SocketOwnerRef](ctx)
  endWrite(addr owner.state)
proc retainedStop(ctx: pointer) =
  let owner = cast[SocketOwnerRef](ctx)
  stop(addr owner.state)
proc retainedClose(ctx: pointer): int {.passive.} =
  let owner = cast[SocketOwnerRef](ctx)
  result = finish(addr owner.state)
proc retainedDispose(ctx: pointer): int =
  let owner = cast[SocketOwnerRef](ctx)
  result = disposeOwner(addr owner.state)
var retainedOps = StreamOps(recv: retainedRead, send: retainedWrite,
                           shutdownWrite: retainedEnd, interrupt: retainedStop)

var ops = StreamOps(recv: readPart, send: writePart, shutdownWrite: endWrite,
                    interrupt: stop)
var key = default(CertifiedKey)
var server = default(ServerConfig)
var client = default(ClientConfig)
var finished = false
var quietFinished = default(Event)
var acceptFinished = default(Event)

proc cancelSoon(tok: CancelToken; done: ptr Event) {.passive.} =
  parkUntil(afterMs(20))
  cancel(tok)
  release(tok)
  setEvent(done)

proc quietPeer(tcp: TcpStreamPtr): int {.passive.} =
  parkUntil(afterMs(100))
  close(tcp)
  setEvent(addr quietFinished)
  result = 0

proc cancelledHandshake(tcp: TcpStreamPtr): int {.passive.} =
  var tls = default(TlsStream)
  let tok = newCancelToken()
  var done = default(Event)
  retain(tok)
  spawnTask cancelSoon(tok, addr done)
  expect(acceptTls(addr tls, tcp, addr server, tok = tok) == ECancelled,
         "cancel server handshake waiting for ClientHello")
  expect(not tcp[].isOpen, "started handshake owns accepted TCP on failure")
  expect(wait(addr done, afterMs(2000)) == wrReady, "server canceller finished")
  release(tok)
  close(addr tls)
  close(addr tls)
  setEvent(addr acceptFinished)
  result = 0

proc echoBorrowed(tcp: TcpStreamPtr): int {.passive.} =
  var rejected = default(TlsStream)
  let stopped = newCancelToken()
  cancel(stopped)
  expect(acceptTls(addr rejected, tcp, addr server, tok = stopped) == ECancelled,
         "pre-cancelled accept does not take the TCP owner")
  expect(tcp[].isOpen, "TCP owner preserved on rejected accept")
  close(addr rejected)
  release(stopped)
  var owner = SocketOwner(tcp: takeTcp(tcp))
  var tls = default(TlsStream)
  expect(unsafeWrapServer(addr tls, unsafeBorrowStream(addr owner, addr ops), addr server) == 0, "server wrap")
  var buf = default(array[32, byte])
  let n = recvInto(addr tls, addr buf[0], buf.len)
  expect(n == 4, "payload")
  parkUntil(afterMs(80))  # client first cancels its pending read, then resumes it
  expect(sendFrom(addr tls, addr buf[0], n) == n, "echo")
  expect(recvInto(addr tls, buf, afterMs(2000)) == TlsTruncated,
         "cancelled partial record is closed rather than reused")
  close(addr tls)
  close(addr tls)
  expect(owner.closes == 0 and owner.tcp.isOpen, "borrowed transport survives close")
  close(addr owner.tcp)
  finished = true
  result = 0

type FlushLifetime = object
  acquired: int
  dropped: int
  done: Event

proc holdFlush(ctx: pointer) {.nimcall.} =
  let life = cast[ptr FlushLifetime](ctx)
  life.acquired = life.acquired + 1

proc dropFlush(ctx: pointer) {.nimcall.} =
  let life = cast[ptr FlushLifetime](ctx)
  life.dropped = life.dropped + 1
  setEvent(addr life.done)

var flushPeerDone = default(Event)

proc flushPeer(tcp: TcpStreamPtr): int {.passive.} =
  var tls = default(TlsStream)
  expect(acceptTls(addr tls, tcp, addr server) == 0, "flush peer handshake")
  var buf = default(array[1, byte])
  expect(recvInto(addr tls, buf, afterMs(2000)) == 0, "ordered close_notify")
  close(addr tls)
  setEvent(addr flushPeerDone)
  result = 0

proc unblockFlush(owner: ptr SocketOwner) {.passive.} =
  expect(wait(addr owner.flushEntered, afterMs(2000)) == wrReady,
         "background flush entered transport before close")
  parkUntil(afterMs(5))
  owner.stopWriting = false
  setEvent(addr owner.blocked)

proc checkFlushLifetime() {.passive.} =
  # The close caller retains its raw owner and custom context until the queued
  # flush acknowledges completion. Reuse the same stream after every close.
  var tls = default(TlsStream)
  for iteration in 0..<24:
    clearEvent(addr flushPeerDone)
    var listener = listenTcp(0, "127.0.0.1")
    serve(listener, flushPeer)
    var owner = SocketOwner(tcp: connect("127.0.0.1", port(listener)))
    var life = default(FlushLifetime)
    expect(unsafeWrapClient(addr tls, unsafeBorrowStream(addr owner, addr ops), addr client,
                      "test.example") == 0, "flush client handshake")
    expect(setBackgroundLease(addr tls, BackgroundLease(context: addr life,
                           acquire: holdFlush, drop: dropFlush)), "install flush lease")
    owner.stopWriting = true
    shutdownWrite(addr tls)
    expect(life.acquired == 1, "queued flush retains context")
    expect(not closeNow(addr tls), "queued flush prevents synchronous disposal")
    spawnTask unblockFlush(addr owner)
    close(addr tls)
    close(addr tls)
    expect(wait(addr life.done, afterMs(2000)) == wrReady and life.dropped == 1,
           "completion releases exactly one copied lease")
    expect(owner.closes == 0 and owner.tcp.isOpen, "borrowed flush transport preserved")
    close(addr owner.tcp)
    expect(wait(addr flushPeerDone, afterMs(2000)) == wrReady, "flush peer drained")
    discard close(listener)

proc main() {.passive.} =
  let baseline = liveCancelTokens()
  var unused = default(TlsStream)
  var empty = default(array[0, byte])
  expect(sendFrom(addr unused, empty) == 0 and recvInto(addr unused, empty) == 0,
         "empty TLS windows are no-ops on default owners")
  close(addr unused)
  close(addr unused)
  var listener = listenTcp(0, "127.0.0.1")
  serve(listener, echoBorrowed)
  let owner = SocketOwnerRef(state: SocketOwner(tcp: connect("127.0.0.1", port(listener))))
  var tls = default(TlsStream)
  let stopped = newCancelToken()
  cancel(stopped)
  expect(connectTls("localhost", port(listener), addr client, addr tls, tok = stopped) == ECancelled,
         "pre-cancelled connect before DNS/TCP")
  let transport = unsafeBorrowStream(addr owner.state, addr ops)
  expect(unsafeWrapClient(addr tls, transport, addr client, "test.example", tok=stopped) == ECancelled,
         "pre-cancelled borrowed construction")
  expect(unsafeWrapClient(addr tls, transport, addr client, "test.example") == 0,
         "standard backend borrowed construction")
  expect(useKtls(addr tls) == NotSupported, "custom transport has no native kTLS handle")
  var payload = [1'u8, 2, 3, 4]
  expect(sendFrom(addr tls, payload, tok = stopped) == ECancelled and isReady(addr tls),
         "cancellation before sealing leaves TLS usable")
  release(stopped)
  expect(sendFrom(addr tls, addr payload[0], 4) == 4, "send")
  var received = default(array[4, byte])
  let readToken = newCancelToken()
  var readDone = default(Event)
  retain(readToken)
  spawnTask cancelSoon(readToken, addr readDone)
  expect(recvInto(addr tls, received, afterMs(2000), readToken) == ECancelled and isReady(addr tls),
         "cancelled application read retains the TLS state")
  expect(wait(addr readDone, afterMs(2000)) == wrReady, "read canceller finished")
  release(readToken)
  expect(recvInto(addr tls, addr received[0], 4) == 4 and received == payload, "receive")
  owner.state.stopWriting = true
  owner.state.writeBudget = 1
  let writeToken = newCancelToken()
  var writeDone = default(Event)
  retain(writeToken)
  spawnTask cancelSoon(writeToken, addr writeDone)
  expect(sendFrom(addr tls, payload, afterMs(2000), writeToken) == ECancelled,
         "partial sealed record cancellation")
  expect(wait(addr writeDone, afterMs(2000)) == wrReady, "write canceller finished")
  release(writeToken)
  expect(sendFrom(addr tls, payload) == ECancelled, "partial record makes later TLS writes fail")
  close(addr tls)
  close(addr tls)
  discard disposeOwner(addr owner.state)
  expect(owner.state.closes == 1 and not owner.state.tcp.isOpen, "owned transport closes once")
  while not finished: parkUntil(afterMs(1))
  discard close(listener)
  var quietListener = listenTcp(0, "127.0.0.1")
  serve(quietListener, quietPeer)
  var handshake = default(TlsStream)
  let handshakeToken = newCancelToken()
  var handshakeDone = default(Event)
  retain(handshakeToken)
  spawnTask cancelSoon(handshakeToken, addr handshakeDone)
  expect(connectTls("127.0.0.1", port(quietListener), addr client, addr handshake,
                    "test.example", tok = handshakeToken) == ECancelled,
         "cancel client handshake waiting for ServerHello")
  expect(wait(addr handshakeDone, afterMs(2000)) == wrReady, "client canceller finished")
  release(handshakeToken)
  close(addr handshake)
  close(addr handshake)
  expect(wait(addr quietFinished, afterMs(2000)) == wrReady, "quiet peer drained")
  discard close(quietListener)
  var cancelListener = listenTcp(0, "127.0.0.1")
  serve(cancelListener, cancelledHandshake)
  var quietClient = connect("127.0.0.1", port(cancelListener))
  expect(quietClient.isOpen, "quiet client connected")
  expect(wait(addr acceptFinished, afterMs(2000)) == wrReady, "server handshake drained")
  close(addr quietClient)
  discard close(cancelListener)
  expect(tlsAlert(TlsEof) == 0 and tlsAlert(TlsTruncated) == 0 and
         tlsAlert(TlsEchRejected) == 0, "statuses are not alerts")
  checkFlushLifetime()
  expect(liveCancelTokens() == baseline, "operation tokens released")
  echo "PASS custom transport: cancellation/reuse, partial-record failure, borrow/transfer and close"
  quit 0

proc textFile(path: string): string =
  try: result = readFile(path)
  except: result = ""
var certs: seq[Cert] = @[]
expect(certsPem(textFile("tests/data/root.pem"), certs) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no roots"
expect(addRoot(roots, certs[0]), "trust root")
expect(loadCertifiedKey(textFile("tests/data/leaf.pem") & textFile("tests/data/inter.pem"),
                        textFile("tests/data/leaf.key"), key) == "", "key")
server = defaultServerConfig()
server.resolver = singleCert(addr key)
client = defaultClientConfig(roots)
initRuntime()
spawnTask main()
drainRuntime()
