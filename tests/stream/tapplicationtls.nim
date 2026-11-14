## Application API: validated configs, transfer, custom transport and I/O errors.
import std/[assertions, syncio]
import zal_net/rt, zal_net/rt/sync
import zal_net/rt/cancel as cancellation
import zal_net/net/tcp as tcp
import zal_net/net/[tcpview, transport]
import zal_tls as tls

type Context = ref object
  config: nil tls.ServerConfig
  done: Event
  failure: ErrorCode

proc text(path: string): string =
  try:
    result = readFile(path)
  except:
    result = ""

proc countedDeadline(calls: var int): Deadline =
  inc calls
  afterMs(5000)

proc countedToken(calls: var int; token: CancelToken): CancelToken =
  inc calls
  token

proc echoPeer(server: sink tcp.TcpListener; ctx: sink Context) {.passive.} =
  try:
    var underlying: nil tcp.TcpStream = server.accept(deadline=afterMs(5000))
    let config = ctx.config
    if config == nil:
      assert false
    else:
      let stopped = cancellation.newCancelToken()
      cancellation.cancel(stopped)
      try:
        discard tls.wrapOwned(config, underlying, cancel=stopped)
        assert false
      except ErrorCode as error:
        assert error == AbortedOperation and underlying != nil
      cancellation.release(stopped)
      let stream = tls.wrapOwned(config, underlying, deadline=afterMs(5000))
      assert underlying == nil
      ctx.config = nil
      defer: stream.close()
      var bytes = default(array[8, byte])
      assert stream.read(bytes, deadline=afterMs(5000)) == 1
      assert bytes[0] == 73
      stream.write(bytes.toOpenArray(0, 0), deadline=afterMs(5000))
      # Cross several TLS records; one full write owns one fixed deadline/token.
      var payload = newSeq[byte](65537)
      var received = 0
      while received < payload.len:
        let count = stream.read(payload.toOpenArray(received, payload.len - 1),
                                deadline=afterMs(5000))
        assert count > 0
        received += count
      for i in 0..<payload.len:
        assert payload[i] == byte(i mod 251)
      var deadlineCalls = 0
      stream.write(payload, deadline=countedDeadline(deadlineCalls))
      assert deadlineCalls == 1
      stream.shutdownWrite()
  except ErrorCode as error:
    ctx.failure = error
  setEvent(addr ctx.done)

proc exchange(config: tls.ClientConfig; mode: int) {.passive, raises.} =
  let ctx = Context()
  ctx.config = tls.newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                   text("tests/data/leaf.key"), alpn = @["http/1.1"])
  let server = tcp.listen(0, "127.0.0.1")
  defer: server.close()
  assert trySpawnTask(echoPeer(server, ctx))
  var stream: nil tls.TlsStream = nil
  var underlying: nil tcp.TcpStream = nil
  if mode == 0:
    stream = tls.connect(config, "127.0.0.1", server.port,
                         serverName="test.example", deadline=afterMs(5000))
  else:
    underlying = tcp.connect("127.0.0.1", server.port, deadline=afterMs(5000))
    let retained = underlying
    if retained == nil:
      assert false
    else:
      if mode == 1:
        stream = tls.wrapBorrowed(config, retained, "test.example", deadline=afterMs(5000))
      elif mode == 2:
        stream = tls.wrapOwned(config, underlying, "test.example", deadline=afterMs(5000))
        assert underlying == nil
      else:
        let view = tcpTransport(retained)
        if mode == 3:
          stream = tls.wrapBorrowed(config, view, "test.example", deadline=afterMs(5000))
          assert view.isOpen
        else:
          stream = tls.wrapOwned(config, view, "test.example", deadline=afterMs(5000))
          assert not view.isOpen
  let connected = stream
  if connected == nil:
    assert false
  else:
    defer: connected.close()
    let protocol = connected.negotiatedProtocol()
    assert protocol == "http/1.1"
    var bytes = [73'u8]
    let stopped = cancellation.newCancelToken()
    cancellation.cancel(stopped)
    try:
      discard connected.read(bytes, cancel=stopped)
      assert false
    except ErrorCode as error:
      assert error == AbortedOperation
      assert connected.lastReadFailure.code == ECancelled
    cancellation.release(stopped)
    try:
      connected.write(bytes, deadline=afterMs(-1))
      assert false
    except ErrorCode as error: assert error == TimeoutError
    connected.write(bytes, deadline=afterMs(5000))
    assert connected.lastWriteFailure.code == 0
    assert connected.lastWriteFailure.transferred == 1
    var empty = default(array[0, byte])
    connected.write(empty)
    assert connected.read(empty) == 0
    assert connected.read(bytes, deadline=afterMs(5000)) == 1 and bytes[0] == 73
    var payload = newSeq[byte](65537)
    for i in 0..<payload.len:
      payload[i] = byte(i mod 251)
    let writeToken = cancellation.newCancelToken()
    defer: cancellation.release(writeToken)
    var deadlineCalls, tokenCalls = 0
    connected.write(payload, deadline=countedDeadline(deadlineCalls),
                    cancel=countedToken(tokenCalls, writeToken))
    echo "TLS multi-record arguments: deadlines=", deadlineCalls, " tokens=", tokenCalls
    assert deadlineCalls == 1 and tokenCalls == 1
    assert connected.lastWriteFailure.transferred == payload.len
    assert connected.read(payload.toOpenArray(0, 0), deadline=afterMs(5000)) == 1
    try:
      discard connected.read(bytes, deadline=afterMs(-1))
      assert false
    except ErrorCode as error: assert error == TimeoutError
    var received = 1
    while received < payload.len:
      let count = connected.read(payload.toOpenArray(received, payload.len - 1),
                                 deadline=afterMs(5000))
      assert count > 0
      received += count
    for i in 0..<payload.len:
      assert payload[i] == byte(i mod 251)
    assert connected.read(bytes, deadline=afterMs(5000)) == 0
    connected.close()
    connected.close()
    assert protocol == "http/1.1" # Caller-owned metadata survives connection cleanup.
    try:
      discard connected.negotiatedProtocol()
      assert false
    except ErrorCode as error:
      assert error == DeadResource
    try:
      connected.write(empty)
      assert false
    except ErrorCode as error:
      assert error == DeadResource
  let borrowed = underlying
  if borrowed != nil:
    borrowed.close()
  assert wait(addr ctx.done, afterMs(5000)) == wrReady
  assert ctx.failure == Success

proc rejectName(config: tls.ClientConfig) {.passive, raises.} =
  let ctx = Context()
  ctx.config = tls.newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                 text("tests/data/leaf.key"), alpn = @["http/1.1"])
  let server = tcp.listen(0, "127.0.0.1")
  defer: server.close()
  assert trySpawnTask(echoPeer(server, ctx))
  var underlying: nil tcp.TcpStream = tcp.connect("127.0.0.1", server.port)
  try:
    discard tls.wrapOwned(config, underlying, "wrong.example", deadline=afterMs(5000))
    assert false
  except ErrorCode as error:
    assert error == ProtocolError
    assert underlying == nil
  assert wait(addr ctx.done, afterMs(5000)) == wrReady
  assert ctx.failure != Success

proc main() {.passive.} =
  try:
    try:
      discard tls.newClientConfig(pemTrust(""))
      assert false
    except ErrorCode as error:
      assert error == ValueError
    let config = tls.newClientConfig(pemTrust(text("tests/data/root.pem")), alpn = @["http/1.1"])
    for mode in 0..<5:
      exchange(config, mode)
    rejectName(config)
    assert cancellation.liveCancelTokens() == 0
    echo "PASS application TLS: direct, borrowed, transferred and custom streams"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
