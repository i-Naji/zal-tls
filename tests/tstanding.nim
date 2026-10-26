## A first request sent by connect, and a standing deadline on TLS streams.
import std/[assertions, syncio]
import zal_net/rt, zal_net/rt/sync
import zal_net/rt/cancel as cancellation
import zal_net/net/tcp as nettcp
import zal_tls as tls

type Context = ref object
  config: nil tls.ServerConfig
  done, quiet: Event
  failure: ErrorCode

proc text(path: string): string =
  try:
    result = readFile(path)
  except:
    result = ""

proc peer(server: sink nettcp.TcpListener; ctx: sink Context) {.passive.} =
  ## Reads the request, answers it, then stays quiet until told to go on.
  try:
    var underlying: nil nettcp.TcpStream = server.accept(deadline=afterMs(5000))
    let config = ctx.config
    if config == nil:
      assert false
    else:
      let stream = tls.wrapOwned(config, underlying, deadline=afterMs(5000))
      ctx.config = nil
      defer: stream.close()
      var bytes = default(array[16, byte])
      var got = 0
      while got < 5:
        let count = stream.read(bytes.toOpenArray(got, bytes.len - 1), deadline=afterMs(5000))
        assert count > 0
        got += count
      assert got == 5 and bytes[0] == byte('h') and bytes[4] == byte('o'), "the request came first"
      stream.write([byte('o'), byte('k')], deadline=afterMs(5000))
      assert wait(addr ctx.quiet, afterMs(5000)) == wrReady
      stream.write([byte('!')], deadline=afterMs(5000))
  except ErrorCode as error:
    ctx.failure = error
  setEvent(addr ctx.done)

proc exercise(config: tls.ClientConfig) {.passive, raises.} =
  let ctx = Context()
  ctx.config = tls.newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                   text("tests/data/leaf.key"))
  let server = nettcp.listen(0, "127.0.0.1")
  defer: server.close()
  assert trySpawnTask(peer(server, ctx))
  let request = [byte('h'), byte('e'), byte('l'), byte('l'), byte('o')]
  let stream = tls.connect(config, "127.0.0.1", server.port, request,
                           serverName="test.example", deadline=afterMs(5000))
  defer: stream.close()
  var bytes = default(array[2, byte])
  var got = 0
  while got < 2:
    let count = stream.read(bytes.toOpenArray(got, 1), deadline=afterMs(5000))
    assert count > 0
    got += count
  assert bytes[0] == byte('o') and bytes[1] == byte('k'), "the answer to the request"

  assert stream.deadline == never
  stream.renew(afterMs(100))
  try:
    discard stream.read(bytes)
    assert false, "a quiet peer must time out"
  except ErrorCode as error:
    assert error == TimeoutError, "the standing deadline expires the read"
  stream.renew(never)
  setEvent(addr ctx.quiet)
  assert stream.read(bytes, deadline=afterMs(5000)) == 1 and bytes[0] == byte('!'),
    "the stream is usable after the timeout"
  stream.renew(afterMs(-1))
  try:
    stream.write(bytes)
    assert false
  except ErrorCode as error:
    assert error == TimeoutError, "the standing deadline bounds writes"
  stream.renew(never)
  assert wait(addr ctx.done, afterMs(5000)) == wrReady
  assert ctx.failure == Success

proc main() {.passive.} =
  try:
    let config = tls.newClientConfig(pemTrust(text("tests/data/root.pem")))
    exercise(config)
    assert cancellation.liveCancelTokens() == 0
    echo "PASS TLS connect with a request, standing deadline on reads and writes"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
