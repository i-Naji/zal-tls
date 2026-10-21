## A TLS stream dropped without close still ends cleanly for the peer.
import std/[assertions, syncio]
import zal_net/rt, zal_net/rt/sync
import zal_net/rt/cancel as cancellation
import zal_net/net/tcp as tcp
import zal_tls as tls

type Context = ref object
  config: nil tls.ServerConfig
  done: Event
  failure: ErrorCode
  ended: int

proc text(path: string): string =
  try:
    result = readFile(path)
  except:
    result = ""

proc peer(server: sink tcp.TcpListener; ctx: sink Context) {.passive.} =
  try:
    var underlying: nil tcp.TcpStream = server.accept(deadline=afterMs(5000))
    let config = ctx.config
    if config == nil:
      assert false
    else:
      let stream = tls.wrapOwned(config, underlying, deadline=afterMs(5000))
      ctx.config = nil
      defer: stream.close()
      var bytes = default(array[8, byte])
      var got = 0
      while true:
        let count = stream.read(bytes, deadline=afterMs(5000))
        if count == 0: break
        got += count
      ctx.ended = got
  except ErrorCode as error:
    ctx.failure = error
  setEvent(addr ctx.done)

proc dropped(config: tls.ClientConfig; port: uint16) {.passive, raises.} =
  let stream = tls.connect(config, "127.0.0.1", port, serverName="test.example",
                           deadline=afterMs(5000))
  stream.write([1'u8, 2, 3], deadline=afterMs(5000))
  # No close: the last reference goes here.

proc main() {.passive.} =
  try:
    let config = tls.newClientConfig(pemTrust(text("tests/data/root.pem")))
    let ctx = Context()
    ctx.config = tls.newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                     text("tests/data/leaf.key"))
    let server = tcp.listen(0, "127.0.0.1")
    defer: server.close()
    assert trySpawnTask(peer(server, ctx))
    dropped(config, server.port)
    assert wait(addr ctx.done, afterMs(5000)) == wrReady
    assert ctx.failure == Success, "the peer saw close_notify, not a cut stream"
    assert ctx.ended == 3
    assert cancellation.liveCancelTokens() == 0
    echo "PASS a dropped TLS stream sends close_notify"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
