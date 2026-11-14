import std/[assertions, syncio]
import zal_net/rt
import zal_net/rt/sync
import zal_tls as tls
import zal_tls/secure

type Shared = ref object
  done: Event
  config: tls.ServerConfig
  lines: int

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc serve(listener: ptr Listener; shared: Shared) {.passive.} =
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    c.secure(shared.config)
    while true:
      let line = c.readLine()
      if line.len == 0: break
      c.write "echo " & line & "\n"
      inc shared.lines
    c.shutdownWrite()
  except ErrorCode as error:
    echo "server: ", error
  setEvent(addr shared.done)

proc main() {.passive.} =
  try:
    let clientConfig = tls.newClientConfig(tls.pemTrust(text("tests/data/root.pem")))
    let shared = Shared(config: tls.newServerConfig(
      text("tests/data/leaf.pem") & text("tests/data/inter.pem"), text("tests/data/leaf.key")))
    var listener = listen(0, "127.0.0.1")
    assert trySpawnTask(serve(addr listener, shared))

    var c = connect("127.0.0.1", listener.port, afterMs(5000))
    c.renew afterMs(5000)
    c.secure(clientConfig, "test.example")
    c.write "one\n"
    assert c.readLine() == "echo one"
    c.write "two\n"
    assert c.readLine() == "echo two"
    c.shutdownWrite()
    assert c.fill() == 0                 # the server's close_notify
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.lines == 2
    close c

    # The wrong name fails the handshake and closes the connection.
    var failed = false
    var d = connect("127.0.0.1", listener.port, afterMs(5000))
    try: d.secure(clientConfig, "other.example", afterMs(500))
    except ErrorCode: failed = true
    assert failed and not d.isOpen
    close listener
    echo "PASS TLS on a Conn: handshake, lines both ways, close_notify, a refused name"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
