import std/[assertions, syncio]
import zal_net
import zal_tls

type Shared = ref object
  done: Event
  config: ServerConfig
  inner: ServerConfig
  lines: int
  protocol: string
  sawEnd: bool

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc echoLines(c: var Conn; shared: Shared) {.passive, raises.} =
  while true:
    let line = c.readLine()
    if line.len == 0: break
    c.write "echo " & line & "\n"
    inc shared.lines
  shared.sawEnd = true
  c.shutdownWrite()

proc serveOne(listener: ptr Listener; shared: Shared; layers: int) {.passive.} =
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    c.secure(shared.config)
    if layers == 2: c.secure(shared.inner)
    shared.protocol = c.negotiatedProtocol
    echoLines(c, shared)
  except ErrorCode as error:
    echo "server: ", error
  setEvent(addr shared.done)

proc readToEnd(listener: ptr Listener; shared: Shared) {.passive.} =
  ## Reads until the peer is gone. The client drops its connection without
  ## a half-close, and this side must still see the end at once.
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    c.secure(shared.config)
    while c.readLine().len > 0: inc shared.lines
    shared.sawEnd = true
  except ErrorCode as error:
    echo "server: ", error
  setEvent(addr shared.done)

proc reset(shared: Shared) =
  clearEvent(addr shared.done)
  shared.lines = 0
  shared.sawEnd = false
  shared.protocol = ""

proc sayAndDrop(config: ClientConfig; port: uint16) {.passive, raises.} =
  var gone = connect(config, "127.0.0.1", port, "test.example", afterMs(5000))
  gone.write "last\n"

proc main() {.passive.} =
  try:
    let roots = pemTrust(text("tests/data/root.pem"))
    let chain = text("tests/data/leaf.pem") & text("tests/data/inter.pem")
    let key = text("tests/data/leaf.key")
    let clientConfig = newClientConfig(roots)
    let shared = Shared(config: newServerConfig(chain, key),
                        inner: newServerConfig(chain, key, @["h2", "echo"]))
    var listener = listen(0, "127.0.0.1")

    # Secure an existing connection.
    assert trySpawnTask(serveOne(addr listener, shared, 1))
    var c = connect("127.0.0.1", listener.port, afterMs(5000))
    c.renew afterMs(5000)
    assert not c.isSecure
    c.secure(clientConfig, "test.example")
    assert c.isSecure and c.negotiatedProtocol == ""
    c.write "one\n"
    assert c.readLine() == "echo one"
    c.write "two\n"
    assert c.readLine() == "echo two"
    c.shutdownWrite()
    assert c.fill() == 0                 # the server's close_notify
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.lines == 2
    close c

    # Connect and handshake in one call; TLS inside TLS with ALPN on the inner one.
    reset shared
    assert trySpawnTask(serveOne(addr listener, shared, 2))
    let innerClient = newClientConfig(roots, @["echo"])
    var t = connect(clientConfig, "127.0.0.1", listener.port, "test.example", afterMs(5000))
    t.secure(innerClient, "test.example")
    assert t.negotiatedProtocol == "echo"
    t.write "three\n"
    assert t.readLine() == "echo three"
    t.shutdownWrite()
    assert t.fill() == 0
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.lines == 1 and shared.protocol == "echo"
    close t

    # A connection dropped without a half-close ends the peer's read.
    reset shared
    assert trySpawnTask(readToEnd(addr listener, shared))
    sayAndDrop(clientConfig, listener.port)
    assert wait(addr shared.done, afterMs(2000)) == wrReady
    assert shared.lines == 1 and shared.sawEnd

    # The wrong name fails the handshake and closes the connection.
    var failed = false
    var d = connect("127.0.0.1", listener.port, afterMs(5000))
    try: d.secure(clientConfig, "other.example", afterMs(500))
    except ErrorCode: failed = true
    assert failed and not d.isOpen
    close listener
    echo "PASS TLS on a Conn: lines both ways, close_notify, TLS inside TLS, ALPN, a dropped peer, a refused name"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
