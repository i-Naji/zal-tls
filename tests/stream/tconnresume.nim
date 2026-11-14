## Resumption and 0-RTT on a Conn. The first connection stores the server's
## ticket while it reads; the next one resumes and sends its request as
## 0-RTT, which the server reads first and counts in `earlyBytes`. A server
## that takes no 0-RTT still reads the request once, after the handshake.
import std/[assertions, syncio]
import zal_net
import zal_tls

type Shared = ref object
  config: ServerConfig
  done: Event
  failure: ErrorCode
  resumed: bool
  early: int
  request: string

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc echoOne(listener: ptr Listener; shared: Shared) {.passive.} =
  ## Answer the first line with itself, then read to the end.
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    c.secure(shared.config)
    shared.resumed = c.resumed
    shared.early = c.earlyBytes
    shared.request = c.readLine()
    c.write shared.request & "\n"
    c.shutdownWrite()
    while c.readLine().len > 0: discard
  except ErrorCode as error:
    shared.failure = error
  setEvent(addr shared.done)

proc bytesOf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

proc ask(client: ClientConfig; listener: ptr Listener; shared: Shared;
         line: string; asRequest: bool): bool {.passive, raises.} =
  ## One exchange; whether the client resumed.
  clearEvent(addr shared.done)
  shared.failure = Success
  assert trySpawnTask(echoOne(listener, shared))
  let port = listener[].port
  var c = if asRequest: connect(client, "127.0.0.1", port, bytesOf(line & "\n"), "test.example", afterMs(5000))
          else: connect(client, "127.0.0.1", port, "test.example", afterMs(5000))
  c.renew afterMs(5000)
  if not asRequest: c.write line & "\n"
  assert c.readLine() == line
  assert c.readLine() == "" and c.buffered == 0
  result = c.resumed
  c.shutdownWrite()
  assert wait(addr shared.done, afterMs(5000)) == wrReady
  assert shared.failure == Success and shared.request == line

proc main() {.passive.} =
  try:
    let shared = Shared(config: newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                                text("tests/data/leaf.key")))
    assert shared.config.issueTickets(maxEarlyData = 16384)
    let client = newClientConfig(pemTrust(text("tests/data/root.pem")))
    client.keepSessions(earlyData = true)
    var listener = listen(0, "127.0.0.1")

    # A full handshake; the ticket arrives while the client reads.
    assert not ask(client, addr listener, shared, "first", false)
    assert not shared.resumed and shared.early == 0

    # Resumed, the request as 0-RTT: the server reads it first and knows it.
    assert ask(client, addr listener, shared, "GET /early", true)
    assert shared.resumed and shared.early == "GET /early\n".len

    # A server that takes no 0-RTT: the request goes after the handshake, once.
    assert shared.config.issueTickets(maxEarlyData = 0)
    assert ask(client, addr listener, shared, "GET /late", true)
    assert shared.resumed and shared.early == 0

    close listener
    echo "PASS resumption and 0-RTT on a Conn: a ticket stored, resumed, the request as 0-RTT, refused 0-RTT sent once"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
