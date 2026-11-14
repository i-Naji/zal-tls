## A secured Conn talking to its peer: a request sent by connect, ALPN on
## both sides, a payload of several records each way, deadlines per call and
## standing ones, and close_notify from close.
import std/[assertions, syncio]
import zal_net
import zal_tls

const Size = 65537

type Shared = ref object
  config: ServerConfig
  done, quiet: Event
  failure: ErrorCode
  protocol, request: string
  ended: bool

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc pattern(n: int): seq[byte] =
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(i mod 251)

proc readAll(c: var Conn; dest: var seq[byte]; start: int) {.passive, raises.} =
  ## Fill `dest` from `start` on.
  var have = start
  while have < dest.len:
    let n = c.read(dest.toOpenArray(have, dest.len - 1), afterMs(5000))
    assert n > 0
    have += n

proc peer(listener: ptr Listener; shared: Shared) {.passive.} =
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(10000)
    c.secure(shared.config)
    shared.protocol = c.negotiatedProtocol
    shared.request = c.readLine()
    c.write "ok\n"
    var payload = newSeq[byte](Size)
    readAll(c, payload, 0)
    c.write payload
    assert wait(addr shared.quiet, afterMs(5000)) == wrReady
    c.write "!\n"
    var rest = default(array[16, byte])
    shared.ended = c.read(rest) == 0
  except ErrorCode as error:
    shared.failure = error
  setEvent(addr shared.done)

proc timesOut(c: var Conn; dl: Deadline): bool {.passive.} =
  var one = default(array[1, byte])
  result = false
  try: discard c.read(one, dl)
  except ErrorCode as error: result = error == TimeoutError

proc writeTimesOut(c: var Conn; dl: Deadline): bool {.passive.} =
  result = false
  try: c.write("x", dl)
  except ErrorCode as error: result = error == TimeoutError

proc exchange(client: ClientConfig; port: uint16; shared: Shared) {.passive, raises.} =
  # The request goes with the handshake and the peer reads it first.
  let request = [byte('G'), byte('E'), byte('T'), byte(' '), byte('/'), byte('\n')]
  var c = connect(client, "127.0.0.1", port, request, "test.example", afterMs(5000))
  assert c.isSecure and c.negotiatedProtocol == "http/1.1"
  assert c.readLine(afterMs(5000)) == "ok"

  # Nothing to send or read is not an error.
  var empty = default(array[0, byte])
  c.write empty
  assert c.read(empty) == 0

  # A deadline that has passed fails the call and leaves the connection usable.
  assert writeTimesOut(c, afterMs(-1))
  let payload = pattern(Size)
  c.write(payload, afterMs(5000))
  var first = default(array[1, byte])
  assert c.read(first, afterMs(5000)) == 1   # the rest of the record waits in the TLS layer
  assert timesOut(c, afterMs(-1))
  var back = newSeq[byte](Size)
  back[0] = first[0]
  readAll(c, back, 1)
  assert back == payload

  # The standing deadline bounds reads and writes until it is renewed.
  c.renew afterMs(100)
  assert timesOut(c, never), "a quiet peer runs into the standing deadline"
  c.renew never
  setEvent(addr shared.quiet)
  assert c.readLine(afterMs(5000)) == "!"
  c.renew afterMs(-1)
  assert writeTimesOut(c, never)
  c.renew never

  # close sends close_notify: the peer reads the end, not a cut stream.
  close c
  close c
  assert not c.isOpen and not c.isSecure and c.negotiatedProtocol == ""

proc main() {.passive.} =
  try:
    let tokens = liveCancelTokens()
    let client = newClientConfig(pemTrust(text("tests/data/root.pem")), @["http/1.1"])
    let shared = Shared(config: newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                                text("tests/data/leaf.key"), @["http/1.1"]),
                        failure: Success)
    var listener = listen(0, "127.0.0.1")
    assert trySpawnTask(peer(addr listener, shared))
    exchange(client, listener.port, shared)
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.failure == Success
    assert shared.protocol == "http/1.1" and shared.request == "GET /" and shared.ended
    close listener
    assert liveCancelTokens() == tokens, "every connection released its token"
    echo "PASS a secured Conn: a request with the handshake, ALPN, many records, deadlines, close_notify on close"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
