## Ending a secured Conn: its own token cancelled from another task, a
## parent token given to connect, and a token cancelled before the
## handshake, on either side, which fails it and closes the connection.
import std/[assertions, syncio]
import zal_net
import zal_tls

type Shared = ref object
  config: ServerConfig
  entered, done, served: Event
  outcome, peerOutcome: ErrorCode
  peerOpen: bool

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc reset(shared: Shared) =
  clearEvent(addr shared.entered)
  clearEvent(addr shared.done)
  clearEvent(addr shared.served)
  shared.outcome = Success
  shared.peerOutcome = Success

proc parkedRead(c: ptr Conn; shared: Shared) {.passive.} =
  var bytes = default(array[4, byte])
  setEvent(addr shared.entered)
  try:
    discard c[].read(bytes, afterMs(5000))
  except ErrorCode as error:
    shared.outcome = error
  setEvent(addr shared.done)

proc peer(listener: ptr Listener; shared: Shared) {.passive.} =
  ## Secure, then read until the client goes. A cancelled client shuts its
  ## socket down without close_notify.
  try:
    var c = accept(listener[], afterMs(5000))
    try:
      c.secure(shared.config, afterMs(5000))
      var bytes = default(array[4, byte])
      discard c.read(bytes, afterMs(5000))
    except ErrorCode as error:
      shared.peerOutcome = error
    shared.peerOpen = c.isOpen
  except ErrorCode as error:
    echo "accept: ", error
  setEvent(addr shared.served)

proc cancelWhileParked(c: var Conn; token: nil CancelToken; shared: Shared) {.passive.} =
  assert trySpawnTask(parkedRead(addr c, shared))
  assert wait(addr shared.entered, afterMs(5000)) == wrReady
  parkUntil(afterMs(30))
  cancel(token)
  assert wait(addr shared.done, afterMs(5000)) == wrReady
  assert shared.outcome == AbortedOperation

proc ownToken(client: ClientConfig; listener: ptr Listener; shared: Shared) {.passive, raises.} =
  reset shared
  assert trySpawnTask(peer(listener, shared))
  var c = connect(client, "127.0.0.1", listener[].port, "test.example", afterMs(5000))
  cancelWhileParked(c, c.cancelToken, shared)
  assert wait(addr shared.served, afterMs(5000)) == wrReady
  assert shared.peerOutcome != Success, "the peer reads a cut stream"

proc parentToken(client: ClientConfig; listener: ptr Listener; shared: Shared) {.passive, raises.} =
  reset shared
  assert trySpawnTask(peer(listener, shared))
  let parent = newCancelToken()
  var c = connect(client, "127.0.0.1", listener[].port, "test.example", afterMs(5000), parent)
  cancelWhileParked(c, parent, shared)
  assert cancelled(c.cancelToken)
  release(parent)
  assert wait(addr shared.served, afterMs(5000)) == wrReady
  assert shared.peerOutcome != Success

proc cancelledFirst(client: ClientConfig; listener: ptr Listener) {.passive, raises.} =
  var c = connect("127.0.0.1", listener[].port, afterMs(5000))
  cancel(c.cancelToken)
  var refused = Success
  try: c.secure(client, "test.example", afterMs(5000))
  except ErrorCode as error: refused = error
  assert refused == AbortedOperation and not c.isOpen and not c.isSecure

proc serverCancelledFirst(shared: Shared) {.passive, raises.} =
  ## The listener's connections end with a token that is already cancelled.
  reset shared
  let ending = newCancelToken()
  cancel(ending)
  var listener = listen(0, "127.0.0.1")
  listener.endConnectionsWith(ending)
  assert trySpawnTask(peer(addr listener, shared))
  var c = connect("127.0.0.1", listener.port, afterMs(5000))
  assert wait(addr shared.served, afterMs(5000)) == wrReady
  assert shared.peerOutcome == AbortedOperation and not shared.peerOpen
  close c
  close listener
  release(ending)

proc main() {.passive.} =
  try:
    let tokens = liveCancelTokens()
    let client = newClientConfig(pemTrust(text("tests/data/root.pem")))
    let shared = Shared(config: newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                                text("tests/data/leaf.key")))
    var listener = listen(0, "127.0.0.1")
    ownToken(client, addr listener, shared)
    parentToken(client, addr listener, shared)
    cancelledFirst(client, addr listener)
    close listener
    serverCancelledFirst(shared)
    assert liveCancelTokens() == tokens, "every connection released its token"
    echo "PASS a secured Conn ends through its token, a parent token, or a token cancelled before the handshake"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
