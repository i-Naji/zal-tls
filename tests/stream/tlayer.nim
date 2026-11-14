## TLS over a layer of the program's own. Both ends install a layer that
## passes at most 7 bytes per read and 11 per write and counts them, then
## `secure` goes on top: the records cross it in pieces, each side's count
## matches the other's, and the layer is released once, also after a
## handshake that fails.
import std/[assertions, syncio]
import zal_net
import zal_net/raw/tcp as rawtcp
import zal_tls

type
  Meter = object
    tcp: rawtcp.TcpStream
    received, sent, releases: int
  MeterPtr = ptr Meter

proc meterRecv(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let m = cast[MeterPtr](ctx)
  result = recvInto(addr m.tcp, buf, min(count, 7), until, tok)
  if result > 0: m.received += result

proc meterSend(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let m = cast[MeterPtr](ctx)
  result = sendFrom(addr m.tcp, buf, min(count, 11), until, tok)
  if result > 0: m.sent += result

proc meterShutdown(ctx: pointer) {.nimcall.} =
  let m = cast[MeterPtr](ctx)
  shutdownWrite(addr m.tcp)

proc meterInterrupt(ctx: pointer) {.nimcall.} =
  let m = cast[MeterPtr](ctx)
  interrupt(addr m.tcp)

proc meterRelease(ctx: pointer) {.nimcall.} =
  ## The layer owns the socket: it closes it here. The counts stay for the test.
  let m = cast[MeterPtr](ctx)
  close(addr m.tcp)
  inc m.releases

let meterOps = StreamOps(recv: meterRecv, send: meterSend,
                         shutdownWrite: meterShutdown, interrupt: meterInterrupt)

proc newMeter(): MeterPtr = cast[MeterPtr](alloc0(sizeof(Meter)))

proc meter(c: var Conn; m: MeterPtr) =
  var fd = releaseDescriptor(c)
  assert adoptTcp(addr m.tcp, fd, 0)
  install(c, m, unsafeAddr meterOps, meterRelease)

type Shared = ref object
  config: ServerConfig
  done: Event
  failure: ErrorCode
  server: MeterPtr
  lines: int

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc echoLines(listener: ptr Listener; shared: Shared) {.passive.} =
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    meter(c, shared.server)
    c.secure(shared.config)
    while true:
      let line = c.readLine()
      if line.len == 0: break
      c.write "echo " & line & "\n"
      inc shared.lines
    c.shutdownWrite()
    assert c.readLine() == ""
  except ErrorCode as error:
    shared.failure = error
  setEvent(addr shared.done)

proc refuse(listener: ptr Listener; shared: Shared) {.passive.} =
  ## The server's half of a handshake the client refuses.
  try:
    var c = accept(listener[], afterMs(5000))
    meter(c, shared.server)
    c.secure(shared.config, afterMs(5000))
  except ErrorCode as error:
    shared.failure = error
  setEvent(addr shared.done)

proc talk(client: ClientConfig; listener: ptr Listener; shared: Shared; mine: MeterPtr) {.passive, raises.} =
  var c = connect("127.0.0.1", listener[].port, afterMs(5000))
  c.renew afterMs(5000)
  meter(c, mine)
  c.secure(client, "test.example")
  assert c.isSecure
  let long = newString(3000)
  for line in ["one", "two", long]:
    c.write line & "\n"
    assert c.readLine() == "echo " & line
  c.shutdownWrite()
  assert c.readLine() == "" and c.buffered == 0
  assert wait(addr shared.done, afterMs(5000)) == wrReady
  close c
  assert mine.releases == 1
  close c
  assert mine.releases == 1, "a second close releases nothing"

proc main() {.passive.} =
  try:
    let client = newClientConfig(pemTrust(text("tests/data/root.pem")))
    let shared = Shared(config: newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                                text("tests/data/leaf.key")),
                        failure: Success, server: newMeter())
    var listener = listen(0, "127.0.0.1")

    # Lines both ways over the layer, and the bytes it moved.
    let mine = newMeter()
    assert trySpawnTask(echoLines(addr listener, shared))
    talk(client, addr listener, shared, mine)
    assert shared.failure == Success and shared.lines == 3
    assert shared.server.releases == 1
    assert mine.sent > 3000 and mine.received > 3000
    assert mine.sent == shared.server.received and mine.received == shared.server.sent,
      "every byte went through both layers"
    dealloc(mine)
    dealloc(shared.server)

    # A refused name fails the handshake; the layer goes with the connection.
    let refused = newMeter()
    shared.server = newMeter()
    clearEvent(addr shared.done)
    assert trySpawnTask(refuse(addr listener, shared))
    var failure = Success
    block:
      var c = connect("127.0.0.1", listener.port, afterMs(5000))
      meter(c, refused)
      try: c.secure(client, "other.example", afterMs(5000))
      except ErrorCode as error: failure = error
      assert not c.isOpen and refused.releases == 1
    assert failure == ProtocolError
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.failure == ProtocolError and shared.server.releases == 1
    dealloc(refused)
    dealloc(shared.server)

    close listener
    echo "PASS TLS over a layer of the program's own: records in pieces, every byte counted, one release, a refused handshake"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
