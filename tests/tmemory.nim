## Native-heap ownership regression. LSan cannot see live cells in the native
## allocator's retained mappings. Measure this calling thread's occupied bytes,
## not RSS or reserved pages; crypto/C allocations still require sanitizer tests.
import std/[assertions, syncio]
import zal_net/buffers
import zal_tls/common
import zal_tls/config/config
import zal_tls/crypto/x509
import zal_tls/record as records
import zal_tls/handshake as handshakes

const FlightCapacity = 16 * 1024

type
  Input = object
    bytes: array[FlightCapacity, byte]
    used: int
  RecordPeer = object
    conn: records.TlsConn
    input: Input
    failed: bool
  HandshakePeer = object
    conn: handshakes.Handshake
    input: array[4, Input]
    ready, failed: bool

proc append(input: var Input; data: Bytes; size: int) =
  assert size >= 0 and size <= input.bytes.len - input.used
  if size > 0:
    copyMem(addr input.bytes[input.used], data, size)
    input.used = input.used + size

proc consume(input: var Input; size: int) =
  assert size >= 0 and size <= input.used
  input.used = input.used - size
  if input.used > 0: moveMem(addr input.bytes[0], addr input.bytes[size], input.used)

proc recordTurn(peer: ptr RecordPeer; destination: ptr RecordPeer) =
  var output = default(array[FlightCapacity, byte])
  var status = default(StepResult)
  let event = records.step(addr peer.conn, ptrOf(peer.input.bytes), peer.input.used,
                           ptrOf(output), output.len, status)
  consume(peer.input, status.consumed)
  append(destination.input, ptrOf(output), status.outLen)
  if event == stFailed: peer.failed = true

proc recordCycle(client: ClientConfigPtr; server: ServerConfigPtr; reject: bool) =
  var a = default(RecordPeer)
  var b = default(RecordPeer)
  records.release(addr a.conn)
  assert records.initClient(addr a.conn, client,
    if reject: "wrong.example" else: "test.example")
  assert records.initServer(addr b.conn, server)
  var turns = 0
  while not a.failed and not b.failed and
        (not records.isReady(addr a.conn) or not records.isReady(addr b.conn)):
    assert turns < 128
    recordTurn(addr a, addr b)
    recordTurn(addr b, addr a)
    turns = turns + 1
  if reject: assert a.failed
  else: assert records.isReady(addr a.conn) and records.isReady(addr b.conn)
  records.release(addr a.conn)
  records.release(addr b.conn)
  records.release(addr a.conn)
  records.release(addr b.conn)

proc handshakeTurn(peer: ptr HandshakePeer; destination: ptr HandshakePeer) =
  var index = 0
  while index < peer.input.len and peer.input[index].used == 0: index = index + 1
  if index == peer.input.len: index = 0
  let level = handshakes.EncryptionLevel(index)
  var output = default(array[FlightCapacity, byte])
  var status = default(handshakes.HandshakeResult)
  let event = handshakes.step(addr peer.conn, level,
    ptrOf(peer.input[index].bytes), peer.input[index].used,
    ptrOf(output), output.len, status)
  consume(peer.input[index], status.consumed)
  case event
  of handshakes.heOutput:
    append(destination.input[ord(status.level)], ptrOf(output), status.dataLen)
  of handshakes.heComplete: peer.ready = true
  of handshakes.heFailed: peer.failed = true
  of handshakes.heOutputBlocked: assert false
  else: discard
  handshakes.clear(status) # every exported secret copy is wiped

proc handshakeCycle(client: ClientConfigPtr; server: ServerConfigPtr;
                    mode: handshakes.HandshakeMode; reject: bool) =
  var a = default(HandshakePeer)
  var b = default(HandshakePeer)
  var parameters = [1'u8, 1, 5]
  let options = handshakes.HandshakeOptions(mode: mode,
    applicationContext: "memory-test/v1", transportParameters: view(parameters))
  assert handshakes.initClient(addr a.conn, client,
    if reject: "wrong.example" else: "test.example", options)
  assert handshakes.initServer(addr b.conn, server, options)
  var turns = 0
  while not a.failed and not b.failed and (not a.ready or not b.ready):
    assert turns < 256
    handshakeTurn(addr a, addr b)
    handshakeTurn(addr b, addr a)
    turns = turns + 1
  if reject: assert a.failed
  else: assert a.ready and b.ready
  handshakes.release(addr a.conn)
  handshakes.release(addr b.conn)
  handshakes.release(addr a.conn)
  handshakes.release(addr b.conn)

proc partialCycle(client: ClientConfigPtr; server: ServerConfigPtr) =
  var a = default(handshakes.Handshake)
  var b = default(handshakes.Handshake)
  let invalid = handshakes.HandshakeOptions(maxQueuedBytes: 1,
    applicationContext: "memory-test/v1")
  # These fail after the shared TLS state was initialized.
  assert not handshakes.initClient(addr a, client, "test.example", invalid)
  assert not handshakes.initServer(addr b, server, invalid)
  handshakes.release(addr a)
  handshakes.release(addr b)
  handshakes.release(addr a)
  handshakes.release(addr b)

proc cycles(client: ClientConfigPtr; server: ServerConfigPtr; count: int) =
  for i in 0 ..< count:
    recordCycle(client, server, false)
    recordCycle(client, server, true)
    handshakeCycle(client, server, handshakes.handshakeTls, false)
    handshakeCycle(client, server, handshakes.handshakeTls, true)
    handshakeCycle(client, server, handshakes.handshakeQuic, false)
    partialCycle(client, server)

proc readText(path: string): string =
  try: result = readFile(path)
  except: quit "missing fixture"

when defined(nimNativeAlloc):
  proc counterProbe(): int =
    var bytes = newSeq[byte](8192)
    bytes[0] = 1
    result = getOccupiedMem()
    assert bytes[0] == 1
  let initial = getOccupiedMem()
  assert counterProbe() > initial
  assert getOccupiedMem() == initial

var certificates: seq[Cert] = @[]
assert certsPem(readText("tests/data/root.pem"), certificates) == 1
let roots = newRoots()
assert roots != nil and addRoot(roots, certificates[0])
var key = default(CertifiedKey)
assert loadCertifiedKey(readText("tests/data/leaf.pem") & readText("tests/data/inter.pem"),
                        readText("tests/data/leaf.key"), key) == ""
var client = defaultClientConfig(roots)
var server = defaultServerConfig()
client.alpn = @["h3"]
server.alpn = @["h3"]
server.resolver = singleCert(addr key)
cycles(addr client, addr server, 16)
when defined(nimNativeAlloc):
  let baseline = getOccupiedMem()
  var samples = default(array[4, int])
  for batch in 0 ..< 4:
    cycles(addr client, addr server, 32)
    let occupied = getOccupiedMem()
    samples[batch] = occupied
    assert occupied == baseline
  # Formatting temporaries in the module frame can live until program exit.
  # Print only after all occupancy snapshots, so observation cannot perturb them.
  for sample in samples:
    echo "native occupied bytes: ", sample, " (baseline ", baseline, ")"
else:
  cycles(addr client, addr server, 128)
  echo "SKIP per-thread occupied-byte assertion: native allocator not selected"
release(key)
release(roots)
for certificate in certificates: release(certificate)
echo "PASS record/handshake success, rejection, partial-init and repeated-release cycles"
