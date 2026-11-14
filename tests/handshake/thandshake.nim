## The public handshake-only interface: fragmented messages, bounded output,
## key transitions, authentication, and QUIC rules without a TLS record layer.
import std/[assertions, syncio]
import zal_net/buffers
import zal_tls/handshake
import zal_tls/config/config
import zal_tls/common
import zal_tls/crypto/[x509, kx]
import zal_tls/wire/consts

type
  Flight = object
    level: EncryptionLevel
    data: seq[byte]
  Side = object
    h: Handshake
    tx, rx: array[4, Secret]
    ready, resumed: bool
    early: EarlyDecision
    failed: int
    limited: bool
    parameters: seq[byte]

proc readText(path: string): string =
  try: result = readFile(path)
  except: quit "missing fixture"

proc turn(s: ptr Side; incoming, outgoing: var seq[Flight]; chunk, room: int): bool =
  var input = default(array[4096, byte])
  var output = default(array[4096, byte])
  var level = levelInitial
  var count = 0
  if incoming.len > 0:
    level = incoming[0].level
    count = min(chunk, incoming[0].data.len)
    for i in 0 ..< count: input[i] = incoming[0].data[i]
  var r = default(HandshakeResult)
  let event = step(addr s.h, level, ptrOf(input), count, ptrOf(output), room, r)
  if r.consumed > 0:
    var rest: seq[byte] = @[]
    for i in r.consumed ..< incoming[0].data.len: rest.add incoming[0].data[i]
    incoming[0].data = rest
    if rest.len == 0:
      var flights: seq[Flight] = @[]
      for i in 1 ..< incoming.len: flights.add incoming[i]
      incoming = flights
  result = r.consumed > 0 or event != heNeedInput
  case event
  of heOutput:
    if r.level != levelInitial: assert s.tx[ord(r.level)].n > 0
    if outgoing.len == 0 or outgoing[outgoing.len - 1].level != r.level:
      outgoing.add Flight(level: r.level, data: @[])
    for i in 0 ..< r.dataLen: outgoing[outgoing.len - 1].data.add output[i]
  of heSecret:
    assert r.secret.n > 0
    if r.forRead: s.rx[ord(r.level)] = r.secret
    else: s.tx[ord(r.level)] = r.secret
  of hePeerParameters:
    for i in 0 ..< r.dataLen: s.parameters.add output[i]
  of heEarlyData:
    s.early = r.early
  of heComplete:
    s.ready = true
    s.resumed = r.resumed
  of heFailed:
    s.failed = r.alert
    s.limited = r.queueLimitExceeded
  else: discard
  clear(r)

proc run(a, b: ptr Side; ab, ba: var seq[Flight]; chunk, room: int) =
  var idle = 0
  var count = 0
  while idle < 3 and count < 100000 and a.failed == 0 and b.failed == 0:
    count = count + 1
    var moved = turn(a, ba, ab, chunk, room)
    if turn(b, ab, ba, chunk, room): moved = true
    if moved: idle = 0
    else: idle = idle + 1
  assert count < 100000

proc dispose(s: var Side) =
  release(addr s.h)
  release(addr s.h)
  for i in 0 ..< 4:
    wipe(s.tx[i])
    wipe(s.rx[i])

var rootsPem: seq[Cert] = @[]
assert certsPem(readText("tests/data/root.pem"), rootsPem) == 1
let roots = newRoots()
assert roots != nil and addRoot(roots, rootsPem[0])
var key = default(CertifiedKey)
assert loadCertifiedKey(readText("tests/data/leaf.pem") & readText("tests/data/inter.pem"),
                        readText("tests/data/leaf.key"), key) == ""
var client = defaultClientConfig(roots)
client.alpn = @["h3"]
var server = defaultServerConfig()
server.alpn = @["h3"]
server.resolver = singleCert(addr key)
var a, b: Side
var ab, ba: seq[Flight]
var parametersA = [0x01'u8, 0x01, 0x05]
var parametersB = [0x01'u8, 0x01, 0x06]
for mode in [handshakeTls, handshakeQuic]:
  a = default(Side)
  b = default(Side)
  ab = @[]
  ba = @[]
  let optionsA = HandshakeOptions(mode: mode, applicationContext: "test/v1", transportParameters: view(parametersA))
  let optionsB = HandshakeOptions(mode: mode, applicationContext: "test/v1", transportParameters: view(parametersB))
  assert initClient(addr a.h, addr client, "test.example", optionsA)
  assert initServer(addr b.h, addr server, optionsB)
  # Generation may proceed, but zero output space cannot consume the queued CH.
  var dummy = [0'u8]
  var r = default(HandshakeResult)
  assert step(addr a.h, levelInitial, ptrOf(dummy), 0, ptrOf(dummy), 0, r) == heOutputBlocked
  assert r.consumed == 0 and r.dataLen == 0
  run(addr a, addr b, ab, ba, 1, 3)
  assert a.ready and b.ready and a.failed == 0 and b.failed == 0
  assert isComplete(addr a.h) and isComplete(addr b.h)
  assert alpn(addr a.h) == "h3" and alpn(addr b.h) == "h3"
  for level in [levelHandshake, levelApplication]:
    assert a.tx[ord(level)] == b.rx[ord(level)]
    assert a.rx[ord(level)] == b.tx[ord(level)]
  if mode == handshakeQuic:
    assert a.parameters == @parametersB and b.parameters == @parametersA
    var keyUpdate = [24'u8, 0, 0, 1, 0]
    assert step(addr a.h, levelApplication, ptrOf(keyUpdate), 5, ptrOf(dummy), 1, r) == heFailed
    assert r.alert == alUnexpectedMessage
  dispose(a)
  dispose(b)
echo "PASS record-free handshakes, one-byte input, three-byte output, secret transitions, QUIC parameters and KeyUpdate rejection"

# RFC 9001 8.2: recognizing QUIC parameters in ordinary TLS is fatal.
# Keep a real ClientHello and fragmented input/output to exercise shared parsing.
a = default(Side)
b = default(Side)
ab = @[]
ba = @[]
assert initClient(addr a.h, addr client, "test.example",
                  HandshakeOptions(mode: handshakeQuic, transportParameters: view(parametersA)))
assert initServer(addr b.h, addr server)
run(addr a, addr b, ab, ba, 7, 11)
assert b.failed == alUnsupportedExtension and not b.ready,
       "ordinary TLS server accepted QUIC transport parameters"
dispose(a)
dispose(b)
echo "PASS ordinary TLS server rejects QUIC transport parameters"

# A handshake sent at the wrong encryption level is rejected before copying it.
a = default(Side)
assert initServer(addr a.h, addr server, HandshakeOptions(mode: handshakeQuic))
var header = [1'u8, 0, 0, 0]
var outb = default(array[256, byte])
var result = default(HandshakeResult)
assert step(addr a.h, levelEarly, ptrOf(header), 4, ptrOf(outb), outb.len, result) == heFailed
assert result.consumed == 0 and result.alert == alUnexpectedMessage
dispose(a)

# Certificate failures remain fatal with the ordinary verifier.
a = default(Side)
b = default(Side)
ab = @[]
ba = @[]
assert initClient(addr a.h, addr client, "wrong.example")
assert initServer(addr b.h, addr server)
run(addr a, addr b, ab, ba, 7, 11)
assert a.failed != 0 and not a.ready
dispose(a)
dispose(b)

# The output queue is bounded; an undersized flight limit fails explicitly.
a = default(Side)
b = default(Side)
ab = @[]
ba = @[]
assert initClient(addr a.h, addr client, "test.example")
assert initServer(addr b.h, addr server, HandshakeOptions(maxQueuedBytes: 256))
run(addr a, addr b, ab, ba, 31, 17)
assert b.failed == alInternalError and b.limited and not b.ready
dispose(a)
dispose(b)
# QUIC retry and ECH use the same transcript, selection and authentication code.
client.shareGroups = @[kxX25519]
server.groups = @[kxSecp256r1]
server.echKeys = @[newEchKey(3, "public.example")]
client.echConfigs = echConfigList(server.echKeys)
a = default(Side)
b = default(Side)
ab = @[]
ba = @[]
assert initClient(addr a.h, addr client, "test.example", HandshakeOptions(mode: handshakeQuic))
assert initServer(addr b.h, addr server, HandshakeOptions(mode: handshakeQuic))
run(addr a, addr b, ab, ba, 7, 11)
assert a.ready and b.ready and a.failed == 0 and b.failed == 0
dispose(a)
dispose(b)
server.groups = @[kxX25519]
client.echConfigs = @[]
server.echKeys = @[]
echo "PASS QUIC HelloRetryRequest with ECH"

# Tickets, 0-RTT decisions and secrets, and application-context separation.
var ticketer = default(KeyedTicketer)
assert initKeyedTicketer(ticketer)
var store = default(MemoryStore)
initMemoryStore(store)
var replay = default(MemoryReplay)
initMemoryReplay(replay)
client.sessions = memoryStore(addr store)
client.earlyData = true
server.ticketer = keyedTicketer(addr ticketer)
server.ticketScope = "handshake-test"
server.maxEarlyData = high(uint32) # RFC 9001 4.6.1: QUIC's only nonzero value
server.antiReplay = memoryReplay(addr replay)
var longContext = newString(1024)
for i in 0 ..< longContext.len: longContext[i] = 'x'
for round in 0 ..< 3:
  a = default(Side)
  b = default(Side)
  ab = @[]
  ba = @[]
  let context = longContext & (if round < 2: "parameters-v1" else: "parameters-v2")
  let options = HandshakeOptions(mode: handshakeQuic, applicationContext: context)
  assert initClient(addr a.h, addr client, "test.example", options)
  assert initServer(addr b.h, addr server, options)
  run(addr a, addr b, ab, ba, 7, 11)
  assert a.ready and b.ready and a.failed == 0 and b.failed == 0
  assert a.resumed == (round == 1) and b.resumed == (round == 1)
  if round == 1:
    assert a.early == earlyAccepted and b.early == earlyAccepted
    assert a.tx[ord(levelEarly)].n > 0
    assert a.tx[ord(levelEarly)] == b.rx[ord(levelEarly)]
  dispose(a)
  dispose(b)
release(store)
release(replay)
release(ticketer)
echo "PASS QUIC resumption, early-data acceptance and matching early secrets, context isolation"

release(key)
release(roots)
release(rootsPem[0])
echo "PASS wrong level, verification failure, bounded output, repeated release"
