{.feature: "assumeSync".}
import std/[assertions, syncio]
import zal_net/rt, zal_net/rt/[time, cancel]
import zal_net/unsafe/streamview
import zal_tls/common
import zal_tls/raw/stream
import zal_tls/config/config
import zal_tls/crypto/x509
import zal_tls/private/core/conn as core
import zal_tls/private/core/server as server
import loophelp

type Peer = object
  server: Side
  outgoing: seq[byte]
  offset: int
  readLimit, budget: int

proc readPeer(ctx: pointer; p: pointer; n: int; deadline: Deadline;
              tok: nil CancelToken): int {.passive.} =
  let peer = cast[ptr Peer](ctx)
  if peer.budget == 0: return IoTimedOut
  result = min(min(n, peer.readLimit), peer.outgoing.len - peer.offset)
  if peer.budget > 0: result = min(result, peer.budget)
  if result > 0:
    copyMem(p, addr peer.outgoing[peer.offset], result)
    peer.offset += result
    if peer.budget > 0: peer.budget -= result

proc writePeer(ctx: pointer; p: pointer; n: int; deadline: Deadline;
               tok: nil CancelToken): int {.passive.} =
  let peer = cast[ptr Peer](ctx)
  assert peer.server.inLen + n <= peer.server.inb.len
  copyMem(addr peer.server.inb[peer.server.inLen], p, n)
  peer.server.inLen += n
  while turn(peer.server, peer.outgoing): discard
  assert peer.server.failed < 0
  n

proc endPeer(ctx: pointer) = discard
var operations = StreamOps(recv: readPeer, send: writePeer,
                           shutdownWrite: endPeer, interrupt: endPeer)

proc text(path: string): string =
  try: result = readFile(path)
  except: result = ""

var key = default(CertifiedKey)
var serverConfig = default(ServerConfig)
var clientConfig = default(ClientConfig)

proc receive(recordSize, readSize, fragment: int; timeout: bool; total: int) {.passive.} =
  var peer = Peer(readLimit: fragment, budget: -1)
  initSide(peer.server)
  assert server.initServer(peer.server.c, addr serverConfig)
  defer: core.release(peer.server.c)
  var stream = default(TlsStream)
  assert unsafeWrapClient(addr stream, unsafeBorrowStream(addr peer, addr operations),
                          addr clientConfig, "test.example") == 0
  defer: assert closeNow(addr stream)
  assert peer.server.ready
  assert peer.offset == peer.outgoing.len
  peer.outgoing.setLen(0)
  peer.offset = 0
  let payload = pattern(total, 31)
  assert sendApp(peer.server, peer.outgoing, payload, recordSize)
  var notify = default(array[64, byte])
  let count = core.close(peer.server.c, ptrOf(notify), notify.len)
  assert count > 0
  for i in 0..<count: peer.outgoing.add notify[i]
  # Stop after one record and part of the next header, then resume the read.
  if timeout: peer.budget = recordSize + 22 + 3
  var buffer = newSeq[byte](readSize)
  var received = 0
  var timedOut = false
  let started = monoNow()
  while true:
    let count = recvInto(addr stream, addr buffer[0], buffer.len)
    if count == IoTimedOut:
      assert timeout and not timedOut
      assert received == recordSize
      timedOut = true
      peer.budget = -1
      continue
    if count == 0: break
    assert count > 0 and received + count <= payload.len
    for i in 0..<count: assert buffer[i] == payload[received + i]
    received += count
  let elapsed = int64(monoNow()) - int64(started)
  assert received == payload.len and timedOut == timeout
  assert peer.offset == peer.outgoing.len
  when defined(tlsBufferBench):
    echo "record_bytes=", recordSize, " app_read_bytes=", readSize,
         " bytes=", received, " elapsed_ns=", elapsed

proc main() {.passive.} =
  when defined(tlsBufferBench):
    for size in [64, 1024, 16384]:
      for run in 0..<5: receive(size, 16384, 65536, false, 4 * 1024 * 1024)
  else:
    for size in [1, 64, 16384]:
      receive(size, 37, 65536, false, 131079)
      receive(size, 4096, 7, false, 65539)
    receive(64, 7, 65536, true, 131079)
    echo "PASS stream buffers: batched records, fragments, partial reads and timeout recovery"

var certificates: seq[Cert] = @[]
assert certsPem(text("tests/data/root.pem"), certificates) == 1
let roots = newRoots()
assert roots != nil and addRoot(roots, certificates[0])
assert loadCertifiedKey(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                        text("tests/data/leaf.key"), key) == ""
serverConfig = defaultServerConfig()
serverConfig.resolver = singleCert(addr key)
clientConfig = defaultClientConfig(roots)
assert runMain(main())
release(key)
release(roots)
