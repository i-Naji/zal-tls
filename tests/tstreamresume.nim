{.feature: "assumeSync".}
## Resumption and 0-RTT over TlsStream: the client's store gets the
## server's tickets while it reads; the next connection resumes and its
## first bytes go as 0-RTT, which the server's application reads first;
## a server that refuses 0-RTT reads the same bytes after the handshake.
import std/[syncio, assertions]
import zal_net/raw
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/config/config
import zal_tls/raw/stream
import hexutil

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var gCk = default(CertifiedKey)
var gServer = default(ServerConfig)
var gClient = default(ClientConfig)
var gTicketer = default(KeyedTicketer)
var gReplay = default(MemoryReplay)
var gStore = default(MemoryStore)
var gSrvResumed = false
var gSrvEarly = false
var gSrvFirst = ""
var gSrvEarlyBytes = -1

proc echo1(t: TcpStreamPtr): int {.passive.} =
  ## Echo one request (what arrives first, 0-RTT or not), then close.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  gSrvResumed = resumed(addr s)
  gSrvEarly = earlyAccepted(addr s)
  let earlyCount = earlyBytes(addr s)
  gSrvEarlyBytes = earlyCount
  var buf = default(array[256, byte])
  when defined(nimNativeAlloc):
    let occupiedBefore = getOccupiedMem()
  let n = recvInto(addr s, addr buf[0], buf.len)
  when defined(nimNativeAlloc):
    let occupiedAfter = getOccupiedMem()
    if runtimeWorkers() == 1 and earlyCount > 0 and earlyCount <= buf.len:
      expect(occupiedAfter < occupiedBefore, "consumed early data storage released before close")
  expect(earlyBytes(addr s) == earlyCount, "early byte count survives consumption")
  gSrvFirst = ""
  for i in 0 ..< max(n, 0): gSrvFirst.add char(buf[i])
  if n > 0: discard sendFrom(addr s, addr buf[0], n)
  shutdownWrite(addr s)
  # Drain the rest of the request after our sending half-close. Closing TCP
  # with unread application bytes can reset it and discard the echo on Windows.
  while recvInto(addr s, addr buf[0], buf.len) > 0:
    expect(earlyBytes(addr s) == earlyCount, "early byte count survives partial reads")
  expect(earlyBytes(addr s) == earlyCount, "early byte count survives draining")
  close(addr s)
  expect(earlyBytes(addr s) == 0, "closed stream releases early data state")
  result = 0

var gLastResumed = false
var gLastEarly = false
var gLastRejected = false

proc request(port: uint16; req: string; asEarly: bool): string {.passive.} =
  ## One request, echoed; the stream's flags are checked by the caller.
  var s = default(TlsStream)
  var r = req
  let rc = if asEarly: connectTls("127.0.0.1", port, addr gClient, addr s, "test.example",
                                  earlyData = cast[pointer](r.toCString), earlyLen = r.len)
           else: connectTls("127.0.0.1", port, addr gClient, addr s, "test.example")
  expect(rc == 0, "connect: " & $rc)
  if not asEarly: expect(sendFrom(addr s, cast[pointer](r.toCString), r.len) == r.len, "send")
  var buf = default(array[256, byte])
  result = ""
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0: break
    for i in 0 ..< n: result.add char(buf[i])
  gLastResumed = resumed(addr s)
  gLastEarly = earlyAccepted(addr s)
  gLastRejected = earlyRejected(addr s)
  close(addr s)

proc main() {.passive.} =
  var l = listenTcp(0, "127.0.0.1")
  expect(l.ok, "listen")
  serve(l, echo1)
  # 1. A full handshake; its tickets arrive while the client reads.
  expect(request(port(l), "first", false) == "first", "echo 1")
  expect(not gLastResumed and not gSrvResumed, "a full handshake first")
  # 2. Resumed, the request as 0-RTT: the server reads it first.
  expect(request(port(l), "GET /early", true) == "GET /early", "echo 2")
  expect(gLastResumed and gSrvResumed, "resumed")
  expect(gLastEarly and gSrvEarly and gSrvFirst == "GET /early", "0-RTT accepted and read first")
  expect(gSrvEarlyBytes == 10, "the server knows how many bytes came as 0-RTT: " & $gSrvEarlyBytes)
  echo "PASS TlsStream: tickets stored, resumed, 0-RTT read first by the server"
  # 3. A server that refuses 0-RTT: the same bytes come after the handshake.
  gServer.maxEarlyData = 0
  expect(request(port(l), "GET /late", true) == "GET /late", "echo 3")
  expect(gLastResumed and gLastRejected and not gLastEarly and not gSrvEarly, "0-RTT refused, sent again")
  expect(gSrvFirst == "GET /late", "the server read it once")
  expect(gSrvEarlyBytes == 0, "none as 0-RTT")
  gServer.maxEarlyData = 16384
  echo "PASS TlsStream: refused 0-RTT sent again after the handshake, read once"
  # 4. More than the ticket allows: sent after the handshake, all of it.
  var big = newString(20000)
  for i in 0 ..< big.len: big[i] = char(ord('a') + i mod 26)
  gServer.maxEarlyData = 16384
  let back = request(port(l), big, true)
  expect(back.len == 256 and back == big.substr(0, 255), "the server echoes its first read")
  echo "PASS TlsStream: early data past the ticket's limit goes after the handshake"
  let partial = big.substr(0, 8191)
  expect(request(port(l), partial, true) == partial.substr(0, 255), "partial early read")
  expect(gLastEarly and gSrvEarlyBytes == partial.len, "buffered early data drained in parts")
  # 5. Refused 0-RTT for another protocol than the ticket's: not sent again
  #    (RFC 8446 4.2.10); the connection is up, the caller decides.
  gClient.alpn = @["h2", "http/1.1"]
  gServer.alpn = @["h2", "http/1.1"]
  expect(request(port(l), "for h2", false) == "for h2", "an h2 ticket")
  gServer.alpn = @["http/1.1"]
  var s5 = default(TlsStream)
  var h2 = "PRI * HTTP/2.0"
  let rc5 = connectTls("127.0.0.1", port(l), addr gClient, addr s5, "test.example",
                       earlyData = cast[pointer](h2.toCString), earlyLen = h2.len)
  expect(rc5 == TlsEarlyNotSent and isReady(addr s5) and alpn(addr s5) == "http/1.1", "not sent again: " & $rc5)
  var later = "GET /"
  expect(sendFrom(addr s5, cast[pointer](later.toCString), later.len) == later.len, "the caller's own")
  var buf5 = default(array[64, byte])
  let n5 = recvInto(addr s5, addr buf5[0], buf5.len)
  expect(n5 == later.len and gSrvFirst == "GET /", "the server never saw the h2 bytes")
  close(addr s5)
  gClient.alpn = @[]
  gServer.alpn = @[]
  echo "PASS refused 0-RTT for another protocol is not sent again"
  discard close(l)
  quit 0

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), gCk) == "", "leaf")
assert initKeyedTicketer(gTicketer)
initMemoryReplay(gReplay)
initMemoryStore(gStore)
gServer = defaultServerConfig()
gServer.resolver = singleCert(addr gCk)
gServer.ticketer = keyedTicketer(addr gTicketer)
gServer.antiReplay = memoryReplay(addr gReplay)
gServer.maxEarlyData = 16384
gClient = defaultClientConfig(roots)
gClient.sessions = memoryStore(addr gStore)
gClient.earlyData = true
initRuntime()
spawnTask main()
drainRuntime()
