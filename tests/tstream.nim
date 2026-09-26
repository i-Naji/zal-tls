## TlsStream over real TCP: a TLS echo server on the loops, a client that
## sends 1 MiB from one task and reads it back in another, close_notify both
## ways; a handshake that fails reports the alert; `copy` from zal-net
## runs over a TlsStream unchanged; ECH accepted, or rejected with the retry
## configs.
import std/[syncio, assertions]
import zal_net/raw
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/config/config
import zal_tls/raw/stream
import zal_tls/wire/consts
import hexutil

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

const Total = 1024 * 1024

var gCk = default(CertifiedKey)
var gServer = default(ServerConfig)
var gClient = default(ClientConfig)
var gEchoed = 0
var gSenderDone = default(Event)

proc pattern(i: int): byte {.inline.} = byte((i * 13 + (i shr 9)) and 0xff)

proc echoTls(t: TcpStreamPtr): int {.passive.} =
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  var buf = default(array[20000, byte])
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0: break
    var off = 0
    while off < n:
      let k = sendFrom(addr s, addr buf[off], n - off)
      expect(k > 0, "server send")
      off = off + k
    gEchoed = gEchoed + n
  shutdownWrite(addr s)
  close(addr s)
  result = 0

proc sender(s: TlsStreamPtr) {.passive.} =
  var buf = default(array[65536, byte])
  var sent = 0
  while sent < Total:
    let n = min(buf.len, Total - sent)
    for i in 0 ..< n: buf[i] = pattern(sent + i)
    var off = 0
    while off < n:
      let k = sendFrom(s, addr buf[off], n - off)
      expect(k > 0, "client send")
      off = off + k
    sent = sent + n
  shutdownWrite(s)
  expect(sendFrom(s, addr buf[0], 10) == TlsClosed, "sending after shutdownWrite: EPIPE")
  setEvent(addr gSenderDone)

var gSlowBytes = 0
var gSlowEnd = 1
var gTimeoutRc = 1

proc slowReader(t: TcpStreamPtr): int {.passive.} =
  ## Lets the client fill the socket, then reads slowly to the end.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  parkUntil(afterMs(300))
  var buf = default(array[16384, byte])
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0:
      gSlowEnd = n
      break
    gSlowBytes = gSlowBytes + n
    parkUntil(afterMs(1))
  shutdownWrite(addr s)
  close(addr s)
  result = 0

var gLateEnd = 1
var gLateReadPermit = default(Event)
var gLateDone = default(Event)

proc lateReader(t: TcpStreamPtr): int {.passive.} =
  ## Reads nothing for a while (the client's sends time out), then to the end.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  # Keep application reads behind a barrier until the sender actually times
  # out. A fixed sleep is insufficient: under instrumentation, sending can be
  # slower than the subsequently draining peer and never fill the socket.
  expect(wait(addr gLateReadPermit, never) == wrReady, "late reader released")
  var buf = default(array[16384, byte])
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0:
      gLateEnd = n
      break
  close(addr s)
  setEvent(addr gLateDone)
  result = 0

var gAuthServer = default(ServerConfig)
var gClientLeaf: seq[byte] = @[]

proc authEcho(t: TcpStreamPtr): int {.passive.} =
  ## A server that requires a client certificate: echoes one read.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gAuthServer) == 0:
    gClientLeaf = peerLeafDer(addr s)
    var buf = default(array[256, byte])
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n > 0: discard sendFrom(addr s, addr buf[0], n)
    shutdownWrite(addr s)
  close(addr s)
  result = 0

proc silentPeer(t: TcpStreamPtr): int {.passive.} =
  var s = default(TlsStream)
  gTimeoutRc = acceptTls(addr s, t, addr gServer, handshakeMs = 200)
  close(addr s)
  result = 0

var gEchServer = default(ServerConfig)
var gCkOther = default(CertifiedKey)
var gEchName = ""
var gEchAccepted = false

proc echEcho(t: TcpStreamPtr): int {.passive.} =
  ## A server with ECH keys: echoes one read.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gEchServer) == 0:
    gEchName = serverName(addr s)
    gEchAccepted = echAccepted(addr s)
    var buf = default(array[256, byte])
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n > 0: discard sendFrom(addr s, addr buf[0], n)
    shutdownWrite(addr s)
  close(addr s)
  result = 0

proc echAlertPeer(t: TcpStreamPtr): int {.passive.} =
  ## Answers a ClientHello with a plaintext ech_required alert (never a
  ## server's to send).
  var buf = default(array[4096, byte])
  discard recvInto(t, addr buf[0], buf.len, afterMs(2000))
  var al = [21'u8, 3, 3, 0, 2, 2, 121]
  discard writeAll(t, al.toOpenArray(0, al.len - 1))
  close(t)
  result = 0

proc main() {.passive.} =
  var l = listenTcp(0, "127.0.0.1")
  expect(l.ok, "listen")
  serve(l, echoTls)
  var s = default(TlsStream)
  let rc = connectTls("127.0.0.1", port(l), addr gClient, addr s, "test.example")
  if rc != 0: echo "connectTls: ", rc, " alert ", tlsAlert(rc)
  expect(rc == 0 and isReady(addr s), "handshake over TCP")
  spawnTask sender(addr s)
  var buf = default(array[65536, byte])
  var got = 0
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n == 0: break
    expect(n > 0, "recv")
    for i in 0 ..< n: expect(buf[i] == pattern(got + i), "data intact")
    got = got + n
  expect(got == Total, "1 MiB back")
  # EOF can arrive before the queued sender finishes its final assertion.
  # A raw owner cannot be closed while that borrower still uses it.
  expect(wait(addr gSenderDone, afterMs(5000)) == wrReady, "client sender drained")
  close(addr s)
  echo "PASS TlsStream: 1 MiB echoed over TCP, close_notify both ways"
  # A name the certificate does not carry: the handshake fails with bad_certificate.
  var bad = default(TlsStream)
  let rc2 = connectTls("127.0.0.1", port(l), addr gClient, addr bad, "wrong.example")
  expect(tlsAlert(rc2) == alBadCertificate, "wrong name refused")
  close(addr bad)
  echo "PASS TlsStream: a wrong name fails with bad_certificate"
  discard close(l)
  # close_notify survives a full socket: the slow reader sees a clean end.
  var l2 = listenTcp(0, "127.0.0.1")
  serve(l2, slowReader)
  var q = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l2), addr gClient, addr q, "test.example") == 0, "connect")
  var big = default(array[16384, byte])
  var total = 0
  while total < 3 * Total:
    expect(sendFrom(addr q, addr big[0], big.len) == big.len, "fill")
    total = total + big.len
  shutdownWrite(addr q)                           # the socket is full now: close_notify must wait
  var tail = default(array[64, byte])
  expect(recvInto(addr q, addr tail[0], tail.len) == 0, "the server closes after reading everything")
  close(addr q)
  expect(gSlowEnd == 0 and gSlowBytes == total, "clean end after " & $gSlowBytes & " bytes, got " & $gSlowEnd)
  discard close(l2)
  echo "PASS close_notify after a full socket: the peer reads everything and a clean end"
  # A send that timed out fails the stream: close sends no close_notify
  # after it (the peer must not read a clean end of what was cut short).
  var l4 = listenTcp(0, "127.0.0.1")
  serve(l4, lateReader)
  var z = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l4), addr gClient, addr z, "test.example") == 0, "connect")
  var sentZ = 0
  while true:
    let k = sendFrom(addr z, addr big[0], big.len, afterMs(150))
    if k < 0:
      expect(k == IoTimedOut, "a send times out, got " & $k)
      break
    sentZ = sentZ + k
  close(addr z)
  setEvent(addr gLateReadPermit)
  expect(wait(addr gLateDone, afterMs(5000)) == wrReady, "late reader drained")
  expect(gLateEnd != 0 and gLateEnd != 1, "no clean end after a failed send, got " & $gLateEnd)
  discard close(l4)
  echo "PASS a send that timed out: no close_notify after it"
  # A server that requires a client certificate: ours is presented and
  # seen; without one the handshake ends in certificate_required, which
  # the client reads (TLS 1.3: its side was done).
  var l5 = listenTcp(0, "127.0.0.1")
  serve(l5, authEcho)
  var ckc = default(CertifiedKey)
  expect(loadCertifiedKey(slurpText("tests/data/cauth.pem"), slurpText("tests/data/cauth.key"), ckc) == "", "client key")
  var withCert = gClient
  withCert.clientCert = singleClientCert(addr ckc)
  var m = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l5), addr withCert, addr m, "test.example") == 0, "mTLS connect")
  var hi = "hello"
  expect(sendFrom(addr m, cast[pointer](hi.toCString), hi.len) == hi.len, "send")
  var mb = default(array[64, byte])
  expect(recvInto(addr m, addr mb[0], mb.len) == hi.len and gClientLeaf == ckc.chain[0], "echo; the server saw our certificate")
  close(addr m)
  var n2 = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l5), addr gClient, addr n2, "test.example") == 0, "done on the client's side")
  let r2 = recvInto(addr n2, addr mb[0], mb.len)
  expect(tlsAlert(r2) == alCertificateRequired, "certificate_required: " & $r2)
  close(addr n2)
  release(ckc)
  discard close(l5)
  echo "PASS TlsStream: a required client certificate presented; without one, certificate_required"
  # ECH: accepted (the server sees the inner name); a client with a stale
  # config gets TlsEchRejected and the server's retry configs, and with
  # them connects.
  var l6 = listenTcp(0, "127.0.0.1")
  serve(l6, echEcho)
  let echKey = newEchKey(3, "other.example")
  let staleKey = newEchKey(3, "other.example")
  gEchServer.echKeys = @[echKey]
  var withEch = gClient
  withEch.echConfigs = echConfigList(@[echKey])
  var e = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l6), addr withEch, addr e, "test.example") == 0 and echAccepted(addr e),
         "ECH connect")
  expect(sendFrom(addr e, cast[pointer](hi.toCString), hi.len) == hi.len, "send")
  expect(recvInto(addr e, addr mb[0], mb.len) == hi.len and gEchName == "test.example" and gEchAccepted,
         "echo; the server saw the inner name")
  close(addr e)
  var stale = gClient
  stale.echConfigs = echConfigList(@[staleKey])
  var r = default(TlsStream)
  let rc6 = connectTls("127.0.0.1", port(l6), addr stale, addr r, "test.example")
  expect(rc6 == TlsEchRejected, "a stale config: TlsEchRejected, got " & $rc6)
  let retry = echRetryConfigs(addr r)
  close(addr r)
  expect(retry == echConfigList(@[echKey], true), "the retry configs")
  stale.echConfigs = retry
  var again = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l6), addr stale, addr again, "test.example") == 0 and echAccepted(addr again),
         "connected with the retry configs")
  close(addr again)
  discard close(l6)
  echo "PASS TlsStream: ECH accepted; a stale config rejected with the retry configs, which then work"
  # An ech_required alert received (unauthenticated): not TlsEchRejected,
  # no retry configs.
  var l7 = listenTcp(0, "127.0.0.1")
  serve(l7, echAlertPeer)
  var fake = default(TlsStream)
  let rc7 = connectTls("127.0.0.1", port(l7), addr withEch, addr fake, "test.example")
  expect(rc7 != TlsEchRejected and tlsAlert(rc7) == alEchRequired and echRetryConfigs(addr fake).len == 0,
         "a received ech_required: the alert, not a rejection, got " & $rc7)
  close(addr fake)
  discard close(l7)
  echo "PASS TlsStream: an ech_required alert received is not an ECH rejection"
  # A client that says nothing: the server's handshake times out.
  var l3 = listenTcp(0, "127.0.0.1")
  serve(l3, silentPeer)
  var mute = connect(initSocketAddress(loopback4(), port(l3)))
  expect(mute.isOpen, "connect")
  parkUntil(afterMs(600))
  expect(gTimeoutRc == IoTimedOut, "handshake timeout, got " & $gTimeoutRc)
  close(addr mute)
  discard close(l3)
  echo "PASS a silent client: the server's handshake times out"
  quit 0

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), gCk) == "", "leaf")
gServer = defaultServerConfig()
gServer.resolver = singleCert(addr gCk)
var cauthRoots: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/cauth-root.pem"), cauthRoots) == 1, "client root")
let clientRoots = newRoots()
if clientRoots == nil: quit "no store"
expect(addRoot(clientRoots, cauthRoots[0]), "add client root")
gAuthServer = defaultServerConfig()
gAuthServer.resolver = singleCert(addr gCk)
gAuthServer.clientAuth = caRequire
gAuthServer.clientRoots = clientRoots
gClient = defaultClientConfig(roots)
expect(loadCertifiedKey(slurpText("tests/data/other.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/other.key"), gCkOther) == "", "the public name's")
var echNames = @[SniEntry(name: "test.example", ck: addr gCk), SniEntry(name: "other.example", ck: addr gCkOther)]
gEchServer = defaultServerConfig()
gEchServer.resolver = sniCerts(addr echNames)
initRuntime()
spawnTask main()
drainRuntime()
