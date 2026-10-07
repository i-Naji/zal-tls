{.feature: "assumeSync".}
## kTLS (Linux): two TLS streams over loopback hand their keys to the
## kernel; plaintext written on one side is read on the other; a key update
## each way (a handshake record, then new kernel keys); close_notify as an
## alert record. Skipped where kTLS is missing (not Linux, no tls module).
import std/[syncio, assertions]
import zal_net/raw
import zal_tls/common
import zal_tls/crypto/[x509, kx]
import zal_tls/keys/schedule
import zal_tls/config/config
import zal_tls/private/core/conn
import zal_tls/raw/ktls
include zal_tls/raw/stream
import zal_tls/wire/consts
import hexutil

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var gCk = default(CertifiedKey)
var gServer = default(ServerConfig)
var gClient = default(ClientConfig)
var gSrv = default(TlsStream)
var gAccepted = false

proc accept1(t: TcpStreamPtr): int {.passive.} =
  gAccepted = acceptTls(addr gSrv, t, addr gServer) == 0
  while gSrv.tcp.isOpen: parkUntil(afterMs(50))   # the test owns it now
  result = 0

proc install(s: TlsStreamPtr): int =
  var tx = default(Secret)
  var rx = default(Secret)
  var txSeq = 0'u64
  var rxSeq = 0'u64
  if not exportSecrets(s.conn, tx, rx, txSeq, rxSeq): return -1
  result = ktlsAttach(nativeHandle(s.tcp))
  if result == 0: result = ktlsKeys(nativeHandle(s.tcp), true, suite(s.conn), tx, txSeq)
  if result == 0: result = ktlsKeys(nativeHandle(s.tcp), false, suite(s.conn), rx, rxSeq)

proc readRecord(fd: cint; p: pointer; n: int; ctype: var int): int {.passive.} =
  var res = 0
  while true:
    result = ktlsRecv(fd, p, n, ctype)
    if result != -35 and result != -11: return        # EAGAIN (macOS 35, Linux 11)
    parkPoll(fd, {evRead}, afterMs(5000), res)
    if res <= 0: return -110

const Total = 4 * 1024 * 1024
var gKtlsServer = true
var gEvery = 0'u64
var gServerRc = 0

proc pattern(i: int): byte {.inline.} = byte((i * 7 + (i shr 9)) and 0xff)

proc echoKtls(t: TcpStreamPtr): int {.passive.} =
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  s.conn.keyUpdateEvery = gEvery
  if gKtlsServer: gServerRc = useKtls(addr s)
  var buf = default(array[20000, byte])
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0: break
    var off = 0
    while off < n:
      let k = sendFrom(addr s, addr buf[off], n - off)
      if k <= 0: break
      off = off + k
  shutdownWrite(addr s)
  close(addr s)
  result = 0

proc sender(s: TlsStreamPtr; requestUpdate: bool) {.passive.} =
  var buf = default(array[16384, byte])
  var sent = 0
  var asked = false
  while sent < Total:
    for i in 0 ..< buf.len: buf[i] = pattern(sent + i)
    var off = 0
    while off < buf.len:
      let k = sendFrom(s, addr buf[off], buf.len - off)
      expect(k > 0, "send")
      off = off + k
    sent = sent + buf.len
    if requestUpdate and not asked and sent >= Total div 2:
      # A key update request, sealed here and written as the writer.
      asked = true
      var rec = default(array[64, byte])
      let n = keyUpdate(s.conn, true, ptrOf(rec), rec.len)
      expect(n > 0 and writeAll(addr s.tcp, addr rec[0], n), "request a key update")
  shutdownWrite(s)

proc streamCase(l: TcpListener; clientKtls, serverKtls, request: bool; every: uint64; label: string) {.passive.} =
  gKtlsServer = serverKtls
  gEvery = every
  var c = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l), addr gClient, addr c, "test.example") == 0, "connect")
  c.conn.keyUpdateEvery = every
  if gClient.suites.len == 1: expect(suite(c.conn) == gClient.suites[0], label & ": the suite asked for")
  if clientKtls: expect(useKtls(addr c) == 0, "client useKtls")
  spawnTask sender(addr c, request)
  var buf = default(array[65536, byte])
  var got = 0
  while true:
    let n = recvInto(addr c, addr buf[0], buf.len)
    if n == 0: break
    if n < 0: echo label, ": recv ", n, " alert ", tlsAlert(n)
    expect(n > 0, "recv")
    for i in 0 ..< n: expect(buf[i] == pattern(got + i), "data intact")
    got = got + n
  expect(got == Total and gServerRc == 0, label & ": 4 MiB back, got " & $got)
  expect(not clientKtls or (c.ktx and c.krx), label & ": the kernel sends and reads")
  if every > 0:
    # About 256 records each way, a key update every 20: counted, not just survived.
    expect(c.conn.keyUpdatesOut >= 5 and c.conn.keyUpdatesIn >= 5,
           label & ": key updates out " & $c.conn.keyUpdatesOut & ", in " & $c.conn.keyUpdatesIn)
  close(addr c)
  echo "PASS kTLS stream: ", label

# --------------------------------------------- the phase 3 review's cases

const Burst = 3 * 16384
var gBurstGo = false

proc burster(t: TcpStreamPtr): int {.passive.} =
  ## Three records at once, then (after the client's byte) three more.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  var buf = default(array[16384, byte])
  for round in 0 ..< 2:
    var sent = 0
    while sent < Burst:
      for i in 0 ..< buf.len: buf[i] = pattern(round * Burst + sent + i)
      expect(sendFrom(addr s, addr buf[0], buf.len) == buf.len, "burst send")
      sent = sent + buf.len
    if round == 0: expect(recvInto(addr s, addr buf[0], 1) == 1, "the client's go")
  shutdownWrite(addr s)
  discard recvInto(addr s, addr buf[0], buf.len)
  close(addr s)
  result = 0

var gLateEnd = 1

proc lateReader(t: TcpStreamPtr): int {.passive.} =
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  parkUntil(afterMs(500))
  var buf = default(array[16384, byte])
  while true:
    let n = recvInto(addr s, addr buf[0], buf.len)
    if n <= 0:
      gLateEnd = n
      break
  close(addr s)
  result = 0

var gCorruptRead = 1

proc corrupter(t: TcpStreamPtr): int {.passive.} =
  ## A user-space server that sends a corrupt record, then reads what comes.
  var s = default(TlsStream)
  if acceptTls(addr s, t, addr gServer) != 0:
    close(addr s)
    return 0
  var bad = default(array[40, byte])
  bad[0] = 23
  bad[1] = 3
  bad[2] = 3
  bad[4] = 35
  for i in 5 ..< 40: bad[i] = byte(i)
  expect(writeAll(addr s.tcp, addr bad[0], bad.len), "corrupt record out")
  var buf = default(array[256, byte])
  gCorruptRead = recvInto(addr s, addr buf[0], buf.len)
  close(addr s)
  result = 0

proc reviewCases() {.passive.} =
  # Every suite through the kernel (the three crypto_info layouts), key updates counted.
  var l2 = listenTcp(0, "127.0.0.1")
  serve(l2, echoKtls)
  for su in [suiteAes128Gcm, suiteAes256Gcm, suiteChaCha20]:
    gClient.suites = @[su]
    streamCase(l2, true, true, false, 20, name(su) & " in the kernel both ways, key updates every 20 records")
  gClient.suites = @AllSuites
  # The ULP attached, no keys: the socket passes plaintext; user space goes on.
  gKtlsServer = false
  var u = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l2), addr gClient, addr u, "test.example") == 0, "connect")
  expect(ktlsAttach(nativeHandle(u.tcp)) == 0, "attach only")
  var buf = default(array[65536, byte])
  for i in 0 ..< 60000: buf[i] = pattern(i)
  expect(sendFrom(addr u, addr buf[0], 16384) == 16384, "user-space send over the ULP")
  var got = 0
  while got < 16384:
    let n = recvInto(addr u, addr buf[40000 + got], 16384 - got)
    expect(n > 0, "user-space read over the ULP")
    got = got + n
  for i in 0 ..< 16384: expect(buf[40000 + i] == pattern(i), "echo over the ULP")
  close(addr u)
  echo "PASS kTLS: the ULP attached without keys, user space carries on"
  discard close(l2)
  # Reading moves to the kernel with records already buffered in user space.
  var l3 = listenTcp(0, "127.0.0.1")
  serve(l3, burster)
  var b = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l3), addr gClient, addr b, "test.example") == 0, "connect")
  got = 0
  var all = newSeq[byte](2 * Burst)
  var n = recvInto(addr b, addr all[0], 100)
  expect(n == 100, "a first read")
  got = n
  parkUntil(afterMs(100))                        # the other records arrive, some into inb
  expect(useKtls(addr b) == 0, "useKtls with records buffered")
  while got < Burst:
    n = recvInto(addr b, addr all[got], Burst - got)
    expect(n > 0, "the buffered records")
    got = got + n
  var go = [1'u8]
  expect(sendFrom(addr b, addr go[0], 1) == 1, "go")
  while got < 2 * Burst:
    n = recvInto(addr b, addr all[got], 2 * Burst - got)
    expect(n > 0, "records after the switch")
    got = got + n
  for i in 0 ..< 2 * Burst: expect(all[i] == pattern(i), "intact across the switch at " & $i)
  expect(b.krx and recvInto(addr b, addr buf[0], 10) == 0, "the kernel reads; close_notify")
  close(addr b)
  discard close(l3)
  echo "PASS kTLS: reading moves to the kernel after the records buffered in user space"
  # 1-byte reads: close_notify still ends cleanly (it arrives whole).
  var l4 = listenTcp(0, "127.0.0.1")
  serve(l4, echoKtls)
  gKtlsServer = true
  var o = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l4), addr gClient, addr o, "test.example") == 0, "connect")
  expect(useKtls(addr o) == 0, "useKtls")
  for i in 0 ..< 10: buf[i] = byte(i + 1)
  expect(sendFrom(addr o, addr buf[0], 10) == 10, "ten bytes")
  shutdownWrite(addr o)
  var one = [0'u8]
  var count = 0
  while true:
    let k = recvInto(addr o, addr one[0], 1)
    if k <= 0:
      expect(k == 0 and count == 10, "one byte at a time, then a clean end: " & $k & " after " & $count)
      break
    expect(one[0] == byte(count + 1), "byte " & $count)
    count = count + 1
  close(addr o)
  discard close(l4)
  echo "PASS kTLS: 1-byte reads, close_notify a clean end"
  # A send that timed out under kTLS (records end on boundaries): no close_notify after it.
  var l5 = listenTcp(0, "127.0.0.1")
  serve(l5, lateReader)
  var z = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l5), addr gClient, addr z, "test.example") == 0, "connect")
  expect(useKtls(addr z) == 0, "useKtls")
  while true:
    let k = sendFrom(addr z, addr buf[0], 65536, afterMs(150))
    if k < 0:
      expect(k == IoTimedOut, "a send times out: " & $k)
      break
  close(addr z)
  parkUntil(afterMs(2000))
  expect(gLateEnd != 0 and gLateEnd != 1, "no clean end after a failed send: " & $gLateEnd)
  discard close(l5)
  echo "PASS kTLS: a send that timed out, no close_notify after it"
  # Kernel sending, user-space reading: a bad record's alert goes as a kernel record.
  var l6 = listenTcp(0, "127.0.0.1")
  serve(l6, corrupter)
  var k6 = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l6), addr gClient, addr k6, "test.example") == 0, "connect")
  expect(useKtls(addr k6, rx = false) == 0, "useKtls, sending only")
  let r6 = recvInto(addr k6, addr buf[0], buf.len)
  expect(tlsAlert(r6) == alBadRecordMac, "the corrupt record fails: " & $r6)
  parkUntil(afterMs(300))
  expect(gCorruptRead < 0 and gCorruptRead != 1, "the peer reads our alert, not data: " & $gCorruptRead)
  close(addr k6)
  discard close(l6)
  echo "PASS kTLS: sending in the kernel, our alert goes as its record"

proc main() {.passive.} =
  var l = listenTcp(0, "127.0.0.1")
  serve(l, accept1)
  var c = default(TlsStream)
  expect(connectTls("127.0.0.1", port(l), addr gClient, addr c, "test.example") == 0, "connect")
  var spins = 0
  while not gAccepted and spins < 100:
    parkUntil(afterMs(10))
    spins = spins + 1
  expect(gAccepted, "accepted")
  let a = install(addr c)
  if a == KtlsUnavailable or a == -2 or a == -92:   # not Linux; no tls module (ENOENT, ENOPROTOOPT)
    echo "SKIP kTLS not available here (", a, ")"
    quit 0
  expect(a == 0 and install(addr gSrv) == 0, "kernel keys on both sides: " & $a)
  # Plaintext both ways.
  var buf = default(array[65536, byte])
  var total = 0
  for round in 0 ..< 3:
    for i in 0 ..< 1000: buf[i] = byte((i + round) and 0xff)
    expect(writeAll(addr c.tcp, addr buf[0], 1000), "client write")
    var got = 0
    while got < 1000:
      var t = 0
      let n = readRecord(nativeHandle(gSrv.tcp), addr buf[got], buf.len - got, t)
      expect(n > 0 and t == 23, "server read: " & $n & " type " & $t)
      got = got + n
    for i in 0 ..< 1000: expect(buf[i] == byte((i + round) and 0xff), "data intact")
    total = total + got
  echo "PASS kTLS: plaintext through the kernel's records (", total, " bytes)"
  # A key update from the client: a handshake record, then new keys each side.
  var ku = [24'u8, 0, 0, 1, 0]
  expect(ktlsSendRecord(nativeHandle(c.tcp), 22, addr ku[0], 5) == 5, "send KeyUpdate")
  let next = nextTrafficSecret(hashOf(suite(c.conn)), c.conn.wrSecret)
  let rk = ktlsKeys(nativeHandle(c.tcp), true, suite(c.conn), next, 0)
  if rk != 0:
    echo "SKIP this kernel cannot rekey kTLS (", rk, "): key updates end the connection"
    quit 0
  var t = 0
  var msg = default(array[64, byte])
  let n = readRecord(nativeHandle(gSrv.tcp), addr msg[0], msg.len, t)
  expect(n == 5 and t == 22 and msg[0] == 24, "the server reads the KeyUpdate: " & $n & " type " & $t)
  let snext = nextTrafficSecret(hashOf(suite(gSrv.conn)), gSrv.conn.rdSecret)
  expect(ktlsKeys(nativeHandle(gSrv.tcp), false, suite(gSrv.conn), snext, 0) == 0, "server rekeys")
  for i in 0 ..< 500: buf[i] = byte((i * 3) and 0xff)
  expect(writeAll(addr c.tcp, addr buf[0], 500), "client write after rekey")
  var got = 0
  while got < 500:
    let k = readRecord(nativeHandle(gSrv.tcp), addr buf[got], buf.len - got, t)
    expect(k > 0 and t == 23, "read after rekey")
    got = got + k
  for i in 0 ..< 500: expect(buf[i] == byte((i * 3) and 0xff), "data after rekey")
  echo "PASS kTLS: a key update (record, then new kernel keys both sides)"
  # close_notify as an alert record.
  var cn = [1'u8, 0]
  expect(ktlsSendRecord(nativeHandle(c.tcp), 21, addr cn[0], 2) == 2, "send close_notify")
  let e = readRecord(nativeHandle(gSrv.tcp), addr msg[0], msg.len, t)
  expect(e == 2 and t == 21 and msg[1] == 0, "close_notify read as an alert record")
  echo "PASS kTLS: close_notify"
  close(addr c.tcp)
  close(addr gSrv.tcp)
  # TlsStream in kTLS mode: an echo, both sides and mixed.
  var l2 = listenTcp(0, "127.0.0.1")
  serve(l2, echoKtls)
  streamCase(l2, true, true, false, 0, "both sides in the kernel, 4 MiB each way, close_notify both ways")
  streamCase(l2, true, true, false, 20, "both sides in the kernel, key updates every 20 records both ways")
  streamCase(l2, false, true, true, 0, "a user-space client asks the kernel-side server for a key update")
  streamCase(l2, true, false, false, 20, "a kernel-side client, a user-space server, key updates every 20 records")
  discard close(l2)
  reviewCases()
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
gClient = defaultClientConfig(roots)
gClient.groups = @[kxX25519]
gClient.shareGroups = @[kxX25519]
initRuntime()
spawnTask main()
drainRuntime()
