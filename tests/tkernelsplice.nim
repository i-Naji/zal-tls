## Opt-in TCP -> kTLS splice: verified payload, close_notify, control rekey,
## cancellation/deadline rejection, and forced output-refusal recovery.
import std/[assertions, syncio]
import zal_net/raw
import zal_net/errors
when defined(ntSpliceControlTest) or defined(ntSpliceSequenceFaultTest):
  import zal_tls/[common, errors]
  import zal_tls/config/config
  include zal_tls/raw/stream
else:
  import zal_tls/raw
  import zal_tls/raw/splice
import zal_tls/raw/ktls
import zal_tls/crypto/x509
import zal_tls/crypto/kx

proc slurp(path: string): string =
  try: result = readFile(path)
  except: result = ""

var key = default(CertifiedKey)
var serverConfig = default(ServerConfig)
var clientConfig = default(ClientConfig)
var sinkDone = default(Event)
var sinkCount = 0
var sinkError = 1
const Total = 2 * 1024 * 1024
proc pattern(index: int): byte = byte(index mod 251)

proc receiver(tcp: TcpStreamPtr): int {.passive.} =
  var tls = default(TlsStream)
  assert acceptTls(addr tls, tcp, addr serverConfig) == 0
  var buffer = default(array[16384, byte])
  while true:
    let count = recvInto(addr tls, buffer, afterMs(10000))
    if count <= 0:
      sinkError = count
      break
    for index in 0..<count: assert buffer[index] == pattern(sinkCount + index)
    sinkCount = sinkCount + count
  shutdownWrite(addr tls)
  close(addr tls)
  setEvent(addr sinkDone)
  result = 0

proc producer(tcp: TcpStreamPtr; done: ptr Event) {.passive.} =
  var buffer = default(array[16384, byte])
  var offset = 0
  while offset < Total:
    for index in 0..<buffer.len: buffer[index] = pattern(offset + index)
    assert writeAll(tcp, buffer, afterMs(10000))
    offset = offset + buffer.len
  shutdownWrite(tcp)
  setEvent(done)

when defined(linux) and defined(ntSpliceFaultTest):
  proc rejectOutput() {.importc: "nt_test_reject_splice_output".}
  proc rejectionPending(): cint {.importc: "nt_test_splice_rejection_pending".}

when defined(linux) and defined(ntSpliceSequenceFaultTest):
  proc rejectSequence() {.importc: "nt_test_reject_tx_sequence".}

proc main() {.passive.} =
  var tlsListener = listenTcp(0, "127.0.0.1")
  assert tlsListener.ok
  serve(tlsListener, receiver)
  var tls = default(TlsStream)
  assert connectTls("127.0.0.1", tlsListener.port, addr clientConfig, addr tls, "test.example") == 0
  var listener = listenTcp(0, "127.0.0.1")
  assert listener.ok
  var producerTcp = connect("127.0.0.1", listener.port)
  var source = accept(listener)
  let notInstalled = copyToKernel(addr source, addr tls, afterMs(2000))
  when defined(linux): assert notInstalled.error == NotSupported and notInstalled.bytes == 0
  else: assert notInstalled.error == KtlsUnavailable and notInstalled.bytes == 0
  let installed = useKtls(addr tls, rx = false)
  if installed != 0:
    echo "SKIP kernel splice: kTLS TX unavailable (", installed, ")"
  else:
    when defined(linux) and defined(ntSpliceSequenceFaultTest):
      assert setKeyUpdateInterval(tls.conn, 1)
      var one = [55'u8]
      assert writeAll(addr producerTcp, one, afterMs(2000))
      shutdownWrite(addr producerTcp)
      rejectSequence()
      let failed = copyToKernel(addr source, addr tls, afterMs(2000))
      assert failed.error == -5 and failed.bytes == 0 and not tls.isOpen
      assert sendFrom(addr tls, one, afterMs(2000)) == -5
      echo "PASS failed kernel sequence query blocks application output"
    else:
      when defined(ntSpliceControlTest):
        assert setKeyUpdateInterval(tls.conn, 20)
      let token = newCancelToken()
      cancel(token)
      let stopped = copyToKernel(addr source, addr tls, afterMs(2000), token)
      assert stopped.error == ECancelled and stopped.bytes == 0
      release(token)
      let timed = copyToKernel(addr source, addr tls, afterMs(10))
      assert timed.error == IoTimedOut and timed.bytes == 0
      var producerDone = default(Event)
      assert trySpawnTask(producer(addr producerTcp, addr producerDone))
      when defined(linux) and defined(ntSpliceFaultTest): rejectOutput()
      let copied = copyToKernel(addr source, addr tls, afterMs(10000))
      assert copied.error == 0 and copied.bytes == Total
      assert copied.kernelBytes + copied.fallbackBytes == Total
      when defined(ntSpliceControlTest):
        assert tls.conn.keyUpdatesOut >= 5, "splice must send due KeyUpdates"
        echo "PASS kTLS splice updates: ", tls.conn.keyUpdatesOut
      when defined(linux) and defined(ntSpliceFaultTest):
        assert rejectionPending() == 0 and copied.fallbackBytes == Total
        echo "PASS rejected kTLS splice output preserves all pipe bytes"
      else:
        assert copied.kernelBytes == Total and copied.fallbackBytes == 0
        echo "PASS kTLS splice: 2 MiB payload stays outside userspace"
      assert wait(addr producerDone, afterMs(10000)) == wrReady
  shutdownWrite(addr tls)
  var byteBuffer = [0'u8]
  when defined(linux) and defined(ntSpliceSequenceFaultTest):
    assert recvInto(addr tls, byteBuffer, afterMs(10000)) == -5
  else:
    assert recvInto(addr tls, byteBuffer, afterMs(10000)) == 0
  close(addr tls)
  assert wait(addr sinkDone, afterMs(10000)) == wrReady
  when defined(linux) and defined(ntSpliceSequenceFaultTest):
    assert sinkError == TlsTruncated and sinkCount == 0
  else:
    assert sinkError == 0
  close(addr source)
  close(addr producerTcp)
  closeNow(listener)
  discard close(tlsListener)

var chain: seq[Cert] = @[]
assert certsPem(slurp("tests/data/root.pem"), chain) == 1
let roots = newRoots()
if roots == nil: quit "no trust store"
assert addRoot(roots, chain[0])
for certificate in chain: release(certificate)
# The pin cannot setLen on a sequence of non-nil pointer elements.
# Released pointer values are never used again.
assert loadCertifiedKey(slurp("tests/data/leaf.pem") & slurp("tests/data/inter.pem"), slurp("tests/data/leaf.key"), key) == ""
serverConfig = defaultServerConfig()
serverConfig.resolver = singleCert(addr key)
clientConfig = defaultClientConfig(roots)
clientConfig.groups = @[kxX25519]
clientConfig.shareGroups = @[kxX25519]
assert runMain(main())
release(key)
release(roots)
