## Public kTLS relay adapter, payload/half-close and control transitions.
import std/[assertions, syncio]
import zal_net/raw
import zal_net/errors
when defined(ntSpliceControlTest):
  import zal_tls/[common, errors]
  import zal_tls/config/config
  include zal_tls/raw/stream
else:
  import zal_tls/raw
  import zal_tls/raw/splice
import zal_tls/raw/ktls
import zal_tls/crypto/[x509, kx]

proc slurp(path: string): string =
  try: result = readFile(path)
  except: result = ""
var key = default(CertifiedKey)
var serverConfig = default(ServerConfig)
var clientConfig = default(ClientConfig)
const Total = 2 * 1024 * 1024
const Prefix = when defined(linux) and defined(ntSplicePreloadedTest): 128 else: 0
proc pattern(index: int): byte = byte(index mod 251)
type Work = object
  done: Event
  bytes: int
  code: int
  result: KernelRelayStats

proc echoPeer(tcp: TcpStreamPtr): int {.passive.} =
  var tls = default(TlsStream)
  assert acceptTls(addr tls, tcp, addr serverConfig) == 0
  when defined(ntSpliceControlTest):
    assert setKeyUpdateInterval(tls.conn, 20)
  when Prefix > 0:
    var prefix = default(array[Prefix, byte])
    for index in 0..<prefix.len: prefix[index] = pattern(index)
    assert sendFrom(addr tls, prefix, afterMs(10000)) == prefix.len
  var buffer = default(array[16384, byte])
  while true:
    let count = recvInto(addr tls, buffer, afterMs(10000))
    when not defined(ntSpliceCancelTest): assert count >= 0
    if count <= 0: break
    var offset = 0
    while offset < count:
      let sent = sendFrom(addr tls, addr buffer[offset], count - offset, afterMs(10000))
      assert sent > 0
      offset = offset + sent
  when defined(ntSpliceControlTest) and defined(linux):
    assert tls.conn.keyUpdatesOut >= 5
  when defined(ntSpliceTruncateTest) and defined(linux):
    interrupt(addr tls)      # intentional bare TCP termination without close_notify
  else:
    shutdownWrite(addr tls)
  close(addr tls)
  result = 0

proc forwarding(plain: TcpStreamPtr; tls: TlsStreamPtr; work: ptr Work) {.passive.} =
  work.result = relayKernel(plain, tls, afterMs(10000))
  setEvent(addr work.done)

proc producing(plain: TcpStreamPtr; work: ptr Work) {.passive.} =
  var buffer = default(array[16384, byte])
  var count = 0
  while count < Total:
    for index in 0..<buffer.len: buffer[index] = pattern(count + index)
    assert writeAll(plain, buffer, afterMs(10000))
    count = count + buffer.len
  shutdownWrite(plain)
  setEvent(addr work.done)

proc stopper(token: CancelToken; done: ptr Event) {.passive.} =
  parkUntil(afterMs(20))
  cancel(token)
  setEvent(done)

proc main() {.passive.} =
  var remote = listenTcp(0, "127.0.0.1")
  serve(remote, echoPeer)
  var tls = default(TlsStream)
  assert connectTls("127.0.0.1", remote.port, addr clientConfig, addr tls, "test.example") == 0
  var listener = listenTcp(0, "127.0.0.1")
  var plain = connect("127.0.0.1", listener.port)
  var forwardingPlain = accept(listener)
  when Prefix > 0:
    var first = [0'u8]
    assert recvInto(addr tls, first, afterMs(10000)) == 1 and first[0] == pattern(0)
  let installed = useKtls(addr tls)
  when not defined(linux):
    let refused = relayKernel(addr forwardingPlain, addr tls, afterMs(10000))
    assert refused.toTls.error == KtlsUnavailable
    echo "SKIP kTLS compound relay requires Linux"
  else:
    if installed != 0:
      echo "SKIP kTLS not available: ", installed
    else:
      when defined(ntSpliceCancelTest):
        let token = newCancelToken()
        var stopped = default(Event)
        assert trySpawnTask(stopper(token, addr stopped))
        let cancelledRelay = relayKernel(addr forwardingPlain, addr tls, afterMs(10000), token)
        assert cancelledRelay.toTls.bytes == 0 and cancelledRelay.fromTls.bytes == 0
        assert cancelledRelay.toTls.error == ECancelled or cancelledRelay.fromTls.error == ECancelled
        assert wait(addr stopped, afterMs(10000)) == wrReady
        release(token)
        echo "PASS cancelling parked kTLS relay drains both pumps"
      else:
        var flow = default(Work)
        var sender = default(Work)
        assert trySpawnTask(forwarding(addr forwardingPlain, addr tls, addr flow))
        assert trySpawnTask(producing(addr plain, addr sender))
        var buffer = default(array[16384, byte])
        var count = 0
        while true:
          let received = recvInto(addr plain, buffer, afterMs(10000))
          when not defined(ntSpliceTruncateTest): assert received >= 0
          if received <= 0: break
          for index in 0..<received:
            let position = count + index
            when Prefix > 0:
              let expected = if position < Prefix - 1: pattern(position + 1) else: pattern(position - (Prefix - 1))
              assert buffer[index] == expected
            else:
              assert buffer[index] == pattern(position)
          count = count + received
        assert count == Total + max(Prefix - 1, 0)
        assert wait(addr sender.done, afterMs(10000)) == wrReady
        assert wait(addr flow.done, afterMs(10000)) == wrReady
        assert flow.result.toTls.error == 0
        when defined(ntSpliceTruncateTest): assert flow.result.fromTls.error == TlsTruncated
        else: assert flow.result.fromTls.error == 0
        assert flow.result.toTls.bytes == Total
        assert flow.result.fromTls.bytes == Total + max(Prefix - 1, 0)
        assert flow.result.toTls.kernelBytes == Total
        assert flow.result.fromTls.kernelBytes + flow.result.fromTls.fallbackBytes == Total + max(Prefix - 1, 0)
        when Prefix > 0: assert flow.result.fromTls.fallbackBytes >= Prefix - 1
        echo "PASS kTLS relay: TX kernel=", flow.result.toTls.kernelBytes, " RX kernel=", flow.result.fromTls.kernelBytes, " RX buffered=", flow.result.fromTls.fallbackBytes
  # Refused paths keep the connection usable and do not consume payload.
  shutdownWrite(addr tls)
  when not defined(linux):
    var buffer = [0'u8]
    assert recvInto(addr tls, buffer, afterMs(10000)) == 0
  close(addr tls)
  close(addr forwardingPlain)
  close(addr plain)
  closeNow(listener)
  discard close(remote)

var chain: seq[Cert] = @[]
assert certsPem(slurp("tests/data/root.pem"), chain) == 1
let roots = newRoots()
if roots == nil: quit "no store"
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
