## Friendly configuration/connection lifetimes, custom adapters and close drain.
import std/[assertions, syncio]
import zal_net/[rt, errors], zal_net/rt/[sync, cancel]
import zal_net/foundation/tcp, zal_net/foundation/tcplistener, zal_net/net/address, zal_net/net/transport, zal_net/net/tcpview
import zal_tls/config/[owned, config]
import zal_tls/crypto/x509
import zal_tls/foundation/stream, zal_tls/net/tlsview

proc text(path: string): string =
  try: result = readFile(path)
  except: result = ""

type ContextObj = object
  config: nil ServerConfigRef
  done, entered: Event
  code: int
  abandonAfterShutdown: bool
  stayOpen: bool
type Context = ref ContextObj

proc newContext(): Context = Context()

proc server(listener: sink TcpListenerRef; context: sink Context) {.passive.} =
  let accepted = acceptConn(listener, streamTimeoutMs=0, deadline=afterMs(5000))
  assert accepted.code == 0, "ttlsref check 24"
  var tcp = accepted.value
  let cfg = context.config
  if cfg != nil:
    let cancelled = newCancelToken()
    cancel(cancelled)
    let before = tcp
    let rejected = takeTlsServer(cfg, tcp, tok=cancelled)
    assert rejected.code == ECancelled and tcp == before, "rejected transfer preserves the original Ref"
    let preserved = tcp
    if preserved != nil: assert state(preserved) == ownerOpen
    else: assert false
    release(cancelled)
    var established = default(TlsConnResult)
    if context.abandonAfterShutdown:
      let held = tcp
      if held != nil: established = borrowTlsServer(cfg, held, afterMs(5000))
      else: assert false
      assert tcp != nil, "borrow preserves the TCP owner"
    else:
      established = takeTlsServer(cfg, tcp, afterMs(5000))
      assert tcp == nil, "transfer consumes the TCP owner"
    assert established.code == 0, "TLS server constructor result " & $established.code
    let connection = established.value
    if connection != nil:
      context.config = nil
      var payload = default(array[8, byte])
      let count = recvInto(connection, payload, afterMs(5000))
      assert count == 1 and payload[0] == 9, "ttlsref check 35"
      assert sendFrom(connection, payload.toOpenArray(0, 0), afterMs(5000)) == 1, "ttlsref check 36"
      if context.stayOpen:
        context.code = recvInto(connection, payload, afterMs(5000))
        assert context.code < 0, "terminal close interrupts the peer"
        discard close(connection, afterMs(5000))
      else:
        assert shutdownWrite(connection) == 0, "ttlsref check 37"
      if not context.abandonAfterShutdown and not context.stayOpen:
        discard close(connection, afterMs(5000))
    else: assert false, "ttlsref check 40"
  else: assert false, "ttlsref check 41"
  setEvent(addr context.done)

var readEntered, readDone: Event
var readCode = 0
proc pending(owner: sink TlsConnRef) {.passive.} =
  var bytes = default(array[1, byte])
  setEvent(addr readEntered)
  readCode = recvInto(owner, bytes, afterMs(5000))
  setEvent(addr readDone)

proc exchange(clientCfg: ClientConfigRef; abandon: bool; stayOpen = false; mode = 0) {.passive.} =
  let context = newContext()
  context.abandonAfterShutdown = abandon
  context.stayOpen = stayOpen
  block:
    let built = newServerConfig(text("tests/data/leaf.pem") & text("tests/data/inter.pem"),
                                text("tests/data/leaf.key"))
    assert built.code == 0, "ttlsref check 89"
    context.config = built.value
  let bound = listenTcpRef(0, "127.0.0.1")
  let listener = bound.value
  if listener != nil:
    assert trySpawnTask(server(listener, context)), "ttlsref check 94"
    block:
      var connected = default(TlsConnResult)
      var transportHold: nil TcpConnRef = nil
      if mode == 0:
        connected = connectTlsConn(clientCfg, "127.0.0.1", port(listener),
                                   serverName="test.example", deadline=afterMs(5000), timeoutMs=5000)
      else:
        let tcpResult = connectTcpConn("127.0.0.1", port(listener), deadline=afterMs(5000))
        transportHold = tcpResult.value
        let tcp = transportHold
        if tcp == nil: assert false, "client TCP failed"
        else:
          let cancelled = newCancelToken()
          cancel(cancelled)
          if mode == 1:
            let rejected = takeTlsClient(clientCfg, transportHold, "test.example", tok=cancelled)
            assert rejected.code == ECancelled and transportHold == tcp
            assert state(tcp) == ownerOpen
            connected = takeTlsClient(clientCfg, transportHold, "test.example", afterMs(5000))
            assert transportHold == nil and state(tcp) == ownerClosed
          else:
            var view = tcpTransport(tcp)
            let rejected = takeTlsClient(clientCfg, view, "test.example", tok=cancelled)
            assert rejected.code == ECancelled and view.isOpen
            connected = takeTlsClient(clientCfg, view, "test.example", afterMs(5000))
            assert not view.isOpen
          release(cancelled)
      assert connected.code == 0, "TLS connect result " & $connected.code
      let connection = connected.value
      if connection != nil:
        let token = newCancelToken()
        cancel(token)
        var payload = [9'u8]
        assert recvInto(connection, payload, tok=token) == ECancelled, "ttlsref check 104"
        release(token)
        assert sendFrom(connection, payload, afterMs(5000)) == 1, "ttlsref check 106"
        var view = tlsTransport(connection)
        assert recvInto(view, payload, afterMs(5000)) == 1 and payload[0] == 9, "ttlsref check 108"
        if stayOpen:
          clearEvent(addr readEntered)
          clearEvent(addr readDone)
          let handle = nativeHandle(connection)
          assert trySpawnTask(pending(connection)), "pending reader task admitted"
          assert wait(addr readEntered, afterMs(5000)) == wrReady, "pending reader entered"
          assert recvInto(connection, payload) == ResourceBusy, "pending reader holds read admission"
          assert closeNow(connection) == ResourceBusy and nativeHandle(connection) == handle,
            "pending read rejects immediate disposal and preserves the descriptor"
          let closing = close(connection, afterMs(0))
          assert closing == 0 or closing == IoTimedOut
          if closing == IoTimedOut:
            let phase = state(connection)
            assert phase == ownerClosing or phase == ownerClosed,
              "close timeout ends the wait; retained cleanup may already finish"
          assert close(connection, afterMs(5000)) == 0
          assert wait(addr readDone, afterMs(5000)) == wrReady and readCode == ResourceClosed
        else:
          assert recvInto(connection, payload, afterMs(5000)) == 0, "ttlsref check 109"
        assert close(connection, afterMs(5000)) == 0, "ttlsref check 110"
        assert state(connection) == ownerClosed and close(connection) == 0, "ttlsref check 111"
        assert sendFrom(connection, payload) == ResourceClosed, "ttlsref check 112"
        let heldTcp = transportHold
        if heldTcp != nil: assert state(heldTcp) == ownerClosed
      else: assert false, "ttlsref check 113"
    assert wait(addr context.done, afterMs(5000)) == wrReady, "ttlsref check 114"
    assert context.config == nil, "ttlsref check 115"
    assert close(listener) == 0, "ttlsref check 116"
  else: assert false, "ttlsref check 117"
  yieldNow()

proc main() {.passive.} =
  assert newServerConfig("", "").code == InvalidInput, "ttlsref check 53"
  assert newServerConfig(text("tests/data/leaf.pem"), text("tests/data/rsa.key")).code == InvalidInput, "ttlsref check 54"
  assert newClientConfig(pemTrust("")).code == InvalidInput, "ttlsref check 55"
  assert newClientConfig(pemTrust(text("tests/data/root.pem")), @[""]).code == InvalidInput, "ttlsref check 56"
  var certs: seq[Cert] = @[]
  assert certsPem(text("tests/data/root.pem"), certs) == 1, "ttlsref check 58"
  let roots = newRoots()
  if roots != nil:
    assert addRoot(roots, certs[0]), "ttlsref check 61"
    let stored = newClientConfig(storeTrust(roots))
    assert stored.code == 0, "ttlsref check 63"
    release(roots)
    let cfg = stored.value
    if cfg != nil:
      let anchors = unsafeBorrowConfig(cfg).roots
      if anchors != nil: assert rootCount(anchors) == 1, "ttlsref check 68"
      else: assert false, "ttlsref check 69"
    else: assert false, "ttlsref check 70"
  else: assert false, "ttlsref check 71"
  release(certs[0])
  let clientBuilt = newClientConfig(pemTrust(text("tests/data/root.pem")))
  assert clientBuilt.code == 0, "ttlsref check 74"
  let clientCfg = clientBuilt.value
  if clientCfg != nil:
    when not defined(release):
      let baseline = liveTlsOwners()
    for cycle in 0..<6:
      exchange(clientCfg, cycle mod 2 == 0, mode=cycle mod 3)
    exchange(clientCfg, false, true)
    when not defined(release):
      let until = afterMs(5000)
      while liveTlsOwners() != baseline and monoNow() < until: parkUntil(afterMs(1))
      assert liveTlsOwners() == baseline, "TLS final owner/background lease leaked"
    assert connectTlsConn(clientCfg, "bad\0host", 1).code == InvalidInput, "ttlsref check 123"
    echo "PASS friendly TLS configuration retention, transfer, views, EOF and background lifetime"
  else: assert false, "ttlsref check 125"

assert runMain(main()), "ttlsref check 127"
