## TLS constructors preserve transport errors before the handshake starts.
import std/[assertions, syncio]
import zal_net/[rt, errors], zal_net/rt/cancel
import zal_net/raw/tcp
import zal_tls/raw

proc main() {.passive.} =
  let tokenBaseline = liveCancelTokens()
  var config = default(ClientConfig)
  var stream = default(TlsStream)
  let tok = newCancelToken()
  cancel(tok)
  assert connectTls("127.0.0.1", 0, addr config, addr stream, tok=tok) == ECancelled
  release(tok)
  # Pre-start cancellation leaves a default owner reusable.
  assert connectTls("127.0.0.1\0suffix", 0, addr config, addr stream) == InvalidInput
  assert not stream.isOpen
  assert connectTls("127.0.0.1", 0, addr config, addr stream) == ResourceBusy
  close(addr stream)
  close(addr stream)
  assert connectTls("127.0.0.1", 0, addr config, addr stream, deadline=afterMs(0)) == IoTimedOut
  close(addr stream)

  var listener = listenTcp(0, "127.0.0.1")
  assert listener.ok
  let port = listener.port
  closeNow(listener)
  const refusedCode = when defined(macosx): -61 else: -111
  let code = connectTls("127.0.0.1", port, addr config, addr stream, deadline=afterMs(5000))
  assert code == refusedCode, "TLS TCP refusal code " & $code
  assert not stream.isOpen
  close(addr stream)
  close(addr stream)
  assert liveCancelTokens() == tokenBaseline
  echo "PASS TLS preserves TCP errors, input rejection, deadlines and cancellation"

assert runMain(main())
