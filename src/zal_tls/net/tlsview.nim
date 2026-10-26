## Retained transport adapter for composing protocols over a TLS connection.
import zal_net/net/transport
import zal_net/rt/[cancel, time]
import zal_tls/foundation/stream
import zal_net/unsafe/refcontext

proc connection(context: pointer): TlsConnRef {.inline.} =
  ## Only contexts created by retainTransport are accepted by this table.
  cast[TlsConnRef](context)

proc read(context: pointer; p: pointer; n: int; deadline: Deadline;
          tok: nil CancelToken): int {.nimcall, passive.} =
  let held = connection(context)
  result = recvInto(held, p, n, deadline, tok)

proc write(context: pointer; p: pointer; n: int; deadline: Deadline;
           tok: nil CancelToken): int {.nimcall, passive.} =
  let held = connection(context)
  result = sendFrom(held, p, n, deadline, tok)

proc halfCloseView(context: pointer) {.nimcall.} =
  let held = connection(context)
  discard halfClose(held)

proc abort(context: pointer) {.nimcall.} =
  let held = connection(context)
  discard interrupt(held)

proc closeView(context: pointer): int {.nimcall, passive.} =
  let held = connection(context)
  result = retire(held)

proc dispose(context: pointer): int {.nimcall.} =
  let held = connection(context)
  result = closeNow(held)

let operations = StreamOps(recv: read, send: write, shutdownWrite: halfCloseView,
                          interrupt: abort)


proc transferCheck(context: pointer): int {.nimcall.} =
  let held = connection(context)
  result = transferStatus(held)

proc tlsTransport*(owner: TlsConnRef): Transport =
  retainTransport(owner, operations, TransportControl(close: closeView,
    dispose: dispose, checkTransfer: transferCheck))
