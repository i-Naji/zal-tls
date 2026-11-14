# TLS on a `Conn`. After `secure`, the same connection value reads and writes
# plaintext, and code written for a plain `Conn` works unchanged.
#
#   let config = newClientConfig(systemTrust())
#   var c = connect("example.com", 443, afterMs(5_000))
#   c.secure(config, "example.com", afterMs(5_000))
#   c.write "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
#
#   var s = accept(listener)
#   s.secure(serverConfig, afterMs(5_000))
#
# `secure` runs the handshake and installs a layer on the connection. The
# layer owns the socket from then on and the TLS state with it, so both go
# when the `Conn` goes. A failed handshake raises and leaves the connection
# closed.
#
# Underneath is `zal_tls/raw/stream`, the stream the relay and kTLS paths
# use, so this adds no second implementation of the record layer.

import std/ticketlocks
import zal_net/conn as netconn
import zal_net/raw/tcp as rawtcp
import zal_net/unsafe/[streamview, refcontext]
import zal_net/errors as neterrors
import zal_tls/raw/stream
import zal_tls/config/owned
import zal_tls/private/streamlease
import zal_tls/errors

export netconn, owned.ClientConfigRef, owned.ServerConfigRef

type
  SecuredObj = object of LayerObj
    stream: TlsStream
    client: nil ClientConfigRef   ## the stream borrows its configuration
    server: nil ServerConfigRef
    lock: TicketLock
    background: int               ## queued flushes that still use the stream
    hold: nil Secured             ## keeps this alive while `background` > 0
  Secured = ref SecuredObj

proc `=destroy`(o: var SecuredObj) =
  ## Runs when the connection is gone and no flush is queued. Sends
  ## close_notify only if the socket takes it at once, then closes the socket.
  discard closeNow(addr o.stream)
  o.client = nil
  o.server = nil

proc `=wasMoved`(o: var SecuredObj) {.nodestroy, inline.} =
  zeroMem(addr o, sizeof(o))

proc acquireBackground(context: pointer) {.nimcall.} =
  let s = cast[Secured](context)
  s.lock.acquire()
  if s.background == 0: s.hold = s
  inc s.background
  s.lock.release()

proc dropBackground(context: pointer) {.nimcall.} =
  let s = cast[Secured](context)
  s.lock.acquire()
  dec s.background
  let last = s.background == 0
  s.lock.release()
  if last: s.hold = nil

proc layerRecv(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let s = cast[Secured](ctx)
  result = recvInto(addr s.stream, buf, count, until, tok)

proc layerSend(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let s = cast[Secured](ctx)
  result = sendFrom(addr s.stream, buf, count, until, tok)

proc layerShutdownWrite(ctx: pointer) {.nimcall.} =
  let s = cast[Secured](ctx)
  shutdownWrite(addr s.stream)

proc layerInterrupt(ctx: pointer) {.nimcall.} =
  let s = cast[Secured](ctx)
  interrupt(addr s.stream)

let tlsOps = StreamOps(recv: layerRecv, send: layerSend,
                       shutdownWrite: layerShutdownWrite, interrupt: layerInterrupt)

proc finish(s: Secured; c: var netconn.Conn; code: int): int =
  ## Install the layer either way: once the handshake has started the stream
  ## holds the socket, so the layer is what closes it.
  install(c, s, unsafeAddr tlsOps)
  result = code
  if code != 0:
    close c
  else:
    discard setBackgroundLease(addr s.stream, BackgroundLease(
      context: borrowRefContext(s), acquire: acquireBackground, drop: dropBackground))

proc trySecure*(connection: var netconn.Conn; config: ClientConfigRef; serverName: string;
                dl: Deadline = never): int {.passive.} =
  ## The client handshake with the failure as a code: 0, or a negative zal
  ## error. For callers that cannot raise, such as a server's accept hook.
  ## A failure closes the connection.
  let s = Secured()
  s.client = config
  var fd = releaseDescriptor(connection)
  var tcp = default(rawtcp.TcpStream)
  if not adoptTcp(addr tcp, fd, 0): return neterrors.ResourceClosed
  let code = takeClient(addr s.stream, addr tcp, unsafeBorrowConfig(config), serverName,
                        budget(connection, dl), tok = cancelToken(connection))
  result = finish(s, connection, code)

proc trySecure*(connection: var netconn.Conn; config: ServerConfigRef;
                dl: Deadline = never): int {.passive.} =
  ## The server handshake with the failure as a code.
  let s = Secured()
  s.server = config
  var fd = releaseDescriptor(connection)
  var tcp = default(rawtcp.TcpStream)
  if not adoptTcp(addr tcp, fd, 0): return neterrors.ResourceClosed
  let code = acceptTls(addr s.stream, addr tcp, unsafeBorrowConfig(config),
                       budget(connection, dl), tok = cancelToken(connection))
  result = finish(s, connection, code)

proc secure*(connection: var netconn.Conn; config: ClientConfigRef; serverName: string;
             dl: Deadline = never) {.passive, raises.} =
  ## Run the client handshake on a connected `Conn` and verify the server
  ## against `serverName`. `dl` bounds the handshake. A failure raises and
  ## leaves the connection closed.
  let code = trySecure(connection, config, serverName, dl)
  checkTls(code)
  if code != 0: raise ProtocolError

proc secure*(connection: var netconn.Conn; config: ServerConfigRef; dl: Deadline = never) {.passive, raises.} =
  ## Run the server handshake on an accepted `Conn`.
  let code = trySecure(connection, config, dl)
  checkTls(code)
  if code != 0: raise ProtocolError
