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
# A connection that already has a layer can be secured again, which is how
# TLS runs inside another tunnel. The new layer keeps the old one and sends
# its records through it.
#
# Underneath is `zal_tls/raw/stream`, the stream the relay and kTLS paths
# use, so this adds no second implementation of the record layer.

import std/ticketlocks
import zal_net/conn as netconn
import zal_net/raw/tcp as rawtcp
import zal_net/unsafe/streamview
import zal_net/errors as neterrors
import zal_tls/raw/stream
import zal_tls/config/owned
import zal_tls/private/streamlease
import zal_tls/errors

export netconn, owned.ClientConfigRef, owned.ServerConfigRef

type
  Secured = object
    ## The TLS state of one connection. It is allocated by hand and counted by
    ## hand: the `Conn` holds one count and each queued flush holds one, so a
    ## connection dropped with a close_notify still on its way out does not
    ## free the stream under the task that sends it.
    stream: TlsStream
    client: nil ClientConfigRef   ## the stream borrows its configuration
    server: nil ServerConfigRef
    lock: TicketLock
    holders: int
    inner: nil pointer            ## the layer underneath, when there was one
    innerRelease: LayerRelease
  SecuredPtr = ptr Secured

proc noRelease(ctx: pointer) {.nimcall.} = discard

proc newSecured(): SecuredPtr =
  result = cast[SecuredPtr](alloc0(sizeof(Secured)))
  result.holders = 1
  result.innerRelease = noRelease

proc retainLayer(ctx: pointer) {.nimcall.} =
  let s = cast[SecuredPtr](ctx)
  s.lock.acquire()
  inc s.holders
  s.lock.release()

proc releaseLayer(ctx: pointer) {.nimcall.} =
  ## Drop one count. The last one sends close_notify if the socket takes it
  ## at once, closes the socket, and then lets go of the layer underneath,
  ## whose operations the stream was borrowing until that moment.
  let s = cast[SecuredPtr](ctx)
  s.lock.acquire()
  dec s.holders
  let last = s.holders == 0
  s.lock.release()
  if last:
    discard closeNow(addr s.stream)
    s.client = nil
    s.server = nil
    let below = s.inner
    if below != nil: s.innerRelease(below)
    dealloc(s)

proc layerRecv(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let s = cast[SecuredPtr](ctx)
  result = recvInto(addr s.stream, buf, count, until, tok)

proc layerSend(ctx: pointer; buf: pointer; count: int; until: Deadline;
               tok: nil CancelToken): int {.nimcall, passive.} =
  let s = cast[SecuredPtr](ctx)
  result = sendFrom(addr s.stream, buf, count, until, tok)

proc layerShutdownWrite(ctx: pointer) {.nimcall.} =
  let s = cast[SecuredPtr](ctx)
  shutdownWrite(addr s.stream)

proc layerInterrupt(ctx: pointer) {.nimcall.} =
  let s = cast[SecuredPtr](ctx)
  interrupt(addr s.stream)

let tlsOps = StreamOps(recv: layerRecv, send: layerSend,
                       shutdownWrite: layerShutdownWrite, interrupt: layerInterrupt)

proc finish(s: SecuredPtr; c: var netconn.Conn; code: int): int =
  ## Install the layer either way: once the handshake has started the stream
  ## holds the socket, so the layer is what closes it.
  install(c, s, unsafeAddr tlsOps, releaseLayer)
  result = code
  if code != 0:
    close c
  else:
    discard setBackgroundLease(addr s.stream, BackgroundLease(
      context: s, acquire: retainLayer, drop: releaseLayer))

proc trySecure*(connection: var netconn.Conn; config: ClientConfigRef; serverName: string;
                dl: Deadline = never; earlyData: nil pointer = nil;
                earlyLen = 0): int {.passive.} =
  ## The client handshake with the failure as a code: 0, or a negative zal
  ## error. For callers that cannot raise, such as a server's accept hook.
  ## A failure closes the connection.
  ##
  ## `earlyData` is sent with the handshake as 0-RTT when the configuration
  ## holds a ticket that allows it, and right after the handshake otherwise.
  ## An attacker can replay 0-RTT, so only an idempotent request belongs there.
  let s = newSecured()
  s.client = config
  var belowOps: nil StreamOpsPtr = nil
  let below = takeLayer(connection, belowOps, s.innerRelease)
  var code = 0
  var tcp = default(rawtcp.TcpStream)
  if below != nil and belowOps != nil:
    s.inner = below
    code = unsafeWrapClient(addr s.stream, unsafeBorrowStream(below, belowOps),
                            unsafeBorrowConfig(config), serverName,
                            budget(connection, dl), tok = cancelToken(connection))
  else:
    var fd = releaseDescriptor(connection)
    if not adoptTcp(addr tcp, fd, 0):
      releaseLayer(s)
      return neterrors.ResourceClosed
    code = takeClient(addr s.stream, addr tcp, unsafeBorrowConfig(config), serverName,
                      budget(connection, dl), tok = cancelToken(connection),
                      earlyData = earlyData, earlyLen = earlyLen)
  result = finish(s, connection, code)
  # A handshake refused before it began (a cancelled token) never took the
  # socket. Close it here, after `finish` has told the token about it.
  if tcp.isOpen: close(addr tcp)

proc trySecure*(connection: var netconn.Conn; config: ServerConfigRef;
                dl: Deadline = never): int {.passive.} =
  ## The server handshake with the failure as a code.
  let s = newSecured()
  s.server = config
  var belowOps: nil StreamOpsPtr = nil
  let below = takeLayer(connection, belowOps, s.innerRelease)
  var code = 0
  var tcp = default(rawtcp.TcpStream)
  if below != nil and belowOps != nil:
    s.inner = below
    code = unsafeWrapServer(addr s.stream, unsafeBorrowStream(below, belowOps),
                            unsafeBorrowConfig(config),
                            budget(connection, dl), tok = cancelToken(connection))
  else:
    var fd = releaseDescriptor(connection)
    if not adoptTcp(addr tcp, fd, 0):
      releaseLayer(s)
      return neterrors.ResourceClosed
    code = acceptTls(addr s.stream, addr tcp, unsafeBorrowConfig(config),
                     budget(connection, dl), tok = cancelToken(connection))
  result = finish(s, connection, code)
  # A handshake refused before it began (a cancelled token) never took the
  # socket. Close it here, after `finish` has told the token about it.
  if tcp.isOpen: close(addr tcp)

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

proc secured(c: netconn.Conn): nil SecuredPtr =
  ## The TLS layer of `c`, recognised by its operation table.
  result = nil
  let layer = layerContext(c)
  if layer != nil and layerOps(c) == unsafeAddr tlsOps:
    result = cast[SecuredPtr](layer)

proc isSecure*(c: netconn.Conn): bool = secured(c) != nil
  ## Whether `secure` ran on this connection.

proc negotiatedProtocol*(c: netconn.Conn): string =
  ## The ALPN protocol both sides agreed on. Empty when none was chosen or
  ## the connection is not secured.
  result = ""
  let s = secured(c)
  if s != nil: result = alpn(addr s.stream)

proc resumed*(c: netconn.Conn): bool =
  ## Whether the handshake resumed an earlier session.
  result = false
  let s = secured(c)
  if s != nil: result = resumed(addr s.stream)

proc earlyBytes*(c: netconn.Conn): int =
  ## Server side: how many of the first bytes read arrived as 0-RTT. Those
  ## can be a replay, so act on them only if the request is idempotent.
  result = 0
  let s = secured(c)
  if s != nil: result = earlyBytes(addr s.stream)
