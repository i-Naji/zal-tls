from zal_net/io import IoResult, ioResult
from zal_net/buffers import dataPtr
## Application TLS over the existing record and transport implementations.
## Errors raise Nimony's ErrorCode; detailed I/O codes remain on the stream.
## Configuration owners are retained through handshake, I/O and final cleanup.
import zal_tls/config/owned as configs
import zal_tls/foundation/stream as owners
import zal_net/net/tcp
import zal_net/net/transport
import zal_net/net/failure
import zal_tls/errors
from zal_net/errors import NoProgress, ResourceClosed
import zal_net/rt/[time, cancel]

export configs.TrustSource, configs.pemTrust, configs.systemTrust, configs.storeTrust
export time, cancel.CancelToken, failure.IoFailure

type
  ClientConfig* = configs.ClientConfigRef
  ServerConfig* = configs.ServerConfigRef
  TlsStream* = owners.TlsConnRef

template newClientConfig*(trust: TrustSource; alpn: seq[string] = @[]): ClientConfig =
  block:
    let built = configs.newClientConfig(trust, alpn)
    checkTls(built.code)
    let value = built.value
    if value == nil:
      failIo(ResourceClosed)
    value

template newServerConfig*(certPem, keyPem: string; alpn: seq[string] = @[]): ServerConfig =
  block:
    let built = configs.newServerConfig(certPem, keyPem, alpn)
    checkTls(built.code)
    let value = built.value
    if value == nil:
      failIo(ResourceClosed)
    value

template connect*(config: ClientConfig; host: string; port: uint16;
                  serverName = ""; deadline: Deadline = never;
                  cancel: nil CancelToken = nil): TlsStream =
  block:
    let connected = owners.connectTlsConn(config, host, port,
      serverName=serverName, deadline=deadline, tok=cancel)
    checkTls(connected.code)
    let value = connected.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapBorrowed*(config: ClientConfig; transport: TcpStream; serverName: string;
                       deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.borrowTlsClient(config, transport, serverName, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapBorrowed*(config: ServerConfig; transport: TcpStream;
                       deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.borrowTlsServer(config, transport, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapBorrowed*(config: ClientConfig; transport: Transport; serverName: string;
                       deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  ## The retained adapter owns callback storage and keeps its context alive.
  block:
    let wrapped = owners.borrowTlsClient(config, transport, serverName, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapBorrowed*(config: ServerConfig; transport: Transport;
                       deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.borrowTlsServer(config, transport, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapOwned*(config: ClientConfig; transport: var nil TcpStream; serverName: string;
                    deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  ## Rejection preserves transport. Once handshake starts, transfer consumes
  ## it even on failure; all aliases of the original owner observe it closed.
  block:
    let wrapped = owners.takeTlsClient(config, transport, serverName, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapOwned*(config: ServerConfig; transport: var nil TcpStream;
                    deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.takeTlsServer(config, transport, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapOwned*(config: ClientConfig; transport: Transport; serverName: string;
                    deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.takeTlsClient(config, transport, serverName, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template wrapOwned*(config: ServerConfig; transport: Transport;
                    deadline: Deadline = never; cancel: nil CancelToken = nil): TlsStream =
  block:
    let wrapped = owners.takeTlsServer(config, transport, deadline, tok=cancel)
    checkTls(wrapped.code)
    let value = wrapped.value
    if value == nil:
      failIo(ResourceClosed)
    value

template read*(stream: TlsStream; buffer: var openArray[byte];
               deadline: Deadline = never; cancel: nil CancelToken = nil): int =
  block:
    let held = stream
    let count = owners.recvInto(held, buffer, deadline, cancel)
    owners.recordRead(held, if count < 0: count else: 0, if count > 0: count else: 0)
    checkTls(count)
    count

template write*(stream: TlsStream; buffer: openArray[byte];
                deadline: Deadline = never; cancel: nil CancelToken = nil) =
  block:
    let held = stream
    let bytes: openArray[byte] = buffer
    var outcome = ioResult(0, 0)
    owners.writeAllInto(held, dataPtr(bytes), bytes.len, deadline, cancel, outcome)
    checkTls(outcome.error)

template close*(stream: TlsStream; deadline: Deadline = never) =
  checkTls(owners.close(stream, deadline))

proc shutdownWrite*(stream: TlsStream) {.raises.} = checkTls(owners.shutdownWrite(stream))
proc lastReadFailure*(stream: TlsStream): IoFailure {.inline.} = owners.lastReadFailure(stream)
proc lastWriteFailure*(stream: TlsStream): IoFailure {.inline.} = owners.lastWriteFailure(stream)

template negotiatedProtocol*(stream: TlsStream): string =
  ## Empty means no ALPN was selected. HTTP can reject an unexpected protocol.
  # The pinned compiler mislowers a raises/string result in passive callers.
  block:
    let held = stream
    var protocol = ""
    checkTls(owners.negotiatedProtocol(held, protocol))
    protocol
