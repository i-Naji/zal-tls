## Narrow transport seam for the shared TLS handshake. Callbacks are synchronous
## and borrowed for the connection's lifetime; record connections leave it nil.
import zal_net/buffers
import zal_tls/common
import zal_tls/keys/schedule

type
  EncryptionLevel* = enum
    levelInitial, levelEarly, levelHandshake, levelApplication
  HandshakeWire* = object
    ctx*: nil pointer
    quic*: bool
    applicationContext*: string
    localParams*: ByteView
    readLevel*, writeLevel*: EncryptionLevel
    output*: nil proc (ctx: nil pointer; level: EncryptionLevel; data: Bytes; size: int): bool {.nimcall.}
    secret*: nil proc (ctx: nil pointer; level: EncryptionLevel; forRead: bool; suite: Suite; secret: Secret): bool {.nimcall.}
    parameters*: nil proc (ctx: nil pointer; data: Bytes; size: int): bool {.nimcall.}
  HandshakeWirePtr* = ptr HandshakeWire

proc bindContext*(wire: HandshakeWirePtr; original: string): string =
  ## Length-delimited context separates QUIC/handshake-only tickets from record
  ## TLS and from incompatible application or transport settings.
  result = (if wire.quic: "quic:" else: "handshake:") &
    $wire.applicationContext.len & ":" & wire.applicationContext & ":" & original

proc emitOutput*(wire: HandshakeWirePtr; level: EncryptionLevel; data: Bytes; size: int): bool =
  let callback = wire.output
  result = callback != nil and callback(wire.ctx, level, data, size)

proc emitSecret*(wire: HandshakeWirePtr; level: EncryptionLevel; forRead: bool;
                 suite: Suite; secret: Secret): bool =
  let callback = wire.secret
  result = callback != nil and callback(wire.ctx, level, forRead, suite, secret)

proc receiveParameters*(wire: HandshakeWirePtr; data: Bytes; size: int): bool =
  let callback = wire.parameters
  result = callback != nil and callback(wire.ctx, data, size)
