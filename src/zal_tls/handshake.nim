## Advanced, I/O-independent TLS handshake messages, without TLS records.
## Keep the owner at one address from init until release. Configurations are
## borrowed. Call step until need-input; pending events exert input backpressure.
## QUIC mode supplies transport parameters and traffic secrets, not QUIC packets.
import zal_net/buffers
import zal_tls/common
import zal_tls/config/config
import zal_tls/keys/schedule
import zal_tls/crypto/rand
import zal_tls/private/core/[conn, client, server]

import zal_tls/private/[rawbuf, handshakewire]
import zal_tls/wire/consts
export EncryptionLevel, Suite, Secret, wipe

type
  HandshakeMode* = enum
    handshakeTls, handshakeQuic
  HandshakeEvent* = enum
    heNeedInput, heOutput, heSecret, hePeerParameters, heEarlyData,
    heComplete, heFailed, heOutputBlocked
  EarlyDecision* = enum
    earlyNotOffered, earlyOffered, earlyAccepted, earlyRejected
  HandshakeOptions* = object
    mode*: HandshakeMode
    transportParameters*: ByteView
    applicationContext*: string  ## bind tickets to compatible application/transport settings
    maxQueuedBytes*: int         ## 0: 1 MiB; must fit one outbound handshake flight
  HandshakeResult* = object
    consumed*, dataLen*: int
    remaining*: int              ## this output/parameter event's bytes left
    level*: EncryptionLevel
    forRead*: bool
    suite*: Suite
    secret*: Secret              ## caller owns this copy: wipe after installing transport keys
    early*: EarlyDecision
    resumed*, peerCertificateVerified*: bool
    alert*: int
    queueLimitExceeded*: bool
  QueuedEvent = object
    kind: HandshakeEvent
    level: EncryptionLevel
    forRead: bool
    suite: Suite
    secret: Secret
    start, size: int
  Handshake* = object
    connection: TlsConn
    wire: HandshakeWire
    output: RawBuf
    localParameters: RawBuf
    peerParameters: RawBuf
    havePeerParameters: bool
    queue: array[32, QueuedEvent]
    head, tail: int
    maxQueued: int
    live, completed, limitExceeded: bool
    early: EarlyDecision
  HandshakePtr* = ptr Handshake

proc enqueue(h: HandshakePtr; event: QueuedEvent): bool =
  if h.tail >= h.queue.len:
    h.limitExceeded = true
    return false
  h.queue[h.tail] = event
  h.tail = h.tail + 1
  result = true

proc queueBytes(h: HandshakePtr; kind: HandshakeEvent; level: EncryptionLevel;
                data: Bytes; size: int): bool =
  if size < 0 or size > h.maxQueued - h.output.len:
    h.limitExceeded = true
    return false
  if not enqueue(h, QueuedEvent(kind: kind, level: level, start: h.output.len, size: size)):
    return false
  append(h.output, data, size)
  result = true

proc outputMessage(ctx: nil pointer; level: EncryptionLevel; data: Bytes; size: int): bool {.nimcall.} =
  if ctx == nil: return false
  let h = cast[HandshakePtr](ctx)
  result = queueBytes(h, heOutput, level, data, size)

proc trafficSecret(ctx: nil pointer; level: EncryptionLevel; forRead: bool;
                   suite: Suite; secret: Secret): bool {.nimcall.} =
  if ctx == nil: return false
  let h = cast[HandshakePtr](ctx)
  result = enqueue(h, QueuedEvent(kind: heSecret, level: level, forRead: forRead,
                                  suite: suite, secret: secret))

proc peerParameters(ctx: nil pointer; data: Bytes; size: int): bool {.nimcall.} =
  if ctx == nil: return false
  let h = cast[HandshakePtr](ctx)
  # A second ClientHello after HRR must carry the same parameters.
  if h.havePeerParameters:
    return size == h.peerParameters.len and ctEqual(base(h.peerParameters), data, size)
  if size > h.maxQueued: return false
  h.havePeerParameters = true
  append(h.peerParameters, data, size)
  result = queueBytes(h, hePeerParameters, h.wire.readLevel, data, size)

proc configure(h: HandshakePtr; options: HandshakeOptions): bool =
  result = false
  let limit = if options.maxQueuedBytes == 0: 1 shl 20 else: options.maxQueuedBytes
  if limit < 256 or limit > (1 shl 26) or options.transportParameters.len < 0 or
     options.transportParameters.len > 65535: return
  if options.transportParameters.len > 0 and options.transportParameters.data == nil: return
  h.maxQueued = limit
  h.wire = HandshakeWire(ctx: h, quic: options.mode == handshakeQuic,
    applicationContext: options.applicationContext, output: outputMessage,
    secret: trafficSecret, parameters: peerParameters)
  if h.wire.quic:
    let tp = options.transportParameters.data
    if tp != nil: append(h.localParameters, tp, options.transportParameters.len)
    h.wire.localParams = ByteView(data: base(h.localParameters), len: h.localParameters.len)
  h.connection.wire = addr h.wire
  h.live = true
  result = true

proc release*(h: HandshakePtr) =
  ## All callbacks are synchronous; no background task retains this owner.
  release(h.connection)
  free(h.output)
  free(h.localParameters)
  free(h.peerParameters)
  for i in 0 ..< h.queue.len: wipe(h.queue[i].secret)
  h[] = default(Handshake)

proc initClient*(h: HandshakePtr; cfg: ClientConfigPtr; name: string;
                 options = default(HandshakeOptions)): bool =
  if h.live: return false
  if options.mode == handshakeQuic and cfg.alpn.len == 0: return false
  if not client.initClient(h.connection, cfg, name): return false
  result = configure(h, options)
  if not result: release(h)

proc initServer*(h: HandshakePtr; cfg: ServerConfigPtr;
                 options = default(HandshakeOptions)): bool =
  if h.live: return false
  if options.mode == handshakeQuic and
     (cfg.alpn.len == 0 or (cfg.maxEarlyData != 0 and cfg.maxEarlyData != high(uint32))):
    return false
  if not server.initServer(h.connection, cfg): return false
  result = configure(h, options)
  if not result: release(h)

proc clear*(r: var HandshakeResult) =
  wipe(r.secret)
  r = default(HandshakeResult)

proc drain(h: HandshakePtr; outp: Bytes; outCap: int; r: var HandshakeResult): HandshakeEvent =
  let index = h.head
  let event = addr h.queue[index]
  r.level = event.level
  r.forRead = event.forRead
  r.suite = event.suite
  result = event.kind
  if event.kind == heOutput or event.kind == hePeerParameters:
    if event.size > 0 and outCap <= 0: return heOutputBlocked
    let count = min(outCap, event.size)
    if count > 0:
      let source = at(base(h.output), event.start)
      copyMem(outp, source, count)
      wipeBytes(source, count)
    event.start = event.start + count
    event.size = event.size - count
    r.dataLen = count
    r.remaining = event.size
    if event.size > 0: return
  else:
    r.secret = event.secret
  wipe(event.secret)
  event[] = default(QueuedEvent)
  h.head = h.head + 1
  if h.head == h.tail:
    h.head = 0
    h.tail = 0
    h.output.len = 0

proc fail(h: HandshakePtr; alert: int; r: var HandshakeResult): HandshakeEvent =
  h.connection.state = stateFailed
  h.connection.failAlert = alert
  freeHandshake(h.connection)
  for i in 0 ..< h.queue.len: wipe(h.queue[i].secret)
  h.head = 0
  h.tail = 0
  free(h.output)
  r.alert = alert
  r.queueLimitExceeded = h.limitExceeded
  result = heFailed

proc decision(h: HandshakePtr): EarlyDecision =
  if h.connection.earlyAccepted: return earlyAccepted
  if h.connection.earlyRejected: return earlyRejected
  let hs = h.connection.hs
  if hs != nil and hs.earlyOffered: return earlyOffered
  result = earlyNotOffered

proc pending(h: HandshakePtr; outp: Bytes; outCap: int;
             r: var HandshakeResult): HandshakeEvent =
  if h.head < h.tail: return drain(h, outp, outCap, r)
  let early = decision(h)
  if early != h.early:
    h.early = early
    r.early = early
    return heEarlyData
  if h.connection.state == stateConnected and not h.completed:
    h.completed = true
    h.connection.ready = true
    h.connection.readyPending = false
    r.resumed = h.connection.resumed
    r.peerCertificateVerified = h.connection.peerLeaf.len > 0
    freeHandshake(h.connection)
    return heComplete
  result = heNeedInput

proc step*(h: HandshakePtr; level: EncryptionLevel; inp: Bytes; inLen: int;
           outp: Bytes; outCap: int; r: var HandshakeResult): HandshakeEvent =
  ## Inputs are ordered, already decrypted handshake bytes at `level`. The caller
  ## retains input after r.consumed. Outputs can be fragmented down to one byte;
  ## zero output room returns heOutputBlocked without consuming new input.
  ## Each secret precedes bytes requiring it. Drain all events before feeding
  ## more input. Wipe r.secret after installing it; step also wipes the previous r.
  clear(r)
  if not h.live: return fail(h, alInternalError, r)
  if h.connection.state == stateFailed: return fail(h, h.connection.failAlert, r)
  if inLen < 0 or outCap < 0: return fail(h, alInternalError, r)
  result = pending(h, outp, outCap, r)
  if result != heNeedInput: return
  let hs = h.connection.hs
  if hs != nil and h.connection.state == csStart:
    let start = h.connection.onStart
    let alert = if start != nil: start(addr h.connection, hs) else: alInternalError
    if alert != 0: return fail(h, alert, r)
    return pending(h, outp, outCap, r)
  if inLen == 0: return heNeedInput
  if level != h.wire.readLevel: return fail(h, alUnexpectedMessage, r)
  # Consume at most one message. Bound allocation before accepting its body,
  # and never combine bytes from different encryption levels in one message.
  var used = 0
  if h.connection.msg.len < 4:
    let count = min(inLen, 4 - h.connection.msg.len)
    append(h.connection.msg, inp, count)
    used = count
  if h.connection.msg.len >= 4:
    let header = base(h.connection.msg)
    let size = 4 + (int(header[1]) shl 16) + (int(header[2]) shl 8) + int(header[3])
    if size > h.connection.maxMsg:
      r.consumed = used
      return fail(h, alDecodeError, r)
    let count = min(inLen - used, size - h.connection.msg.len)
    append(h.connection.msg, at(inp, used), count)
    used = used + count
    r.consumed = used
    if h.connection.msg.len == size:
      h.connection.keyChanged = false
      let alert = processMessages(h.connection)
      if alert != 0: return fail(h, alert, r)
      return pending(h, outp, outCap, r)
  r.consumed = used
  result = heNeedInput

proc alpn*(h: HandshakePtr): string = conn.alpn(h.connection)
proc isComplete*(h: HandshakePtr): bool = h.completed and h.connection.state == stateConnected
proc echRetryConfigs*(h: HandshakePtr): seq[byte] = conn.echRetryConfigs(h.connection)
proc exportKeyingMaterial*(h: HandshakePtr; label: string; context: Bytes; ctxLen: int;
                           outp: Bytes; outLen: int): bool =
  conn.exportKeyingMaterial(h.connection, label, context, ctxLen, outp, outLen)
