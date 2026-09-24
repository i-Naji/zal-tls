## Included by private/core/conn: shared transcript, key installation, flight
## output and handshake lifetime for both record and handshake-only adapters.
# -------------------------------------------------------------- transcript

proc addTranscript*(hs: HandshakeStatePtr; p: Bytes; n: int) =
  if not hs.algKnown or hs.alg == hashSha256: discard update(hs.tr256, p, n)
  if not hs.algKnown or hs.alg == hashSha384: discard update(hs.tr384, p, n)

proc transcriptHash*(hs: HandshakeStatePtr; outp: Bytes) =
  if hs.alg == hashSha256: peek(hs.tr256, outp)
  else: peek(hs.tr384, outp)

proc restartTranscript*(hs: HandshakeStatePtr) =
  ## ClientHello1 becomes message_hash(Hash(ClientHello1)) (4.4.1).
  var h = default(array[48, byte])
  transcriptHash(hs, ptrOf(h))
  let n = digestLen(hs.alg)
  var mh = default(array[52, byte])
  mh[0] = byte(htMessageHash)
  mh[3] = byte(n)
  copyMem(addr mh[4], addr h[0], n)
  if hs.alg == hashSha256: init(hs.tr256, hashSha256)
  else: init(hs.tr384, hashSha384)
  addTranscript(hs, ptrOf(mh), 4 + n)

proc setSuite*(c: TlsConnPtr; hs: HandshakeStatePtr; s: Suite) =
  c.cs = s
  hs.alg = hashOf(s)
  hs.algKnown = true

# --------------------------------------------------------- output building

proc beginMsg*(hs: HandshakeStatePtr; need: int): Writer =
  ## A writer for one handshake message of at most `need` bytes.
  let p = grow(hs.stage, need)
  result = initWriter(p, hs.stage.len, need)

proc endMsg*(hs: HandshakeStatePtr; w: Writer): bool =
  ## Keep the message just written and add it to the transcript.
  if not w.ok: return false
  let p = base(hs.stage)
  addTranscript(hs, at(p, hs.stage.len), w.pos - hs.stage.len)
  hs.stage.len = w.pos
  result = true

proc lastMsg*(hs: HandshakeStatePtr; start: int): Bytes =
  at(base(hs.stage), start)

proc quicMode*(c: TlsConnPtr): bool {.inline.} =
  let wire = c.wire
  wire != nil and wire.quic

proc installTraffic*(c: TlsConnPtr; forRead: bool; level: EncryptionLevel;
                     suite: Suite; secret: Secret): bool =
  let wire = c.wire
  if wire == nil:
    if forRead: result = install(c.rd, suite, secret)
    else: result = install(c.wr, suite, secret)
  else:
    result = emitSecret(wire, level, forRead, suite, secret)
    if result:
      if forRead: wire.readLevel = level
      else: wire.writeLevel = level

proc boundSessionKey*(c: TlsConnPtr; cfg: ClientConfigPtr; name: string): string =
  result = sessionKey(cfg, name)
  let wire = c.wire
  if wire != nil: result = bindContext(wire, result)

proc flushStage*(c: TlsConnPtr; hs: HandshakeStatePtr; protected: bool; first = false): bool =
  ## Pack the staged messages into handshake records (sealed with `wr` when
  ## `protected`) at the end of the output queue.
  result = true
  let wire = c.wire
  if wire != nil:
    let level = if protected: wire.writeLevel else: levelInitial
    result = emitOutput(wire, level, base(hs.stage), hs.stage.len)
    hs.stage.len = 0
    return
  let src = base(hs.stage)
  var i = 0
  while i < hs.stage.len:
    let n = min(MaxPlaintext, hs.stage.len - i)
    let o = grow(hs.outb, RecordHeaderLen + n + 1 + AeadTagLen)
    copyMem(addr o[hs.outb.len + RecordHeaderLen], addr src[i], n)
    var recLen = 0
    if protected:
      recLen = sealRecord(c.wr, o, hs.outb.len, n, ctHandshake, 0)
    else:
      writePlainHeader(o, hs.outb.len, ctHandshake, n, first)
      recLen = RecordHeaderLen + n
    if recLen == 0: return false
    hs.outb.len = hs.outb.len + recLen
    i = i + n
  hs.stage.len = 0

proc queueCcs*(c: TlsConnPtr; hs: HandshakeStatePtr) =
  if c.wire != nil: return
  ## The middlebox-compatibility change_cipher_spec record (RFC 8446 D.4).
  var ccs = [20'u8, 3, 3, 0, 1, 1]
  append(hs.outb, ptrOf(ccs), ccs.len)
  hs.ccsSent = true

export randomFill

proc logSecret*(c: TlsConnPtr; hs: HandshakeStatePtr; label: string; s: Secret) =
  var kl = default(KeyLog)
  let cc = c.ccfg
  let sc = c.scfg
  if cc != nil: kl = cc.keyLog
  elif sc != nil: kl = sc.keyLog
  let f = kl.log
  if f != nil: f(kl.ctx, label, ptrOf(hs.clientRandom), s)

proc setAlpn*(c: TlsConnPtr; s: string) =
  c.alpnLen = min(s.len, c.alpnBuf.len)
  for i in 0 ..< c.alpnLen: c.alpnBuf[i] = byte(s[i])

proc setName*(c: TlsConnPtr; s: string) =
  c.nameLen = min(s.len, c.nameBuf.len)
  for i in 0 ..< c.nameLen: c.nameBuf[i] = byte(s[i])

proc nameOf*(c: TlsConnPtr): string =
  result = newString(c.nameLen)
  for i in 0 ..< c.nameLen: result[i] = char(c.nameBuf[i])

proc completeHandshake*(c: TlsConnPtr) =
  ## Called by a handshake when it is done: traffic from now on.
  c.state = stateConnected
  c.readyPending = true

proc installAppKeys*(c: TlsConnPtr; hs: HandshakeStatePtr; forRead: bool): bool =
  ## Our or the peer's application traffic keys from the schedule (no
  ## copies of the secrets besides the connection's own).
  let clientSide = c.role == roleClient
  if forRead:
    c.rdSecret = if clientSide: hs.sched.sAp else: hs.sched.cAp
    c.keyChanged = true
    result = installTraffic(c, true, levelApplication, c.cs, c.rdSecret)
  else:
    c.wrSecret = if clientSide: hs.sched.cAp else: hs.sched.sAp
    c.appWrite = true
    result = installTraffic(c, false, levelApplication, c.cs, c.wrSecret)

# ------------------------------------------------------------------- misc

proc freeHandshake*(c: var TlsConn) =
  let hs = c.hs
  if hs == nil: return
  wipe(hs.sched)
  wipe(hs.psk)
  for i in 0 ..< hs.keys.len: clear(hs.keys[i])
  release(hs.peerKey)
  free(hs.ch)
  free(hs.stage)
  free(hs.outb)
  free(hs.cookie)
  free(hs.certReqCtx)
  free(hs.clientLeafPending)
  free(hs.chOuter)
  free(hs.echRetryPending)
  clear(hs.echCtx)
  wipeBytes(hs, sizeof(HandshakeState))
  dealloc(hs)
  c.hs = nil
  if c.msg.len == 0: free(c.msg)

proc newHandshake*(c: var TlsConn): HandshakeStatePtr =
  result = cast[HandshakeStatePtr](alloc0(sizeof(HandshakeState)))
  init(result.tr256, hashSha256)
  init(result.tr384, hashSha384)
  init(result.trOuter256, hashSha256)
  init(result.trOuter384, hashSha384)
  c.hs = result
