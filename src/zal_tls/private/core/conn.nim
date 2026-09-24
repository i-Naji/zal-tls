## A TLS 1.3 connection, sans I/O. `step` takes the bytes that arrived and
## gives back the bytes to send, application data decrypted in place, and
## events. The client and server handshakes (client.nim, server.nim) plug
## in their message handlers; this module owns records, handshake message
## reassembly, the output queue, alerts, the post-handshake messages and
## the exporters.

import zal_tls/private/[rawbuf, handshakewire]
export rawbuf
import std/atomics
import zal_tls/common
import zal_tls/crypto/[aead, hash, hpke, kx, sig, rand]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages]
import zal_tls/config/config

# Cohesive source components share one private compilation unit. Separate C
# units duplicated type/glue output and measurably increased clean build time.
include zal_tls/private/core/connectionstate
include zal_tls/private/core/handshakeops

const
  KeyUpdateAfter* = 1'u64 shl 24       ## records per AES-GCM key before a key update
  MaxCcs = 4                           ## change_cipher_spec records tolerated
  MaxEmptyRecords = 32                 ## empty application records in a row tolerated
  MaxEarlySkip = 1 shl 16              ## 0-RTT bytes skipped at least (tickets from elsewhere)

proc skipLimit(c: TlsConn): int =
  ## 0-RTT a server skips at most: what its tickets allow (the one offered
  ## too, when it opened), 64 KiB at least.
  let sc = c.scfg
  result = if sc != nil: max(MaxEarlySkip, int(sc.maxEarlyData)) else: MaxEarlySkip
  let hs = c.hs
  if hs != nil: result = max(result, int(hs.earlySkipMax))

proc reasonOf(alert: int; received: bool): string =
  let what = case alert
    of alCloseNotify: "close notify"
    of alUnexpectedMessage: "unexpected message"
    of alBadRecordMac: "bad record MAC"
    of alRecordOverflow: "record overflow"
    of alHandshakeFailure: "handshake failure"
    of alBadCertificate: "bad certificate"
    of alUnsupportedCertificate: "unsupported certificate"
    of alCertificateExpired: "certificate expired or not yet valid"
    of alCertificateUnknown: "certificate unknown"
    of alIllegalParameter: "illegal parameter"
    of alUnknownCa: "unknown certificate authority"
    of alDecodeError: "decode error"
    of alDecryptError: "decrypt error (bad signature or Finished)"
    of alProtocolVersion: "protocol version"
    of alInsufficientSecurity: "insufficient security"
    of alInternalError: "internal error"
    of alMissingExtension: "missing extension"
    of alUnsupportedExtension: "unsupported extension"
    of alUnrecognizedName: "unrecognized name"
    of alNoApplicationProtocol: "no application protocol"
    of alEchRequired: "ECH required (refused: see the retry configs)"
    of alCertificateRequired: "certificate required"
    else: "alert " & $alert
  result = if received: "peer sent: " & what else: what

proc alertRecord(c: var TlsConn; level, desc: int; outp: Bytes; cap: int; plain = false): int =
  ## An alert record at outp[0 ..]: 0 when it does not fit.
  if cap < RecordHeaderLen + 2 + 1 + AeadTagLen: return 0
  outp[RecordHeaderLen] = byte(level)
  outp[RecordHeaderLen + 1] = byte(desc)
  if c.wr.live and not plain:
    result = sealRecord(c.wr, outp, 0, 2, ctAlert, 0)
  else:
    writePlainHeader(outp, 0, ctAlert, 2, false)
    result = RecordHeaderLen + 2

proc fail(c: var TlsConn; alert: int; outp: Bytes; outCap: int;
          r: var StepResult): Step =
  c.failAlert = alert
  r.alert = alert
  r.reason = reasonOf(alert, false)
  # A server that has not answered the ClientHello yet: the client has no
  # keys, the alert goes out in plaintext (its ServerHello never will).
  # A client waiting for the ServerHello: plaintext too (not under its
  # early keys, which a server that refused 0-RTT skips).
  let plain = (c.role == roleServer and (c.state == ssStart or c.state == ssWaitCh2)) or
              (c.role == roleClient and c.state == csWaitSh)
  # A client that offered 0-RTT still writes under the early keys until
  # EncryptedExtensions: its alert goes under the handshake keys, which the
  # server reads whether it took the 0-RTT or not (it skips early records
  # it refused).
  let hsf = c.hs
  if c.role == roleClient and c.state == csWaitEe and hsf != nil and hsf.earlyOffered and
     hsf.sched.cHs.n > 0:
    if not install(c.wr, c.cs, hsf.sched.cHs):
      # Never emit an alert using stale early-data keys after key setup failed.
      c.state = stateFailed
      c.wrClosed = true
      c.failAlert = alInternalError
      r.alert = alInternalError
      r.reason = reasonOf(alInternalError, false)
      r.outLen = 0
      freeHandshake(c)
      return stFailed
  c.state = stateFailed
  r.outLen = alertRecord(c, 2, alert, outp, outCap, plain)
  c.wrClosed = true
  freeHandshake(c)
  result = stFailed

proc failedByPeer(c: var TlsConn; alert: int; r: var StepResult): Step =
  c.state = stateFailed
  c.failAlert = alert
  c.failReceived = true
  r.alert = alert
  r.reason = reasonOf(alert, true)
  freeHandshake(c)
  result = stFailed

proc drain(c: var TlsConn; outp: Bytes; outCap: int; r: var StepResult): bool =
  ## Pending output into outp; true when there was some.
  let hs = c.hs
  if hs == nil or hs.outb.len == 0: return false
  let n = min(outCap, hs.outb.len - hs.outSent)
  if n <= 0: return false
  copyMem(outp, at(base(hs.outb), hs.outSent), n)
  hs.outSent = hs.outSent + n
  if hs.outSent == hs.outb.len:
    hs.outb.len = 0
    hs.outSent = 0
    if c.state == stateConnected: freeHandshake(c)
  r.outLen = n
  result = true

# ---------------------------------------------------- post-handshake messages

proc alpn*(c: TlsConn): string =
  ## The protocol agreed by ALPN ("" for none).
  result = newString(c.alpnLen)
  for i in 0 ..< c.alpnLen: result[i] = char(c.alpnBuf[i])

proc serverName*(c: TlsConn): string =
  result = newString(c.nameLen)
  for i in 0 ..< c.nameLen: result[i] = char(c.nameBuf[i])

proc postHandshake(c: var TlsConn; typ: int; msg: Bytes; len: int): int =
  case typ
  of htNewSessionTicket:
    if c.role != roleClient: return alUnexpectedMessage
    var tv = default(TicketView)   # not `t`: the store hook's parameter name leaks (Nimony bug c37)
    result = parseNewSessionTicket(msg, len, tv)
    if result != 0: return
    if quicMode(addr c) and tv.maxEarlyData != 0 and tv.maxEarlyData != high(uint32):
      return alIllegalParameter
    let cfg = c.ccfg
    if cfg == nil: return
    let put = cfg.sessions.put
    if put == nil or c.resumption.n == 0 or tv.ticketLen > MaxTicketLen: return
    # A ticket to offer later: its PSK from the resumption secret and nonce (4.6.1).
    var st = default(SessionTicket)
    st.ticket = newSeq[byte](tv.ticketLen)
    copyMem(addr st.ticket[0], addr msg[tv.ticketAt], tv.ticketLen)
    st.psk = ticketPsk(hashOf(c.cs), c.resumption, at(msg, tv.nonceAt), tv.nonceLen)
    st.suite = c.cs
    st.alpn = alpn(c)
    st.serverName = boundSessionKey(addr c, cfg, serverName(c))   # (with the client certificate's tag)
    let clk = cfg.clock
    st.issuedMs = if clk != nil: clk() else: unixMs()
    st.lifetime = min(tv.lifetime, 604800'u32)
    st.ageAdd = tv.ageAdd
    st.maxEarlyData = tv.maxEarlyData
    if c.peerLeaf.len > 0:                       # the server's certificate, for after resumption
      st.serverLeaf = newSeq[byte](c.peerLeaf.len)
      copyMem(addr st.serverLeaf[0], base(c.peerLeaf), c.peerLeaf.len)
    if st.psk.n > 0 and st.lifetime > 0: put(cfg.sessions.ctx, addr st)
    wipe(st.psk)
  of htKeyUpdate:
    if c.wire != nil: return alUnexpectedMessage
    var requested = false
    result = parseKeyUpdate(msg, len, requested)
    if result != 0: return
    c.rdSecret = nextTrafficSecret(hashOf(c.cs), c.rdSecret)
    if c.rdSecret.n == 0 or not install(c.rd, c.cs, c.rdSecret): return alInternalError
    c.keyChanged = true
    c.keyUpdatesIn = c.keyUpdatesIn + 1
    # One reply, however many requests arrive before it goes out (4.6.3);
    # the writer seals it just before its next record (`takeControl`). The
    # two flags cross between a relay's two pumps: atomics.
    if requested and not atomicLoad(c.wrClosed, moAcquire): atomicStore(c.replyOwed, true, moRelease)
  else:
    result = alUnexpectedMessage

proc processMessages*(c: var TlsConn): int =
  ## Handle every complete message in the reassembly buffer.
  result = 0
  while c.msg.len >= 4 and c.state != stateFailed:
    let p = base(c.msg)
    let mlen = (int(p[1]) shl 16) or (int(p[2]) shl 8) or int(p[3])
    if mlen + 4 > c.maxMsg: return alDecodeError
    if c.msg.len < 4 + mlen: break
    let typ = int(p[0])
    let hs = c.hs
    if c.state == stateConnected or hs == nil:
      result = postHandshake(c, typ, p, 4 + mlen)
    else:
      let f = c.onMsg
      result = if f == nil: alInternalError else: f(addr c, hs, typ, p, 4 + mlen)
    if result != 0: return
    let rest = c.msg.len - (4 + mlen)
    if rest > 0: moveMem(p, addr p[4 + mlen], rest)
    c.msg.len = rest
    if c.keyChanged and rest > 0: return alUnexpectedMessage
  if c.msg.len > 4:
    let p = base(c.msg)
    let mlen = (int(p[1]) shl 16) or (int(p[2]) shl 8) or int(p[3])
    if mlen + 4 > c.maxMsg: return alDecodeError

# ---------------------------------------------------------------------- step

proc step*(c: var TlsConn; inp: Bytes; inLen: int;
           outp: Bytes; outCap: int; r: var StepResult): Step =
  ## Advance the connection. See `Step` for what each result asks of the
  ## caller; `r.consumed` input bytes are used up in every case.
  r = default(StepResult)
  if c.state == stateFailed:
    r.alert = c.failAlert
    r.reason = reasonOf(c.failAlert, c.failReceived)
    return stFailed
  if drain(c, outp, outCap, r): return stSend
  if c.readyPending:
    c.readyPending = false
    c.ready = true
    return stReady
  let hs0 = c.hs
  if hs0 != nil and c.state == csStart:
    let f = c.onStart
    let a = if f == nil: alInternalError else: f(addr c, hs0)
    if a != 0: return fail(c, a, outp, outCap, r)
    if drain(c, outp, outCap, r): return stSend
  if c.rdClosed:
    return (if c.wrClosed: stClosed else: stPeerClosed)
  var pos = 0
  while pos < inLen:
    let n = recordLen(inp, pos, inLen - pos)
    if n == 0: break
    if n < 0:
      r.consumed = pos
      return fail(c, -n, outp, outCap, r)
    let ct = int(inp[pos])
    var typ = 0
    var off = 0
    var len = 0
    let hsNow = c.hs
    if ct == ctChangeCipherSpec:
      # Dropped during the handshake (RFC 8446 5): one byte, 0x01.
      c.ccsSeen = c.ccsSeen + 1
      if c.state == stateConnected or c.state == csStart or c.state == ssStart or
         n != RecordHeaderLen + 1 or inp[pos + RecordHeaderLen] != 1 or c.ccsSeen > MaxCcs:
        r.consumed = pos
        return fail(c, alUnexpectedMessage, outp, outCap, r)
      pos = pos + n
      continue
    elif hsNow != nil and hsNow.skipEarly and ct == ctApplicationData and
         (not c.rd.live or openRecord(c.rd, inp, pos, n, typ, off, len) != 0):
      # 0-RTT data we did not accept (4.2.10): skipped, as much as our
      # tickets let a client send (counted as plaintext: at least a
      # record's overhead less), and at least MaxEarlySkip.
      hsNow.earlySkipped = hsNow.earlySkipped + max(0, n - RecordHeaderLen - 1 - AeadTagLen)
      if hsNow.earlySkipped > skipLimit(c):
        r.consumed = pos
        return fail(c, alBadRecordMac, outp, outCap, r)
      pos = pos + n
      continue
    elif c.rd.live and ct == ctAlert and
         (c.state == ssWaitFinished or c.state == ssWaitEoed or c.state == ssWaitClientCert) and
         n == RecordHeaderLen + 2:
      # A client that could not use our ServerHello answers in plaintext.
      typ = ctAlert
      off = pos + RecordHeaderLen
      len = 2
    elif c.rd.live:
      if hsNow != nil and hsNow.skipEarly:
        hsNow.skipEarly = false                  # opened above: the client's own records now
      elif ct != ctApplicationData:
        r.consumed = pos
        return fail(c, alUnexpectedMessage, outp, outCap, r)
      else:
        let a = openRecord(c.rd, inp, pos, n, typ, off, len)
        if a != 0:
          r.consumed = pos
          return fail(c, a, outp, outCap, r)
    else:
      if ct != ctHandshake and ct != ctAlert:
        r.consumed = pos
        return fail(c, alUnexpectedMessage, outp, outCap, r)
      if n - RecordHeaderLen > MaxPlaintext:
        r.consumed = pos
        return fail(c, alRecordOverflow, outp, outCap, r)
      typ = ct
      off = pos + RecordHeaderLen
      len = n - RecordHeaderLen
    pos = pos + n
    r.consumed = pos
    if typ != ctHandshake and c.msg.len > 0:
      return fail(c, alUnexpectedMessage, outp, outCap, r)   # a message was cut by another type
    case typ
    of ctHandshake:
      if len == 0: return fail(c, alUnexpectedMessage, outp, outCap, r)
      append(c.msg, at(inp, off), len)          # processMessages bounds each message
      c.keyChanged = false
      let a = processMessages(c)
      if a != 0: return fail(c, a, outp, outCap, r)
      let hs1 = c.hs
      if c.state == stateConnected and hs1 != nil and hs1.outb.len == 0: freeHandshake(c)
      if drain(c, outp, outCap, r): return stSend
      if c.readyPending:
        c.readyPending = false
        c.ready = true
        return stReady
    of ctAlert:
      if len != 2: return fail(c, alDecodeError, outp, outCap, r)
      let desc = int(inp[off + 1])
      if desc == alCloseNotify:
        c.rdClosed = true
        freeHandshake(c)
        return (if c.wrClosed: stClosed else: stPeerClosed)
      if desc != 90:                                   # user_canceled: close_notify follows
        return failedByPeer(c, desc, r)
    of ctApplicationData:
      if c.state == ssWaitEoed and hsNow != nil:
        # 0-RTT we took: delivered as it comes, up to the ticket's limit (4.2.10).
        hsNow.earlySent = hsNow.earlySent + len
        if uint64(hsNow.earlySent) > uint64(hsNow.earlyMax): return fail(c, alUnexpectedMessage, outp, outCap, r)
        if len > 0:
          r.off = off
          r.len = len
          return stEarlyData
        continue
      if c.state != stateConnected: return fail(c, alUnexpectedMessage, outp, outCap, r)
      if len > 0:
        c.emptyRun = 0
        r.off = off
        r.len = len
        return stAppData
      c.emptyRun = c.emptyRun + 1
      if c.emptyRun > MaxEmptyRecords: return fail(c, alUnexpectedMessage, outp, outCap, r)
    else:
      return fail(c, alUnexpectedMessage, outp, outCap, r)
  r.consumed = pos
  result = stNeedInput

# ------------------------------------------------------------- after the handshake

proc sealApp*(c: var TlsConn; buf: Bytes; off, len: int): int =
  ## Application data at buf[off+5 ..< off+5+len] into a record in place
  ## (see `sealRecord`); 0 before the handshake is complete, after `close`,
  ## or for more than 16384 bytes. Call `takeControl` first: a key update
  ## the peer asked for must go out before the next record.
  if c.state != stateConnected or not c.appWrite or c.wrClosed or len > MaxPlaintext: return 0
  result = sealRecord(c.wr, buf, off, len, ctApplicationData, 0)

proc sealEarly*(c: var TlsConn; buf: Bytes; off, len: int): int =
  ## Client 0-RTT: data at buf[off+5 ..< off+5+len] into an early record in
  ## place, after the ClientHello's record went out and before the server
  ## answers; 0 when early data is not possible now, or over the ticket's
  ## limit. Replayable by an attacker: only idempotent requests.
  let hs = c.hs
  if not c.earlyWrite or hs == nil or hs.outb.len > 0 or len <= 0 or len > MaxPlaintext: return 0
  if uint64(hs.earlySent + len) > uint64(hs.earlyMax): return 0
  result = sealRecord(c.wr, buf, off, len, ctApplicationData, 0)
  if result > 0: hs.earlySent = hs.earlySent + len

proc keyUpdateDue*(c: TlsConn): bool =
  ## The write key has sealed enough records: send `keyUpdate` next.
  c.wr.seq >= (if c.keyUpdateEvery > 0: c.keyUpdateEvery else: KeyUpdateAfter)

proc handshakeRecord*(c: var TlsConn; p: Bytes; n: int): int =
  ## The plaintext of a handshake record opened outside `step` (the relay
  ## framer): tickets, key updates (read keys rolled, a reply owed). 0 or
  ## the alert.
  if c.state != stateConnected or n <= 0: return alUnexpectedMessage
  append(c.msg, p, n)
  c.keyChanged = false
  result = processMessages(c)

proc keyUpdate*(c: var TlsConn; requestPeer: bool; outp: Bytes; outCap: int): int =
  ## A KeyUpdate record at outp (then new write keys); 0 when not connected.
  ## It also answers a key update the peer asked for.
  if c.state != stateConnected or c.wrClosed or outCap < 32: return 0
  var w = initWriter(outp, RecordHeaderLen, outCap - RecordHeaderLen)
  writeKeyUpdate(w, requestPeer)
  result = sealRecord(c.wr, outp, 0, w.pos - RecordHeaderLen, ctHandshake, 0)
  if result == 0: return
  c.wrSecret = nextTrafficSecret(hashOf(c.cs), c.wrSecret)
  if c.wrSecret.n == 0 or not install(c.wr, c.cs, c.wrSecret): return 0
  c.keyUpdatesOut = c.keyUpdatesOut + 1
  atomicStore(c.replyOwed, false, moRelease)

proc rollWriteKey*(c: var TlsConn): bool =
  ## Our write secret moves on after a KeyUpdate someone else sealed (the
  ## kernel, with kTLS); a reply owed is paid.
  if c.state != stateConnected: return false
  c.wrSecret = nextTrafficSecret(hashOf(c.cs), c.wrSecret)
  result = c.wrSecret.n != 0 and install(c.wr, c.cs, c.wrSecret)
  if result: c.keyUpdatesOut = c.keyUpdatesOut + 1
  atomicStore(c.replyOwed, false, moRelease)

proc takeControl*(c: var TlsConn; outp: Bytes; outCap: int): int =
  ## The control records owed before our next record (the key update the
  ## peer asked for), sealed now; 0 when none. The caller sends them first.
  if not atomicLoad(c.replyOwed, moAcquire): return 0
  result = keyUpdate(c, false, outp, outCap)

proc replyDue*(c: var TlsConn): bool =
  ## A key update the peer asked for is owed (any thread).
  atomicLoad(c.replyOwed, moAcquire)

proc close*(c: var TlsConn; outp: Bytes; outCap: int): int =
  ## A close_notify record at outp; nothing more may be sent after it.
  if c.wrClosed or c.state == stateFailed: return 0
  result = alertRecord(c, 1, alCloseNotify, outp, outCap)
  if result > 0: atomicStore(c.wrClosed, true, moRelease)

proc suite*(c: TlsConn): Suite = c.cs

proc echRetryConfigs*(c: var TlsConn): seq[byte] =
  ## Client: the ECHConfigList a server that refused our ECH sent, once it
  ## proved to be the public name's (its Finished verified; the handshake
  ## then ended with our ech_required): try again with it. Empty otherwise,
  ## or when that server sent none (it takes no ECH now).
  result = newSeq[byte](c.echRetry.len)
  if c.echRetry.len > 0: copyMem(addr result[0], base(c.echRetry), c.echRetry.len)

proc isReady*(c: TlsConn): bool =
  ## The handshake is complete.
  c.state == stateConnected

proc peerLeafDer*(c: var TlsConn): seq[byte] =
  ## The peer's certificate (DER): the server's, on a client; the client's,
  ## on a server that asked and got one (also when resumed); empty otherwise.
  result = newSeq[byte](c.peerLeaf.len)
  if c.peerLeaf.len > 0: copyMem(addr result[0], base(c.peerLeaf), c.peerLeaf.len)

proc exportKeyingMaterial*(c: var TlsConn; label: string; context: Bytes;
                           ctxLen: int; outp: Bytes; outLen: int): bool =
  ## RFC 8446 7.5 (TLS-Exporter).
  if c.state != stateConnected: return false
  let alg = hashOf(c.cs)
  var e = default(array[48, byte])
  var h = default(Hash)
  init(h, alg)
  final(h, ptrOf(e))
  var s = deriveSecret(alg, c.exporter, label, ptrOf(e))
  var hc = default(array[48, byte])
  init(h, alg)
  discard update(h, context, ctxLen)
  final(h, ptrOf(hc))
  result = s.n != 0 and expandLabel(alg, s, "exporter", ptrOf(hc), digestLen(alg), outp, outLen)
  wipe(s)

proc exportSecrets*(c: TlsConn; txSecret, rxSecret: var Secret; txSeq, rxSeq: var uint64): bool =
  ## The current application traffic secrets and sequence numbers (kTLS).
  if c.state != stateConnected: return false
  txSecret = c.wrSecret
  rxSecret = c.rdSecret
  txSeq = c.wr.seq
  rxSeq = c.rd.seq
  result = true

proc release*(c: var TlsConn) =
  ## Wipe and free everything the connection owns.
  freeHandshake(c)
  clear(c.rd)
  clear(c.wr)
  wipe(c.rdSecret)
  wipe(c.wrSecret)
  wipe(c.exporter)
  wipe(c.resumption)
  free(c.msg)
  free(c.peerLeaf)
  free(c.echRetry)
  c.state = stateFailed

# Adapter operations keep record protection and key mutation in the core.
proc openIncomingRecord*(c: var TlsConn; buf: Bytes; off, count: int;
                         typ, payloadOffset, payloadLen: var int): int {.inline.} =
  result = openRecord(c.rd, buf, off, count, typ, payloadOffset, payloadLen)

proc hasPartialHandshake*(c: var TlsConn): bool {.inline.} =
  result = c.msg.len > 0

proc recordFailure*(c: var TlsConn; alert: int; received = false) {.inline.} =
  c.failAlert = alert
  c.failReceived = received

proc takeReadKeyChange*(c: var TlsConn): bool {.inline.} =
  result = c.keyChanged
  c.keyChanged = false

proc writeClosed*(c: var TlsConn): bool {.inline.} =
  result = atomicLoad(c.wrClosed, moAcquire)

proc markWriteClosed*(c: var TlsConn) {.inline.} =
  atomicStore(c.wrClosed, true, moRelease)

proc keyUpdateInterval*(c: var TlsConn): uint64 {.inline.} =
  result = c.keyUpdateEvery

proc setKeyUpdateInterval*(c: var TlsConn; records: uint64): bool =
  ## Zero restores the default. A caller may rotate more often, never less.
  if records > KeyUpdateAfter: return false
  c.keyUpdateEvery = records
  result = true

proc exportTrafficSecret*(c: var TlsConn; forWrite: bool;
                          secret: var Secret; sequence: var uint64): bool =
  ## Borrowers receive a copy and must wipe it after use.
  if c.state != stateConnected: return false
  if forWrite:
    secret = c.wrSecret
    sequence = c.wr.seq
  else:
    secret = c.rdSecret
    sequence = c.rd.seq
  result = true
