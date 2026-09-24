## The TLS 1.3 server handshake (RFC 8446 section 4, appendix A.2): choose
## from the ClientHello (suite, group, certificate, signature scheme, ALPN),
## send a HelloRetryRequest when no key share fits, send the whole flight
## (ServerHello .. Finished) at once, check the client's Finished.
## Resumption: a ticket the ticketer opens, with a binder that matches,
## skips the certificate (psk_dhe_ke: a fresh key exchange still); its 0-RTT
## data is taken once (anti-replay) when fresh and for the same suite and
## ALPN. Tickets go out after the client's Finished.

import zal_tls/private/handshakewire
import zal_net/buffers
import zal_tls/common
import zal_tls/crypto/[hash, hpke, kx, sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages, ech]
import zal_tls/config/config
import zal_tls/private/core/conn

const
  MaxClientChain = 10                   ## certificates in a client's chain, at most
  MaxPskTried = 4                       ## offered tickets opened per ClientHello, at most
  MaxTickets = 8                        ## tickets sent after one handshake, at most

proc has(s: seq[int]; x: int): bool =
  result = false
  for y in s:
    if y == x: return true

proc respondShare(cfg: ServerConfigPtr; grp: KxGroup; peerShare: Bytes; peerShareLen: int;
                  ours, shared: Bytes): bool =
  ## (Local names differ from the hook's parameter names: Nimony bug c37.)
  let f = cfg.kx.respond
  result = if f != nil: f(cfg.kx.ctx, grp, peerShare, peerShareLen, ours, shared)
           else: respond(grp, peerShare, peerShareLen, ours, shared)

proc signWith(cfg: ServerConfigPtr; key: PrivateKey; scheme: SigScheme; content: Bytes; clen: int;
              outSig: Bytes; room: int; outLen: var int): bool =
  let f = cfg.signer.sign
  result = if f != nil: f(cfg.signer.ctx, scheme, content, clen, outSig, room, outLen)
           else: sign(scheme, key, content, clen, outSig, room, outLen)

proc clockMs(cfg: ServerConfigPtr): int64 =
  let clk = cfg.clock
  result = if clk != nil: clk() else: unixMs()

proc scopeOf(c: TlsConnPtr; cfg: ServerConfigPtr): seq[byte] =
  ## What a ticket must carry to resume here: the configuration's
  ## ticketScope, or this configuration object alone.
  result = @[]
  if cfg.ticketScope.len > 0:
    for ch in cfg.ticketScope: result.add byte(ch)
  else:
    let a = cast[uint64](cfg)
    for i in 0 ..< 8: result.add byte((a shr (uint64(i) * 8)) and 0xff)

  let wire = c.wire
  if wire != nil:
    var encoded = newString(result.len)
    for i in 0 ..< result.len: encoded[i] = char(result[i])
    var bound = bindContext(wire, encoded)
    # Fixed-width domain binding fits the ticket codec even for long transport
    # settings. bindContext delimits the application context before hashing.
    var digest = default(Hash)
    init(digest, hashSha256)
    discard update(digest, textBytes(bound), bound.len)
    result = newSeq[byte](digestLen(hashSha256))
    final(digest, bytesOf(result))

proc identityGood(cfg: ServerConfigPtr; st: SessionState; serverName: string; now: int64): bool =
  ## A ticket's client certificate, if any, is still valid now; and the
  ## resumption check (if set) agrees.
  result = true
  if st.clientLeaf.len > 0:
    var der = st.clientLeaf
    let cert = certDer(bytesOf(der), der.len)
    if cert == nil: return false
    let na = notAfter(cert)
    release(cert)
    if na == 0 or na * 1000 <= now: return false
  let rc = cfg.resumeCheck.check
  if rc != nil:
    var leafCopy = st.clientLeaf
    result = rc(cfg.resumeCheck.ctx, addr leafCopy, serverName)

proc choosePsk(c: TlsConnPtr; cfg: ServerConfigPtr; v: HelloView; msg: Bytes; now: int64; hrrSuite: int;
               o: var PskOffer; state: var SessionState; k: var int): int =
  ## The first offered ticket that opens and fits (a suite of ours the client
  ## offers, the retry's if there was one; the same server name; not
  ## expired): its index `k` and state; -1 for none (a full handshake). An
  ## alert for a malformed offer. (No local named like the hook's
  ## parameters: Nimony bug c37.)
  k = -1
  result = 0
  if not v.hasPsk: return
  if v.pskModes.len == 0: return alMissingExtension            # 4.2.9
  if v.extOrder[v.extOrder.len - 1] != extPreSharedKey: return alIllegalParameter   # last (4.2.11)
  result = parsePskOffer(msg, v, o)
  if result != 0: return
  let opener = cfg.ticketer.open
  if opener == nil or not has(v.pskModes, 1): return          # psk_dhe_ke only
  for i in 0 ..< min(o.identityAt.len, MaxPskTried):
    var got = default(SessionState)
    if opener(cfg.ticketer.ctx, at(msg, o.identityAt[i]), o.identityLen[i], got) and
       got.suite in cfg.suites and has(v.suites, code(got.suite)) and
       (hrrSuite == 0 or code(got.suite) == hrrSuite) and got.serverName == v.serverName and
       now < got.issuedMs + int64(got.lifetime) * 1000 and
       (cfg.resumeWithin == 0 or now - got.authMs < int64(cfg.resumeWithin) * 1000) and
       (cfg.clientAuth != caRequire or got.clientLeaf.len > 0) and   # a required identity comes along
       got.scope == scopeOf(c, cfg) and identityGood(cfg, got, v.serverName, now):
      if o.binderLen[i] != digestLen(hashOf(got.suite)):
        wipe(got.psk)
        return alDecryptError                    # this PSK's binder cannot be right (4.2.11)
      state = got
      k = i
      wipe(got.psk)
      return
    wipe(got.psk)

proc binderOk(hs: HandshakeStatePtr; state: var SessionState; msg: Bytes; o: PskOffer; k: int): bool =
  ## The ticket's binder (4.2.11.2), in constant time; the schedule starts
  ## from its PSK.
  let alg = hashOf(state.suite)
  if not startSchedule(hs.sched, alg, ptrOf(state.psk.b), state.psk.n): return false
  var bk = binderKey(hs.sched, true)
  var h = if alg == hashSha256: hs.tr256 else: hs.tr384
  discard update(h, msg, o.truncLen)
  var th = default(array[48, byte])
  final(h, ptrOf(th))
  var mine = default(array[48, byte])
  result = bk.n != 0 and verifyData(alg, bk, ptrOf(th), ptrOf(mine)) and
    ctEqual(addr mine[0], addr msg[o.binderAt[k]], digestLen(alg))
  wipe(bk)

proc earlyOk(cfg: ServerConfigPtr; state: SessionState; msg: Bytes; o: PskOffer; k: int;
             now: int64; s: Suite; alpn: string; cap: uint32): bool =
  ## 0-RTT for the first ticket (4.2.10): the same suite and ALPN, no more
  ## than we take now (the configuration, the connection's `cap`) — else the
  ## client, told the ticket's amount, might send more — an age that agrees
  ## with ours (8.3), and never before (anti-replay; last, as it remembers
  ## the ticket).
  result = false
  if k != 0 or cfg.maxEarlyData == 0 or state.maxEarlyData == 0 or state.suite != s or state.alpn != alpn:
    return
  if state.maxEarlyData > cfg.maxEarlyData or (cap > 0 and state.maxEarlyData > cap): return
  let clientAge = int64((uint64(o.ages[k]) + 0x1_0000_0000'u64 - uint64(state.ageAdd)) and 0xffff_ffff'u64)
  let drift = clientAge - (now - state.issuedMs)
  # Strictly inside the window: the replay memory keeps an identity for
  # twice the window, so a replay is refused by one or the other at any time.
  if drift >= int64(cfg.earlyWindowMs) or drift <= -int64(cfg.earlyWindowMs): return
  let fu = cfg.antiReplay.firstUse
  if fu == nil: return                           # no replay memory: no 0-RTT
  result = fu(cfg.antiReplay.ctx, at(msg, o.identityAt[k]), o.identityLen[k], now,
              2 * int64(cfg.earlyWindowMs))

proc echConfirm(hs: HandshakeStatePtr; m: Bytes; len, confAt: int; hrr: bool): bool =
  ## Our ECH confirmation (RFC 9849 7.2) into m[confAt ..< confAt + 8]
  ## (zeros now): over the transcript so far and this message.
  var h = if hs.alg == hashSha256: hs.tr256 else: hs.tr384
  discard update(h, m, len)
  var th = default(array[48, byte])
  final(h, ptrOf(th))
  result = echConfirmation(hs.alg, ptrOf(hs.clientRandom), ptrOf(th), hrr, at(m, confAt))

proc echConfigIdOf(k: EchKey): int =
  if k.config.len > 4: int(k.config[4]) else: -1

proc echInfo(k: EchKey): seq[byte] =
  result = @[]
  for ch in "tls ech": result.add byte(ch)
  result.add 0
  for x in k.config: result.add x

proc openEch(hs: HandshakeStatePtr; cfg: ServerConfigPtr; msg: Bytes; len: int; v: HelloView;
             inner: var seq[byte]): int =
  ## ECH (RFC 9849 7.1): the outer hello's payload opened with one of our
  ## keys (each whose config id it names) and decoded against it, `inner`
  ## then the hello to handshake on; refused (`inner` empty: the outer
  ## hello goes on, retry configs follow) when none opens. After a retry
  ## that took ECH, the second hello must open with the same context; after
  ## a first hello without ECH, a second one's is not looked at (7.1.1).
  ## 0 or the alert.
  inner = @[]
  result = 0
  if hs.echSrvRejected: return                   # refused at the first hello: again
  if hs.hrr and not hs.echSrvAccepted: return    # the first hello had none
  if v.echLen == 0:
    if hs.echSrvAccepted: result = alMissingExtension
    return
  var ev = default(EchExtView)
  result = parseEchExtension(msg, v.echAt, v.echLen, ev)
  if result != 0: return
  if not ev.outer: return alIllegalParameter     # an inner mark in the hello we were sent
  if hs.echSrvAccepted and (ev.configId != hs.echConfigId or ev.kdf != EchKdfSha256 or
                            ev.aead != EchAeadAes128Gcm or ev.encLen != 0):
    return alIllegalParameter
  var aad = newSeq[byte](len - 4)
  copyMem(addr aad[0], at(msg, 4), len - 4)
  for i in 0 ..< ev.payloadLen: aad[ev.payloadAt - 4 + i] = 0
  var encoded = newSeq[byte](ev.payloadLen)
  var n = 0
  var opened = false
  if hs.echSrvAccepted:
    opened = open(hs.echCtx, at(msg, ev.payloadAt), ev.payloadLen, bytesOf(aad), aad.len,
                  bytesOf(encoded), encoded.len, n)
    if not opened: result = alDecryptError       # the second hello must open
  else:
    if ev.kdf == EchKdfSha256 and ev.aead == EchAeadAes128Gcm and ev.encLen == HpkeEncLen:
      for k in 0 ..< cfg.echKeys.len:
        if not opened and echConfigIdOf(cfg.echKeys[k]) == ev.configId:
          var info = echInfo(cfg.echKeys[k])
          var priv = cfg.echKeys[k].priv
          opened = setupRecipient(hs.echCtx, ptrOf(priv), at(msg, ev.encAt), bytesOf(info), info.len) and
                   open(hs.echCtx, at(msg, ev.payloadAt), ev.payloadLen, bytesOf(aad), aad.len,
                        bytesOf(encoded), encoded.len, n)
          wipeBytes(addr priv[0], 32)
    if not opened:                               # no key, another suite, a changed payload: refused
      clear(hs.echCtx)
      hs.echSrvRejected = true
  wipeBytes(addr aad[0], aad.len)
  if not opened:
    wipeBytes(addr encoded[0], encoded.len)
    return
  result = decodeInner(bytesOf(encoded), n, msg, len, inner)
  wipeBytes(addr encoded[0], encoded.len)
  if result != 0: return
  var iv = default(HelloView)
  result = parseClientHello(bytesOf(inner), inner.len, iv)
  if result != 0: return
  var mark = default(EchExtView)
  if iv.echLen == 0 or parseEchExtension(bytesOf(inner), iv.echAt, iv.echLen, mark) != 0 or mark.outer:
    return alIllegalParameter                    # the inner hello carries its mark
  if iv.versions.len == 0: return alIllegalParameter
  for x in iv.versions:
    if x < Tls13: return alIllegalParameter      # and offers TLS 1.3 alone (RFC 9849 7.1)
  hs.echSrvAccepted = true
  hs.echConfigId = ev.configId

proc sendRetry(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr; v: var HelloView;
               msg: Bytes; len: int; s: Suite; g: KxGroup): int =
  ## A HelloRetryRequest for group `g`, with a cookie the second ClientHello
  ## must echo; none when ECH was taken: a client may compress the inner
  ## hello's cookie without putting it in the outer hello (Go 1.26 does).
  hs.hrr = true
  c.retried = true
  hs.hrrSuite = code(s)
  hs.hrrGroup = groupCode(g)
  setSuite(c, hs, s)
  copyMem(addr hs.clientRandom[0], addr msg[v.randomAt], 32)   # (the ECH confirmation's)
  addTranscript(hs, msg, len)
  restartTranscript(hs)
  hs.cookie.len = 0
  let ck = grow(hs.cookie, 32)
  if not randomFill(cfg.rand, ck, 32): return alInternalError
  hs.cookie.len = if hs.echSrvAccepted: 0 else: 32
  var hrrRandom = HrrRandom
  let start = hs.stage.len
  var w = beginMsg(hs, 256)
  writeServerHello(w, ptrOf(hrrRandom), at(msg, v.sessionIdAt), v.sessionIdLen, code(s), groupCode(g),
                   ptrOf(hrrRandom), 0, 0, ck, hs.cookie.len, echConf = hs.echSrvAccepted)
  if hs.echSrvAccepted and w.ok and not echConfirm(hs, lastMsg(hs, start), w.pos - start, w.pos - start - 8, true):
    return alInternalError
  if not endMsg(hs, w) or not flushStage(c, hs, false): return alInternalError
  if v.sessionIdLen > 0: queueCcs(c, hs)
  c.state = ssWaitCh2
  result = 0

proc helloBody(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr;
                   msg: Bytes; len: int): int =
  var v = default(HelloView)
  result = parseClientHello(msg, len, v)
  if result != 0: return
  if not has(v.versions, Tls13) or v.legacyVersion < 0x0301: return alProtocolVersion
  if v.compression != @[0]: return alIllegalParameter
  let wire = c.wire
  if wire != nil and wire.quic:
    if v.sessionIdLen != 0: return alIllegalParameter
    let tp = v.transportParams.data
    if tp == nil: return alMissingExtension
    if not receiveParameters(wire, tp, v.transportParams.len): return alIllegalParameter
  elif v.transportParams.data != nil:
    return alUnsupportedExtension
  # The suite: ours first.
  var s = suiteAes128Gcm
  var found = false
  for x in cfg.suites:
    if not found and has(v.suites, code(x)):
      s = x
      found = true
  if not found: return alHandshakeFailure
  if hs.hrr:                                     # the second ClientHello: the retry's suite
    if not suiteOf(hs.hrrSuite, s) or not has(v.suites, hs.hrrSuite): return alIllegalParameter
  # A ticket: its suite (checked after a retry, whose hello it comes again in).
  let now = clockMs(cfg)
  var o = default(PskOffer)
  var state = default(SessionState)
  var k = -1
  if not has(v.extOrder, extKeyShare) or v.groups.len == 0: return alMissingExtension
  if v.sigSchemes.len == 0: return alMissingExtension   # (shares outside supported_groups: the parser)
  let pa = choosePsk(c, cfg, v, msg, now, (if hs.hrr: hs.hrrSuite else: 0), o, state, k)
  if pa != 0: return pa
  if k >= 0: s = state.suite
  # Groups: a share the client sent, in our order; else a HelloRetryRequest.
  var share = -1
  var g = kxX25519
  for x in cfg.groups:
    if share < 0:
      for i in 0 ..< v.shareGroups.len:
        if share < 0 and v.shareGroups[i] == groupCode(x):
          share = i
          g = x
  if hs.hrr:
    # The second ClientHello: the cookie echoed, one share for our group, the same suite.
    if v.cookieLen != hs.cookie.len or
       not ctEqual(addr msg[v.cookieAt], base(hs.cookie), hs.cookie.len) or
       v.shareGroups.len != 1 or v.shareGroups[0] != hs.hrrGroup or code(s) != hs.hrrSuite or
       v.hasEarlyData:                          # no early data after a retry (4.1.2)
      wipe(state.psk)
      return alIllegalParameter
  elif share < 0:
    wipe(state.psk)                              # checked in the second hello
    hs.skipEarly = v.hasEarlyData                # 0-RTT after it: skipped until the second hello
    for x in cfg.groups:
      if has(v.groups, groupCode(x)): return sendRetry(c, hs, cfg, v, msg, len, s, x)
    return alHandshakeFailure
  if v.shareLen[share] != clientShareLen(g):
    wipe(state.psk)
    return alIllegalParameter
  # Resumed: the binder proves the client holds the ticket's PSK.
  let resumed = k >= 0
  if resumed and not binderOk(hs, state, msg, o, k):
    wipe(state.psk)
    return alDecryptError
  wipe(state.psk)
  # The certificate and scheme (not when resumed); ALPN; SNI.
  var ckp: nil CertifiedKeyPtr = nil
  var scheme = sigEcdsaP256Sha256
  if not resumed:
    let rf = cfg.resolver.resolve
    if rf == nil: return alInternalError
    let got = rf(cfg.resolver.ctx, addr v)
    if got == nil: return alHandshakeFailure
    found = false
    for x in got.schemes:
      if not found and has(v.sigSchemes, int(code(x))):
        for y in cfg.sigSchemes:
          if y == x:
            scheme = x
            found = true
    if not found: return alHandshakeFailure
    ckp = got
  var alpn = ""
  if v.alpn.len > 0 and cfg.alpn.len > 0:
    for a in v.alpn:
      if alpn.len == 0:
        for b in cfg.alpn:
          if a == b: alpn = a
    if alpn.len == 0: return alNoApplicationProtocol
  setAlpn(c, alpn)
  setName(c, v.serverName)
  copyMem(addr hs.clientRandom[0], addr msg[v.randomAt], 32)
  # 0-RTT: taken, or skipped until the client's own flight (4.2.10); none
  # after a HelloRetryRequest (the second hello ends it).
  let early = v.hasEarlyData and not hs.hrr and resumed and
              earlyOk(cfg, state, msg, o, k, now, s, alpn, c.earlyCap)
  if resumed:
    hs.earlySkipMax = state.maxEarlyData
    hs.authMs = state.authMs
  hs.skipEarly = v.hasEarlyData and not hs.hrr and not early
  hs.earlyMax = state.maxEarlyData
  hs.pskAccepted = resumed
  c.resumed = resumed
  c.earlyAccepted = early
  if resumed and state.clientLeaf.len > 0:       # the client's identity, from its ticket
    c.peerLeaf.len = 0
    append(c.peerLeaf, bytesOf(state.clientLeaf), state.clientLeaf.len)
  # ServerHello.
  setSuite(c, hs, s)
  addTranscript(hs, msg, len)
  if early:
    var eh = default(array[48, byte])
    transcriptHash(hs, ptrOf(eh))
    if not earlySecrets(hs.sched, ptrOf(eh)): return alInternalError
    logSecret(c, hs, "CLIENT_EARLY_TRAFFIC_SECRET", hs.sched.cEarly)
    logSecret(c, hs, "EARLY_EXPORTER_SECRET", hs.sched.earlyExporter)
  var random = default(array[32, byte])
  if not randomFill(cfg.rand, ptrOf(random), 32): return alInternalError
  var ours = default(array[1120, byte])
  var secret = default(array[64, byte])
  if not respondShare(cfg, g, at(msg, v.shareAt[share]), v.shareLen[share], ptrOf(ours), ptrOf(secret)):
    return alIllegalParameter
  if hs.echSrvAccepted:
    for i in 24 ..< 32: random[i] = 0            # the ECH confirmation goes there (RFC 9849 7.2)
  let shStart = hs.stage.len
  var w = beginMsg(hs, 256 + serverShareLen(g))
  writeServerHello(w, ptrOf(random), at(msg, v.sessionIdAt), v.sessionIdLen, code(s), 0,
                   ptrOf(ours), serverShareLen(g), groupCode(g), ptrOf(ours), 0,
                   if resumed: k else: -1)
  if hs.echSrvAccepted and w.ok and not echConfirm(hs, lastMsg(hs, shStart), w.pos - shStart, 4 + 2 + 24, false):
    return alInternalError
  if not endMsg(hs, w) or not flushStage(c, hs, false): return alInternalError
  if v.sessionIdLen > 0 and not hs.ccsSent: queueCcs(c, hs)
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  # Resumed: the early secret from the PSK is already there (the binder's).
  let ok = (resumed or startSchedule(hs.sched, hs.alg, ptrOf(secret), 0)) and
    handshakeSecrets(hs.sched, ptrOf(secret), secretLen(g), ptrOf(th))
  wipeBytes(addr secret[0], secret.len)
  # Reading: the early keys until EndOfEarlyData when 0-RTT is taken.
  if early and quicMode(c):
    let wire = c.wire
    if wire != nil and not emitSecret(wire, levelEarly, true, s, hs.sched.cEarly):
      return alInternalError
  if not ok or not installTraffic(c, false, levelHandshake, s, hs.sched.sHs) or
     not installTraffic(c, true, (if early and not quicMode(c): levelEarly else: levelHandshake),
       s, (if early and not quicMode(c): hs.sched.cEarly else: hs.sched.cHs)):
    return alInternalError
  c.keyChanged = true
  logSecret(c, hs, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", hs.sched.cHs)
  logSecret(c, hs, "SERVER_HANDSHAKE_TRAFFIC_SECRET", hs.sched.sHs)
  # EncryptedExtensions, [Certificate, CertificateVerify], Finished. No SNI
  # acknowledgement when resumed (RFC 6066 3).
  var retry: seq[byte] = @[]                     # when ECH was offered and refused (RFC 9849 7.1)
  if hs.echSrvRejected: retry = echConfigList(cfg.echKeys, true)
  var params = default(ByteView)
  if wire != nil and wire.quic:
    if alpn.len == 0: return alNoApplicationProtocol
    params = wire.localParams
  var ee = beginMsg(hs, 64 + alpn.len + retry.len + params.len)
  if retry.len > 2:
    writeEncryptedExtensions(ee, alpn, v.serverName.len > 0 and not resumed, early, bytesOf(retry), retry.len, params)
  else:
    writeEncryptedExtensions(ee, alpn, v.serverName.len > 0 and not resumed, early, params = params)
  if not endMsg(hs, ee): return alInternalError
  # CertificateRequest: never on a resumed handshake (4.3.2).
  if cfg.clientAuth != caIgnore and not resumed:
    var schemes: seq[int] = @[]
    for x in cfg.sigSchemes: schemes.add int(code(x))
    var need = 64 + 2 * schemes.len
    for n in cfg.clientCaNames: need = need + n.len + 2
    var cr = beginMsg(hs, need)
    writeCertificateRequest(cr, nil, 0, schemes, cfg.clientCaNames)
    if not endMsg(hs, cr): return alInternalError
    hs.certRequested = true
  let certKey = ckp
  if certKey != nil:
    let key = certKey.key
    if key == nil: return alInternalError
    var need = 64
    for d in certKey.chain: need = need + d.len + 5
    var cw = beginMsg(hs, need)
    writeCertificate(cw, certKey.chain)
    if not endMsg(hs, cw): return alInternalError
    transcriptHash(hs, ptrOf(th))
    var content = default(array[200, byte])
    let clen = signedContent(true, ptrOf(th), digestLen(hs.alg), ptrOf(content))
    var sigBuf = default(array[1024, byte])
    var sigLen = 0
    if not signWith(cfg, key, scheme, ptrOf(content), clen, ptrOf(sigBuf), sigBuf.len, sigLen):
      return alInternalError
    var vw = beginMsg(hs, 8 + sigLen)
    writeCertificateVerify(vw, int(code(scheme)), ptrOf(sigBuf), sigLen)
    if not endMsg(hs, vw): return alInternalError
  transcriptHash(hs, ptrOf(th))
  let n = digestLen(hs.alg)
  var fin = default(array[48, byte])
  if not verifyData(hs.alg, hs.sched.sHs, ptrOf(th), ptrOf(fin)): return alInternalError
  var fw = beginMsg(hs, 4 + n)
  writeFinished(fw, ptrOf(fin), n)
  if not endMsg(hs, fw) or not flushStage(c, hs, true): return alInternalError
  # Application keys: ours now (0.5-RTT data may follow), theirs after their Finished.
  transcriptHash(hs, ptrOf(th))
  if not masterSecrets(hs.sched, ptrOf(th)) or not installAppKeys(c, hs, false):
    return alInternalError
  logSecret(c, hs, "CLIENT_TRAFFIC_SECRET_0", hs.sched.cAp)
  logSecret(c, hs, "SERVER_TRAFFIC_SECRET_0", hs.sched.sAp)
  logSecret(c, hs, "EXPORTER_SECRET", hs.sched.exporter)
  c.exporter = hs.sched.exporter
  c.state = if early and not quicMode(c): ssWaitEoed elif hs.certRequested: ssWaitClientCert else: ssWaitFinished

proc onClientHello(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr;
                   msg: Bytes; len: int): int =
  ## With ECH keys, an outer hello that opens gives the inner hello, which
  ## the handshake runs on (its transcript, name, protocols, ticket).
  if cfg.echKeys.len > 0:
    var v = default(HelloView)
    result = parseClientHello(msg, len, v)
    if result != 0: return
    var inner: seq[byte] = @[]
    result = openEch(hs, cfg, msg, len, v, inner)
    if result != 0: return
    if inner.len > 0:
      c.echAccepted = true
      result = helloBody(c, hs, cfg, bytesOf(inner), inner.len)
      wipeBytes(addr inner[0], inner.len)         # the real name, the ticket's binder
      return
    c.echRejected = hs.echSrvRejected
  result = helloBody(c, hs, cfg, msg, len)

proc onEndOfEarlyData(c: TlsConnPtr; hs: HandshakeStatePtr; msg: Bytes; len: int): int =
  ## The client's last early record (4.5): its handshake keys from here.
  ## Its Finished next: 0-RTT means a resumed handshake, which never asks
  ## for a client certificate.
  result = parseEndOfEarlyData(msg, len)
  if result != 0: return
  addTranscript(hs, msg, len)
  if not installTraffic(c, true, levelHandshake, c.cs, hs.sched.cHs): return alInternalError
  c.keyChanged = true
  c.state = ssWaitFinished

proc issueTickets(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr): int =
  ## NewSessionTickets after the handshake (4.6.1): each seals the session
  ## (its PSK from the resumption secret and the ticket's nonce). None when
  ## the ticketer cannot seal. (No local named like the hook's parameters:
  ## Nimony bug c37.)
  result = 0
  let sealer = cfg.ticketer.seal
  let count = min(cfg.ticketsAfter, MaxTickets)
  let life = min(cfg.ticketLifetime, 604800'u32)  # 7 days at most
  if sealer == nil or count <= 0 or life == 0: return
  var state = default(SessionState)
  state.suite = c.cs
  state.alpn = alpn(c[])
  state.serverName = serverName(c[])
  state.issuedMs = clockMs(cfg)
  state.authMs = if c.resumed: hs.authMs else: state.issuedMs
  state.lifetime = life
  state.maxEarlyData = if c.earlyCap > 0: min(cfg.maxEarlyData, c.earlyCap) else: cfg.maxEarlyData
  if c.peerLeaf.len > MaxClientLeaf: return         # no tickets: they would lose the identity
  if c.peerLeaf.len > 0:                         # the client's identity goes along
    state.clientLeaf = newSeq[byte](c.peerLeaf.len)
    copyMem(addr state.clientLeaf[0], base(c.peerLeaf), c.peerLeaf.len)
  state.scope = scopeOf(c, cfg)
  for i in 0 ..< count:
    var nonce = [byte(i)]
    var aa = default(array[4, byte])
    if not randomFill(cfg.rand, ptrOf(aa), 4):
      result = alInternalError
      break
    state.ageAdd = (uint32(aa[0]) shl 24) or (uint32(aa[1]) shl 16) or (uint32(aa[2]) shl 8) or uint32(aa[3])
    state.psk = ticketPsk(hs.alg, c.resumption, ptrOf(nonce), 1)
    var sealed: seq[byte] = @[]
    if state.psk.n == 0 or not sealer(cfg.ticketer.ctx, addr state, sealed) or sealed.len == 0:
      break
    var w = beginMsg(hs, 32 + sealed.len)
    writeNewSessionTicket(w, state.lifetime, state.ageAdd, ptrOf(nonce), 1, bytesOf(sealed), sealed.len,
                          state.maxEarlyData)
    if not endMsg(hs, w):
      result = alInternalError
      break
  wipe(state.psk)
  if result == 0 and not flushStage(c, hs, true): result = alInternalError

proc onClientCertificate(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr;
                         msg: Bytes; len: int): int =
  ## The client's chain (4.4.2): none (required: certificate_required), or
  ## verified; a bad one fails even when only requested.
  var certs: seq[seq[byte]] = @[]
  result = parseCertificate(msg, len, certs)
  if result != 0: return
  if certs.len == 0:
    if cfg.clientAuth == caRequire: return alCertificateRequired
    addTranscript(hs, msg, len)
    c.state = ssWaitFinished
    return
  if certs.len > MaxClientChain: return alBadCertificate
  let vf = cfg.clientVerifier.verify
  if vf != nil:
    result = vf(cfg.clientVerifier.ctx, addr certs, serverName(c[]))
  else:
    let roots = cfg.clientRoots
    let clk = cfg.clock
    let atUnix = if clk != nil: clk() div 1000 else: 0'i64
    result = if roots == nil: alUnknownCa else: webPkiVerifyClient(roots, addr certs, atUnix)
  if result != 0: return
  let leaf = certDer(bytesOf(certs[0]), certs[0].len)
  if leaf == nil: return alBadCertificate
  hs.peerKey = publicKey(leaf)
  release(leaf)
  if hs.peerKey == nil: return alBadCertificate
  hs.clientLeafPending.len = 0                   # the identity once its key is proven (CertificateVerify)
  append(hs.clientLeafPending, bytesOf(certs[0]), certs[0].len)
  addTranscript(hs, msg, len)
  c.state = ssWaitClientCv

proc onClientCertificateVerify(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr;
                               msg: Bytes; len: int): int =
  ## The client's signature over the transcript through its Certificate,
  ## the client context string (4.4.3), with a scheme we asked for.
  var scheme = 0
  var sigAt = 0
  var sigLen = 0
  result = parseCertificateVerify(msg, len, scheme, sigAt, sigLen)
  if result != 0: return
  var s = sigEcdsaP256Sha256
  let key = hs.peerKey
  if key == nil: return alInternalError
  var asked = false
  for x in cfg.sigSchemes:
    if int(code(x)) == scheme: asked = true
  if not asked or not schemeOf(scheme, s) or not matches(s, key): return alIllegalParameter
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  var content = default(array[200, byte])
  let n = signedContent(false, ptrOf(th), digestLen(hs.alg), ptrOf(content))
  if not verify(s, key, ptrOf(content), n, at(msg, sigAt), sigLen): return alDecryptError
  addTranscript(hs, msg, len)
  c.peerLeaf.len = 0
  append(c.peerLeaf, base(hs.clientLeafPending), hs.clientLeafPending.len)
  c.state = ssWaitFinished

proc onClientFinished(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ServerConfigPtr;
                      msg: Bytes; len: int): int =
  var vAt = 0
  var vLen = 0
  result = parseFinished(msg, len, vAt, vLen)
  if result != 0: return
  let n = digestLen(hs.alg)
  if vLen != n: return alDecodeError
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))                  # through our Finished [and EndOfEarlyData]
  var expected = default(array[48, byte])
  if not verifyData(hs.alg, hs.sched.cHs, ptrOf(th), ptrOf(expected)): return alInternalError
  if not ctEqual(addr expected[0], addr msg[vAt], n): return alDecryptError
  addTranscript(hs, msg, len)
  transcriptHash(hs, ptrOf(th))
  if not resumptionSecret(hs.sched, ptrOf(th)) or not installAppKeys(c, hs, true):
    return alInternalError
  c.resumption = hs.sched.resumption
  result = issueTickets(c, hs, cfg)
  if result != 0: return
  completeHandshake(c)

proc serverMsg(c: TlsConnPtr; hs: HandshakeStatePtr; typ: int; msg: Bytes; len: int): int {.nimcall.} =
  let cfg = c.scfg
  if cfg == nil: return alInternalError
  case c.state
  of ssStart, ssWaitCh2:
    result = if typ == htClientHello: onClientHello(c, hs, cfg, msg, len) else: alUnexpectedMessage
  of ssWaitEoed:
    result = if typ == htEndOfEarlyData: onEndOfEarlyData(c, hs, msg, len) else: alUnexpectedMessage
  of ssWaitClientCert:
    result = if typ == htCertificate: onClientCertificate(c, hs, cfg, msg, len) else: alUnexpectedMessage
  of ssWaitClientCv:
    result = if typ == htCertificateVerify: onClientCertificateVerify(c, hs, cfg, msg, len)
             else: alUnexpectedMessage
  of ssWaitFinished:
    result = if typ == htFinished: onClientFinished(c, hs, cfg, msg, len) else: alUnexpectedMessage
  else:
    result = alUnexpectedMessage

proc initServer*(c: var TlsConn; cfg: ServerConfigPtr): bool =
  ## A server connection: feed `step` what the client sends.
  c = default(TlsConn)
  if cfg.suites.len == 0 or cfg.groups.len == 0 or cfg.sigSchemes.len == 0: return false
  # Client certificates asked for: something to check them, CA names that fit.
  if cfg.clientAuth != caIgnore and cfg.clientRoots == nil and cfg.clientVerifier.verify == nil: return false
  var names = 0
  for n in cfg.clientCaNames:
    if n.len == 0: return false
    names = names + 2 + n.len
  if names > 60000: return false
  # ECH keys: each a config we can open (one of version 0xfe0d, X25519,
  # HKDF-SHA256 and AES-128-GCM, a valid public name), some sent as retry
  # configs (a server with ECH must send them when it refuses, RFC 9849 7.1).
  var retry = false
  for k in cfg.echKeys:
    var one = @[byte(k.config.len shr 8), byte(k.config.len and 0xff)]
    for x in k.config: one.add x
    var views: seq[EchConfigView] = @[]
    if k.config.len == 0 or not parseEchConfigList(bytesOf(one), one.len, views) or views.len != 1 or
       views[0].kemId != EchKemX25519 or views[0].pubLen != 32 or views[0].kdfs.len != 1 or
       views[0].kdfs[0] != EchKdfSha256 or views[0].aeads[0] != EchAeadAes128Gcm:
      return false
    if k.retry: retry = true
  if cfg.echKeys.len > 0 and not retry: return false
  c.role = roleServer
  c.state = ssStart
  c.scfg = cfg
  c.maxMsg = if cfg.maxHandshakeMsg > 0: cfg.maxHandshakeMsg else: DefaultMaxHandshakeMsg
  c.onMsg = serverMsg
  discard newHandshake(c)
  result = true
