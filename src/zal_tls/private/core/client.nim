## The TLS 1.3 client handshake (RFC 8446 section 4, appendix A.1): our
## ClientHello (or a `HelloBuilder`'s), a HelloRetryRequest, the server's
## flight, and our Finished. Every check fails with the RFC's alert.
## Resumption: a stored ticket is offered as a PSK (psk_dhe_ke), with
## 0-RTT data when the ticket and the configuration allow it.

import zal_tls/private/handshakewire
import zal_net/buffers
import zal_tls/common
import zal_tls/crypto/[aead, hash, hpke, kx, sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages, ech]
import zal_tls/config/config
import zal_tls/private/core/conn

const
  MaxChain* = 10                        ## certificates in the server's chain
  MaxTicketTries = 4                    ## stored tickets taken, at most, to find one we can use

proc has(s: seq[int]; x: int): bool =
  result = false
  for y in s:
    if y == x: return true

proc offered(hs: HandshakeStatePtr; v: var HelloView): bool =
  ## What our ClientHello offered (parsed back from the bytes sent).
  result = parseClientHello(base(hs.ch), hs.ch.len, v) == 0

# ------------------------------------------------------------ ClientHello

proc newShare(cfg: ClientConfigPtr; key: var KxKey; grp: KxGroup; pub: var seq[byte]): bool =
  ## (Local names differ from the hook's parameter names: Nimony bug c37.)
  pub = newSeq[byte](clientShareLen(grp))
  let f = cfg.kx.generate
  result = if f != nil: f(cfg.kx.ctx, grp, key, bytesOf(pub)) else: generate(key, grp, bytesOf(pub))

proc writeDefaultHello*(w: var Writer; cfg: ClientConfigPtr; p: ptr HelloParams) =
  ## Our ClientHello: server_name, supported_groups, signature_algorithms,
  ## supported_versions, psk_key_exchange_modes, key_share, cookie, ALPN
  ## (`p.alpn`), early_data, encrypted_client_hello (inner or outer form)
  ## and pre_shared_key (with a zero binder: filled in later).
  ## A `HelloBuilder` may call it and change the result.
  put8(w, htClientHello)
  let m = begin24(w)
  put16(w, Tls12)
  putBytes(w, ptrOf(p.random), 32)
  let sid = begin8(w)
  putBytes(w, ptrOf(p.sessionId), p.sessionIdLen)
  finish8(w, sid)
  let su = begin16(w)
  for s in cfg.suites: put16(w, code(s))
  finish16(w, su)
  put8(w, 1)
  put8(w, 0)
  let exts = begin16(w)
  if p.serverName.len > 0:
    put16(w, extServerName)
    let e = begin16(w)
    let l = begin16(w)
    put8(w, 0)
    let n = begin16(w)
    putStr(w, p.serverName)
    finish16(w, n)
    finish16(w, l)
    finish16(w, e)
  put16(w, extSupportedGroups)
  let eg = begin16(w)
  let lg = begin16(w)
  for g in cfg.groups: put16(w, groupCode(g))
  finish16(w, lg)
  finish16(w, eg)
  put16(w, extSignatureAlgorithms)
  let es = begin16(w)
  let ls = begin16(w)
  for s in cfg.sigSchemes: put16(w, int(code(s)))
  finish16(w, ls)
  finish16(w, es)
  put16(w, extSupportedVersions)
  let ev = begin16(w)
  put8(w, 2)
  put16(w, Tls13)
  finish16(w, ev)
  put16(w, extPskKeyExchangeModes)
  let ep = begin16(w)
  put8(w, 1)
  put8(w, 1)                                     # psk_dhe_ke
  finish16(w, ep)
  put16(w, extKeyShare)
  let ek = begin16(w)
  let lk = begin16(w)
  for i in 0 ..< p.shareGroups.len:
    put16(w, groupCode(p.shareGroups[i]))
    let s = begin16(w)
    putBytes(w, bytesOf(p.shares[i]), p.shares[i].len)
    finish16(w, s)
  finish16(w, lk)
  finish16(w, ek)
  if p.cookie.len > 0:
    put16(w, extCookie)
    let ec = begin16(w)
    let c = begin16(w)
    putBytes(w, bytesOf(p.cookie), p.cookie.len)
    finish16(w, c)
    finish16(w, ec)
  if p.alpn.len > 0:
    put16(w, extAlpn)
    let ea = begin16(w)
    let la = begin16(w)
    for a in p.alpn:
      put8(w, a.len)
      putStr(w, a)
    finish16(w, la)
    finish16(w, ea)
  if p.quic:
    put16(w, extQuicTransportParameters)
    let qt = begin16(w)
    let tp = p.transportParams.data
    if tp != nil: putBytes(w, tp, p.transportParams.len)
    finish16(w, qt)
  if p.early:
    put16(w, extEarlyData)
    put16(w, 0)
  if p.echInner: writeEchInner(w)
  if p.echOuter:
    var enc: nil Bytes = nil
    if p.echEnc.len > 0: enc = bytesOf(p.echEnc)
    p.echPayloadAt = writeEchOuter(w, p.echKdf, p.echAead, p.echConfigId, enc, p.echEnc.len, p.echPayloadLen)
  if p.pskTicket.len > 0:                        # last (4.2.11); the binder comes after
    writePskExtension(w, bytesOf(p.pskTicket), p.pskTicket.len, p.pskAge, p.pskBinderLen)
  finish16(w, exts)
  finish24(w, m)

proc bindPsk(hs: HandshakeStatePtr; p: var HelloParams; msg: Bytes; v: HelloView): int =
  ## The binder of the ticket offered in the hello at `msg` (4.2.11.2): the
  ## early secret from the ticket's PSK, over the transcript so far (after a
  ## HelloRetryRequest: message_hash and the HRR) and this hello up to its
  ## binders; written in place.
  if not hs.pskOffered or v.extOrder.len == 0 or v.extOrder[v.extOrder.len - 1] != extPreSharedKey:
    return alInternalError
  var o = default(PskOffer)
  if parsePskOffer(msg, v, o) != 0 or o.identityLen.len != 1: return alInternalError
  let alg = hashOf(hs.pskSuite)
  let n = digestLen(alg)
  if o.identityLen[0] != p.pskTicket.len or o.binderLen[0] != n or
     not ctEqual(addr msg[o.identityAt[0]], addr p.pskTicket[0], p.pskTicket.len):
    return alInternalError                       # a builder's hello offers what we hold
  if not startSchedule(hs.sched, alg, ptrOf(hs.psk.b), hs.psk.n): return alInternalError
  var bk = binderKey(hs.sched, true)
  var h = if alg == hashSha256: hs.tr256 else: hs.tr384
  discard update(h, msg, o.truncLen)
  var th = default(array[48, byte])
  final(h, ptrOf(th))
  var binder = default(array[48, byte])
  let ok = bk.n != 0 and verifyData(alg, bk, ptrOf(th), ptrOf(binder))
  wipe(bk)
  if not ok: return alInternalError
  copyMem(addr msg[o.binderAt[0]], addr binder[0], n)
  result = 0

proc startEarly(c: TlsConnPtr; hs: HandshakeStatePtr): int =
  ## 0-RTT after the first ClientHello (4.2.10): [change_cipher_spec right
  ## after it (D.4)], then `sealEarly` under client_early_traffic_secret.
  if hs.sessionIdLen > 0 and not hs.ccsSent: queueCcs(c, hs)
  let alg = hashOf(hs.pskSuite)
  let h = if alg == hashSha256: hs.tr256 else: hs.tr384
  var th = default(array[48, byte])
  peek(h, ptrOf(th))
  if not earlySecrets(hs.sched, ptrOf(th)) or not installTraffic(c, false, levelEarly, hs.pskSuite, hs.sched.cEarly):
    return alInternalError
  logSecret(c, hs, "CLIENT_EARLY_TRAFFIC_SECRET", hs.sched.cEarly)
  logSecret(c, hs, "EARLY_EXPORTER_SECRET", hs.sched.earlyExporter)
  c.earlyWrite = hs.earlyMax > 0
  result = 0

proc sendEchHello(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; p: var HelloParams;
                  first: bool): int

proc sendHello(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; p: var HelloParams;
               first: bool): int =
  ## Write the ClientHello (ours or the builder's), bind its PSK, keep a
  ## copy, queue its record (and start 0-RTT when it offers early data).
  ## With ECH offered (and not refused yet): the inner and outer hellos.
  if hs.echOffered and not hs.echRejected: return sendEchHello(c, hs, cfg, p, first)
  var need = 4096 + p.transportParams.len + p.cookie.len + p.serverName.len + p.pskTicket.len + p.echPayloadLen
  for s in p.shares: need = need + s.len + 4
  for a in cfg.alpn: need = need + a.len + 1
  let b = cfg.builder.build
  if b != nil: need = need + 16384
  let start = hs.stage.len
  var w = beginMsg(hs, need)
  if b != nil:
    if not b(cfg.builder.ctx, addr p, w): return alInternalError
  else:
    writeDefaultHello(w, cfg, addr p)
  if not w.ok: return alInternalError
  # What was sent is what counts (a builder may differ from `p`).
  let msg = lastMsg(hs, start)
  let mlen = w.pos - start
  if b == nil and p.echOuter and p.echPayloadLen > 0:
    if not randomFill(cfg.rand, at(msg, p.echPayloadAt - start), p.echPayloadLen): return alInternalError
  var v = default(HelloView)
  if parseClientHello(msg, mlen, v) != 0 or v.sessionIdLen > 32: return alInternalError
  if quicMode(c) and (v.sessionIdLen != 0 or v.transportParams.data == nil): return alInternalError
  if v.hasPsk:
    let a = bindPsk(hs, p, msg, v)
    if a != 0: return a
  elif hs.pskOffered:
    hs.pskOffered = false                        # the builder left the ticket out
    wipe(hs.psk)
  # Early data needs a PSK, and never follows a HelloRetryRequest (4.1.2).
  if v.hasEarlyData and (not v.hasPsk or not first): return alInternalError
  hs.earlyOffered = v.hasEarlyData
  if not endMsg(hs, w): return alInternalError
  hs.ch.len = 0
  append(hs.ch, msg, mlen)
  let chp = base(hs.ch)
  copyMem(addr hs.clientRandom[0], addr chp[v.randomAt], 32)
  hs.sessionIdLen = v.sessionIdLen
  if v.sessionIdLen > 0: copyMem(addr hs.sessionId[0], addr chp[v.sessionIdAt], v.sessionIdLen)
  if not flushStage(c, hs, false, first): return alInternalError
  result = if hs.earlyOffered: startEarly(c, hs) else: 0

const EchCompress = [extSupportedGroups, extSignatureAlgorithms, extSupportedVersions,
                     extPskKeyExchangeModes, extKeyShare]
  ## The inner hello's extensions the outer carries as they are (contiguous
  ## in both: `writeDefaultHello`'s order); the cookie too after a retry.

proc sendEchHello(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; p: var HelloParams;
                  first: bool): int =
  ## ECH (RFC 9849 6.1): the inner hello (the real name and protocols, the
  ## ticket, its mark) goes into our transcript, encoded and sealed into the
  ## outer hello (the public name, its own random, no protocols, no ticket),
  ## which is what we send; its own transcript is kept until the server
  ## says which one counts. A second hello reuses the HPKE context (enc empty).
  var need = 4096 + p.transportParams.len + p.cookie.len + p.serverName.len + p.pskTicket.len
  for sh in p.shares: need = need + sh.len + 4
  for a in p.alpn: need = need + a.len + 1
  for a in cfg.echOuterAlpn: need = need + a.len + 1
  var ib = newSeq[byte](need)
  var wi = initWriter(bytesOf(ib), 0, ib.len)
  p.echInner = true
  p.echOuter = false
  writeDefaultHello(wi, cfg, addr p)
  if not wi.ok: return alInternalError
  let innerLen = wi.pos
  var v = default(HelloView)
  if parseClientHello(bytesOf(ib), innerLen, v) != 0: return alInternalError
  if v.hasPsk:
    let a = bindPsk(hs, p, bytesOf(ib), v)
    if a != 0: return a
  if v.hasEarlyData and (not v.hasPsk or not first): return alInternalError
  hs.earlyOffered = v.hasEarlyData
  addTranscript(hs, bytesOf(ib), innerLen)
  hs.ch.len = 0
  append(hs.ch, bytesOf(ib), innerLen)
  copyMem(addr hs.clientRandom[0], addr ib[v.randomAt], 32)
  hs.sessionIdLen = v.sessionIdLen
  if v.sessionIdLen > 0: copyMem(addr hs.sessionId[0], addr ib[v.sessionIdAt], v.sessionIdLen)
  var compress: seq[int] = @[]
  for t in EchCompress: compress.add t
  if p.cookie.len > 0: compress.add extCookie
  var encoded: seq[byte] = @[]
  if not encodeInner(bytesOf(ib), innerLen, compress, hs.echMaxNameLen, encoded): return alInternalError
  # The outer hello: what goes on the wire.
  var po = p
  po.echInner = false
  po.echOuter = true
  po.serverName = newString(hs.echPublicNameLen)
  for i in 0 ..< hs.echPublicNameLen: po.serverName[i] = char(hs.echPublicName[i])
  po.random = hs.outerRandom
  po.alpn = cfg.echOuterAlpn
  po.pskTicket = @[]
  po.echConfigId = hs.echConfigId
  po.echKdf = EchKdfSha256
  po.echAead = EchAeadAes128Gcm
  if not first: po.echEnc = @[]
  po.echPayloadLen = encoded.len + AeadTagLen
  hs.echPayloadLen = po.echPayloadLen
  let start = hs.stage.len
  var w = beginMsg(hs, need + po.echPayloadLen + 64)
  writeDefaultHello(w, cfg, addr po)
  if not w.ok: return alInternalError
  let om = lastMsg(hs, start)
  let olen = w.pos - start
  var ctLen = 0
  var ct = newSeq[byte](po.echPayloadLen)
  if not seal(hs.echCtx, bytesOf(encoded), encoded.len, at(om, 4), olen - 4, bytesOf(ct), ct.len, ctLen) or
     ctLen != po.echPayloadLen:
    return alInternalError
  copyMem(at(om, po.echPayloadAt - start), addr ct[0], ctLen)
  wipeBytes(addr ib[0], ib.len)                  # the inner hello (the real name) is in hs.ch now
  wipeBytes(addr encoded[0], encoded.len)
  hs.stage.len = w.pos                           # sent, but in the outer transcript only
  discard update(hs.trOuter256, om, olen)
  discard update(hs.trOuter384, om, olen)
  hs.chOuter.len = 0
  append(hs.chOuter, om, olen)
  if not flushStage(c, hs, false, first): return alInternalError
  result = if hs.earlyOffered: startEarly(c, hs) else: 0

proc echReject(c: TlsConnPtr; hs: HandshakeStatePtr) =
  ## The server answered the outer hello: its transcript and hello count
  ## now; no ticket (the outer had none); the public name is checked.
  ## Nothing of this shows (`c.echRejected`, the retry configs) until that
  ## server's Finished is verified: before, anyone could have said it.
  hs.echRejected = true
  hs.tr256 = hs.trOuter256
  hs.tr384 = hs.trOuter384
  hs.ch.len = 0
  append(hs.ch, base(hs.chOuter), hs.chOuter.len)
  hs.clientRandom = hs.outerRandom
  if hs.pskOffered:
    hs.pskOffered = false
    wipe(hs.psk)
  var name = newString(hs.echPublicNameLen)
  for i in 0 ..< hs.echPublicNameLen: name[i] = char(hs.echPublicName[i])
  setName(c, name)

proc echConfirmed(hs: HandshakeStatePtr; s: Suite; msg: Bytes; len: int; confAt: int; hrr: bool): bool =
  ## The server's ECH confirmation (RFC 9849 7.2): over our (inner)
  ## transcript and its message with the confirmation zeroed; a retry's
  ## over message_hash of the first inner hello and the retry.
  let alg = hashOf(s)
  var h = if alg == hashSha256: hs.tr256 else: hs.tr384
  if hrr:
    var ch1 = default(array[48, byte])
    peek(h, ptrOf(ch1))
    let n = digestLen(alg)
    var mh = default(array[52, byte])
    mh[0] = byte(htMessageHash)
    mh[3] = byte(n)
    copyMem(addr mh[4], addr ch1[0], n)
    init(h, alg)
    discard update(h, ptrOf(mh), 4 + n)
  var m = newSeq[byte](len)
  copyMem(addr m[0], msg, len)
  for i in 0 ..< EchConfirmLen: m[confAt + i] = 0
  discard update(h, bytesOf(m), len)
  var th = default(array[48, byte])
  final(h, ptrOf(th))
  var conf = default(array[8, byte])
  result = echConfirmation(alg, ptrOf(hs.clientRandom), ptrOf(th), hrr, ptrOf(conf)) and
    ctEqual(addr conf[0], addr msg[confAt], EchConfirmLen)

proc eeEch*(hs: HandshakeStatePtr; accepted: bool; msg: Bytes; len: int): int =
  ## EncryptedExtensions' encrypted_client_hello (RFC 9849 6.1.4, 6.2): none
  ## unless we sent ECH or GREASE, none when the server took our ECH; else
  ## a well-formed ECHConfigList, kept when the server refused our ECH (it
  ## counts once the server's Finished is verified). 0 or the alert.
  var rat = 0
  var rn = 0
  if not findEchRetry(msg, len, rat, rn): return 0
  if accepted or not (hs.echOffered or hs.greaseOn): return alUnsupportedExtension
  var cfgs: seq[EchConfigView] = @[]
  if not parseEchConfigList(at(msg, rat), rn, cfgs): return alDecodeError
  if hs.echRejected:
    hs.echRetryPending.len = 0
    append(hs.echRetryPending, at(msg, rat), rn)
  result = 0

proc clockMs(cfg: ClientConfigPtr): int64 =
  let clk = cfg.clock
  result = if clk != nil: clk() else: unixMs()

proc obfuscatedAge(hs: HandshakeStatePtr; now: int64): uint32 =
  ## The ticket's age in ms plus its age_add, mod 2^32 (4.2.11.1).
  let age = uint64(max(0'i64, now - hs.pskIssuedMs))
  result = uint32((age + uint64(hs.pskAgeAdd)) and 0xffff_ffff'u64)

proc offerTicket(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; name: string;
                 p: var HelloParams) =
  ## A stored ticket for `name`, taken (used once; one we cannot use is
  ## dropped and the next taken): offered as the PSK, with early data when
  ## the configuration wants it and the ticket allows it.
  let take = cfg.sessions.take
  if take == nil: return
  let now = clockMs(cfg)
  var tk = default(SessionTicket)
  var tries = 0
  var usable = false
  while not usable and tries < MaxTicketTries:
    tries = tries + 1
    tk = default(SessionTicket)
    if not take(cfg.sessions.ctx, boundSessionKey(c, cfg, name), now, tk): return
    usable = tk.suite in cfg.suites and tk.psk.n == digestLen(hashOf(tk.suite)) and tk.ticket.len > 0 and
             tk.ticket.len <= MaxTicketLen and now >= tk.issuedMs and now - tk.issuedMs < int64(tk.lifetime) * 1000
    if not usable: wipe(tk.psk)
  let n = digestLen(hashOf(tk.suite))
  if usable:
    if tk.serverLeaf.len > 0:                    # the server's certificate, should it resume
      c.peerLeaf.len = 0
      append(c.peerLeaf, bytesOf(tk.serverLeaf), tk.serverLeaf.len)
    hs.psk = tk.psk
    hs.pskSuite = tk.suite
    hs.pskIssuedMs = tk.issuedMs
    hs.pskAgeAdd = tk.ageAdd
    hs.pskOffered = true
    p.pskTicket = tk.ticket
    p.pskAge = obfuscatedAge(hs, now)
    p.pskBinderLen = n
    # 0-RTT speaks the ticket's protocol: one we still offer (or none).
    let alpnOk = tk.alpn.len == 0 or tk.alpn in cfg.alpn
    if cfg.earlyData and tk.maxEarlyData > 0 and
       (not quicMode(c) or tk.maxEarlyData == high(uint32)) and alpnOk and tk.alpn.len <= hs.earlyAlpn.len:
      p.early = true
      hs.earlyMax = tk.maxEarlyData
      hs.earlyAlpnLen = tk.alpn.len
      for i in 0 ..< tk.alpn.len: hs.earlyAlpn[i] = byte(tk.alpn[i])
  wipe(tk.psk)

proc earlyAlpnIs(hs: HandshakeStatePtr; alpn: string): bool =
  result = alpn.len == hs.earlyAlpnLen
  if result:
    for i in 0 ..< alpn.len:
      if hs.earlyAlpn[i] != byte(alpn[i]): return false

proc usableEch(e: EchConfigView): bool =
  ## A configuration we can seal to: X25519, HKDF-SHA256 with AES-128-GCM.
  var suiteOk = false
  for i in 0 ..< e.kdfs.len:
    if e.kdfs[i] == EchKdfSha256 and e.aeads[i] == EchAeadAes128Gcm: suiteOk = true
  result = e.kemId == EchKemX25519 and e.pubLen == 32 and suiteOk

proc echConfigsUsable(cfg: ClientConfigPtr): bool =
  ## `echConfigs`, when set, holds a usable configuration (and our hello is
  ## ours: a HelloBuilder cannot carry ECH).
  if cfg.echConfigs.len == 0: return true
  if cfg.builder.build != nil: return false
  var configs: seq[EchConfigView] = @[]
  var lst = cfg.echConfigs
  if not parseEchConfigList(bytesOf(lst), lst.len, configs): return false
  result = false
  for e in configs:
    if usableEch(e): result = true

proc offerEch(hs: HandshakeStatePtr; cfg: ClientConfigPtr; p: var HelloParams): int =
  ## ECH with the first usable configuration (X25519, HKDF-SHA256,
  ## AES-128-GCM; `initClient` saw there is one): the HPKE sender set up
  ## now. Without configs, GREASE (when on).
  result = 0
  var configs: seq[EchConfigView] = @[]
  var lst = cfg.echConfigs
  if lst.len > 0 and parseEchConfigList(bytesOf(lst), lst.len, configs):
    for e in configs:
      if not hs.echOffered and usableEch(e) and e.publicName.len <= hs.echPublicName.len:
        var info: seq[byte] = @[]
        for ch in "tls ech": info.add byte(ch)
        info.add 0
        for i in 0 ..< e.len: info.add lst[e.at + i]
        var enc = newSeq[byte](HpkeEncLen)
        if not setupSender(hs.echCtx, at(bytesOf(lst), e.pubAt), bytesOf(info), info.len, bytesOf(enc)):
          return alInternalError
        hs.echOffered = true
        hs.echConfigId = e.configId
        hs.echMaxNameLen = e.maxNameLen
        hs.echPublicNameLen = e.publicName.len
        for i in 0 ..< e.publicName.len: hs.echPublicName[i] = byte(e.publicName[i])
        if not randomFill(cfg.rand, ptrOf(hs.outerRandom), 32): return alInternalError
        p.echEnc = enc
  if cfg.echConfigs.len > 0 and not hs.echOffered: return alInternalError   # never the name in clear
  if not hs.echOffered and cfg.echGrease:
    # GREASE (RFC 9849 6.2): the shape of a real one, random.
    var b = default(array[2, byte])
    if not randomFill(cfg.rand, ptrOf(b), 2): return alInternalError
    p.echOuter = true
    p.echConfigId = int(b[0])
    p.echKdf = EchKdfSha256
    p.echAead = EchAeadAes128Gcm
    p.echEnc = newSeq[byte](HpkeEncLen)
    if not randomFill(cfg.rand, bytesOf(p.echEnc), HpkeEncLen): return alInternalError
    p.echPayloadLen = 144 + 32 * int(b[1] and 3)
    hs.greaseOn = true
    hs.echConfigId = p.echConfigId
    hs.echPayloadLen = p.echPayloadLen

proc startClient(c: TlsConnPtr; hs: HandshakeStatePtr): int {.nimcall.} =
  let cfg = c.ccfg
  if cfg == nil: return alInternalError
  var p = default(HelloParams)
  p.cfg = cfg
  let wire = c.wire
  if wire != nil:
    p.quic = wire.quic
    p.transportParams = wire.localParams
  p.alpn = cfg.alpn
  if not randomFill(cfg.rand, ptrOf(p.random), 32): return alInternalError
  p.sessionIdLen = if quicMode(c): 0 else: 32 # QUIC forbids middlebox compatibility
  if not randomFill(cfg.rand, ptrOf(p.sessionId), 32): return alInternalError
  let name = nameOf(c)
  if not isIpLiteral(name): p.serverName = name
  offerTicket(c, hs, cfg, name, p)
  if cfg.builder.build == nil:
    let a = offerEch(hs, cfg, p)
    if a != 0: return a
  var shared: seq[KxGroup] = @[]
  for g in cfg.shareGroups:
    if g in cfg.groups: shared.add g        # a share must be for a listed group (4.2.8)
  if shared.len == 0: shared.add cfg.groups[0]
  for g in shared:
    if hs.nkeys == hs.keys.len: break
    var share: seq[byte] = @[]
    if not newShare(cfg, hs.keys[hs.nkeys], g, share): return alInternalError
    hs.nkeys = hs.nkeys + 1
    p.shareGroups.add g
    p.shares.add share
  result = sendHello(c, hs, cfg, p, true)
  c.state = csWaitSh

# ------------------------------------------------------------ ServerHello

proc onRetry(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; v: var ServerHelloView;
             s: Suite; msg: Bytes; len: int): int =
  if hs.hrr: return alUnexpectedMessage          # a second HelloRetryRequest
  if hs.echOffered and not hs.echRejected:
    # ECH accepted for this retry, or the outer hello is what counts now.
    if v.echConfAt >= 0 and echConfirmed(hs, s, msg, len, v.echConfAt, true): hs.echHrrAccepted = true
    else: echReject(c, hs)
  elif v.echConfAt >= 0 and not hs.greaseOn:
    return alUnsupportedExtension                # we sent no ECH (GREASE: random bytes, ignored)
  var o = default(HelloView)
  if not offered(hs, o): return alInternalError
  var g = kxX25519
  if v.selectedGroup != 0:
    if not groupOf(v.selectedGroup, g) or not has(o.groups, v.selectedGroup) or
       has(o.shareGroups, v.selectedGroup):
      return alIllegalParameter
  elif v.cookieLen == 0:
    return alIllegalParameter                    # it would change nothing
  hs.hrr = true
  c.retried = true
  hs.hrrSuite = v.suite
  hs.hrrGroup = v.selectedGroup
  # No early data after a HelloRetryRequest (4.1.4): the server skips it.
  if hs.earlyOffered: c.earlyRejected = true
  hs.earlyOffered = false
  c.earlyWrite = false
  clear(c.wr)
  var ticket: seq[byte] = @[]
  if hs.pskOffered and hashOf(s) == hashOf(hs.pskSuite):
    var po = default(PskOffer)
    let chp = base(hs.ch)
    if parsePskOffer(chp, o, po) != 0 or po.identityLen.len != 1: return alInternalError
    ticket = newSeq[byte](po.identityLen[0])
    copyMem(addr ticket[0], addr chp[po.identityAt[0]], ticket.len)
  elif hs.pskOffered:
    hs.pskOffered = false                        # the suite's hash is not the ticket's: dropped
    wipe(hs.psk)
  setSuite(c, hs, s)
  restartTranscript(hs)
  addTranscript(hs, msg, len)
  var p = default(HelloParams)
  p.cfg = cfg
  let wire = c.wire
  if wire != nil:
    p.quic = wire.quic
    p.transportParams = wire.localParams
  p.alpn = o.alpn                                # what the first hello offered
  p.random = hs.clientRandom
  p.sessionId = hs.sessionId
  p.sessionIdLen = hs.sessionIdLen
  p.serverName = o.serverName
  p.retry = true
  if hs.greaseOn or hs.echRejected:
    # Again an ECH extension of the same shape, enc empty (RFC 9849 6.1.5, 6.2).
    p.echOuter = true
    p.echConfigId = hs.echConfigId
    p.echKdf = EchKdfSha256
    p.echAead = EchAeadAes128Gcm
    p.echPayloadLen = hs.echPayloadLen
  if ticket.len > 0:                             # the same ticket, its age and binder anew
    p.pskTicket = ticket
    p.pskAge = obfuscatedAge(hs, clockMs(cfg))
    p.pskBinderLen = digestLen(hashOf(hs.pskSuite))
  if v.cookieLen > 0:
    p.cookie = newSeq[byte](v.cookieLen)
    copyMem(addr p.cookie[0], addr msg[v.cookieAt], v.cookieLen)
  if v.selectedGroup != 0:
    for i in 0 ..< hs.nkeys: clear(hs.keys[i])
    hs.nkeys = 0
    var share: seq[byte] = @[]
    if not newShare(cfg, hs.keys[0], g, share): return alInternalError
    hs.nkeys = 1
    p.shareGroups.add g
    p.shares.add share
  else:
    let chp = base(hs.ch)
    for i in 0 ..< o.shareGroups.len:
      var gg = kxX25519
      if groupOf(o.shareGroups[i], gg):
        var share = newSeq[byte](o.shareLen[i])
        copyMem(addr share[0], addr chp[o.shareAt[i]], o.shareLen[i])
        p.shareGroups.add gg
        p.shares.add share
  if hs.sessionIdLen > 0 and not hs.ccsSent: queueCcs(c, hs)
  result = sendHello(c, hs, cfg, p, false)

proc endsWith(random: array[32, byte]; tail: array[8, byte]): bool =
  result = true
  for i in 0 ..< 8:
    if random[24 + i] != tail[i]: return false

proc onServerHello(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr;
                   msg: Bytes; len: int): int =
  var v = default(ServerHelloView)
  result = parseServerHello(msg, len, v)
  if result != 0: return
  if endsWith(v.random, Downgrade12) or endsWith(v.random, Downgrade11): return alIllegalParameter
  if v.version == 0: return alProtocolVersion    # TLS 1.2 or older: not ours
  if v.version != Tls13 or v.legacyVersion != Tls12: return alIllegalParameter
  if v.unknownExt: return alUnsupportedExtension
  if v.sessionIdLen != hs.sessionIdLen or
     (v.sessionIdLen > 0 and not ctEqual(addr msg[v.sessionIdAt], addr hs.sessionId[0], v.sessionIdLen)):
    return alIllegalParameter
  if v.compression != 0: return alIllegalParameter
  var o = default(HelloView)
  if not offered(hs, o): return alInternalError
  var s = suiteAes128Gcm
  if not has(o.suites, v.suite) or not suiteOf(v.suite, s): return alIllegalParameter
  if hs.hrr and v.suite != hs.hrrSuite: return alIllegalParameter
  if not v.isHrr and hs.echOffered and not hs.echRejected:
    # The last 8 bytes of the random confirm ECH (RFC 9849 7.2), or the
    # outer hello is what the server answered.
    if echConfirmed(hs, s, msg, len, 4 + 2 + 24, false): c.echAccepted = true
    elif hs.echHrrAccepted: return alIllegalParameter   # accepted at the retry: it must be now
    else: echReject(c, hs)
  if v.isHrr: return onRetry(c, hs, cfg, v, s, msg, len)
  # One ticket offered: index 0, for a suite with the ticket's hash.
  if v.pskIndex >= 0 and (not hs.pskOffered or v.pskIndex != 0 or hashOf(s) != hashOf(hs.pskSuite)):
    return alIllegalParameter
  let resumed = v.pskIndex == 0
  var k = -1
  for i in 0 ..< hs.nkeys:
    if groupCode(hs.keys[i].group) == v.shareGroup: k = i
  if k < 0 or v.shareLen != serverShareLen(hs.keys[k].group): return alIllegalParameter
  var secret = default(array[64, byte])
  if not complete(hs.keys[k], at(msg, v.shareAt), v.shareLen, ptrOf(secret)): return alIllegalParameter
  let secretLen = secretLen(hs.keys[k].group)
  for i in 0 ..< hs.nkeys: clear(hs.keys[i])
  hs.nkeys = 0
  setSuite(c, hs, s)
  addTranscript(hs, msg, len)
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  # Resumed: the early secret from the PSK is already there (the binder's).
  let ok = (resumed or startSchedule(hs.sched, hs.alg, ptrOf(secret), 0)) and
    handshakeSecrets(hs.sched, ptrOf(secret), secretLen, ptrOf(th))
  wipeBytes(addr secret[0], secret.len)
  # With 0-RTT offered we keep writing under the early keys until EE says.
  if not ok or not installTraffic(c, true, levelHandshake, s, hs.sched.sHs) or
     ((not hs.earlyOffered or quicMode(c)) and not installTraffic(c, false, levelHandshake, s, hs.sched.cHs)):
    return alInternalError
  hs.pskAccepted = resumed
  c.resumed = resumed
  c.keyChanged = true
  logSecret(c, hs, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", hs.sched.cHs)
  logSecret(c, hs, "SERVER_HANDSHAKE_TRAFFIC_SECRET", hs.sched.sHs)
  c.state = csWaitEe

# ------------------------------------------------------- the server's flight

proc onEncryptedExtensions(c: TlsConnPtr; hs: HandshakeStatePtr; msg: Bytes; len: int): int =
  var alpn = ""
  var sniAck = false
  var early = false
  var params = default(ByteView)
  result = parseEncryptedExtensions(msg, len, alpn, sniAck, early, addr params)
  if result != 0: return
  let wire = c.wire
  if wire != nil and wire.quic:
    let tp = params.data
    if tp == nil: return alMissingExtension
    if alpn.len == 0: return alNoApplicationProtocol
    if not receiveParameters(wire, tp, params.len): return alIllegalParameter
  elif params.data != nil: return alUnsupportedExtension
  var o = default(HelloView)
  if not offered(hs, o): return alInternalError
  if alpn.len > 0:
    if o.alpn.len == 0: return alUnsupportedExtension
    var mine = false
    for a in o.alpn:
      if a == alpn: mine = true
    if not mine: return alNoApplicationProtocol
  if sniAck and o.serverName.len == 0: return alUnsupportedExtension
  result = eeEch(hs, c.echAccepted, msg, len)
  if result != 0: return
  if early:
    # 0-RTT accepted (4.2.10): for the ticket we offered, its protocol.
    if not hs.earlyOffered: return alUnsupportedExtension
    if not hs.pskAccepted or not earlyAlpnIs(hs, alpn) or c.cs != hs.pskSuite: return alIllegalParameter
    c.earlyAccepted = true
  elif hs.earlyOffered:
    c.earlyRejected = true                       # skipped by the server: send it again later ...
    c.earlyAlpnChanged = not earlyAlpnIs(hs, alpn)   # ... unless for another protocol (4.2.10)
    c.earlyWrite = false
    if not installTraffic(c, false, levelHandshake, c.cs, hs.sched.cHs): return alInternalError
  setAlpn(c, alpn)
  addTranscript(hs, msg, len)
  c.state = if hs.pskAccepted: csWaitFinished else: csWaitCertCr   # no certificate when resumed

proc onCertificateRequest(c: TlsConnPtr; hs: HandshakeStatePtr; msg: Bytes; len: int): int =
  ## The server asks for our certificate: chosen now, sent with our Finished.
  var crq = default(CertRequestView)   # not `req`: the resolver's parameter leaks (c37)
  result = parseCertificateRequest(msg, len, crq)
  if result != 0: return
  if crq.ctxLen != 0: return alIllegalParameter  # empty during the handshake (4.3.2)
  if hs.certRequested: return alUnexpectedMessage
  hs.certRequested = true
  hs.certReqCtx.len = 0
  append(hs.certReqCtx, at(msg, crq.ctxAt), crq.ctxLen)
  # Our certificate, if we have one the request allows: a scheme it lists,
  # our configuration allows and the key makes (4.4.2.3).
  let cfg = c.ccfg
  if cfg != nil:
    var ck: nil CertifiedKeyPtr = nil
    let res = cfg.clientCert.resolve
    if res != nil: ck = res(cfg.clientCert.ctx, addr crq)
    if ck != nil and ck.key != nil and ck.chain.len > 0:
      var found = false
      for s in ck.schemes:
        if not found and has(crq.schemes, int(code(s))):
          for y in cfg.sigSchemes:
            if y == s:
              hs.clientScheme = s
              found = true
      if found: hs.clientCk = ck
  addTranscript(hs, msg, len)

proc sendClientCert(c: TlsConnPtr; hs: HandshakeStatePtr; ck: CertifiedKeyPtr): int =
  ## Our Certificate (the request's context) and CertificateVerify over the
  ## transcript through it, the client's context string (4.4.3).
  let cfg = c.ccfg
  let key = ck.key
  if cfg == nil or key == nil: return alInternalError
  var need = 64 + hs.certReqCtx.len
  for d in ck.chain: need = need + d.len + 5
  var w = beginMsg(hs, need)
  writeCertificate(w, ck.chain, base(hs.certReqCtx), hs.certReqCtx.len)
  if not endMsg(hs, w): return alInternalError
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  var content = default(array[200, byte])
  let clen = signedContent(false, ptrOf(th), digestLen(hs.alg), ptrOf(content))
  var sigBuf = default(array[1024, byte])
  var sigLen = 0
  let f = cfg.signer.sign
  let ok = if f != nil: f(cfg.signer.ctx, hs.clientScheme, ptrOf(content), clen, ptrOf(sigBuf), sigBuf.len, sigLen)
           else: sign(hs.clientScheme, key, ptrOf(content), clen, ptrOf(sigBuf), sigBuf.len, sigLen)
  if not ok: return alInternalError
  var vw = beginMsg(hs, 8 + sigLen)
  writeCertificateVerify(vw, int(code(hs.clientScheme)), ptrOf(sigBuf), sigLen)
  result = if endMsg(hs, vw): 0 else: alInternalError

proc onCertificate(c: TlsConnPtr; hs: HandshakeStatePtr; cfg: ClientConfigPtr; msg: Bytes; len: int): int =
  var certs: seq[seq[byte]] = @[]
  result = parseCertificate(msg, len, certs)
  if result != 0: return
  if certs.len == 0: return alDecodeError
  if certs.len > MaxChain: return alBadCertificate
  let name = nameOf(c)
  let vf = cfg.verifier.verify
  if vf != nil:
    result = vf(cfg.verifier.ctx, addr certs, name)
  else:
    let roots = cfg.roots
    result = if roots == nil: alUnknownCa else: webPkiVerify(roots, addr certs, name, cfg.verifyAt)
  if result != 0: return
  let leaf = certDer(bytesOf(certs[0]), certs[0].len)
  if leaf == nil: return alBadCertificate
  hs.peerKey = publicKey(leaf)
  release(leaf)
  if hs.peerKey == nil: return alBadCertificate
  c.peerLeaf.len = 0
  append(c.peerLeaf, bytesOf(certs[0]), certs[0].len)
  addTranscript(hs, msg, len)
  c.state = csWaitCv

proc onCertificateVerify(c: TlsConnPtr; hs: HandshakeStatePtr; msg: Bytes; len: int): int =
  var code = 0
  var sigAt = 0
  var sigLen = 0
  result = parseCertificateVerify(msg, len, code, sigAt, sigLen)
  if result != 0: return
  var o = default(HelloView)
  if not offered(hs, o): return alInternalError
  var s = sigEcdsaP256Sha256
  let key = hs.peerKey
  if key == nil: return alInternalError
  if not has(o.sigSchemes, code) or not schemeOf(code, s) or not matches(s, key):
    return alIllegalParameter
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  var content = default(array[200, byte])
  let n = signedContent(true, ptrOf(th), digestLen(hs.alg), ptrOf(content))
  if not verify(s, key, ptrOf(content), n, at(msg, sigAt), sigLen): return alDecryptError
  addTranscript(hs, msg, len)
  c.state = csWaitFinished

proc onFinished(c: TlsConnPtr; hs: HandshakeStatePtr; msg: Bytes; len: int): int =
  var vAt = 0
  var vLen = 0
  result = parseFinished(msg, len, vAt, vLen)
  if result != 0: return
  let n = digestLen(hs.alg)
  if vLen != n: return alDecodeError
  var th = default(array[48, byte])
  transcriptHash(hs, ptrOf(th))
  var expect = default(array[48, byte])
  if not verifyData(hs.alg, hs.sched.sHs, ptrOf(th), ptrOf(expect)): return alInternalError
  if not ctEqual(addr expect[0], addr msg[vAt], n): return alDecryptError
  # ECH refused: the public name is authenticated now, and with it the
  # retry configs; this connection ends here (RFC 9849 6.1.6).
  if hs.echRejected:
    c.echRejected = true
    c.echRetry.len = 0
    if hs.echRetryPending.len > 0: append(c.echRetry, base(hs.echRetryPending), hs.echRetryPending.len)
    return alEchRequired
  addTranscript(hs, msg, len)
  transcriptHash(hs, ptrOf(th))
  if not masterSecrets(hs.sched, ptrOf(th)) or not installAppKeys(c, hs, true): return alInternalError
  c.earlyWrite = false
  if c.earlyAccepted and not quicMode(c):
    # EndOfEarlyData, the last record under the early keys (4.5).
    var we = beginMsg(hs, 4)
    writeEndOfEarlyData(we)
    if not endMsg(hs, we) or not flushStage(c, hs, true) or not installTraffic(c, false, levelHandshake, c.cs, hs.sched.cHs):
      return alInternalError
  # Our flight: [change_cipher_spec] [empty Certificate] Finished.
  if hs.sessionIdLen > 0 and not hs.ccsSent: queueCcs(c, hs)
  if hs.certRequested:
    let ck = hs.clientCk
    if ck == nil:
      var w = beginMsg(hs, 16 + hs.certReqCtx.len)
      let none: seq[seq[byte]] = @[]
      writeCertificate(w, none, base(hs.certReqCtx), hs.certReqCtx.len)
      if not endMsg(hs, w): return alInternalError
    else:
      let a = sendClientCert(c, hs, ck)
      if a != 0: return a
  transcriptHash(hs, ptrOf(th))
  var mine = default(array[48, byte])
  if not verifyData(hs.alg, hs.sched.cHs, ptrOf(th), ptrOf(mine)): return alInternalError
  var w = beginMsg(hs, 4 + n)
  writeFinished(w, ptrOf(mine), n)
  if not endMsg(hs, w) or not flushStage(c, hs, true): return alInternalError
  transcriptHash(hs, ptrOf(th))
  if not resumptionSecret(hs.sched, ptrOf(th)) or not installAppKeys(c, hs, false):
    return alInternalError
  logSecret(c, hs, "CLIENT_TRAFFIC_SECRET_0", hs.sched.cAp)
  logSecret(c, hs, "SERVER_TRAFFIC_SECRET_0", hs.sched.sAp)
  logSecret(c, hs, "EXPORTER_SECRET", hs.sched.exporter)
  c.exporter = hs.sched.exporter
  c.resumption = hs.sched.resumption
  completeHandshake(c)

proc clientMsg(c: TlsConnPtr; hs: HandshakeStatePtr; typ: int; msg: Bytes; len: int): int {.nimcall.} =
  let cfg = c.ccfg
  if cfg == nil: return alInternalError
  case c.state
  of csWaitSh:
    result = if typ == htServerHello: onServerHello(c, hs, cfg, msg, len) else: alUnexpectedMessage
  of csWaitEe:
    result = if typ == htEncryptedExtensions: onEncryptedExtensions(c, hs, msg, len)
             else: alUnexpectedMessage
  of csWaitCertCr:
    if typ == htCertificateRequest: result = onCertificateRequest(c, hs, msg, len)
    elif typ == htCertificate: result = onCertificate(c, hs, cfg, msg, len)
    else: result = alUnexpectedMessage
  of csWaitCv:
    result = if typ == htCertificateVerify: onCertificateVerify(c, hs, msg, len) else: alUnexpectedMessage
  of csWaitFinished:
    result = if typ == htFinished: onFinished(c, hs, msg, len) else: alUnexpectedMessage
  else:
    result = alUnexpectedMessage

proc initClient*(c: var TlsConn; cfg: ClientConfigPtr; serverName: string): bool =
  ## A client connection to `serverName` (a DNS name, sent as SNI and
  ## verified; or an IP literal, verified, not sent). The first `step`
  ## gives the ClientHello.
  ## "" is refused: a name is what the certificate is checked against.
  c = default(TlsConn)
  if cfg.suites.len == 0 or cfg.groups.len == 0 or cfg.sigSchemes.len == 0 or
     serverName.len == 0 or serverName.len > 255:
    return false
  for a in cfg.alpn:
    if a.len == 0 or a.len > 255: return false
  for a in cfg.echOuterAlpn:
    if a.len == 0 or a.len > 255: return false
  # ECH configured but unusable: refused, never a hello with the name in clear.
  if not echConfigsUsable(cfg): return false
  c.role = roleClient
  c.state = csStart
  c.ccfg = cfg
  c.maxMsg = if cfg.maxHandshakeMsg > 0: cfg.maxHandshakeMsg else: DefaultMaxHandshakeMsg
  setName(addr c, serverName)
  c.onStart = startClient
  c.onMsg = clientMsg
  discard newHandshake(c)
  result = true
