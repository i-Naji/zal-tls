## TLS 1.3 handshake messages (RFC 8446 section 4): parsers over a whole
## message (its 4-byte header included) that return 0 or the alert to send,
## and writers into a `Writer`. Offsets in the views are from the message's
## first byte.

import zal_net/buffers
import zal_tls/common
import zal_tls/wire/[bytes, consts]

type
  HelloView* = object
    ## A parsed ClientHello.
    msgLen*: int
    legacyVersion*: int
    randomAt*: int
    sessionIdAt*, sessionIdLen*: int
    suites*: seq[int]
    compression*: seq[int]
    groups*: seq[int]
    shareGroups*, shareAt*, shareLen*: seq[int]
    sigSchemes*, sigSchemesCert*: seq[int]
    serverName*: string
    alpn*: seq[string]
    versions*: seq[int]
    pskModes*: seq[int]
    hasPsk*, hasEarlyData*: bool
    pskAt*, pskLen*: int
    cookieAt*, cookieLen*: int
    echAt*, echLen*: int
    transportParams*: ByteView     ## nil data: absent; otherwise borrowed message bytes
    extOrder*: seq[int]            ## every extension type, in order

  ServerHelloView* = object
    ## A parsed ServerHello or HelloRetryRequest.
    legacyVersion*, suite*, version*, compression*: int
    random*: array[32, byte]
    sessionIdAt*, sessionIdLen*: int
    isHrr*: bool
    shareGroup*, shareAt*, shareLen*: int     ## ServerHello key_share
    selectedGroup*: int                       ## HelloRetryRequest key_share
    cookieAt*, cookieLen*: int
    pskIndex*: int                            ## -1: none
    echConfAt*: int                           ## HelloRetryRequest: its ECH confirmation (8 bytes); -1: none
    unknownExt*: bool                         ## an extension TLS 1.3 does not allow here
    extOrder*: seq[int]

  PskOffer* = object
    ## A ClientHello's pre_shared_key (4.2.11); offsets from the message's
    ## first byte. The binders are over msg[0 ..< truncLen].
    identityAt*, identityLen*: seq[int]
    ages*: seq[uint32]                        ## obfuscated_ticket_age
    binderAt*, binderLen*: seq[int]
    truncLen*: int

  CertRequestView* = object
    ## A parsed CertificateRequest (4.3.2); offsets from the message's first byte.
    ctxAt*, ctxLen*: int
    schemes*: seq[int]                        ## signature_algorithms
    caNames*: seq[seq[byte]]                  ## certificate_authorities (DER names)

  TicketView* = object
    ## A parsed NewSessionTicket; offsets from the message's first byte.
    lifetime*, ageAdd*, maxEarlyData*: uint32
    nonceAt*, nonceLen*, ticketAt*, ticketLen*: int

type TypeSet = object
  ## 16-bit values seen so far: a bit each (duplicate checks in O(1): a
  ## ClientHello of thousands of extensions costs no more than its bytes).
  bits: array[1024, uint64]

proc testAndSet(s: var TypeSet; t: int): bool =
  ## Whether `t` was in the set; it is now.
  let w = (t shr 6) and 1023
  let b = 1'u64 shl uint64(t and 63)
  result = (s.bits[w] and b) != 0
  s.bits[w] = s.bits[w] or b

proc contains(s: TypeSet; t: int): bool =
  (s.bits[(t shr 6) and 1023] and (1'u64 shl uint64(t and 63))) != 0

proc header(r: var Reader; typ: int; len: int): bool =
  ## The message header: its type and a body length that matches.
  result = u8(r) == typ and u24(r) == len - 4 and r.ok

proc toStr(r: Reader): string =
  result = newString(r.left)
  var i = 0
  while i < r.left:
    result[i] = char(r.p[r.pos + i])
    i = i + 1

proc pairs16(l: var Reader; outp: var seq[int]): bool =
  ## A list of 16-bit values filling `l`; false if its length is odd or 0.
  if l.left == 0 or l.left mod 2 != 0: return false
  while not l.atEnd: outp.add u16(l)
  result = l.ok

# ------------------------------------------------------------ ClientHello

proc parseClientHello*(msg: Bytes; len: int; v: var HelloView): int =
  v = default(HelloView)
  v.msgLen = len
  var r = initReader(msg, 0, len)
  if not header(r, htClientHello, len): return alDecodeError
  v.legacyVersion = u16(r)
  v.randomAt = r.pos
  skip(r, 32)
  var sid = vec8(r)
  v.sessionIdAt = sid.pos
  v.sessionIdLen = sid.left
  if sid.left > 32: return alIllegalParameter
  var suites = vec16(r)
  if not pairs16(suites, v.suites): return alDecodeError
  var comp = vec8(r)
  if comp.left == 0: return alDecodeError
  while not comp.atEnd: v.compression.add u8(comp)
  if r.atEnd and r.ok: return 0                 # no extensions at all
  var exts = vec16(r)
  if not r.ok or not r.atEnd: return alDecodeError
  var seenExt = default(TypeSet)
  var seenShare = default(TypeSet)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if not exts.ok: return alDecodeError
    if testAndSet(seenExt, typ): return alIllegalParameter
    if v.hasPsk: return alIllegalParameter      # pre_shared_key must be last
    v.extOrder.add typ
    case typ
    of extServerName:
      var list = vec16(data)
      while not list.atEnd:
        let nameType = u8(list)
        var name = vec16(list)
        if nameType == 0:
          if v.serverName.len > 0 or name.left == 0: return alIllegalParameter
          v.serverName = toStr(name)
      if not list.ok: return alDecodeError
    of extSupportedGroups:
      var l = vec16(data)
      if not pairs16(l, v.groups): return alDecodeError
    of extSignatureAlgorithms:
      var l = vec16(data)
      if not pairs16(l, v.sigSchemes): return alDecodeError
    of extSignatureAlgorithmsCert:
      var l = vec16(data)
      if not pairs16(l, v.sigSchemesCert): return alDecodeError
    of extAlpn:
      var l = vec16(data)
      if l.left == 0: return alDecodeError
      while not l.atEnd:
        var p = vec8(l)
        if p.left == 0: return alDecodeError
        v.alpn.add toStr(p)
      if not l.ok: return alDecodeError
    of extSupportedVersions:
      var l = vec8(data)
      if not pairs16(l, v.versions): return alDecodeError
    of extKeyShare:
      var l = vec16(data)
      while not l.atEnd:
        let g = u16(l)
        var ke = vec16(l)
        if ke.left == 0: return alDecodeError
        if testAndSet(seenShare, g): return alIllegalParameter
        v.shareGroups.add g
        v.shareAt.add ke.pos
        v.shareLen.add ke.left
      if not l.ok: return alDecodeError
    of extPskKeyExchangeModes:
      var l = vec8(data)
      if l.left == 0: return alDecodeError
      while not l.atEnd: v.pskModes.add u8(l)
    of extPreSharedKey:
      v.hasPsk = true
      v.pskAt = data.pos
      v.pskLen = data.left
      skip(data, data.left)
    of extEarlyData:
      v.hasEarlyData = true
    of extQuicTransportParameters:
      v.transportParams = ByteView(data: at(msg, data.pos), len: data.left)
      skip(data, data.left)
    of extCookie:
      var c = vec16(data)
      if c.left == 0: return alDecodeError
      v.cookieAt = c.pos
      v.cookieLen = c.left
    of extEch:
      v.echAt = data.pos
      v.echLen = data.left
      skip(data, data.left)
    else:
      skip(data, data.left)                   # unknown: ignored (4.2)
    if not data.ok or not data.atEnd: return alDecodeError
  if not exts.ok: return alDecodeError
  if v.groups.len > 0:
    # A key share for a group not in supported_groups (4.2.8).
    var listed = default(TypeSet)
    for g in v.groups: discard testAndSet(listed, g)
    for g in v.shareGroups:
      if g notin listed: return alIllegalParameter
  result = 0

proc parsePskOffer*(msg: Bytes; v: HelloView; o: var PskOffer): int =
  ## The identities and binders of a ClientHello's pre_shared_key
  ## (`v.hasPsk`): as many binders as identities, each 32..255 bytes.
  o = default(PskOffer)
  if not v.hasPsk: return alInternalError
  var r = initReader(msg, v.pskAt, v.pskLen)
  var ids = vec16(r)
  if ids.left == 0: return alDecodeError
  while not ids.atEnd:
    var id = vec16(ids)
    let age = u32(ids)
    if not ids.ok or id.left == 0: return alDecodeError
    o.identityAt.add id.pos
    o.identityLen.add id.left
    o.ages.add age
  o.truncLen = r.pos                          # the binders' length field starts here
  var bs = vec16(r)
  while not bs.atEnd:
    var b = vec8(bs)
    if not bs.ok or b.left < 32: return alDecodeError
    o.binderAt.add b.pos
    o.binderLen.add b.left
  if not r.ok or not r.atEnd or o.binderAt.len != o.identityAt.len: return alDecodeError
  result = 0

proc writePskExtension*(w: var Writer; ticket: Bytes; ticketLen: int; obfuscatedAge: uint32;
                        binderLen: int) =
  ## A pre_shared_key extension with one identity and a zeroed binder of
  ## `binderLen` bytes (the last extension of a ClientHello; the binder is
  ## filled in once the whole hello is written: `parsePskOffer` finds it).
  put16(w, extPreSharedKey)
  let e = begin16(w)
  let ids = begin16(w)
  let id = begin16(w)
  putBytes(w, ticket, ticketLen)
  finish16(w, id)
  put32(w, int(obfuscatedAge))
  finish16(w, ids)
  let bs = begin16(w)
  put8(w, binderLen)
  for i in 0 ..< binderLen: put8(w, 0)
  finish16(w, bs)
  finish16(w, e)

# ------------------------------------------------------------ ServerHello

proc parseServerHello*(msg: Bytes; len: int; v: var ServerHelloView): int =
  v = default(ServerHelloView)
  v.pskIndex = -1
  v.echConfAt = -1
  var r = initReader(msg, 0, len)
  if not header(r, htServerHello, len): return alDecodeError
  v.legacyVersion = u16(r)
  var rnd = sub(r, 32)
  if not rnd.ok: return alDecodeError
  copyMem(addr v.random[0], rnd.here, 32)
  v.isHrr = v.random == HrrRandom
  var sid = vec8(r)
  v.sessionIdAt = sid.pos
  v.sessionIdLen = sid.left
  v.suite = u16(r)
  v.compression = u8(r)
  if r.atEnd and r.ok: return 0
  var exts = vec16(r)
  if not r.ok or not r.atEnd: return alDecodeError
  var seenExt = default(TypeSet)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if not exts.ok: return alDecodeError
    if testAndSet(seenExt, typ): return alIllegalParameter
    v.extOrder.add typ
    case typ
    of extSupportedVersions:
      v.version = u16(data)
    of extKeyShare:
      if v.isHrr:
        v.selectedGroup = u16(data)
      else:
        v.shareGroup = u16(data)
        var ke = vec16(data)
        if ke.left == 0: return alDecodeError
        v.shareAt = ke.pos
        v.shareLen = ke.left
    of extCookie:
      if not v.isHrr: return alUnsupportedExtension
      var c = vec16(data)
      if c.left == 0: return alDecodeError
      v.cookieAt = c.pos
      v.cookieLen = c.left
    of extPreSharedKey:
      if v.isHrr: return alUnsupportedExtension
      v.pskIndex = u16(data)
    of extEch:
      if not v.isHrr: return alUnsupportedExtension   # a ServerHello confirms in its random
      if data.left != 8: return alDecodeError
      v.echConfAt = data.pos
      skip(data, 8)
    else:
      v.unknownExt = true                     # the caller decides after the version (a TLS 1.2 hello)
      skip(data, data.left)
    if not data.ok or not data.atEnd: return alDecodeError
  result = if exts.ok: 0 else: alDecodeError

proc writeServerHello*(w: var Writer; random: Bytes;
                       sessionId: Bytes; sidLen: int; suite: int;
                       hrrGroup: int; share: Bytes; shareLen: int; group: int;
                       cookie: Bytes; cookieLen: int; pskIndex = -1; echConf = false) =
  ## A ServerHello (hrrGroup 0) or a HelloRetryRequest asking for `hrrGroup`
  ## (`random` must then be HrrRandom); `pskIndex` >= 0: the PSK identity
  ## chosen; `echConf`: a retry's ECH confirmation, zeros, last (filled in
  ## over the message). Extension order as in RFC 8448.
  put8(w, htServerHello)
  let at = begin24(w)
  put16(w, Tls12)
  putBytes(w, random, 32)
  let s = begin8(w)
  putBytes(w, sessionId, sidLen)
  finish8(w, s)
  put16(w, suite)
  put8(w, 0)
  let ex = begin16(w)
  if pskIndex >= 0 and hrrGroup == 0:
    put16(w, extPreSharedKey)
    put16(w, 2)
    put16(w, pskIndex)
  put16(w, extKeyShare)
  if hrrGroup != 0:
    put16(w, 2)
    put16(w, hrrGroup)
    if cookieLen > 0:
      put16(w, extCookie)
      let c = begin16(w)
      let c2 = begin16(w)
      putBytes(w, cookie, cookieLen)
      finish16(w, c2)
      finish16(w, c)
  else:
    let k = begin16(w)
    put16(w, group)
    let ks = begin16(w)
    putBytes(w, share, shareLen)
    finish16(w, ks)
    finish16(w, k)
  put16(w, extSupportedVersions)
  put16(w, 2)
  put16(w, Tls13)
  if echConf and hrrGroup != 0:
    put16(w, extEch)
    put16(w, 8)
    for i in 0 ..< 8: put8(w, 0)
  finish16(w, ex)
  finish24(w, at)

# ------------------------------------------------------ EncryptedExtensions

proc parseEncryptedExtensions*(msg: Bytes; len: int;
                               alpn: var string; sniAck: var bool; early: var bool;
                               params: nil ptr ByteView = nil): int =
  ## ALPN (exactly one protocol), a server_name acknowledgement, early_data
  ## accepted; other extensions are ignored, the ones not allowed here refused.
  if params != nil: params[] = default(ByteView)
  alpn = ""
  sniAck = false
  early = false
  var r = initReader(msg, 0, len)
  if not header(r, htEncryptedExtensions, len): return alDecodeError
  var exts = vec16(r)
  if not r.ok or not r.atEnd: return alDecodeError
  var seenExt = default(TypeSet)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if not exts.ok: return alDecodeError
    if testAndSet(seenExt, typ): return alIllegalParameter
    case typ
    of extQuicTransportParameters:
      if params != nil: params[] = ByteView(data: at(msg, data.pos), len: data.left)
      skip(data, data.left)
    of extServerName:
      if data.left != 0: return alDecodeError
      sniAck = true
    of extAlpn:
      var l = vec16(data)
      var p = vec8(l)
      if p.left == 0 or not l.atEnd: return alDecodeError   # exactly one protocol
      alpn = toStr(p)
    of extEarlyData:
      if data.left != 0: return alDecodeError
      early = true
    of extKeyShare, extSupportedVersions, extPreSharedKey, extSignatureAlgorithms, extCookie:
      return alIllegalParameter                             # not allowed here (4.2)
    else:
      skip(data, data.left)
    if not data.ok or not data.atEnd: return alDecodeError
  result = if exts.ok: 0 else: alDecodeError

proc findEchRetry*(msg: Bytes; len: int; at, n: var int): bool =
  ## EncryptedExtensions' encrypted_client_hello, when there is one: its
  ## data (retry_configs: an ECHConfigList with its length, unchecked) at
  ## msg[at ..< at + n].
  result = false
  at = 0
  n = 0
  var r = initReader(msg, 0, len)
  if not header(r, htEncryptedExtensions, len): return
  var exts = vec16(r)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if not exts.ok: return
    if typ == extEch:
      at = data.pos
      n = data.left
      return true
    skip(data, data.left)

proc writeEncryptedExtensions*(w: var Writer; alpn: string; sniAck: bool; early = false;
                               retryConfigs: nil Bytes = nil; retryLen = 0;
                               params: ByteView = default(ByteView)) =
  ## (`retryConfigs`: an ECHConfigList with its length, when ECH was refused.)
  put8(w, htEncryptedExtensions)
  let at = begin24(w)
  let ex = begin16(w)
  if retryConfigs != nil and retryLen > 0:
    put16(w, extEch)
    let e = begin16(w)
    putBytes(w, retryConfigs, retryLen)
    finish16(w, e)
  let tp = params.data
  if tp != nil:
    put16(w, extQuicTransportParameters)
    let qp = begin16(w)
    putBytes(w, tp, params.len)
    finish16(w, qp)
  if early:
    put16(w, extEarlyData)
    put16(w, 0)
  if sniAck:
    put16(w, extServerName)
    put16(w, 0)
  if alpn.len > 0:
    put16(w, extAlpn)
    let a = begin16(w)
    let l = begin16(w)
    put8(w, alpn.len)
    putStr(w, alpn)
    finish16(w, l)
    finish16(w, a)
  finish16(w, ex)
  finish24(w, at)

# --------------------------------------------------------------- Certificate

proc parseCertificate*(msg: Bytes; len: int; chain: var seq[seq[byte]]): int =
  ## A server's Certificate (an empty request context); the DER of each entry.
  chain = @[]
  var r = initReader(msg, 0, len)
  if not header(r, htCertificate, len): return alDecodeError
  var ctx = vec8(r)
  if ctx.left != 0: return alIllegalParameter
  var list = vec24(r)
  if not r.ok or not r.atEnd: return alDecodeError
  while not list.atEnd:
    var der = vec24(list)
    discard vec16(list)                          # per-certificate extensions: ignored
    if der.left == 0 or not list.ok: return alDecodeError
    var c = newSeq[byte](der.left)
    copyMem(addr c[0], der.here, der.left)
    chain.add c
  result = if list.ok: 0 else: alDecodeError

proc writeCertificate*(w: var Writer; chain: seq[seq[byte]]; ctx: nil Bytes = nil; ctxLen = 0) =
  ## `ctx`: a client's echo of the CertificateRequest context.
  put8(w, htCertificate)
  let at = begin24(w)
  let c = begin8(w)
  if ctx != nil: putBytes(w, ctx, ctxLen)
  finish8(w, c)
  let l = begin24(w)
  for c in chain:
    put24(w, c.len)
    if c.len > 0: putBytes(w, cast[Bytes](unsafeAddr c[0]), c.len)
    put16(w, 0)
  finish24(w, l)
  finish24(w, at)

proc parseCertificateRequest*(msg: Bytes; len: int; v: var CertRequestView): int =
  ## A CertificateRequest (4.3.2): its context, signature_algorithms
  ## (required) and certificate_authorities; other extensions are ignored.
  v = default(CertRequestView)
  var r = initReader(msg, 0, len)
  if not header(r, htCertificateRequest, len): return alDecodeError
  var ctx = vec8(r)
  v.ctxAt = ctx.pos
  v.ctxLen = ctx.left
  var exts = vec16(r)
  if not r.ok or not r.atEnd: return alDecodeError
  var seenExt = default(TypeSet)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if not exts.ok: return alDecodeError
    if testAndSet(seenExt, typ): return alIllegalParameter
    if typ == extSignatureAlgorithms:
      var l = vec16(data)
      if not pairs16(l, v.schemes): return alDecodeError
    elif typ == extCertificateAuthorities:
      var l = vec16(data)
      if l.left < 3: return alDecodeError
      while not l.atEnd:
        var n = vec16(l)
        if not l.ok or n.left == 0: return alDecodeError
        var name = newSeq[byte](n.left)
        copyMem(addr name[0], n.here, n.left)
        v.caNames.add name
    else:
      skip(data, data.left)
    if not data.ok or not data.atEnd: return alDecodeError
  if not exts.ok: return alDecodeError
  result = if v.schemes.len == 0: alMissingExtension else: 0

proc writeCertificateRequest*(w: var Writer; ctx: nil Bytes; ctxLen: int; schemes: seq[int];
                              caNames: seq[seq[byte]]) =
  ## A CertificateRequest: signature_algorithms, and certificate_authorities
  ## when `caNames` has some (DER names).
  put8(w, htCertificateRequest)
  let at = begin24(w)
  let c = begin8(w)
  if ctx != nil and ctxLen > 0: putBytes(w, ctx, ctxLen)
  finish8(w, c)
  let exts = begin16(w)
  put16(w, extSignatureAlgorithms)
  let e = begin16(w)
  let l = begin16(w)
  for x in schemes: put16(w, x)
  finish16(w, l)
  finish16(w, e)
  if caNames.len > 0:
    put16(w, extCertificateAuthorities)
    let ea = begin16(w)
    let la = begin16(w)
    for n in caNames:
      let one = begin16(w)
      if n.len > 0: putBytes(w, cast[Bytes](unsafeAddr n[0]), n.len)
      finish16(w, one)
    finish16(w, la)
    finish16(w, ea)
  finish16(w, exts)
  finish24(w, at)

# ------------------------------------------------------- CertificateVerify

proc parseCertificateVerify*(msg: Bytes; len: int;
                             scheme: var int; sigAt, sigLen: var int): int =
  var r = initReader(msg, 0, len)
  if not header(r, htCertificateVerify, len): return alDecodeError
  scheme = u16(r)
  var s = vec16(r)
  sigAt = s.pos
  sigLen = s.left
  result = if r.ok and r.atEnd and sigLen > 0: 0 else: alDecodeError

proc writeCertificateVerify*(w: var Writer; scheme: int; sig: Bytes; sigLen: int) =
  put8(w, htCertificateVerify)
  let at = begin24(w)
  put16(w, scheme)
  let s = begin16(w)
  putBytes(w, sig, sigLen)
  finish16(w, s)
  finish24(w, at)

proc signedContent*(server: bool; transcriptHash: Bytes; hashLen: int;
                    outp: Bytes): int =
  ## What a CertificateVerify signs (4.4.3): 64 spaces, the context string,
  ## a 0 byte, the transcript hash. `outp` needs 64 + 34 + 48 bytes.
  const serverCtx = "TLS 1.3, server CertificateVerify"
  const clientCtx = "TLS 1.3, client CertificateVerify"
  var i = 0
  while i < 64:
    outp[i] = 0x20
    i = i + 1
  let ctx = if server: serverCtx else: clientCtx
  var j = 0
  while j < ctx.len:
    outp[64 + j] = byte(ctx[j])
    j = j + 1
  outp[64 + ctx.len] = 0
  copyMem(addr outp[65 + ctx.len], transcriptHash, hashLen)
  result = 65 + ctx.len + hashLen

# ------------------------------------------------ Finished, KeyUpdate, tickets

proc parseFinished*(msg: Bytes; len: int; at, n: var int): int =
  var r = initReader(msg, 0, len)
  if not header(r, htFinished, len): return alDecodeError
  at = r.pos
  n = r.left
  result = 0

proc writeFinished*(w: var Writer; verify: Bytes; n: int) =
  put8(w, htFinished)
  put24(w, n)
  putBytes(w, verify, n)

proc parseKeyUpdate*(msg: Bytes; len: int; requested: var bool): int =
  var r = initReader(msg, 0, len)
  if not header(r, htKeyUpdate, len): return alDecodeError
  let x = u8(r)
  if not r.ok or not r.atEnd: return alDecodeError
  if x > 1: return alIllegalParameter
  requested = x == 1
  result = 0

proc writeKeyUpdate*(w: var Writer; requested: bool) =
  put8(w, htKeyUpdate)
  put24(w, 1)
  put8(w, if requested: 1 else: 0)

proc parseNewSessionTicket*(msg: Bytes; len: int; t: var TicketView): int =
  t = default(TicketView)
  var r = initReader(msg, 0, len)
  if not header(r, htNewSessionTicket, len): return alDecodeError
  t.lifetime = u32(r)
  t.ageAdd = u32(r)
  var nonce = vec8(r)
  t.nonceAt = nonce.pos
  t.nonceLen = nonce.left
  var ticket = vec16(r)
  t.ticketAt = ticket.pos
  t.ticketLen = ticket.left
  if ticket.left == 0: return alDecodeError
  var exts = vec16(r)
  if not r.ok or not r.atEnd: return alDecodeError
  var seenExt = default(TypeSet)
  while not exts.atEnd:
    let typ = u16(exts)
    var data = vec16(exts)
    if testAndSet(seenExt, typ): return alIllegalParameter
    if typ == extEarlyData: t.maxEarlyData = u32(data)
    else: skip(data, data.left)
    if not data.ok or not data.atEnd: return alDecodeError
  result = if exts.ok: 0 else: alDecodeError

proc parseEndOfEarlyData*(msg: Bytes; len: int): int =
  var r = initReader(msg, 0, len)
  result = if header(r, htEndOfEarlyData, len) and r.atEnd: 0 else: alDecodeError

proc writeEndOfEarlyData*(w: var Writer) =
  put8(w, htEndOfEarlyData)
  put24(w, 0)

proc writeNewSessionTicket*(w: var Writer; lifetime, ageAdd: uint32; nonce: Bytes; nonceLen: int;
                            ticket: Bytes; ticketLen: int; maxEarlyData: uint32) =
  ## A NewSessionTicket (4.6.1); `maxEarlyData` > 0 adds early_data.
  put8(w, htNewSessionTicket)
  let at = begin24(w)
  put32(w, int(lifetime))
  put32(w, int(ageAdd))
  let n = begin8(w)
  putBytes(w, nonce, nonceLen)
  finish8(w, n)
  let t = begin16(w)
  putBytes(w, ticket, ticketLen)
  finish16(w, t)
  let ex = begin16(w)
  if maxEarlyData > 0:
    put16(w, extEarlyData)
    put16(w, 4)
    put32(w, int(maxEarlyData))
  finish16(w, ex)
  finish24(w, at)
