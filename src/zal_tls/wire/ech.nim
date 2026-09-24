## Encrypted Client Hello on the wire (RFC 9849): ECHConfig and
## ECHConfigList, the `encrypted_client_hello` extension (outer and inner
## forms), and the EncodedClientHelloInner: the inner ClientHello without
## its session id, extensions it shares with the outer hello replaced by
## `ech_outer_extensions`, padded; decoded against the outer hello.

import zal_tls/common
import zal_tls/wire/[bytes, consts, messages]

const
  EchVersion* = 0xfe0d
  EchKemX25519* = 0x0020
  EchKdfSha256* = 0x0001
  EchAeadAes128Gcm* = 0x0001
  EchConfirmLen* = 8

type
  EchConfigView* = object
    ## One ECHConfig (version 0xfe0d) in a list; offsets into the list's bytes.
    at*, len*: int                  ## the whole ECHConfig (version, length, contents): HPKE's info
    configId*, kemId*: int
    pubAt*, pubLen*: int
    kdfs*, aeads*: seq[int]         ## the cipher suites, pairwise
    maxNameLen*: int
    publicName*: string

  EchExtView* = object
    ## A ClientHello's encrypted_client_hello; offsets from the message's first byte.
    outer*: bool
    kdf*, aead*, configId*: int
    encAt*, encLen*: int
    payloadAt*, payloadLen*: int

  ExtAt = object
    typ, at, total: int             ## an extension: its type, where it starts, its length with the header

  HelloLayout = object
    ## Where a ClientHello's fields lie (offsets from the message's first byte).
    randomAt, sidAt, sidLen: int
    suitesAt, suitesLen: int        ## with the 2-byte length
    compAt, compLen: int            ## with the 1-byte length
    exts: seq[ExtAt]

proc writeEchConfig*(w: var Writer; configId: int; pub: Bytes; publicName: string; maxNameLen: int) =
  ## An ECHConfig: DHKEM(X25519), HKDF-SHA256 and AES-128-GCM, no extensions.
  put16(w, EchVersion)
  let l = begin16(w)
  put8(w, configId)
  put16(w, EchKemX25519)
  let p = begin16(w)
  putBytes(w, pub, 32)
  finish16(w, p)
  let s = begin16(w)
  put16(w, EchKdfSha256)
  put16(w, EchAeadAes128Gcm)
  finish16(w, s)
  put8(w, maxNameLen)
  let n = begin8(w)
  putStr(w, publicName)
  finish8(w, n)
  put16(w, 0)                                    # extensions
  finish16(w, l)

proc validPublicName*(name: string): bool =
  ## A public name clients may use (RFC 9849 6.1.7): dot-separated LDH
  ## labels (1 to 63 letters, digits and inner hyphens), no empty label, no
  ## final dot; the last label not numeric or 0x-hex (an IPv4 address).
  result = false
  if name.len == 0 or name.len > 253: return
  var labelStart = 0
  for i in 0 .. name.len:
    if i == name.len or name[i] == '.':
      let n = i - labelStart
      if n < 1 or n > 63 or name[labelStart] == '-' or name[i - 1] == '-': return
      labelStart = i + 1
    else:
      let ch = name[i]
      if not ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '-'):
        return
  var k = name.len - 1
  while k >= 0 and name[k] != '.': k = k - 1
  let last = name.substr(k + 1)
  var digits = true
  for ch in last:
    if ch < '0' or ch > '9': digits = false
  if digits: return
  if last.len >= 2 and last[0] == '0' and (last[1] == 'x' or last[1] == 'X'):
    var hex = true
    for j in 2 ..< last.len:
      let ch = last[j]
      if not ((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F')): hex = false
    if hex: return
  result = true

proc parseEchConfigList*(p: Bytes; len: int; configs: var seq[EchConfigView]): bool =
  ## The configurations of version 0xfe0d whose extensions we know (none
  ## mandatory) and whose public name is valid (`validPublicName`); false
  ## when the list is malformed (an empty one too: ECHConfigList<4..2^16-1>).
  configs = @[]
  var r = initReader(p, 0, len)
  var lst = vec16(r)
  if not r.ok or not r.atEnd or lst.left < 4: return false
  while not lst.atEnd:
    let cat = lst.pos
    let version = u16(lst)
    var c = vec16(lst)
    if not lst.ok: return false
    let clen = c.left
    if version != EchVersion:
      skip(c, clen)
      continue
    var v = default(EchConfigView)
    v.at = cat
    v.len = 4 + clen
    v.configId = u8(c)
    v.kemId = u16(c)
    var pk = vec16(c)
    v.pubAt = pk.pos
    v.pubLen = pk.left
    skip(pk, pk.left)
    var suites = vec16(c)
    if suites.left < 4 or suites.left mod 4 != 0: return false
    while not suites.atEnd:
      v.kdfs.add u16(suites)
      v.aeads.add u16(suites)
    v.maxNameLen = u8(c)
    var name = vec8(c)
    if name.left == 0: return false
    for i in 0 ..< name.left: v.publicName.add char(name.p[name.pos + i])
    skip(name, name.left)
    var exts = vec16(c)
    var mandatory = false
    while not exts.atEnd:
      let typ = u16(exts)
      var d = vec16(exts)
      skip(d, d.left)
      if (typ and 0x8000) != 0: mandatory = true   # one we do not know and must: skip the config
    if not c.ok or not c.atEnd or not exts.ok or v.pubLen == 0: return false
    if not mandatory and validPublicName(v.publicName): configs.add v
  result = lst.ok

proc parseEchExtension*(msg: Bytes; at, len: int; v: var EchExtView): int =
  ## The extension's data at msg[at ..< at + len]: 0 or the alert.
  v = default(EchExtView)
  var r = initReader(msg, at, len)
  let typ = u8(r)
  if typ == 1:
    result = if r.ok and r.atEnd: 0 else: alDecodeError
    return
  if typ != 0: return alIllegalParameter
  v.outer = true
  v.kdf = u16(r)
  v.aead = u16(r)
  v.configId = u8(r)
  var e = vec16(r)
  v.encAt = e.pos
  v.encLen = e.left
  skip(e, e.left)
  var p = vec16(r)
  v.payloadAt = p.pos
  v.payloadLen = p.left
  skip(p, p.left)
  result = if r.ok and r.atEnd and v.payloadLen > 0: 0 else: alDecodeError

proc writeEchOuter*(w: var Writer; kdf, aead, configId: int; enc: nil Bytes; encLen, payloadLen: int): int =
  ## The outer form, its payload zeros (filled in once sealed: the AAD is
  ## the hello with them); where the payload starts.
  put16(w, extEch)
  let e = begin16(w)
  put8(w, 0)
  put16(w, kdf)
  put16(w, aead)
  put8(w, configId)
  let x = begin16(w)
  if enc != nil and encLen > 0: putBytes(w, enc, encLen)
  finish16(w, x)
  put16(w, payloadLen)
  result = w.pos
  for i in 0 ..< payloadLen: put8(w, 0)
  finish16(w, e)

proc writeEchInner*(w: var Writer) =
  ## The inner form: its type alone.
  put16(w, extEch)
  put16(w, 1)
  put8(w, 1)

proc layoutOf(msg: Bytes; len: int; lay: var HelloLayout; bodyAt: int): bool =
  ## A ClientHello's fields from `bodyAt` (4 with the handshake header, 0 without).
  lay = default(HelloLayout)
  var r = initReader(msg, bodyAt, len - bodyAt)
  skip(r, 2)
  lay.randomAt = r.pos
  skip(r, 32)
  var sid = vec8(r)
  lay.sidAt = sid.pos
  lay.sidLen = sid.left
  skip(sid, sid.left)
  lay.suitesAt = r.pos
  var su = vec16(r)
  skip(su, su.left)
  lay.suitesLen = r.pos - lay.suitesAt
  lay.compAt = r.pos
  var co = vec8(r)
  skip(co, co.left)
  lay.compLen = r.pos - lay.compAt
  var exts = vec16(r)
  while not exts.atEnd:
    let xat = exts.pos
    let typ = u16(exts)
    var d = vec16(exts)
    skip(d, d.left)
    lay.exts.add ExtAt(typ: typ, at: xat, total: exts.pos - xat)
  result = r.ok and exts.ok

proc has(s: seq[int]; x: int): bool =
  result = false
  for y in s:
    if y == x: return true

proc refsExt(w: var Writer; refs: seq[int]) =
  put16(w, extEchOuterExtensions)
  let e = begin16(w)
  let l = begin8(w)
  for t in refs: put16(w, t)
  finish8(w, l)
  finish16(w, e)

proc encodeInnerRaw*(inner: Bytes; len: int; refs: seq[int]; outp: var seq[byte]): bool =
  ## The inner ClientHello (with its header) as it goes into the payload,
  ## unpadded: no header, an empty session id, the extensions of `refs`
  ## left out and one ech_outer_extensions naming `refs` where the first of
  ## them was (at the end when none is there).
  outp = @[]
  var lay = default(HelloLayout)
  if not layoutOf(inner, len, lay, 4): return false
  outp.setLen(len + 256)
  var w = initWriter(bytesOf(outp), 0, outp.len)
  putBytes(w, at(inner, 4), 2)
  putBytes(w, at(inner, lay.randomAt), 32)
  put8(w, 0)                                     # legacy_session_id: the outer's
  putBytes(w, at(inner, lay.suitesAt), lay.suitesLen)
  putBytes(w, at(inner, lay.compAt), lay.compLen)
  let exts = begin16(w)
  var placed = false
  for x in lay.exts:
    if has(refs, x.typ):
      if not placed:
        refsExt(w, refs)
        placed = true
    else:
      putBytes(w, at(inner, x.at), x.total)
  if not placed and refs.len > 0: refsExt(w, refs)
  finish16(w, exts)
  result = w.ok
  outp.setLen(if result: w.pos else: 0)

proc encodeInner*(inner: Bytes; len: int; compress: seq[int]; maxNameLen: int; outp: var seq[byte]): bool =
  ## `encodeInnerRaw`, then padded (RFC 9849 6.1.3): the server name up to
  ## `maxNameLen`, then to a multiple of 32.
  result = encodeInnerRaw(inner, len, compress, outp)
  if not result: return
  var v = default(HelloView)
  if parseClientHello(inner, len, v) != 0: return false
  var pad = if v.serverName.len > 0: max(0, maxNameLen - v.serverName.len) else: maxNameLen + 9
  let l = outp.len + pad
  pad = pad + 31 - ((l - 1) mod 32)
  for i in 0 ..< pad: outp.add 0

proc decodeInner*(encoded: Bytes; encLen: int; outer: Bytes; outerLen: int; inner: var seq[byte]): int =
  ## The inner ClientHello (with its header) from its encoding and the outer
  ## hello: the outer's session id, the extensions named by
  ## ech_outer_extensions copied from the outer (in its order, each once,
  ## never ECH itself). 0 or the alert (illegal_parameter for a bad
  ## reference or padding that is not zeros).
  inner = @[]
  var ol = default(HelloLayout)
  if not layoutOf(outer, outerLen, ol, 4): return alDecodeError
  var r = initReader(encoded, 0, encLen)
  let versionAt = r.pos
  skip(r, 2 + 32)
  var sid = vec8(r)
  if sid.left != 0: return alIllegalParameter
  let suitesAt = r.pos
  var su = vec16(r)
  skip(su, su.left)
  let compAt = r.pos
  var co = vec8(r)
  skip(co, co.left)
  let extsAt = r.pos
  var exts = vec16(r)
  if not r.ok: return alDecodeError
  for i in r.pos ..< encLen:
    if encoded[i] != 0: return alIllegalParameter   # padding: zeros only
  inner.setLen(4 + encLen + outerLen + 64)
  var w = initWriter(bytesOf(inner), 0, inner.len)
  put8(w, htClientHello)
  let m = begin24(w)
  putBytes(w, at(encoded, versionAt), 2 + 32)
  let s = begin8(w)
  putBytes(w, at(outer, ol.sidAt), ol.sidLen)
  finish8(w, s)
  putBytes(w, at(encoded, suitesAt), extsAt - suitesAt)
  let e = begin16(w)
  var next = 0                                   # outer extensions before this one are used up
  var outerRefs = 0
  while not exts.atEnd:
    let xat = exts.pos
    let typ = u16(exts)
    var d = vec16(exts)
    if not exts.ok: return alDecodeError
    if typ == extEchOuterExtensions:
      outerRefs = outerRefs + 1
      if outerRefs > 1: return alIllegalParameter
      var l = vec8(d)
      if l.left < 2 or l.left mod 2 != 0: return alDecodeError
      while not l.atEnd:
        let t = u16(l)
        if t == extEch: return alIllegalParameter
        var found = -1
        var k = next
        while found < 0 and k < ol.exts.len:
          if ol.exts[k].typ == t: found = k
          k = k + 1
        if found < 0: return alIllegalParameter  # missing, twice, or out of order
        putBytes(w, at(outer, ol.exts[found].at), ol.exts[found].total)
        next = found + 1
      if not d.atEnd: return alDecodeError
    else:
      skip(d, d.left)
      putBytes(w, at(encoded, xat), exts.pos - xat)
  finish16(w, e)
  finish24(w, m)
  if not w.ok: return alDecodeError
  inner.setLen(w.pos)
  result = 0
