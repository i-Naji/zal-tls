import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/[bytes, consts, messages]
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import hexutil, loophelp

# Each case builds a handshake in memory, spoils one thing, and checks the
# alert. A man in the middle with the key log's secrets rewrites encrypted
# flights; hand-made ServerHellos cover the downgrade and choice checks.

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
let noRoots = newRoots()
if roots == nil or noRoots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
var ck = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == "", "leaf")
var ckRsa = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf-rsa.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/rsa.key"), ckRsa) == "", "rsa leaf")

# The key log: the handshake secrets, for the man in the middle.
var cHsLog = default(Secret)
var sHsLog = default(Secret)
proc keyLog(ctx: nil pointer; label: string; clientRandom: Bytes; secret: Secret) {.nimcall.} =
  if label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET": cHsLog = secret
  elif label == "SERVER_HANDSHAKE_TRAFFIC_SECRET": sHsLog = secret

type Rec = object
  typ: int                 ## the outer type (plain) or the inner type (encrypted)
  enc: bool
  pay: seq[byte]

proc openFlight(q: seq[byte]; secret: Secret): seq[Rec] =
  ## Every record of q; encrypted ones opened with `secret` (AES-128-GCM).
  result = @[]
  var p = default(Protection)
  expect(install(p, suiteAes128Gcm, secret), "install")
  var buf = q
  var pos = 0
  while pos < buf.len:
    let n = recordLen(bytesOf(buf), pos, buf.len - pos)
    expect(n > 0, "a whole record")
    var rec = Rec(typ: int(buf[pos]), enc: false, pay: @[])
    var off = pos + 5
    var len = n - 5
    if rec.typ == ctApplicationData:
      var ct = 0
      expect(openRecord(p, bytesOf(buf), pos, n, ct, off, len) == 0, "open")
      rec.typ = ct
      rec.enc = true
    for i in off ..< off + len: rec.pay.add buf[i]
    result.add rec
    pos = pos + n
  clear(p)

proc sealFlight(recs: seq[Rec]; secret: Secret): seq[byte] =
  result = @[]
  var p = default(Protection)
  expect(install(p, suiteAes128Gcm, secret), "install")
  for r in recs:
    var buf = newSeq[byte](5 + r.pay.len + 1 + 16)
    for i in 0 ..< r.pay.len: buf[5 + i] = r.pay[i]
    var n = 0
    if r.enc:
      n = sealRecord(p, bytesOf(buf), 0, r.pay.len, r.typ, 0)
    else:
      writePlainHeader(bytesOf(buf), 0, r.typ, r.pay.len, false)
      n = 5 + r.pay.len
    for i in 0 ..< n: result.add buf[i]
  clear(p)

proc clientConfig(): ClientConfig =
  result = defaultClientConfig(roots)
  result.suites = @[suiteAes128Gcm]
  result.keyLog = KeyLog(log: keyLog, ctx: nil)

proc serverConfig(): ServerConfig =
  result = defaultServerConfig()
  result.resolver = singleCert(addr ck)
  result.keyLog = KeyLog(log: keyLog, ctx: nil)

var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]

proc start(cc: ptr ClientConfig; sc: ptr ServerConfig; name: string) =
  ## Client hello to the server; the server's flight waits in `ba`.
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, cc, name), "initClient")
  expect(initServer(b.c, sc), "initServer")
  discard turn(a, ab)
  feed(b, ab, 1 shl 30)
  discard turn(b, ba)
  discard turn(b, ba)

proc finish() =
  run(a, b, ab, ba, 1 shl 30)

proc done() =
  release(a.c)
  release(b.c)

proc check(side: Side; alert: int; what: string) =
  if side.failed != alert: echo what, ": got ", side.failed, " (", side.reason, ")"
  expect(side.failed == alert, what)

# ------------------------------------------- hand-made ServerHellos (client side)

proc clientHelloOf(q: seq[byte]; v: var HelloView) =
  var m = newSeq[byte](q.len - 5)
  for i in 0 ..< m.len: m[i] = q[5 + i]
  expect(parseClientHello(bytesOf(m), m.len, v) == 0, "our ClientHello parses")

proc craftHello(v: HelloView; ch: seq[byte]; suite, version, group, shareLen: int;
                random: array[32, byte]; hrrGroup: int; cookie: bool): seq[byte] =
  ## A ServerHello record answering ClientHello `ch` (its record included).
  var m = newSeq[byte](512)
  var w = initWriter(bytesOf(m), 0, m.len)
  put8(w, htServerHello)
  let at = begin24(w)
  put16(w, Tls12)
  var rnd = random
  putBytes(w, ptrOf(rnd), 32)
  let s = begin8(w)
  for i in 0 ..< v.sessionIdLen: put8(w, int(ch[5 + v.sessionIdAt + i]))
  finish8(w, s)
  put16(w, suite)
  put8(w, 0)
  let ex = begin16(w)
  put16(w, extKeyShare)
  if hrrGroup != 0:
    put16(w, 2)
    put16(w, hrrGroup)
  else:
    let k = begin16(w)
    put16(w, group)
    let ks = begin16(w)
    for i in 0 ..< shareLen: put8(w, 9)
    finish16(w, ks)
    finish16(w, k)
  if cookie:
    put16(w, extCookie)
    put16(w, 6)
    put16(w, 4)
    put32(w, 0x01020304)
  if version != 0:
    put16(w, extSupportedVersions)
    put16(w, 2)
    put16(w, version)
  finish16(w, ex)
  finish24(w, at)
  expect(w.ok, "crafted")
  result = @[22'u8, 3, 3, byte(w.pos shr 8), byte(w.pos and 0xff)]
  for i in 0 ..< w.pos: result.add m[i]

proc helloCase(cc: ptr ClientConfig; suite, version, group, shareLen: int; random: array[32, byte];
               hrrGroup: int; cookie: bool; alert: int; what: string) =
  initSide(a)
  ab = @[]
  expect(initClient(a.c, cc, "test.example"), "init")
  discard turn(a, ab)
  var v = default(HelloView)
  clientHelloOf(ab, v)
  var rec = craftHello(v, ab, suite, version, group, shareLen, random, hrrGroup, cookie)
  var sink: seq[byte] = @[]
  feed(a, rec, 1 shl 30)
  discard turn(a, sink)
  check(a, alert, what)
  release(a.c)

var cc = clientConfig()
var sc = serverConfig()
var plain = default(array[32, byte])
plain[0] = 1
var down12 = plain
for i in 0 ..< 8: down12[24 + i] = Downgrade12[i]
helloCase(addr cc, 0x1301, 0x0303, 0x001d, 32, plain, 0, false, alIllegalParameter, "supported_versions 0x0303")
helloCase(addr cc, 0x1301, 0, 0x001d, 32, plain, 0, false, alProtocolVersion, "no supported_versions")
helloCase(addr cc, 0x1301, 0x0304, 0x001d, 32, down12, 0, false, alIllegalParameter, "downgrade sentinel")
helloCase(addr cc, 0x1302, 0x0304, 0x001d, 32, plain, 0, false, alIllegalParameter, "a suite not offered")
helloCase(addr cc, 0x1301, 0x0304, 0x0017, 65, plain, 0, false, alIllegalParameter, "a group without our share")
helloCase(addr cc, 0x1301, 0x0304, 0x001d, 31, plain, 0, false, alIllegalParameter, "a short share")
helloCase(addr cc, 0x1301, 0x0304, 0, 0, HrrRandom, 0x001d, false, alIllegalParameter, "HRR for the group already shared")
helloCase(addr cc, 0x1301, 0x0304, 0, 0, HrrRandom, 0x0100, false, alIllegalParameter, "HRR for a group not offered")
echo "PASS ServerHello checks: version, downgrade, suite, group, share, HRR group"

# A second HelloRetryRequest.
block:
  initSide(a)
  ab = @[]
  expect(initClient(a.c, addr cc, "test.example"), "init")
  discard turn(a, ab)
  var v = default(HelloView)
  clientHelloOf(ab, v)
  var hrr = craftHello(v, ab, 0x1301, 0x0304, 0, 0, HrrRandom, 0x0017, true)
  let first = ab
  ab = @[]
  feed(a, hrr, 1 shl 30)
  discard turn(a, ab)
  expect(a.failed < 0 and ab.len > 0 and a.c.retried, "first HRR answered")
  var hrr2 = craftHello(v, first, 0x1301, 0x0304, 0, 0, HrrRandom, 0x0017, true)
  var sink: seq[byte] = @[]
  feed(a, hrr2, 1 shl 30)
  discard turn(a, sink)
  check(a, alUnexpectedMessage, "second HRR")
  release(a.c)
echo "PASS second HelloRetryRequest refused"

# ---------------------------------------------- the server's flight, tampered

proc tamperFlight(what: string; alert: int; spoil: proc (recs: var seq[Rec]) {.nimcall.}) =
  cc = clientConfig()
  sc = serverConfig()
  start(addr cc, addr sc, "test.example")
  var recs = openFlight(ba, sHsLog)
  spoil(recs)
  ba = sealFlight(recs, sHsLog)
  var sink: seq[byte] = @[]
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, sink): discard
  check(a, alert, what)
  done()

proc lastEnc(recs: var seq[Rec]): int =
  result = -1
  for i in 0 ..< recs.len:
    if recs[i].enc: result = i

proc flipFinished(recs: var seq[Rec]) {.nimcall.} =
  let i = lastEnc(recs)
  let n = recs[i].pay.len
  recs[i].pay[n - 1] = recs[i].pay[n - 1] xor 1

proc appBeforeFinished(recs: var seq[Rec]) {.nimcall.} =
  let i = lastEnc(recs)
  let fin = recs[i].pay.len - 36                         # Finished: 4 + 32 bytes (SHA-256)
  var head = Rec(typ: ctHandshake, enc: true, pay: @[])
  var tail = Rec(typ: ctHandshake, enc: true, pay: @[])
  for j in 0 ..< fin: head.pay.add recs[i].pay[j]
  for j in fin ..< recs[i].pay.len: tail.pay.add recs[i].pay[j]
  recs[i] = head
  recs.add Rec(typ: ctApplicationData, enc: true, pay: @[1'u8, 2, 3])
  recs.add tail

proc cutInside(recs: var seq[Rec]) {.nimcall.} =
  ## The ServerHello record also carries the start of the next message.
  for x in [8'u8, 0, 0]: recs[0].pay.add x

tamperFlight("tampered Finished", alDecryptError, flipFinished)
tamperFlight("application data before the server's Finished", alUnexpectedMessage, appBeforeFinished)
tamperFlight("a key change inside a record", alUnexpectedMessage, cutInside)
echo "PASS server flight: Finished, early application data, key change inside a record"

# A bad signature (the server signs, then spoils it).
proc badSign(ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int; outSig: Bytes; room: int;
             outLen: var int): bool {.nimcall.} =
  let key = ck.key
  result = key != nil and sign(scheme, key, msg, n, outSig, room, outLen)
  if result: outSig[outLen div 2] = outSig[outLen div 2] xor 1
cc = clientConfig()
sc = serverConfig()
sc.signer = SignHook(sign: badSign, ctx: nil)
start(addr cc, addr sc, "test.example")
finish()
check(a, alDecryptError, "tampered CertificateVerify")
done()
# A scheme the client did not offer (the resolver widens the server's view).
proc widen(ctx: nil pointer; hello: ptr HelloView): nil ptr CertifiedKey {.nimcall.} =
  hello.sigSchemes.add 0x0804
  result = addr ckRsa
cc = clientConfig()
cc.sigSchemes = @[sigEcdsaP256Sha256]
sc = serverConfig()
sc.resolver = CertResolver(resolve: widen, ctx: nil)
start(addr cc, addr sc, "test.example")
finish()
check(a, alIllegalParameter, "a scheme not offered")
done()
echo "PASS CertificateVerify: bad signature, scheme not offered"

# Certificates: host, time, issuer; a chain over the message limit.
cc = clientConfig()
sc = serverConfig()
start(addr cc, addr sc, "wrong.example")
finish()
check(a, alBadCertificate, "wrong host")
done()
cc.verifyAt = 2208988800'i64                            # 2040
start(addr cc, addr sc, "test.example")
finish()
check(a, alCertificateExpired, "expired")
done()
cc = clientConfig()
cc.roots = noRoots
start(addr cc, addr sc, "test.example")
finish()
check(a, alUnknownCa, "unknown CA")
done()
cc = clientConfig()
cc.maxHandshakeMsg = 1000
start(addr cc, addr sc, "test.example")
finish()
check(a, alDecodeError, "handshake message over the limit")
done()
echo "PASS certificates: host, expiry, issuer; message limit"

# Records: MAC failure, overflow (encrypted and plain).
cc = clientConfig()
sc = serverConfig()
start(addr cc, addr sc, "test.example")
ba[ba.len - 3] = ba[ba.len - 3] xor 1
finish()
check(a, alBadRecordMac, "record MAC")
done()
proc headerCase(rec: seq[byte]; alert: int; what: string) =
  initSide(a)
  ab = @[]
  expect(initClient(a.c, addr cc, "test.example"), "init")
  discard turn(a, ab)
  var r = rec
  var sink: seq[byte] = @[]
  feed(a, r, 1 shl 30)
  discard turn(a, sink)
  check(a, alert, what)
  release(a.c)
headerCase(@[23'u8, 3, 3, 0x41, 0x01], alRecordOverflow, "ciphertext over 2^14 + 256")
var big = @[22'u8, 3, 3, 0x40, 0x01]
for i in 0 ..< 0x4001: big.add 0
headerCase(big, alRecordOverflow, "plaintext over 2^14")
var early = @[23'u8, 3, 3, 0, 20]
for i in 0 ..< 20: early.add 0
headerCase(early, alUnexpectedMessage, "encrypted data before keys")
headerCase(@[21'u8, 3, 3, 0, 2, 2, 200], 200, "an unknown alert from the peer")
block:
  initSide(a)
  ab = @[]
  expect(initClient(a.c, addr cc, "test.example"), "init")
  discard turn(a, ab)
  var r = @[21'u8, 3, 3, 0, 2, 1, 0]
  var sink: seq[byte] = @[]
  feed(a, r, 1 shl 30)
  discard turn(a, sink)
  expect(a.peerClosed and a.failed < 0, "close_notify: closed, not failed")
  release(a.c)
echo "PASS records: MAC, overflow, early data, alerts"

# ------------------------------------------------------ the server's checks

proc serverCase(ch: seq[byte]; alert: int; what: string) =
  initSide(b)
  ba = @[]
  expect(initServer(b.c, addr sc), "init")
  var r = ch
  feed(b, r, 1 shl 30)
  discard turn(b, ba)
  check(b, alert, what)
  release(b.c)

proc realHello(): seq[byte] =
  initSide(a)
  ab = @[]
  expect(initClient(a.c, addr cc, "test.example"), "init")
  discard turn(a, ab)
  result = ab
  release(a.c)

proc patchExt(rec: seq[byte]; ext: int; newType: int): seq[byte] =
  ## Rename extension `ext` in a ClientHello record (it is then unknown).
  result = rec
  var v = default(HelloView)
  var m = newSeq[byte](rec.len - 5)
  for i in 0 ..< m.len: m[i] = rec[5 + i]
  expect(parseClientHello(bytesOf(m), m.len, v) == 0, "parse")
  var r = initReader(bytesOf(m), 4 + 2 + 32, m.len - 38)
  discard vec8(r)
  discard vec16(r)
  discard vec8(r)
  var exts = vec16(r)
  while not exts.atEnd:
    let at = exts.pos
    let typ = u16(exts)
    discard vec16(exts)
    if typ == ext:
      result[5 + at] = byte(newType shr 8)
      result[5 + at + 1] = byte(newType and 0xff)

cc = clientConfig()
sc = serverConfig()
serverCase(patchExt(realHello(), extSupportedVersions, 0x7777), alProtocolVersion, "no supported_versions")
serverCase(patchExt(realHello(), extKeyShare, 0x7777), alMissingExtension, "no key_share")
serverCase(patchExt(realHello(), extSignatureAlgorithms, 0x7777), alMissingExtension, "no signature_algorithms")
block:
  var ch = realHello()
  var v = default(HelloView)
  clientHelloOf(ch, v)
  let compAt = 5 + v.sessionIdAt + v.sessionIdLen + 2 + v.suites.len * 2 + 1
  ch[compAt] = 1                                        # compression method 1 instead of 0
  serverCase(ch, alIllegalParameter, "compression other than null")
cc.suites = @[suiteChaCha20]
sc.suites = @[suiteAes128Gcm]
serverCase(realHello(), alHandshakeFailure, "no common suite")
cc = clientConfig()
sc = serverConfig()
cc.groups = @[kxX25519]
sc.groups = @[kxSecp256r1]
serverCase(realHello(), alHandshakeFailure, "no common group")
cc = clientConfig()
cc.sigSchemes = @[sigEd25519]
sc = serverConfig()
serverCase(realHello(), alHandshakeFailure, "no common signature scheme")
echo "PASS ClientHello checks: versions, key_share, signature_algorithms, compression, suites, groups, schemes"

# The client's Finished tampered; application data before it.
proc clientFlightCase(what: string; alert: int; appInstead: bool) =
  cc = clientConfig()
  sc = serverConfig()
  start(addr cc, addr sc, "test.example")
  feed(a, ba, 1 shl 30)
  ba = @[]
  while turn(a, ab): discard
  expect(a.ready, "client done")
  var recs = openFlight(ab, cHsLog)
  let i = lastEnc(recs)
  if appInstead:
    recs[i] = Rec(typ: ctApplicationData, enc: true, pay: @[1'u8])
  else:
    let n = recs[i].pay.len
    recs[i].pay[n - 1] = recs[i].pay[n - 1] xor 1
  ab = sealFlight(recs, cHsLog)
  finish()
  check(b, alert, what)
  done()
clientFlightCase("tampered client Finished", alDecryptError, false)
clientFlightCase("application data before the client's Finished", alUnexpectedMessage, true)
echo "PASS client flight: Finished, early application data"


# ------------------------------------------------- regressions from the review

# The server's flight re-framed into small records (1, 3, 100 bytes of
# plaintext each): the handshake completes the same.
for size in [1, 3, 100]:
  cc = clientConfig()
  sc = serverConfig()
  start(addr cc, addr sc, "test.example")
  var recs = openFlight(ba, sHsLog)
  var out2: seq[Rec] = @[]
  for r in recs:
    if not r.enc:
      out2.add r
    else:
      var i = 0
      while i < r.pay.len:
        var piece = Rec(typ: r.typ, enc: true, pay: @[])
        for j in i ..< min(i + size, r.pay.len): piece.pay.add r.pay[j]
        out2.add piece
        i = i + size
  ba = sealFlight(out2, sHsLog)
  finish()
  expect(a.ready and b.ready, "re-framed into " & $size & "-byte records")
  done()
echo "PASS the server's flight re-framed into 1-, 3- and 100-byte records"

# The message limit counts one message: a Certificate of exactly the limit
# (the largest message with X25519), split over two records, the second
# also carrying CertificateVerify and Finished.
cc = clientConfig()
cc.groups = @[kxX25519]
cc.shareGroups = @[kxX25519]
sc = serverConfig()
start(addr cc, addr sc, "test.example")
block:
  var recs = openFlight(ba, sHsLog)
  let i = lastEnc(recs)
  let p = recs[i].pay
  let eeLen = 4 + ((int(p[1]) shl 16) or (int(p[2]) shl 8) or int(p[3]))
  let certLen = 4 + ((int(p[eeLen + 1]) shl 16) or (int(p[eeLen + 2]) shl 8) or int(p[eeLen + 3]))
  a.c.maxMsg = certLen                           # a whole message, header included
  let cut = eeLen + certLen div 2
  var r1 = Rec(typ: ctHandshake, enc: true, pay: @[])
  var r2 = Rec(typ: ctHandshake, enc: true, pay: @[])
  for j in 0 ..< cut: r1.pay.add p[j]
  for j in cut ..< p.len: r2.pay.add p[j]
  recs[i] = r1
  recs.add r2
  ba = sealFlight(recs, sHsLog)
finish()
if not (a.ready and b.ready): echo "limit: ", a.failed, " ", a.reason, " / ", b.failed, " ", b.reason
expect(a.ready and b.ready, "a Certificate of exactly the limit, split, then more messages")
done()
echo "PASS the handshake message limit counts one message"

# Alerts: a client that refuses our ServerHello answers in plaintext; a
# server that fails after its keys still answers a keyless client in plaintext.
cc = clientConfig()
sc = serverConfig()
start(addr cc, addr sc, "test.example")
block:
  var alert = @[21'u8, 3, 3, 0, 2, 2, 47]
  var sink: seq[byte] = @[]
  feed(b, alert, 1 shl 30)
  discard turn(b, sink)
  expect(b.failed == 47 and b.reason.len > 9 and b.reason[0 ..< 9] == "peer sent", "a plaintext alert read")
done()
proc refuseSign(ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int; outSig: Bytes; room: int;
                outLen: var int): bool {.nimcall.} = false
cc = clientConfig()
sc = serverConfig()
sc.signer = SignHook(sign: refuseSign, ctx: nil)
start(addr cc, addr sc, "test.example")
finish()
check(b, alInternalError, "the server's internal error")
check(a, alInternalError, "the client reads the server's plaintext alert")
done()
echo "PASS plaintext alerts both ways before the client has keys"

# A builder's hello with early_data but no PSK: refused by the client
# (RFC 8446 4.2.10). 0-RTT records the server never accepted are skipped:
# tresume.nim (real tickets, with and without a HelloRetryRequest).
proc earlyBuilder(ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.} =
  ## Our ClientHello with an early_data extension (not in the retry).
  let cfgp = p.cfg
  if cfgp == nil: return false
  let start = w.pos
  writeDefaultHello(w, cfgp, p)
  if p.retry or not w.ok: return w.ok
  var r = initReader(w.p, start + 4 + 2 + 32, w.pos - start - 38)
  discard vec8(r)
  discard vec16(r)
  discard vec8(r)
  let extLenAt = r.pos
  put16(w, extEarlyData)
  put16(w, 0)
  let extLen = ((int(w.p[extLenAt]) shl 8) or int(w.p[extLenAt + 1])) + 4
  w.p[extLenAt] = byte(extLen shr 8)
  w.p[extLenAt + 1] = byte(extLen and 0xff)
  let mlen = w.pos - start - 4
  w.p[start + 1] = byte(mlen shr 16)
  w.p[start + 2] = byte((mlen shr 8) and 0xff)
  w.p[start + 3] = byte(mlen and 0xff)
  result = w.ok
cc = clientConfig()
cc.builder = HelloBuilder(build: earlyBuilder, ctx: nil)
sc = serverConfig()
initSide(a)
initSide(b)
ab = @[]
ba = @[]
expect(initClient(a.c, addr cc, "test.example") and initServer(b.c, addr sc), "init")
discard turn(a, ab)
check(a, alInternalError, "early_data without a PSK")
done()
echo "PASS a hello with early_data and no PSK refused"

# ... and a server given such a hello (patched in here) skips the 0-RTT
# records after it, with and without a HelloRetryRequest, and answers.
for retry in [false, true]:
  cc = clientConfig()
  sc = serverConfig()
  if retry: sc.groups = @[kxSecp256r1]           # the client shares X25519MLKEM768 and X25519
  initSide(a)
  initSide(b)
  ab = @[]
  ba = @[]
  expect(initClient(a.c, addr cc, "test.example") and initServer(b.c, addr sc), "init")
  discard turn(a, ab)
  expect(int(ab[0]) == 22, "the ClientHello record alone")
  var msg: seq[byte] = @[]
  for i in 5 ..< ab.len: msg.add ab[i]
  var at = 4 + 2 + 32
  at = at + 1 + int(msg[at])                     # session id
  at = at + 2 + ((int(msg[at]) shl 8) or int(msg[at + 1]))   # suites
  at = at + 1 + int(msg[at])                     # compression
  let extLen = ((int(msg[at]) shl 8) or int(msg[at + 1])) + 4
  msg[at] = byte(extLen shr 8)
  msg[at + 1] = byte(extLen and 0xff)
  for x in [0'u8, 42, 0, 0]: msg.add x           # early_data, last
  let mlen = msg.len - 4
  msg[1] = byte(mlen shr 16)
  msg[2] = byte((mlen shr 8) and 0xff)
  msg[3] = byte(mlen and 0xff)
  var q = @[22'u8, 3, 1, byte(msg.len shr 8), byte(msg.len and 0xff)]
  for x in msg: q.add x
  for k in 0 ..< 2:
    for x in [23'u8, 3, 3, 0, 50]: q.add x
    for j in 0 ..< 50: q.add byte((j * 7 + k) and 0xff)
  feed(b, q, 1 shl 30)
  while turn(b, ba): discard
  expect(b.failed < 0 and ba.len > 0 and b.inLen == 0, "0-RTT without a PSK skipped, retry " & $retry)
  done()
echo "PASS a server skips the 0-RTT records of a hello without a PSK"

# Limits: change_cipher_spec records, empty application records.
var ccs: seq[byte] = @[]
for k in 0 ..< 5:
  for x in [20'u8, 3, 3, 0, 1, 1]: ccs.add x
cc = clientConfig()
headerCase(ccs, alUnexpectedMessage, "five change_cipher_spec records")
cc = clientConfig()
sc = serverConfig()
start(addr cc, addr sc, "test.example")
finish()
expect(a.ready and b.ready, "handshake")
block:
  var empties: seq[byte] = @[]
  for k in 0 ..< 33:
    var rec = newSeq[byte](5 + 1 + 16)
    let n = sealApp(b.c, bytesOf(rec), 0, 0)
    expect(n == rec.len, "an empty record")
    for x in rec: empties.add x
  var sink: seq[byte] = @[]
  feed(a, empties, 1 shl 30)
  while turn(a, sink): discard
  check(a, alUnexpectedMessage, "33 empty application records")
done()
echo "PASS limits: change_cipher_spec records, empty records"

# A CertificateRequest with a context during the handshake.
proc withRequest(recs: var seq[Rec]) {.nimcall.} =
  let i = lastEnc(recs)
  let p = recs[i].pay
  let eeLen = 4 + ((int(p[1]) shl 16) or (int(p[2]) shl 8) or int(p[3]))
  var np: seq[byte] = @[]
  for j in 0 ..< eeLen: np.add p[j]
  for x in [13'u8, 0, 0, 12, 1, 0xAA, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3]: np.add x
  for j in eeLen ..< p.len: np.add p[j]
  recs[i].pay = np
tamperFlight("a CertificateRequest with a context", alIllegalParameter, withRequest)
echo "PASS a CertificateRequest context must be empty"

release(ck)
release(ckRsa)
release(roots)
release(noRoots)
release(rootCerts[0])
