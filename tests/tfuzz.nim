{.feature: "assumeSync".}
## The decoders and `step` against mutated input (run under SANITIZE=1 too:
## every input sits in a malloc block of its exact size, so a read past it
## is caught). Seeds: RFC 8448's messages and records, and a real flight
## between our client and server. Mutations: bit flips, byte sets,
## truncation, rewritten length fields, repeated and inserted chunks.
## Invariants: no crash; a failure is an alert; a success stays in bounds.
## NN_FUZZ_SEED and NN_FUZZ_ITERS change the run.
import std/[syncio, assertions, envvars]
import zal_tls/common
import zal_tls/crypto/x509
import zal_tls/wire/[consts, messages]
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]
import zal_tls/core/[hello]
import hexutil, rfc8448, loophelp

proc malloc(n: csize_t): pointer {.importc, header: "<stdlib.h>".}
proc free(p: pointer) {.importc, header: "<stdlib.h>".}

var gState = 0x9E3779B97F4A7C15'u64

proc next(): uint64 =
  var x = gState
  x = x xor (x shr 12)
  x = x xor (x shl 25)
  x = x xor (x shr 27)
  gState = x
  result = x * 0x2545F4914F6CDD1D'u64

proc below(n: int): int = int(next() mod uint64(max(1, n)))

proc envInt(name: string; def: int): int =
  result = def
  let s = getEnv(name)
  if s.len == 0: return
  var v = 0
  for c in s:
    if c < '0' or c > '9': return
    v = v * 10 + ord(c) - ord('0')
  result = v

proc mutate(src: seq[byte]): seq[byte] =
  result = src
  for k in 0 ..< 1 + below(4):
    if result.len == 0: result.add byte(below(256))
    case below(7)
    of 0:
      let i = below(result.len)
      result[i] = result[i] xor byte(1 shl below(8))
    of 1:
      result[below(result.len)] = byte(below(256))
    of 2:
      var cut = newSeq[byte](below(result.len + 1))
      for i in 0 ..< cut.len: cut[i] = result[i]
      result = cut
    of 3:                                   # a length field: two bytes to something near
      if result.len > 2:
        let i = below(result.len - 1)
        let v = ((int(result[i]) shl 8) or int(result[i + 1])) + below(9) - 4
        result[i] = byte((v shr 8) and 0xff)
        result[i + 1] = byte(v and 0xff)
    of 4:                                   # repeat a chunk (a duplicated extension)
      let i = below(result.len)
      let n = min(below(64), result.len - i)
      var r = newSeq[byte](0)
      for j in 0 ..< i + n: r.add result[j]
      for j in i ..< i + n: r.add result[j]
      for j in i + n ..< result.len: r.add result[j]
      result = r
    of 5:                                   # insert random bytes
      let i = below(result.len + 1)
      var r = newSeq[byte](0)
      for j in 0 ..< i: r.add result[j]
      for j in 0 ..< 1 + below(8): r.add byte(below(256))
      for j in i ..< result.len: r.add result[j]
      result = r
    else:                                   # the start of a length-prefixed item: 0 or ff
      if result.len > 1: result[below(result.len)] = if below(2) == 0: 0'u8 else: 0xff'u8

proc exact(s: seq[byte]): Bytes =
  ## A malloc copy of exactly s.len bytes (at least 1).
  result = cast[Bytes](malloc(csize_t(max(1, s.len))))
  for i in 0 ..< s.len: result[i] = s[i]

proc isAlert(a: int): bool =
  a in [alUnexpectedMessage, alBadRecordMac, alRecordOverflow, alHandshakeFailure, alBadCertificate,
        alUnsupportedCertificate, alCertificateExpired, alCertificateUnknown, alIllegalParameter,
        alUnknownCa, alDecodeError, alDecryptError, alProtocolVersion, alInternalError,
        alMissingExtension, alUnsupportedExtension, alUnrecognizedName, alNoApplicationProtocol,
        alInsufficientSecurity]

gState = uint64(envInt("NN_FUZZ_SEED", 12345)) or 1
let iters = envInt("NN_FUZZ_ITERS", 50000)

# ---------------------------------------------------------------- decoders

var msgs = @[hex(trace(Simple, "{client} construct a ClientHello", "ClientHello")),
             hex(nth(Resumed, "{client} send handshake record", "payload", 0)),
             hex(trace(Simple, "{server} construct a ServerHello", "ServerHello")),
             hex(nth(Hrr, "{server} construct a ServerHello", "ServerHello", 0)),
             hex(nth(Hrr, "{client} construct a ClientHello", "ClientHello", 1)),
             hex(trace(Simple, "{server} construct an EncryptedExtensions", "EncryptedExtensions")),
             hex(trace(Simple, "{server} construct a Certificate", "Certificate")),
             hex(trace(Simple, "{server} construct a CertificateVerify", "CertificateVerify")),
             hex(trace(Simple, "{server} construct a NewSessionTicket", "NewSessionTicket")),
             hex(trace(rfc8448.ClientAuth, "{server} construct a CertificateRequest", "CertificateRequest")),
             hex(trace(Simple, "{server} construct a Finished", "Finished")),
             @[24'u8, 0, 0, 1, 1]]
var parsed = 0
for it in 0 ..< iters:
  let m = mutate(msgs[below(msgs.len)])
  let p = exact(m)
  var hv = default(HelloView)
  var a = parseClientHello(p, m.len, hv)
  expect(a == 0 or isAlert(a), "ClientHello result")
  if a == 0:
    parsed = parsed + 1
    expect(hv.randomAt + 32 <= m.len, "random in bounds")
    for i in 0 ..< hv.shareAt.len: expect(hv.shareAt[i] + hv.shareLen[i] <= m.len, "share in bounds")
  if a == 0 and hv.hasPsk:
    var po = default(PskOffer)
    let pa = parsePskOffer(p, hv, po)
    expect(pa == 0 or isAlert(pa), "PSK offer result")
    if pa == 0:
      expect(po.truncLen <= m.len, "truncation in bounds")
      for i in 0 ..< po.binderAt.len: expect(po.binderAt[i] + po.binderLen[i] <= m.len, "binder in bounds")
  var sv = default(ServerHelloView)
  a = parseServerHello(p, m.len, sv)
  expect(a == 0 or isAlert(a), "ServerHello result")
  if a == 0: expect(sv.shareAt + sv.shareLen <= m.len and sv.cookieAt + sv.cookieLen <= m.len, "SH bounds")
  var alpn = ""
  var ack = false
  var early = false
  a = parseEncryptedExtensions(p, m.len, alpn, ack, early)
  expect(a == 0 or isAlert(a), "EE result")
  var chain: seq[seq[byte]] = @[]
  a = parseCertificate(p, m.len, chain)
  expect(a == 0 or isAlert(a), "Certificate result")
  var sc = 0
  var sa = 0
  var sl = 0
  a = parseCertificateVerify(p, m.len, sc, sa, sl)
  expect(a == 0 or isAlert(a), "CV result")
  if a == 0: expect(sa + sl <= m.len, "CV bounds")
  var tv = default(TicketView)
  a = parseNewSessionTicket(p, m.len, tv)
  expect(a == 0 or isAlert(a), "NST result")
  if a == 0: expect(tv.ticketAt + tv.ticketLen <= m.len and tv.nonceAt + tv.nonceLen <= m.len, "NST bounds")
  var crv = default(CertRequestView)
  a = parseCertificateRequest(p, m.len, crv)
  expect(a == 0 or isAlert(a), "CR result")
  if a == 0: expect(crv.ctxAt + crv.ctxLen <= m.len, "CR bounds")
  var fa = 0
  var fl = 0
  a = parseFinished(p, m.len, fa, fl)
  expect(a == 0 or isAlert(a), "Finished result")
  var req = false
  a = parseKeyUpdate(p, m.len, req)
  expect(a == 0 or isAlert(a), "KeyUpdate result")
  # readClientHello on the message as a record.
  var rec = @[22'u8, 3, 1, byte(m.len shr 8), byte(m.len and 0xff)]
  for x in m: rec.add x
  if below(4) == 0: rec = mutate(rec)
  let rp = exact(rec)
  var rv = default(HelloView)
  var rl = 0
  var raw: seq[byte] = @[]
  let rr = readClientHello(rp, rec.len, rv, rl, raw)
  expect(rr <= rec.len and (rr >= 0 or isAlert(-rr)), "readClientHello result")
  free(rp)
  free(p)
echo "PASS decoders: ", iters, " cases (", parsed, " ClientHellos still parsed)"

# ------------------------------------------------------------------- step

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var rootCerts: seq[Cert] = @[]
expect(certsPem(slurpText("tests/data/root.pem"), rootCerts) == 1, "root")
let roots = newRoots()
if roots == nil: quit "no store"
expect(addRoot(roots, rootCerts[0]), "add root")
var ck = default(CertifiedKey)
expect(loadCertifiedKey(slurpText("tests/data/leaf.pem") & slurpText("tests/data/inter.pem"),
                        slurpText("tests/data/leaf.key"), ck) == "", "leaf")
var cc = defaultClientConfig(roots)
var scfg = defaultServerConfig()
scfg.resolver = singleCert(addr ck)

# One real exchange for seeds: the client's first flight, the server's.
var a = default(Side)
var b = default(Side)
var ab: seq[byte] = @[]
var ba: seq[byte] = @[]
initSide(a)
initSide(b)
expect(initClient(a.c, addr cc, "test.example") and initServer(b.c, addr scfg), "init")
discard turn(a, ab)
let chRec = ab
feed(b, ab, 1 shl 30)
discard turn(b, ba)
discard turn(b, ba)
let flightRec = ba
release(a.c)
release(b.c)
var simpleFlight = hex(nth(Simple, "{server} send handshake record", "complete record", 0))
for x in hex(nth(Simple, "{server} send handshake record", "complete record", 1)): simpleFlight.add x

var outb = newSeq[byte](1 shl 17)
var fails = 0
let stepIters = iters
for it in 0 ..< stepIters:
  # The server, fed a mutated ClientHello record (sometimes cut into pieces).
  let m = mutate(chRec)
  let p = exact(m)
  var sconn = default(TlsConn)
  expect(initServer(sconn, addr scfg), "server")
  var r = default(StepResult)
  var pos = 0
  var guard = 0
  while guard < 64:
    guard = guard + 1
    let st = step(sconn, at(p, pos), m.len - pos, bytesOf(outb), outb.len, r)
    expect(r.consumed <= m.len - pos and r.outLen <= outb.len, "server step bounds")
    if st == stFailed:
      expect(r.alert > 0 or r.alert == 0, "an alert")
      fails = fails + 1
      break
    pos = pos + r.consumed
    if st == stNeedInput and r.consumed == 0: break
    if st == stAppData: expect(r.off >= 0 and r.off + r.len <= m.len, "payload bounds")
  release(sconn)
  free(p)
  # The client, fed a mutated server flight (ours or RFC 8448's).
  let seed = if below(2) == 0: flightRec else: simpleFlight
  let fm = mutate(seed)
  let fp = exact(fm)
  var cconn = default(TlsConn)
  expect(initClient(cconn, addr cc, "test.example"), "client")
  var none = newSeq[byte](1)
  discard step(cconn, bytesOf(none), 0, bytesOf(outb), outb.len, r)
  pos = 0
  guard = 0
  while guard < 64:
    guard = guard + 1
    let st = step(cconn, at(fp, pos), fm.len - pos, bytesOf(outb), outb.len, r)
    expect(r.consumed <= fm.len - pos, "client step bounds")
    if st == stFailed:
      fails = fails + 1
      break
    pos = pos + r.consumed
    if st == stNeedInput and r.consumed == 0: break
    if st == stAppData: expect(r.off >= 0 and r.off + r.len <= fm.len, "payload bounds")
  release(cconn)
  free(fp)
echo "PASS step: ", stepIters, " servers and ", stepIters, " clients fed mutated flights (", fails, " failed cleanly)"
release(ck)
release(roots)
release(rootCerts[0])
