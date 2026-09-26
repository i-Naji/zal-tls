import std/[syncio, assertions]
import zal_tls/common
import zal_tls/wire/[bytes, consts, messages]
import hexutil, rfc8448

proc has(s: seq[int]; x: int): bool =
  result = false
  for y in s:
    if y == x: return true

var ch = hex(trace(Simple, "{client} construct a ClientHello", "ClientHello"))
var v = default(HelloView)
assert parseClientHello(ua(ch), ch.len, v) == 0
assert v.suites == @[0x1301, 0x1303, 0x1302]
assert v.serverName == "server"
assert v.versions == @[0x0304]
assert v.shareGroups == @[0x001d] and v.shareLen == @[32]
assert has(v.sigSchemes, 0x0804) and has(v.sigSchemes, 0x0403)
assert v.extOrder[0] == extServerName and v.extOrder[v.extOrder.len - 1] == 0x001c
assert v.sessionIdLen == 0 and v.compression == @[0]
echo "PASS ClientHello: RFC 8448 3 parsed"

var sh = hex(trace(Simple, "{server} construct a ServerHello", "ServerHello"))
var s = default(ServerHelloView)
assert parseServerHello(ua(sh), sh.len, s) == 0
assert s.suite == 0x1301 and s.version == 0x0304 and s.shareGroup == 0x001d and s.shareLen == 32 and not s.isHrr
# Rebuild it from its parts: byte-exact.
var outb = newSeq[byte](256)
var w = initWriter(ua(outb), 0, outb.len)
writeServerHello(w, cast[ptr UncheckedArray[byte]](addr s.random[0]), ua(outb), 0, 0x1301, 0,
                 cast[ptr UncheckedArray[byte]](addr sh[s.shareAt]), 32, 0x001d, ua(outb), 0)
assert w.ok and toHex(outb.toOpenArray(0, w.pos - 1)) == toHex(sh)
echo "PASS ServerHello: parsed and rebuilt byte-exact"

var ee = hex(trace(Simple, "{server} construct an EncryptedExtensions", "EncryptedExtensions"))
var alpn = ""
var sniAck = false
var early = false
assert parseEncryptedExtensions(ua(ee), ee.len, alpn, sniAck, early) == 0 and alpn == "" and sniAck and not early
var cert = hex(trace(Simple, "{server} construct a Certificate", "Certificate"))
var chain: seq[seq[byte]] = @[]
assert parseCertificate(ua(cert), cert.len, chain) == 0 and chain.len == 1 and chain[0].len > 400
var cv = hex(trace(Simple, "{server} construct a CertificateVerify", "CertificateVerify"))
var scheme = 0
var sigAt = 0
var sigLen = 0
assert parseCertificateVerify(ua(cv), cv.len, scheme, sigAt, sigLen) == 0 and scheme == 0x0804 and sigLen == 128
var nst = hex(trace(Simple, "{server} construct a NewSessionTicket", "NewSessionTicket"))
var tv = default(TicketView)
assert parseNewSessionTicket(ua(nst), nst.len, tv) == 0 and tv.lifetime == 30 and tv.ticketLen > 0
# Our own EncryptedExtensions and Certificate round-trip.
var w2 = initWriter(ua(outb), 0, outb.len)
writeEncryptedExtensions(w2, "h2", true, true)
var alpn2 = ""
var ack2 = false
var early2 = false
assert w2.ok and parseEncryptedExtensions(ua(outb), w2.pos, alpn2, ack2, early2) == 0 and alpn2 == "h2" and ack2 and early2
var big = newSeq[byte](chain[0].len + 64)
var w3 = initWriter(ua(big), 0, big.len)
writeCertificate(w3, chain)
var chain2: seq[seq[byte]] = @[]
assert w3.ok and parseCertificate(ua(big), w3.pos, chain2) == 0 and chain2 == chain
echo "PASS EncryptedExtensions, Certificate, CertificateVerify, NewSessionTicket parsed; ours round-trip"

# HelloRetryRequest (RFC 8448 5): recognised, group and cookie found.
var hrr = hex(trace(Hrr, "{server} construct a ServerHello", "ServerHello"))
var h = default(ServerHelloView)
assert parseServerHello(ua(hrr), hrr.len, h) == 0 and h.isHrr and h.selectedGroup == 0x0017 and h.cookieLen > 0
# Truncation, a repeated extension, trailing bytes: refused.
assert parseServerHello(ua(sh), sh.len - 1, s) == alDecodeError
var dup = ch
dup.add(0)
assert parseClientHello(ua(dup), dup.len, v) == alDecodeError
echo "PASS HelloRetryRequest recognised; truncation and trailing bytes refused"

# The CertificateVerify signed content (RFC 8446 4.4.3): 64 spaces, context, 0, hash.
var hsh = newSeq[byte](32)
var sc = newSeq[byte](200)
let n = signedContent(true, ua(hsh), 32, ua(sc))
assert n == 64 + 33 + 1 + 32 and sc[0] == 0x20 and sc[63] == 0x20 and sc[64] == byte('T') and sc[97] == 0
echo "PASS signed content"

# Resumption and 0-RTT (RFC 8448 4): the PSK offer, early_data, EndOfEarlyData.
proc r(step, label: string): string = trace(Resumed, step, label)
var rch = hex(nth(Resumed, "{client} send handshake record", "payload", 0))
var rv = default(HelloView)
expect(parseClientHello(ua(rch), rch.len, rv) == 0 and rv.hasPsk and rv.hasEarlyData, "resumed hello")
var offer = default(PskOffer)
expect(parsePskOffer(ua(rch), rv, offer) == 0, "the PSK offer")
expect(offer.identityLen.len == 1 and offer.binderLen == @[32] and offer.truncLen == 477, "one identity, one binder, truncated at 477")
var nst3 = hex(trace(Simple, "{server} construct a NewSessionTicket", "NewSessionTicket"))
var tv3 = default(TicketView)
expect(parseNewSessionTicket(ua(nst3), nst3.len, tv3) == 0 and tv3.maxEarlyData == 1024, "section 3's ticket")
expect(offer.identityLen[0] == tv3.ticketLen and
       toHex(rch.toOpenArray(offer.identityAt[0], offer.identityAt[0] + tv3.ticketLen - 1)) ==
       toHex(nst3.toOpenArray(tv3.ticketAt, tv3.ticketAt + tv3.ticketLen - 1)), "the identity is the ticket")
var ree = hex(r("{server} construct an EncryptedExtensions", "EncryptedExtensions"))
var ralpn = ""
var rack = false
var rearly = false
expect(parseEncryptedExtensions(ua(ree), ree.len, ralpn, rack, rearly) == 0 and rearly and rack, "EE: early data accepted")
var eoed = hex(r("{client} construct an EndOfEarlyData", "EndOfEarlyData"))
expect(parseEndOfEarlyData(ua(eoed), eoed.len) == 0, "EndOfEarlyData")
var ob = newSeq[byte](512)
var w4 = initWriter(ua(ob), 0, ob.len)
writeEndOfEarlyData(w4)
expect(w4.ok and toHex(ob.toOpenArray(0, w4.pos - 1)) == toHex(eoed), "EndOfEarlyData written")
# NewSessionTicket rebuilt byte-exact (section 3).
var w5 = initWriter(ua(ob), 0, ob.len)
writeNewSessionTicket(w5, tv3.lifetime, tv3.ageAdd, at(ua(nst3), tv3.nonceAt), tv3.nonceLen,
                      at(ua(nst3), tv3.ticketAt), tv3.ticketLen, tv3.maxEarlyData)
expect(w5.ok and toHex(ob.toOpenArray(0, w5.pos - 1)) == toHex(nst3), "NewSessionTicket byte-exact")
# The resumed ServerHello rebuilt byte-exact (pre_shared_key first, as RFC 8448 has it).
var rsh = hex(r("{server} construct a ServerHello", "ServerHello"))
var rs = default(ServerHelloView)
expect(parseServerHello(ua(rsh), rsh.len, rs) == 0 and rs.pskIndex == 0, "resumed ServerHello")
var w6 = initWriter(ua(ob), 0, ob.len)
writeServerHello(w6, cast[ptr UncheckedArray[byte]](addr rs.random[0]), ua(ob), 0, 0x1301, 0,
                 at(ua(rsh), rs.shareAt), 32, 0x001d, ua(ob), 0, pskIndex = 0)
expect(w6.ok and toHex(ob.toOpenArray(0, w6.pos - 1)) == toHex(rsh), "resumed ServerHello byte-exact")
# Our PSK extension: written, parsed back, binders where the offer says.
var ticket = @[1'u8, 2, 3, 4, 5]
var w7 = initWriter(ua(ob), 0, ob.len)
put8(w7, htClientHello)
let m7 = begin24(w7)
put16(w7, Tls12)
for i in 0 ..< 32: put8(w7, 0)
put8(w7, 0)
put16(w7, 2)
put16(w7, 0x1301)
put8(w7, 1)
put8(w7, 0)
let e7 = begin16(w7)
writePskExtension(w7, ua(ticket), ticket.len, 0x01020304'u32, 32)
finish16(w7, e7)
finish24(w7, m7)
var v7 = default(HelloView)
var o7 = default(PskOffer)
expect(w7.ok and parseClientHello(ua(ob), w7.pos, v7) == 0 and parsePskOffer(ua(ob), v7, o7) == 0, "our PSK extension")
expect(o7.ages == @[0x01020304'u32] and o7.identityLen == @[5] and o7.binderLen == @[32] and
       o7.binderAt[0] == w7.pos - 32 and o7.truncLen == w7.pos - 35, "identity, age, binder place, truncation")
echo "PASS resumption messages: PSK offer, early_data, EndOfEarlyData, NewSessionTicket and ServerHello byte-exact"

# CertificateRequest (RFC 8448 section 5): written byte-exact, parsed back;
# certificate_authorities both ways; a duplicate extension, a missing
# signature_algorithms refused.
var crRfc = hex(trace(ClientAuth, "{server} construct a CertificateRequest", "CertificateRequest"))
var crv = default(CertRequestView)
expect(parseCertificateRequest(ua(crRfc), crRfc.len, crv) == 0 and crv.ctxLen == 0 and
       crv.schemes.len == 15 and crv.schemes[0] == 0x0403 and crv.caNames.len == 0, "the RFC's CertificateRequest")
var cb = newSeq[byte](4096)
var w8 = initWriter(ua(cb), 0, cb.len)
writeCertificateRequest(w8, nil, 0, crv.schemes, @[])
expect(w8.ok and toHex(cb.toOpenArray(0, w8.pos - 1)) == toHex(crRfc), "written byte-exact")
var names = @[@[0x30'u8, 3, 1, 2, 3], @[0x30'u8, 1, 9]]
var w9 = initWriter(ua(cb), 0, cb.len)
var ctx9 = @[7'u8, 7]
writeCertificateRequest(w9, ua(ctx9), 2, @[0x0804, 0x0403], names)
var crv9 = default(CertRequestView)
expect(w9.ok and parseCertificateRequest(ua(cb), w9.pos, crv9) == 0 and crv9.ctxLen == 2 and
       crv9.schemes == @[0x0804, 0x0403] and crv9.caNames == names, "certificate_authorities both ways")
var crDup = crRfc
for x in [0'u8, 13, 0, 4, 0, 2, 4, 3]: crDup.add x                        # signature_algorithms again
crDup[3] = byte(crDup.len - 4)
crDup[5] = 0
crDup[6] = byte(crDup.len - 7)
var crd = default(CertRequestView)
expect(parseCertificateRequest(ua(crDup), crDup.len, crd) == alIllegalParameter, "a duplicate extension")
var crNone = @[13'u8, 0, 0, 3, 0, 0, 0]
expect(parseCertificateRequest(ua(crNone), crNone.len, crd) == alMissingExtension, "no signature_algorithms")
echo "PASS CertificateRequest: RFC 8448 5 byte-exact, certificate_authorities, bad ones refused"
