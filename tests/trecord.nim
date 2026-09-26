import std/[syncio, assertions]
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/consts
import zal_tls/crypto/aead
import zal_tls/common
import hexutil, rfc8448

proc secretOf(hexs: string): Secret =
  var b = hex(hexs)
  result = default(Secret)
  result.n = b.len
  copyMem(addr result.b[0], addr b[0], b.len)

# The server's handshake flight: one record, EE..Finished inside.
var sHs = secretOf(trace(Simple, "{server} derive secret \"tls13 s hs traffic\"", "expanded"))
var rd = default(Protection)
assert install(rd, suiteAes128Gcm, sHs)
var rec = hex(trace(Simple, "{server} send handshake record", "complete record"))   # the first: ServerHello (plain)
# (the encrypted one is the second "{server} send handshake record"; the helper below finds the n-th)
var enc = hex(nth(Simple, "{server} send handshake record", "complete record", 1))
assert recordLen(ua(enc), 0, enc.len) == enc.len and recordLen(ua(enc), 0, 4) == 0
var ct = 0
var po = 0
var pl = 0
assert openRecord(rd, ua(enc), 0, enc.len, ct, po, pl) == 0 and ct == 22
assert toHex(enc.toOpenArray(po, po + pl - 1)) == nth(Simple, "{server} send handshake record", "payload", 1)
# The client's Finished record, sealed byte-exact.
var cHs = secretOf(trace(Simple, "{server} derive secret \"tls13 c hs traffic\"", "expanded"))
var wr = default(Protection)
assert install(wr, suiteAes128Gcm, cHs)
var cfin = hex(trace(Simple, "{client} construct a Finished", "Finished"))
var buf = newSeq[byte](5 + cfin.len + 1 + 16)
copyMem(addr buf[5], addr cfin[0], cfin.len)
let n = sealRecord(wr, ua(buf), 0, cfin.len, 22, 0)
assert n == buf.len and toHex(buf) == nth(Simple, "{client} send handshake record", "complete record", 1)
# Application data, both ways, and the alerts.
var cAp = secretOf(trace(Simple, "{server} derive secret \"tls13 c ap traffic\"", "expanded"))
var sAp = secretOf(trace(Simple, "{server} derive secret \"tls13 s ap traffic\"", "expanded"))
var cw = default(Protection)
var sr = default(Protection)
assert install(cw, suiteAes128Gcm, cAp) and install(sr, suiteAes128Gcm, sAp)
var app = hex(trace(Simple, "{client} send application_data record", "payload"))
var abuf = newSeq[byte](5 + app.len + 1 + 16)
copyMem(addr abuf[5], addr app[0], app.len)
assert sealRecord(cw, ua(abuf), 0, app.len, 23, 0) == abuf.len
assert toHex(abuf) == trace(Simple, "{client} send application_data record", "complete record")
# (The server's NewSessionTicket record comes first on sAp: skip it, then its application data.)
var nstRec = hex(nth(Simple, "{server} send handshake record", "complete record", 2))
assert openRecord(sr, ua(nstRec), 0, nstRec.len, ct, po, pl) == 0 and ct == 22
var sapp = hex(trace(Simple, "{server} send application_data record", "complete record"))
assert openRecord(sr, ua(sapp), 0, sapp.len, ct, po, pl) == 0 and ct == 23 and pl == app.len
# A flipped byte fails: a fresh reader at the same sequence number (1).
var bad = hex(trace(Simple, "{server} send application_data record", "complete record"))
bad[10] = bad[10] xor 1
var sr2 = default(Protection)
assert install(sr2, suiteAes128Gcm, sAp)
sr2.seq = 1
assert openRecord(sr2, ua(bad), 0, bad.len, ct, po, pl) == alBadRecordMac
# Headers: a record over the limit, an unknown type, a short read.
var hdr = @[23'u8, 3, 3, 0x41, 0x01]
assert recordLen(ua(hdr), 0, 5) == -alRecordOverflow
hdr = @[24'u8, 3, 3, 0, 20]
assert recordLen(ua(hdr), 0, 5) == -alUnexpectedMessage
hdr = @[22'u8, 3, 3, 0, 0]
assert recordLen(ua(hdr), 0, 5) == -alDecodeError
# An all-padding inner plaintext (no content type) is refused.
var pw = default(Protection)
var pr = default(Protection)
assert install(pw, suiteAes128Gcm, cAp) and install(pr, suiteAes128Gcm, cAp)
var zb = newSeq[byte](5 + 4 + 16)
assert sealRecord(pw, ua(zb), 0, 0, 0, 3) == zb.len          # content type 0, 3 bytes of padding
assert openRecord(pr, ua(zb), 0, zb.len, ct, po, pl) == alUnexpectedMessage
# Content, type and padding over 2^14 + 1 (RFC 8446 5.4): record_overflow,
# though the content alone is within 2^14.
var pad = newSeq[byte](5 + 16000 + 1 + 400 + 16)
let innerLen = 16000 + 1 + 400
pad[0] = 23
pad[1] = 3
pad[2] = 3
pad[3] = byte((innerLen + 16) shr 8)
pad[4] = byte((innerLen + 16) and 0xff)
pad[5 + 16000] = 23                                           # the inner type, then 400 zeros
var ps = default(Protection)
assert install(ps, suiteAes128Gcm, cAp)
assert sealInPlace(ps.aead, ptrOf(ps.iv), at(bytesOf(pad), 5), innerLen, at(bytesOf(pad), 5 + innerLen),
                   bytesOf(pad), 5)                           # sequence 0: the nonce is the iv
var po2 = default(Protection)
assert install(po2, suiteAes128Gcm, cAp)
assert openRecord(po2, ua(pad), 0, pad.len, ct, po, pl) == alRecordOverflow
echo "PASS record: RFC 8448 3 records opened and sealed byte-exact, tamper refused"
