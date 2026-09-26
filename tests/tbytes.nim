import std/[syncio, assertions]
import zal_tls/wire/bytes
import hexutil, rfc8448

# Read the ClientHello of RFC 8448 section 3 by hand: type, length, version, random.
var ch = hex(trace(Simple, "{client} construct a ClientHello", "ClientHello"))
var r = initReader(ua(ch), 0, ch.len)
assert u8(r) == 1 and u24(r) == ch.len - 4
assert u16(r) == 0x0303
skip(r, 32)
var sid = vec8(r)
assert sid.left == 0
var suites = vec16(r)
assert suites.left == 6 and u16(suites) == 0x1301
assert r.ok
# Past the end: zeros and ok = false, sticky.
var short = initReader(ua(ch), 0, 3)
assert u16(short) == 0x0100 and u16(short) == 0 and not short.ok and u8(short) == 0
var bad = initReader(ua(ch), 0, 4)
discard u8(bad)
discard vec24(bad)                                   # claims 0xc0 bytes, has 0
assert not bad.ok

# Write a small structure with a patched length.
var buf = newSeq[byte](16)
var w = initWriter(ua(buf), 0, buf.len)
put8(w, 1)
let at = begin24(w)
put16(w, 0x0303)
putBytes(w, ua(ch), 2)
finish24(w, at)
assert w.ok and w.pos == 8 and toHex(buf.toOpenArray(0, 7)) == "0100000403030100"
var tiny = initWriter(ua(buf), 0, 2)
put24(tiny, 5)
assert not tiny.ok
var offset = initWriter(ua(buf), 5, 2)
put16(offset, 0x1234)
assert offset.ok and offset.pos == 7 and buf[5] == 0x12 and buf[6] == 0x34
put8(offset, 1)
assert not offset.ok
var overflow = initWriter(ua(buf), high(int), 1)
assert not overflow.ok
var negative = initReader(ua(buf), -1, 1)
assert not negative.ok
echo "PASS bytes: reader bounds, sticky failure, writer lengths"
