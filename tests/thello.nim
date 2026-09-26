import std/[syncio, assertions]
import zal_tls/common
import zal_tls/wire/[consts, messages]
import zal_tls/config/config
import zal_tls/private/core/[conn, client]
import zal_tls/core/[hello]
import hexutil

# readClientHello peeks at a real ClientHello: whole, partial, split over two
# records, and garbage.
var cc = defaultClientConfig(nil)
cc.alpn = @["h2", "http/1.1"]
var c = default(TlsConn)
expect(initClient(c, addr cc, "test.example"), "init")
var outb = newSeq[byte](4096)
var none = newSeq[byte](1)
var r = default(StepResult)
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "ClientHello")
var rec = newSeq[byte](r.outLen)
for i in 0 ..< r.outLen: rec[i] = outb[i]
release(c)

var v = default(HelloView)
var n = 0
var raw: seq[byte] = @[]
expect(readClientHello(bytesOf(rec), rec.len, v, n, raw) == rec.len and n == rec.len, "whole")
expect(v.serverName == "test.example" and v.alpn == @["h2", "http/1.1"] and v.shareGroups == @[0x11ec, 0x001d], "fields")
expect(v.suites.len == 3 and v.versions == @[0x0304] and v.sessionIdLen == 32, "suites, versions, session id")
expect(readClientHello(bytesOf(rec), rec.len - 1, v, n, raw) == 0, "one byte short: need more")
expect(readClientHello(bytesOf(rec), 3, v, n, raw) == 0, "header short: need more")
# The same message in two records.
let body = rec.len - 5
let cut = 40
var two: seq[byte] = @[22'u8, 3, 1, byte(cut shr 8), byte(cut and 0xff)]
for i in 0 ..< cut: two.add rec[5 + i]
for x in [22'u8, 3, 3, byte((body - cut) shr 8), byte((body - cut) and 0xff)]: two.add x
for i in cut ..< body: two.add rec[5 + i]
var v2 = default(HelloView)
expect(readClientHello(bytesOf(two), two.len, v2, n, raw) == two.len and v2.serverName == "test.example", "split")
# With several records the message itself comes back: its offsets hold.
expect(raw.len == body, "the split message returned")
for i in 0 ..< 32: expect(raw[v2.randomAt + i] == rec[5 + v.randomAt + i], "the random from the split message")
expect(readClientHello(bytesOf(two), two.len - 1, v2, n, raw) == 0, "split, short")
# Not a ClientHello; not a handshake record; a message that overruns.
var junk = rec
junk[5] = 2
expect(readClientHello(bytesOf(junk), junk.len, v, n, raw) == -alUnexpectedMessage, "wrong message type")
junk = rec
junk[0] = 23
expect(readClientHello(bytesOf(junk), junk.len, v, n, raw) == -alUnexpectedMessage, "wrong record type")
junk = rec
junk[8] = junk[8] xor 0x40
expect(readClientHello(bytesOf(junk), junk.len, v, n, raw) < 0 or readClientHello(bytesOf(junk), junk.len, v, n, raw) == 0, "bad length")
echo "PASS readClientHello: whole, partial, split, refused"
