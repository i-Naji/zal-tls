import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/kx
import zal_tls/wire/bytes
import zal_tls/config/config
import zal_tls/private/core/[conn, client]

import hexutil, rfc8448

# RFC 8448 section 5 from the client's side: the server answers the first
# ClientHello (x25519) with a HelloRetryRequest for P-256 and a cookie.
var ch1 = hex(nth(Hrr, "{client} construct a ClientHello", "ClientHello", 0))
var ch2 = hex(nth(Hrr, "{client} construct a ClientHello", "ClientHello", 1))
var xPriv = hex(trace(Hrr, "{client} create an ephemeral x25519", "private key"))
var pPriv = hex(trace(Hrr, "{client} create an ephemeral P-256", "private key"))
var retried = false
var cookieSeen = 0

proc rfcBuild(ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.} =
  if p.retry:
    retried = true
    cookieSeen = p.cookie.len
    expect(p.shareGroups.len == 1 and p.shareGroups[0] == kxSecp256r1, "one P-256 share on retry")
    putBytes(w, bytesOf(ch2), ch2.len)
  else:
    putBytes(w, bytesOf(ch1), ch1.len)
  result = w.ok

proc rfcKey(ctx: nil pointer; g: KxGroup; k: var KxKey; share: Bytes): bool {.nimcall.} =
  result = if g == kxX25519: setPrivate(k, g, bytesOf(xPriv), share)
           else: setPrivate(k, g, bytesOf(pPriv), share)

proc acceptAll(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} = 0

var cfg = defaultClientConfig(nil)
cfg.builder = HelloBuilder(build: rfcBuild, ctx: nil)
cfg.kx = KxHook(generate: rfcKey, respond: nil, ctx: nil)
cfg.shareGroups = @[kxX25519]                    # the RFC's client shares x25519 only
cfg.verifier = CertVerifier(verify: acceptAll, ctx: nil)
var c = default(TlsConn)
expect(initClient(c, addr cfg, "server"), "init")
var outb = newSeq[byte](65536)
var none = newSeq[byte](1)
var r = default(StepResult)

expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "ClientHello1")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Hrr, "{client} send handshake record", "complete record", 0), "CH1 record")
# The HelloRetryRequest: the second ClientHello (record version 0x0303).
var hrr = hex(nth(Hrr, "{server} send handshake record", "complete record", 0))
expect(step(c, bytesOf(hrr), hrr.len, bytesOf(outb), outb.len, r) == stSend and r.consumed == hrr.len, "HRR answered")
expect(retried and cookieSeen > 0, "builder called again with the cookie")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Hrr, "{client} send handshake record", "complete record", 1), "CH2 record")
# ServerHello (P-256), the flight, our Finished byte-exact (message_hash transcript).
var sh = hex(nth(Hrr, "{server} send handshake record", "complete record", 1))
expect(step(c, bytesOf(sh), sh.len, bytesOf(outb), outb.len, r) == stNeedInput, "ServerHello")
var flight = hex(nth(Hrr, "{server} send handshake record", "complete record", 2))
let st = step(c, bytesOf(flight), flight.len, bytesOf(outb), outb.len, r)
if st != stSend: echo st, " ", r.alert, " ", r.reason
expect(st == stSend and r.consumed == flight.len, "flight")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(Hrr, "{client} send handshake record", "complete record", 2), "Finished record")
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stReady, "ready")
# Both close, byte-exact.
let n = close(c, bytesOf(outb), outb.len)
expect(toHex(outb.toOpenArray(0, n - 1)) == trace(Hrr, "{client} send alert record", "complete record"), "close_notify")
var salert = hex(trace(Hrr, "{server} send alert record", "complete record"))
expect(step(c, bytesOf(salert), salert.len, bytesOf(outb), outb.len, r) == stClosed, "closed")
echo "PASS client HelloRetryRequest: RFC 8448 5 byte-exact (P-256 retry, cookie, message_hash)"
release(c)
