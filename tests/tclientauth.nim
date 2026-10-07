{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[kx, sig]
import zal_tls/keys/schedule
import zal_tls/wire/[bytes, messages]
import zal_tls/config/config
import zal_tls/private/core/[conn, client]

import hexutil, rfc8448

# RFC 8448 section 5 from the client's side, byte-exact: the server asks
# for a certificate; ours (the RFC's, with a sign hook giving its RSA-PSS
# signature: RSA-PSS is randomized) goes with CertificateVerify and
# Finished in one record, equal to the RFC's; then the application keys.
proc t(step, label: string): string = trace(rfc8448.ClientAuth, step, label)
proc sec(s: Secret): string = toHex(s.b.toOpenArray(0, s.n - 1))

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

var rfcCh = hex(t("{client} construct a ClientHello", "ClientHello"))
var cPriv = hex(t("{client} create an ephemeral x25519", "private key"))
var cCert = hex(t("{client} construct a Certificate", "Certificate"))
var cCv = hex(t("{client} construct a CertificateVerify", "CertificateVerify"))
var gSchemeUsed = 0

proc rfcBuild(ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.} =
  putBytes(w, bytesOf(rfcCh), rfcCh.len)
  result = w.ok

proc rfcKey(ctx: nil pointer; g: KxGroup; k: var KxKey; share: Bytes): bool {.nimcall.} =
  result = setPrivate(k, g, bytesOf(cPriv), share)

proc acceptAll(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} = 0

proc rfcSign(ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int; sig: Bytes; cap: int;
             sigLen: var int): bool {.nimcall.} =
  ## The RFC's signature (its CertificateVerify: 2 scheme bytes, 2 length bytes).
  gSchemeUsed = int(code(scheme))
  sigLen = cCv.len - 8
  copyMem(sig, addr cCv[8], sigLen)
  result = sigLen <= cap

# The RFC's client certificate (from its Certificate message), with an RSA
# key for the schemes (the hook signs).
var chain: seq[seq[byte]] = @[]
expect(parseCertificate(bytesOf(cCert), cCert.len, chain) == 0 and chain.len == 1, "the RFC's client certificate")
var ck = CertifiedKey(chain: chain, key: privateKeyPem(slurpText("tests/data/rsa.key")),
                      schemes: @[sigRsaPssSha256, sigRsaPssSha384])
expect(ck.key != nil, "an RSA key")

var cfg = defaultClientConfig(nil)
cfg.builder = HelloBuilder(build: rfcBuild, ctx: nil)
cfg.kx = KxHook(generate: rfcKey, respond: nil, ctx: nil)
cfg.shareGroups = @[kxX25519]
cfg.verifier = CertVerifier(verify: acceptAll, ctx: nil)
cfg.clientCert = singleClientCert(addr ck)
cfg.signer = SignHook(sign: rfcSign, ctx: nil)
var c = default(TlsConn)
expect(initClient(c, addr cfg, "server"), "init")
var outb = newSeq[byte](65536)
var none = newSeq[byte](1)
var r = default(StepResult)
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stSend, "hello")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(rfc8448.ClientAuth, "{client} send handshake record", "complete record", 0),
       "the ClientHello record")
var sh = hex(nth(rfc8448.ClientAuth, "{server} send handshake record", "complete record", 0))
expect(step(c, bytesOf(sh), sh.len, bytesOf(outb), outb.len, r) == stNeedInput, "ServerHello")
var flight = hex(nth(rfc8448.ClientAuth, "{server} send handshake record", "complete record", 1))
let st = step(c, bytesOf(flight), flight.len, bytesOf(outb), outb.len, r)
if st != stSend: echo st, " ", r.alert, " ", r.reason
expect(st == stSend and r.consumed == flight.len, "the server's flight")
expect(gSchemeUsed == 0x0804, "rsa_pss_rsae_sha256, as the RFC")
expect(toHex(outb.toOpenArray(0, r.outLen - 1)) == nth(rfc8448.ClientAuth, "{client} send handshake record", "complete record", 1),
       "Certificate, CertificateVerify, Finished: the RFC's record")
expect(step(c, bytesOf(none), 0, bytesOf(outb), outb.len, r) == stReady, "ready")
var tx = default(Secret)
var rx = default(Secret)
var txSeq = 0'u64
var rxSeq = 0'u64
expect(exportSecrets(c, tx, rx, txSeq, rxSeq), "secrets")
expect(sec(tx) == t("{server} derive secret \"tls13 c ap traffic\"", "expanded"), "client application secret")
echo "PASS client certificate: RFC 8448 5 byte-exact (Certificate, CertificateVerify, Finished)"
release(c)

# Asked, but no certificate fits (no scheme in common): an empty Certificate.
var ck2 = CertifiedKey(chain: chain, key: privateKeyPem(slurpText("tests/data/rsa.key")),
                       schemes: @[sigEd25519])
cfg.clientCert = singleClientCert(addr ck2)
var c2 = default(TlsConn)
expect(initClient(c2, addr cfg, "server"), "init 2")
discard step(c2, bytesOf(none), 0, bytesOf(outb), outb.len, r)
discard step(c2, bytesOf(sh), sh.len, bytesOf(outb), outb.len, r)
flight = hex(nth(rfc8448.ClientAuth, "{server} send handshake record", "complete record", 1))   # (opened in place above)
let st2 = step(c2, bytesOf(flight), flight.len, bytesOf(outb), outb.len, r)
if st2 != stSend: echo st2, " ", r.alert, " ", r.reason
expect(st2 == stSend, "flight 2")
expect(r.outLen == 5 + 8 + 36 + 1 + 16, "an empty Certificate and Finished: " & $r.outLen)
release(c2)
echo "PASS no fitting certificate: an empty Certificate"
