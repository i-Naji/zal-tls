## The TLS 1.3 key schedule (RFC 8446 section 7): HKDF-Expand-Label,
## Derive-Secret, the early → handshake → master chain, traffic keys and
## Finished values. Secrets are plain data, wiped by `wipe`.

import zal_tls/common
import zal_tls/crypto/[hash, hkdf, aead, rand]
import zal_tls/wire/bytes

type
  Suite* = enum
    suiteAes128Gcm, suiteAes256Gcm, suiteChaCha20

  Secret* = object
    n*: int                    ## digest length of the suite's hash
    b*: array[48, byte]

  Schedule* = object
    alg*: HashAlg
    early*, handshake*, master*: Secret
    cHs*, sHs*, cAp*, sAp*, exporter*, resumption*: Secret
    cEarly*, earlyExporter*: Secret      ## 0-RTT: client_early_traffic_secret, early_exporter_master_secret

proc code*(s: Suite): int =
  case s
  of suiteAes128Gcm: 0x1301
  of suiteAes256Gcm: 0x1302
  of suiteChaCha20: 0x1303

proc name*(s: Suite): string =
  case s
  of suiteAes128Gcm: "TLS_AES_128_GCM_SHA256"
  of suiteAes256Gcm: "TLS_AES_256_GCM_SHA384"
  of suiteChaCha20: "TLS_CHACHA20_POLY1305_SHA256"

proc suiteOf*(code: int; s: var Suite): bool =
  result = true
  case code
  of 0x1301: s = suiteAes128Gcm
  of 0x1302: s = suiteAes256Gcm
  of 0x1303: s = suiteChaCha20
  else: result = false

proc hashOf*(s: Suite): HashAlg =
  if s == suiteAes256Gcm: hashSha384 else: hashSha256

proc aeadOf*(s: Suite): AeadAlg =
  case s
  of suiteAes128Gcm: aeadAes128Gcm
  of suiteAes256Gcm: aeadAes256Gcm
  of suiteChaCha20: aeadChaCha20Poly1305

template bp(s: Secret): Bytes =
  cast[Bytes](unsafeAddr s.b[0])

proc wipe*(s: var Secret) =
  wipeBytes(addr s.b[0], s.b.len)
  s.n = 0

proc expandLabel*(alg: HashAlg; secret: Secret; label: string;
                  ctx: Bytes; ctxLen: int;
                  outp: Bytes; outLen: int): bool =
  ## HKDF-Expand-Label (7.1); "tls13 " is prefixed to `label` here.
  var info = default(array[520, byte])
  var w = initWriter(ptrOf(info), 0, info.len)
  put16(w, outLen)
  let l = begin8(w)
  putStr(w, "tls13 ")
  putStr(w, label)
  finish8(w, l)
  let c = begin8(w)
  putBytes(w, ctx, ctxLen)
  finish8(w, c)
  result = w.ok and hkdfExpand(alg, bp(secret), secret.n, ptrOf(info), w.pos, outp, outLen)

proc deriveSecret*(alg: HashAlg; secret: Secret; label: string;
                   hash: Bytes): Secret =
  ## Derive-Secret (7.1) over a transcript hash of `digestLen(alg)` bytes;
  ## `n` is 0 on failure.
  result = default(Secret)
  let n = digestLen(alg)
  if expandLabel(alg, secret, label, hash, n, ptrOf(result.b), n): result.n = n

proc emptyHash(alg: HashAlg; outp: Bytes) =
  var h = default(Hash)
  init(h, alg)
  final(h, outp)

proc extract(alg: HashAlg; salt: Secret; ikm: Bytes; ikmLen: int;
             dst: var Secret): bool =
  dst.n = digestLen(alg)
  result = salt.n == dst.n and hkdfExtract(alg, bp(salt), salt.n, ikm, ikmLen, ptrOf(dst.b))

proc startSchedule*(s: var Schedule; alg: HashAlg; psk: Bytes; pskLen: int): bool =
  ## The early secret; `pskLen` 0 means no PSK (an all-zero IKM).
  s.alg = alg
  let n = digestLen(alg)
  var zeros = default(array[48, byte])
  s.early.n = n
  if pskLen == 0: result = hkdfExtract(alg, ptrOf(zeros), n, ptrOf(zeros), n, ptrOf(s.early.b))
  else: result = hkdfExtract(alg, ptrOf(zeros), n, psk, pskLen, ptrOf(s.early.b))

proc handshakeSecrets*(s: var Schedule; ecdhe: Bytes; ecdheLen: int;
                       helloHash: Bytes): bool =
  ## The handshake secret and both handshake traffic secrets; `helloHash`
  ## is the transcript hash through the ServerHello.
  var e = default(array[48, byte])
  emptyHash(s.alg, ptrOf(e))
  var derived = deriveSecret(s.alg, s.early, "derived", ptrOf(e))
  result = derived.n != 0 and extract(s.alg, derived, ecdhe, ecdheLen, s.handshake)
  wipe(derived)
  if not result: return false
  s.cHs = deriveSecret(s.alg, s.handshake, "c hs traffic", helloHash)
  s.sHs = deriveSecret(s.alg, s.handshake, "s hs traffic", helloHash)
  result = s.cHs.n != 0 and s.sHs.n != 0

proc masterSecrets*(s: var Schedule; finishedHash: Bytes): bool =
  ## The master secret, both application traffic secrets and the exporter
  ## secret; `finishedHash` is the transcript hash through the server's
  ## Finished.
  var e = default(array[48, byte])
  emptyHash(s.alg, ptrOf(e))
  var derived = deriveSecret(s.alg, s.handshake, "derived", ptrOf(e))
  var zeros = default(array[48, byte])
  result = derived.n != 0 and extract(s.alg, derived, ptrOf(zeros), derived.n, s.master)
  wipe(derived)
  if not result: return false
  s.cAp = deriveSecret(s.alg, s.master, "c ap traffic", finishedHash)
  s.sAp = deriveSecret(s.alg, s.master, "s ap traffic", finishedHash)
  s.exporter = deriveSecret(s.alg, s.master, "exp master", finishedHash)
  result = s.cAp.n != 0 and s.sAp.n != 0 and s.exporter.n != 0

proc ticketPsk*(alg: HashAlg; resumption: Secret; nonce: Bytes; nonceLen: int): Secret =
  ## A ticket's PSK (4.6.1): HKDF-Expand-Label(resumption_master_secret,
  ## "resumption", ticket_nonce); `n` is 0 on failure.
  result = default(Secret)
  let n = digestLen(alg)
  if expandLabel(alg, resumption, "resumption", nonce, nonceLen, ptrOf(result.b), n): result.n = n

proc binderKey*(s: Schedule; resumption: bool): Secret =
  ## The binder key (7.1): "res binder" for a ticket, "ext binder" for an
  ## external PSK. The binder is `verifyData(alg, binderKey, hash(truncated
  ## ClientHello))`.
  var e = default(array[48, byte])
  emptyHash(s.alg, ptrOf(e))
  result = deriveSecret(s.alg, s.early, if resumption: "res binder" else: "ext binder", ptrOf(e))

proc earlySecrets*(s: var Schedule; clientHelloHash: Bytes): bool =
  ## 0-RTT: client_early_traffic_secret and early_exporter_master_secret
  ## over the ClientHello.
  s.cEarly = deriveSecret(s.alg, s.early, "c e traffic", clientHelloHash)
  s.earlyExporter = deriveSecret(s.alg, s.early, "e exp master", clientHelloHash)
  result = s.cEarly.n != 0 and s.earlyExporter.n != 0

proc echConfirmation*(alg: HashAlg; innerRandom: Bytes; transcriptHash: Bytes; hrr: bool;
                      outp: Bytes): bool =
  ## ECH's acceptance confirmation (RFC 9849 7.2, 7.2.1): 8 bytes from the
  ## inner hello's random and the transcript hash (through the ServerHello
  ## or HelloRetryRequest with the confirmation zeroed).
  var zeros = default(array[48, byte])
  var prk = default(Secret)
  prk.n = digestLen(alg)
  result = hkdfExtract(alg, ptrOf(zeros), prk.n, innerRandom, 32, ptrOf(prk.b)) and
    expandLabel(alg, prk, if hrr: "hrr ech accept confirmation" else: "ech accept confirmation",
                transcriptHash, digestLen(alg), outp, 8)
  wipe(prk)

proc resumptionSecret*(s: var Schedule; clientFinishedHash: Bytes): bool =
  s.resumption = deriveSecret(s.alg, s.master, "res master", clientFinishedHash)
  result = s.resumption.n != 0

proc trafficKeys*(suite: Suite; secret: Secret; key: Bytes;
                  iv: Bytes): bool =
  ## The write key (`keyLen(aeadOf(suite))` bytes) and the 12-byte IV (7.3).
  let alg = hashOf(suite)
  result = expandLabel(alg, secret, "key", key, 0, key, keyLen(aeadOf(suite))) and
    expandLabel(alg, secret, "iv", iv, 0, iv, 12)

proc verifyData*(alg: HashAlg; base: Secret; transcriptHash: Bytes;
                 outp: Bytes): bool =
  ## The Finished value (4.4.4): HMAC(finished_key, transcript hash).
  let n = digestLen(alg)
  var fk = default(array[48, byte])
  result = expandLabel(alg, base, "finished", transcriptHash, 0, ptrOf(fk), n) and
    hmac(alg, ptrOf(fk), n, transcriptHash, n, outp)
  wipeBytes(addr fk[0], fk.len)

proc nextTrafficSecret*(alg: HashAlg; s: Secret): Secret =
  ## application_traffic_secret_N+1 (7.2); `n` is 0 on failure.
  result = default(Secret)
  let n = digestLen(alg)
  if expandLabel(alg, s, "traffic upd", ptrOf(result.b), 0, ptrOf(result.b), n): result.n = n

proc wipe*(s: var Schedule) =
  wipe(s.early)
  wipe(s.handshake)
  wipe(s.master)
  wipe(s.cHs)
  wipe(s.sHs)
  wipe(s.cAp)
  wipe(s.sAp)
  wipe(s.exporter)
  wipe(s.resumption)
  wipe(s.cEarly)
  wipe(s.earlyExporter)
