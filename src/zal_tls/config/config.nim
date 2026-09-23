## Client and server configuration. A config is a plain object set up once
## and shared read-only by many connections (through a pointer); its
## pluggable parts are tables of regular procs with a context pointer.

import zal_net/buffers
import zal_tls/common
import zal_tls/crypto/[kx, sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/wire/[bytes, consts, messages, ech]
import zal_tls/config/session
export session

type
  CertifiedKey* = object
    ## A certificate chain (DER, leaf first) and its private key.
    chain*: seq[seq[byte]]
    key*: nil PrivateKey
    schemes*: seq[SigScheme]        ## the key's schemes, most preferred first

  CertResolver* = object
    ## Server: the certificate for a ClientHello (SNI, ALPN, schemes); nil
    ## refuses the handshake (handshake_failure).
    resolve*: nil proc (ctx: nil pointer; hello: ptr HelloView): nil CertifiedKeyPtr {.nimcall.}
    ctx*: nil pointer

  CertVerifier* = object
    ## Client: accept the server's chain (DER, leaf first) for `host`: 0 or
    ## the alert to send.
    verify*: nil proc (ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.}
    ctx*: nil pointer

  ClientCertVerifier* = object
    ## Server: accept a client's chain (DER, leaf first) for the server name
    ## it asked for: 0 or the alert.
    verify*: nil proc (ctx: nil pointer; chain: ptr seq[seq[byte]]; serverName: string): int {.nimcall.}
    ctx*: nil pointer

  ResumeCheck* = object
    ## Server: may a ticket still be resumed with the client's certificate it
    ## carries (DER; empty: none) for this server name? (Revocation, a
    ## changed policy.) False: a full handshake.
    check*: nil proc (ctx: nil pointer; leaf: ptr seq[byte]; serverName: string): bool {.nimcall.}
    ctx*: nil pointer

  ClientCertResolver* = object
    ## Client: the certificate to present for a CertificateRequest (its
    ## schemes and CA names); nil: none (an empty Certificate).
    resolve*: nil proc (ctx: nil pointer; req: ptr CertRequestView): nil CertifiedKeyPtr {.nimcall.}
    ctx*: nil pointer

  EchKey* = object
    ## Server: one ECH configuration and its HPKE private key (X25519).
    config*: seq[byte]              ## the ECHConfig as published (version, length, contents)
    priv*: array[32, byte]
    retry*: bool                    ## offered in retry_configs when ECH is refused

  ClientAuth* = enum
    caIgnore        ## no CertificateRequest (the default)
    caRequest       ## asked; a client without one connects without an identity
    caRequire       ## asked; a client without one fails (certificate_required)

  KeyLog* = object
    ## Secrets in the SSLKEYLOGFILE format's terms (label, client random).
    log*: nil proc (ctx: nil pointer; label: string; clientRandom: Bytes;
                    secret: Secret) {.nimcall.}
    ctx*: nil pointer

  HelloParams* = object
    ## What the connection chose for its ClientHello, for a `HelloBuilder`.
    quic*: bool                    ## QUIC ClientHello: no compatibility session ID
    transportParams*: ByteView     ## borrowed only during the builder callback
    random*: array[32, byte]
    sessionId*: array[32, byte]
    sessionIdLen*: int
    serverName*: string             ## "" for none (and for IP literals)
    shareGroups*: seq[KxGroup]      ## the key shares, in order ...
    shares*: seq[seq[byte]]         ## ... and their public bytes
    cookie*: seq[byte]              ## from a HelloRetryRequest
    retry*: bool                    ## the second ClientHello (after a HelloRetryRequest)
    alpn*: seq[string]              ## the configuration's protocols
    cfg*: nil ClientConfigPtr      ## the rest of the configuration (suites, groups, schemes)
    pskTicket*: seq[byte]           ## a ticket to offer (empty: none) ...
    pskAge*: uint32                 ## ... its obfuscated age ...
    pskBinderLen*: int              ## ... and its binder's length (filled in after the hello is written)
    early*: bool                    ## offer 0-RTT (early_data)
    echInner*: bool                 ## ECH: this is the inner hello (its mark goes in)
    echOuter*: bool                 ## ECH: an outer-form extension (real or GREASE) goes in ...
    echConfigId*, echKdf*, echAead*: int
    echEnc*: seq[byte]
    echPayloadLen*: int
    echPayloadAt*: int              ## ... its payload's place in the writer (set by writeDefaultHello)

  HelloBuilder* = object
    ## Client: writes the whole ClientHello message (header included).
    ## Unset: our own. (Fingerprint templates and the RFC 8448 tests.)
    build*: nil proc (ctx: nil pointer; p: ptr HelloParams; w: var Writer): bool {.nimcall.}
    ctx*: nil pointer

  KxHook* = object
    ## Tests only: fixed key shares (`setPrivate`, `respondWith`).
    generate*: nil proc (ctx: nil pointer; g: KxGroup; k: var KxKey;
                         share: Bytes): bool {.nimcall.}
    respond*: nil proc (ctx: nil pointer; g: KxGroup; peer: Bytes; peerLen: int;
                        share, secret: Bytes): bool {.nimcall.}
    ctx*: nil pointer

  SignHook* = object
    ## Tests only: fixed signatures.
    sign*: nil proc (ctx: nil pointer; scheme: SigScheme; msg: Bytes; n: int;
                     sig: Bytes; cap: int; sigLen: var int): bool {.nimcall.}
    ctx*: nil pointer

  RandProc* = EntropySource
    ## Fill all requested bytes, or return false to abort the handshake.
  ClockProc* = nil proc (): int64 {.nimcall.}   ## unix milliseconds (nil: the wall clock)

  ClientConfig* = object
    suites*: seq[Suite]             ## offered, in preference order
    groups*: seq[KxGroup]           ## supported
    shareGroups*: seq[KxGroup]      ## key shares sent first (those also in `groups`)
    sigSchemes*: seq[SigScheme]
    alpn*: seq[string]
    roots*: nil Roots               ## trust anchors of the built-in web PKI verifier
    verifyAt*: int64                ## unix time for certificate validity; 0: now
    verifier*: CertVerifier         ## unset: the web PKI over `roots`
    builder*: HelloBuilder
    keyLog*: KeyLog
    kx*: KxHook
    rand*: RandProc                 ## nil: `randomBytes`
    maxHandshakeMsg*: int
    sessions*: SessionStore         ## tickets kept and offered (unset: no resumption)
    earlyData*: bool                ## send 0-RTT data when a ticket allows it (replayable!)
    clock*: ClockProc
    clientCert*: ClientCertResolver ## the certificate to present when asked (unset: none)
    echConfigs*: seq[byte]          ## an ECHConfigList (as published): ECH offered with the first
                                    ## usable config (empty: none)
    echGrease*: bool                ## no configs: a GREASE ECH extension instead
    echOuterAlpn*: seq[string]      ## the protocols the outer hello offers (empty: none, the inner's
                                    ## stay hidden; the inner's, or a common list, look like GREASE)
    signer*: SignHook               ## tests: fixed signatures for our CertificateVerify

  ServerConfig* = object
    suites*: seq[Suite]             ## our preference order: the server chooses
    groups*: seq[KxGroup]
    sigSchemes*: seq[SigScheme]
    alpn*: seq[string]
    resolver*: CertResolver
    keyLog*: KeyLog
    kx*: KxHook
    signer*: SignHook
    rand*: RandProc
    maxHandshakeMsg*: int
    ticketer*: Ticketer             ## tickets issued and accepted (unset: none)
    ticketsAfter*: int              ## tickets sent after each handshake
    ticketLifetime*: uint32         ## seconds (at most 7 days)
    resumeWithin*: uint32           ## seconds after a full handshake that resumptions (and
                                    ## their tickets) may follow; 0: no limit
    maxEarlyData*: uint32           ## 0-RTT bytes accepted per ticket (0: none)
    antiReplay*: AntiReplay         ## needed for 0-RTT: a ticket's early data once
    earlyWindowMs*: int             ## how far a ticket's age may drift for 0-RTT
    clock*: ClockProc
    clientAuth*: ClientAuth         ## ask for a client certificate (caIgnore: never)
    clientRoots*: nil Roots         ## the built-in client verifier's trust anchors
    clientVerifier*: ClientCertVerifier  ## unset: the web PKI (clientAuth) over `clientRoots`
    clientCaNames*: seq[seq[byte]]  ## sent as certificate_authorities (`subjectDer` of the CAs)
    resumeCheck*: ResumeCheck       ## a resumption's last word (unset: an unexpired certificate is enough)
    ticketScope*: string            ## tickets resume only on configurations with the same scope
                                    ## ("": only on this configuration object)
    echKeys*: seq[EchKey]           ## ECH accepted for these configurations (empty: never)

  SniEntry* = object
    name*: string                   ## "host.example" or "*.example"
    ck*: CertifiedKeyPtr

  ClientConfigPtr* = ptr ClientConfig
  ServerConfigPtr* = ptr ServerConfig
  CertifiedKeyPtr* = ptr CertifiedKey

const
  AllSuites* = [suiteAes128Gcm, suiteAes256Gcm, suiteChaCha20]
  AllSchemes* = [sigEcdsaP256Sha256, sigEcdsaP384Sha384, sigRsaPssSha256, sigRsaPssSha384, sigEd25519]
  DefaultMaxHandshakeMsg* = 65536

proc release*(ck: var CertifiedKey) =
  release(ck.key)
  ck.key = nil
  ck.chain = @[]
  ck.schemes = @[]

proc loadCertifiedKey*(chainPem, keyPem: string; ck: var CertifiedKey): string =
  ## A chain (leaf first) and its key from PEM text: "" or what is wrong.
  release(ck)
  var certs: seq[Cert] = @[]
  if certsPem(chainPem, certs) == 0: return "no certificate in the chain PEM"
  let key = privateKeyPem(keyPem)
  if key == nil:
    result = "no private key in the key PEM"
  elif not keyMatches(certs[0], key):
    release(key)
    result = "the key does not belong to the first certificate"
  else:
    ck.key = key
    for c in certs:
      var der: seq[byte] = @[]
      certDerOf(c, der)
      ck.chain.add der
    for s in [sigEd25519, sigEcdsaP256Sha256, sigEcdsaP384Sha384, sigRsaPssSha256, sigRsaPssSha384]:
      if matches(s, key): ck.schemes.add s
    result = if ck.schemes.len == 0: "the key has no TLS 1.3 signature scheme" else: ""
  for c in certs: release(c)

proc chainVerify(roots: Roots; chain: ptr seq[seq[byte]]; host: string; atUnix: int64;
                 purpose: CertPurpose): int =
  if chain[].len == 0: return alDecodeError
  let leaf = certDer(cast[Bytes](addr chain[][0][0]), chain[][0].len)
  if leaf == nil: return alBadCertificate
  var inter: seq[Cert] = @[]
  var ok = true
  for i in 1 ..< chain[].len:
    let c = certDer(cast[Bytes](addr chain[][i][0]), chain[][i].len)
    if c == nil: ok = false
    else: inter.add c
  if not ok:
    result = alBadCertificate
  else:
    result = case verifyChain(roots, leaf, inter, host, atUnix, purpose)
      of vrOk: 0
      of vrExpired, vrNotYetValid: alCertificateExpired
      of vrUnknownIssuer: alUnknownCa
      of vrBadName, vrBadSignature: alBadCertificate
      of vrBadPurpose: alUnsupportedCertificate
      of vrOther: alCertificateUnknown
  for c in inter: release(c)
  release(leaf)

proc webPkiVerify*(roots: Roots; chain: ptr seq[seq[byte]]; host: string; atUnix: int64): int =
  ## The chain to `roots` for `host` at `atUnix` (0: now): 0 or the alert.
  ## An empty `host` fails: a chain is only ever good for a name.
  if host.len == 0: return alInternalError
  result = chainVerify(roots, chain, host, atUnix, cpServer)

proc webPkiVerifyClient*(roots: Roots; chain: ptr seq[seq[byte]]; atUnix: int64): int =
  ## A client's chain to `roots`, for client authentication, at `atUnix`
  ## (0: now; no name is checked): 0 or the alert.
  result = chainVerify(roots, chain, "", atUnix, cpClient)

proc webPkiProc(ctx: nil pointer; chain: ptr seq[seq[byte]]; host: string): int {.nimcall.} =
  let r = cast[nil Roots](ctx)
  result = if r == nil: alUnknownCa else: webPkiVerify(r, chain, host, 0)

proc webPkiVerifier*(roots: Roots): CertVerifier =
  ## The web PKI over `roots`, now: to wrap in a verifier of one's own.
  CertVerifier(verify: webPkiProc, ctx: roots)

proc defaultClientConfig*(roots: nil Roots): ClientConfig =
  ## Every suite and scheme; X25519MLKEM768 and X25519 shared (as browsers
  ## do: servers that prefer the hybrid need no HelloRetryRequest), P-256
  ## supported; the web PKI over `roots`.
  result = ClientConfig(suites: @AllSuites, groups: @[kxX25519MlKem768, kxX25519, kxSecp256r1],
                        shareGroups: @[kxX25519MlKem768, kxX25519], sigSchemes: @AllSchemes, alpn: @[],
                        roots: roots, maxHandshakeMsg: DefaultMaxHandshakeMsg, echGrease: true)

proc defaultServerConfig*(): ServerConfig =
  ## Every suite and scheme; groups X25519MLKEM768, X25519, P-256 (a share
  ## the client sent wins over a HelloRetryRequest). Set `resolver`.
  result = ServerConfig(suites: @AllSuites, groups: @[kxX25519MlKem768, kxX25519, kxSecp256r1],
                        sigSchemes: @AllSchemes, alpn: @[], maxHandshakeMsg: DefaultMaxHandshakeMsg,
                        ticketsAfter: 2, ticketLifetime: 7200, resumeWithin: 604800, maxEarlyData: 0,
                        earlyWindowMs: 10_000)

proc newEchKey*(configId: int; publicName: string; maxNameLen = 32; entropy: EntropySource = nil): EchKey =
  ## A fresh X25519 key and its ECHConfig (DHKEM(X25519), HKDF-SHA256,
  ## AES-128-GCM) for `publicName` (the name the outer hello shows), offered
  ## in retry_configs. A config id outside 0..255, a public name that is not
  ## a host name (`validPublicName`) or a `maxNameLen` outside 0..255: no
  ## config (`initServer` refuses the key).
  result = default(EchKey)
  if configId < 0 or configId > 255 or maxNameLen < 0 or maxNameLen > 255 or not validPublicName(publicName):
    return
  if not randomFill(entropy, ptrOf(result.priv), 32): return
  var k = default(KxKey)
  var pub = default(array[32, byte])
  if not setPrivate(k, kxX25519, ptrOf(result.priv), ptrOf(pub)):
    clear(k)
    wipeBytes(ptrOf(result.priv), result.priv.len)
    return
  clear(k)
  result.config = newSeq[byte](64 + publicName.len)
  var w = initWriter(bytesOf(result.config), 0, result.config.len)
  writeEchConfig(w, configId, ptrOf(pub), publicName, maxNameLen)
  result.config.setLen(if w.ok: w.pos else: 0)
  result.retry = true

proc echConfigList*(keys: seq[EchKey]; retryOnly = false): seq[byte] =
  ## The ECHConfigList to publish (all the keys' configs) or to send as
  ## retry_configs (`retryOnly`).
  result = @[0'u8, 0]
  for k in keys:
    if not retryOnly or k.retry:
      for x in k.config: result.add x
  let n = result.len - 2
  result[0] = byte(n shr 8)
  result[1] = byte(n and 0xff)

proc singleProc(ctx: nil pointer; hello: ptr HelloView): nil CertifiedKeyPtr {.nimcall.} =
  cast[nil CertifiedKeyPtr](ctx)

proc sessionKey*(cfg: ClientConfigPtr; name: string): string =
  ## The session store's key: the server name, and a tag of the client
  ## certificate resolver's context when there is a resolver (for
  ## `singleClientCert`: the certificate): a ticket got with one certificate
  ## is never offered with another, or with none.
  result = name
  if cfg.clientCert.resolve != nil:
    var tag = cast[uint](cfg.clientCert.ctx)
    result.add '#'
    const digits = "0123456789abcdef"
    for i in 0 ..< 16:
      result.add digits[int(tag and 15'u)]
      tag = tag shr 4

proc singleClientProc(ctx: nil pointer; req: ptr CertRequestView): nil CertifiedKeyPtr {.nimcall.} =
  ## The certificate, when one of its key's schemes is asked for.
  result = nil
  let ck = cast[nil CertifiedKeyPtr](ctx)
  if ck == nil: return
  for s in ck.schemes:
    for x in req.schemes:
      if x == int(code(s)): return ck

proc singleClientCert*(ck: CertifiedKeyPtr): ClientCertResolver =
  ## Client: this certificate, whenever a server asks and a scheme fits.
  ## `ck` must outlive the connections using it (a handshake holds it from
  ## the CertificateRequest to its Finished); it also tags the tickets got
  ## with it (`sessionKey`).
  ClientCertResolver(resolve: singleClientProc, ctx: ck)

proc singleCert*(ck: CertifiedKeyPtr): CertResolver =
  CertResolver(resolve: singleProc, ctx: ck)

proc lower(c: char): char =
  if c >= 'A' and c <= 'Z': char(ord(c) + 32) else: c

proc sameName(a, b: string; bFrom: int): bool =
  ## a == b[bFrom ..], ignoring ASCII case.
  if a.len != b.len - bFrom: return false
  result = true
  for i in 0 ..< a.len:
    if lower(a[i]) != lower(b[bFrom + i]): return false

proc nameMatches*(pattern, host: string): bool =
  ## An exact name, or "*.rest" for one more label in front of "rest".
  if pattern.len > 2 and pattern[0] == '*' and pattern[1] == '.':
    var dot = -1
    for i in 0 ..< host.len:
      if host[i] == '.':
        dot = i
        break
    result = dot > 0 and sameName(pattern.substr(1), host, dot)
  else:
    result = sameName(pattern, host, 0)

proc sniProc(ctx: nil pointer; hello: ptr HelloView): nil CertifiedKeyPtr {.nimcall.} =
  let t = cast[nil ptr seq[SniEntry]](ctx)
  if t == nil or t[].len == 0: return nil
  for e in t[]:
    if nameMatches(e.name, hello.serverName): return e.ck
  result = t[][0].ck

proc sniCerts*(table: ptr seq[SniEntry]): CertResolver =
  ## Exact names and "*." wildcards, in order; no match: the first entry.
  CertResolver(resolve: sniProc, ctx: table)
