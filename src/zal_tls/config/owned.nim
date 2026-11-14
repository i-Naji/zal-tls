## Optional address-stable configuration owners. Builders validate PEM/key
## matching and require an explicit client trust source. Connection wrappers
## retain these owners; releasing an application reference cannot free their
## certificate, key, trust store or configuration while it is still borrowed.
import zal_net/errors
import zal_tls/common
import zal_tls/config/config
import zal_tls/crypto/rand
import zal_tls/crypto/x509
import zal_tls/trust/roots

type
  TrustKind = enum
    trustPemKind, trustSystemKind, trustStoreKind
  TrustSource* = object
    kind: TrustKind
    pem: string
    store: nil Roots                 ## borrowed through builder invocation only
  ClientConfigObj = object
    cfg: ClientConfig
    trust: nil Roots                 ## owned independent native reference
    store: MemoryStore               ## tickets, once `keepSessions` ran
    keeps: bool
  ServerConfigObj = object
    cfg: ServerConfig
    certificate: CertifiedKey        ## owned, stable resolver target
    ticketer: KeyedTicketer          ## once `issueTickets` ran
    replay: MemoryReplay
    issues: bool
  ClientConfigRef* = ref ClientConfigObj
  ServerConfigRef* = ref ServerConfigObj
  ClientConfigResult* = object
    value*: nil ClientConfigRef
    code*: int
    message*: string                 ## builder diagnostic, outside I/O hot paths
  ServerConfigResult* = object
    value*: nil ServerConfigRef
    code*: int
    message*: string

proc `=destroy`(owner: var ClientConfigObj) =
  release(owner.trust)
  owner.trust = nil
  if owner.keeps: release(owner.store)
  owner.cfg = default(ClientConfig)

proc `=wasMoved`(owner: var ClientConfigObj) {.nodestroy, inline.} =
  zeroMem(addr owner, sizeof(owner))

proc `=destroy`(owner: var ServerConfigObj) =
  release(owner.certificate)
  if owner.issues:
    release(owner.ticketer)
    release(owner.replay)
  owner.cfg = default(ServerConfig)

proc `=wasMoved`(owner: var ServerConfigObj) {.nodestroy, inline.} =
  zeroMem(addr owner, sizeof(owner))

proc pemTrust*(pem: string): TrustSource =
  TrustSource(kind: trustPemKind, pem: pem)

proc systemTrust*(): TrustSource =
  ## Explicitly choose platform roots (including documented SSL_CERT overrides).
  TrustSource(kind: trustSystemKind)

proc storeTrust*(store: Roots): TrustSource =
  ## Builder acquires a native reference; caller keeps its original reference.
  TrustSource(kind: trustStoreKind, store: store)

proc validAlpn(protocols: seq[string]): bool =
  var size = 0
  for protocol in protocols:
    if protocol.len == 0 or protocol.len > 255: return false
    if size > 65535 - protocol.len - 1: return false
    size += protocol.len + 1
  result = true

proc ownedTrust(source: TrustSource): nil Roots =
  result = nil
  case source.kind
  of trustSystemKind:
    result = systemRoots()
  of trustStoreKind:
    let store = source.store
    if store != nil and rootCount(store) > 0 and retain(store): result = store
  of trustPemKind:
    var certs: seq[Cert] = @[]
    if certsPem(source.pem, certs) == 0: return nil
    let store = newRoots()
    if store != nil:
      for cert in certs: discard addRoot(store, cert)
      if rootCount(store) > 0: result = store
      else: release(store)
    for cert in certs: release(cert)

proc tryNewClientConfig*(trust: TrustSource; alpn: seq[string] = @[]): ClientConfigResult =
  result = default(ClientConfigResult)
  result.code = InvalidInput
  if not validAlpn(alpn):
    result.message = "ALPN identifiers must contain 1..255 bytes and fit one TLS extension"
    return
  let roots = ownedTrust(trust)
  if roots == nil:
    result.message = "no usable trust anchors in the explicit trust source"
    return
  let owner = ClientConfigRef()
  owner.trust = roots
  owner.cfg = defaultClientConfig(roots)
  when defined(windows):
    if trust.kind == trustSystemKind: owner.cfg.verifier = systemVerifier(roots)
  for protocol in alpn: owner.cfg.alpn.add protocol
  result.value = owner
  result.code = 0

proc tryNewServerConfig*(certPem, keyPem: string; alpn: seq[string] = @[]): ServerConfigResult =
  result = default(ServerConfigResult)
  result.code = InvalidInput
  if not validAlpn(alpn):
    result.message = "ALPN identifiers must contain 1..255 bytes and fit one TLS extension"
    return
  let owner = ServerConfigRef()
  result.message = loadCertifiedKey(certPem, keyPem, owner.certificate)
  if result.message.len != 0: return
  owner.cfg = defaultServerConfig()
  owner.cfg.resolver = singleCert(addr owner.certificate)
  # An address can be reused by a later configuration; tickets must not follow it.
  var scope = default(array[16, byte])
  if randomBytes(ptrOf(scope), scope.len):
    for b in scope: owner.cfg.ticketScope.add char(b)
  for protocol in alpn: owner.cfg.alpn.add protocol
  result.value = owner
  result.code = 0

proc keepSessions*(owner: ClientConfigRef; earlyData = false) =
  ## Keep the tickets servers hand out and resume with them, which saves the
  ## certificate exchange on later connections to the same name. Call it
  ## before the first connection uses the configuration.
  ##
  ## With `earlyData`, the request given to `connect` goes as 0-RTT when a
  ## ticket allows it. An attacker can replay 0-RTT data, so turn it on only
  ## where every such request is idempotent.
  if not owner.keeps:
    initMemoryStore(owner.store)
    owner.keeps = true
    owner.cfg.sessions = memoryStore(addr owner.store)
  owner.cfg.earlyData = earlyData

proc issueTickets*(owner: ServerConfigRef; maxEarlyData = 0): bool =
  ## Hand out session tickets and accept them, so returning clients skip the
  ## certificate exchange. The keys live in this configuration and rotate on
  ## their own; they are gone when the program ends. Call it before the first
  ## connection uses the configuration. False when the system gave no
  ## randomness for the keys, and then nothing changes.
  ##
  ## `maxEarlyData` above 0 accepts that many bytes of 0-RTT per ticket. Each
  ## ticket's early data is taken once, but only by this process: several
  ## servers behind one name need a shared replay store from `zal_tls/raw`.
  result = true
  if not owner.issues:
    if not initKeyedTicketer(owner.ticketer):
      release(owner.ticketer)
      return false
    initMemoryReplay(owner.replay)
    owner.issues = true
    owner.cfg.ticketer = keyedTicketer(addr owner.ticketer)
    owner.cfg.antiReplay = memoryReplay(addr owner.replay)
  owner.cfg.maxEarlyData = uint32(max(maxEarlyData, 0))

proc unsafeBorrowConfig*(owner: ClientConfigRef): ClientConfigPtr {.inline.} =
  ## Advanced read-only borrow, valid while owner is retained. Do not change
  ## roots or hook contexts: these builders own exactly their declared resources.
  addr owner.cfg

proc unsafeBorrowConfig*(owner: ServerConfigRef): ServerConfigPtr {.inline.} =
  ## Advanced read-only borrow. For custom mutable policies/hooks use the raw
  ## configuration API with its explicit resource-lifetime contract.
  addr owner.cfg
