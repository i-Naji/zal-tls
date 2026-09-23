## Session resumption's pluggable parts, each a proc table with a built-in
## implementation: the client's ticket store, the server's ticketer (the
## session state sealed into the ticket itself: no server-side cache) and
## the server's anti-replay memory for 0-RTT (a ticket's early data is
## accepted once).

import std/locks
import zal_tls/common
import zal_tls/crypto/[aead, hash, rand]
import zal_tls/keys/schedule
import zal_tls/wire/bytes

type
  SessionTicket* = object
    ## A ticket the client may offer, once: what the server sent and what
    ## the client knows about it.
    ticket*: seq[byte]
    psk*: Secret
    suite*: Suite
    alpn*: string
    serverName*: string
    issuedMs*: int64                ## when it arrived (unix ms)
    lifetime*: uint32               ## seconds
    ageAdd*: uint32
    maxEarlyData*: uint32           ## 0: no 0-RTT with it
    serverLeaf*: seq[byte]          ## the server's certificate (DER), from the full handshake

  SessionStore* = object
    ## Client: `put` keeps a ticket; `take` hands one out (removing it).
    put*: nil proc (ctx: nil pointer; t: ptr SessionTicket) {.nimcall.}
    take*: nil proc (ctx: nil pointer; serverName: string; nowMs: int64; t: var SessionTicket): bool {.nimcall.}
    ctx*: nil pointer

  MemoryStore* = object
    ## Tickets by server name, `perName` each (the newest) and `total` in
    ## all (the oldest go), in memory; any thread.
    lock: Lock
    initialized: bool
    tickets: seq[SessionTicket]
    capacity: int
    perName: int
    total: int

  SessionState* = object
    ## What a server's ticket carries (sealed).
    psk*: Secret
    suite*: Suite
    alpn*: string
    serverName*: string
    issuedMs*: int64
    authMs*: int64                  ## the full handshake's time (tickets from resumed ones keep it)
    lifetime*: uint32
    ageAdd*: uint32
    maxEarlyData*: uint32
    clientLeaf*: seq[byte]          ## the client's certificate (DER), when it presented one
    scope*: seq[byte]               ## the configurations it resumes on (`ServerConfig.ticketScope`)

  Ticketer* = object
    ## Server: `seal` a state into a ticket; `open` one (false: a full handshake).
    seal*: nil proc (ctx: nil pointer; st: ptr SessionState; outp: var seq[byte]): bool {.nimcall.}
    open*: nil proc (ctx: nil pointer; ticket: Bytes; n: int; st: var SessionState): bool {.nimcall.}
    ctx*: nil pointer

  TicketClock* = nil proc (): int64 {.nimcall.}   ## unix ms (nil: the wall clock)

  KeyedTicketer* = object
    ## AES-256-GCM under a random key, a new one every `rotateEverySec`
    ## (and on `rotate`); tickets under the one before still open (not
    ## older ones): a ticket lives between one and two rotation periods, so
    ## keep `ticketLifetime` at most the period. Any thread.
    lock: Lock
    cur, prev: array[32, byte]
    curId, prevId: uint32
    hasPrev, initialized, hasCurrent: bool
    entropy: EntropySource
    rotateMs, lastMs: int64
    clock: TicketClock

  AntiReplay* = object
    ## Server: `firstUse` is true only the first time an identity is seen
    ## within `ttlMs` (a ticket's early data is accepted once).
    firstUse*: nil proc (ctx: nil pointer; id: Bytes; n: int; nowMs, ttlMs: int64): bool {.nimcall.}
    ctx*: nil pointer

  ReplaySlot = object
    key: array[16, byte]
    expiresMs: int64

  MemoryReplay* = object
    ## A fixed table of identities seen (a digest each) and when they expire;
    ## full of live ones, it refuses (no early data rather than a replay).
    lock: Lock
    initialized: bool
    slots: seq[ReplaySlot]

const
  TicketHead = 4 + AeadNonceLen          ## key id, nonce
  StateVersion = 4                        ## 2: the full handshake's time; 3: the client's certificate; 4: the scope
  MaxTicketLen* = 12288                   ## longer tickets are not kept (client) nor opened (server)
  MaxClientLeaf* = 8192                   ## a client certificate this large or less goes in (else no tickets)

# ------------------------------------------------------------ memory store

proc initMemoryStore*(s: var MemoryStore; perName = 4; total = 1024) =
  ## Address-stable owner. Repeated initialization leaves its settings intact.
  if s.initialized: return
  initLock(s.lock)
  s.initialized = true
  s.perName = max(1, perName)
  s.total = max(1, total)
  s.capacity = min(8, s.total)
  s.tickets = newSeqOfCap[SessionTicket](s.capacity)

proc reserveTicket(s: var MemoryStore) =
  ## Called with the lock held, after eviction makes room below the total bound.
  ## Never let seq growth free an allocation that still contains PSK copies.
  if s.tickets.len < s.capacity: return
  let capacity = s.capacity + min(s.capacity, s.total - s.capacity)
  var grown = newSeqOfCap[SessionTicket](capacity)
  for i in 0 ..< s.tickets.len:
    grown.add move(s.tickets[i])
    wipe(s.tickets[i].psk)
  s.tickets = move(grown)
  s.capacity = capacity

proc dropAt(s: var MemoryStore; i: int) =
  wipe(s.tickets[i].psk)                         # the seq's buffer keeps no stale PSK
  var j = i
  while j + 1 < s.tickets.len:
    var next = move(s.tickets[j + 1])
    s.tickets[j] = move(next)
    j = j + 1
  wipe(s.tickets[s.tickets.len - 1].psk)
  s.tickets.setLen(s.tickets.len - 1)

proc clear*(s: var MemoryStore) =
  ## Forget every ticket (a changed configuration: trust, certificates).
  if not s.initialized: return
  acquire(s.lock)
  while s.tickets.len > 0: dropAt(s, s.tickets.len - 1)
  release(s.lock)

proc release*(s: var MemoryStore) =
  ## After every configuration/connection borrowing the callbacks has drained.
  ## Wipes PSKs and releases the lock and capacity. Default/repeated release is safe.
  if not s.initialized: return
  clear(s)
  s.tickets = @[]
  deinitLock(s.lock)
  s = default(MemoryStore)

proc ticketCount*(s: var MemoryStore): int =
  ## Tickets held (for tests and diagnostics).
  if not s.initialized: return 0
  acquire(s.lock)
  result = s.tickets.len
  release(s.lock)

proc putIn(s: var MemoryStore; t: ptr SessionTicket) =
  if not s.initialized: return
  acquire(s.lock)
  var i = 0
  while i < s.tickets.len:                       # the expired ones go (t just arrived: now)
    if s.tickets[i].issuedMs + int64(s.tickets[i].lifetime) * 1000 <= t.issuedMs: dropAt(s, i)
    else: i = i + 1
  var count = 0
  var oldest = -1
  var oldestAll = -1
  for j in 0 ..< s.tickets.len:
    if oldestAll < 0 or s.tickets[j].issuedMs < s.tickets[oldestAll].issuedMs: oldestAll = j
    if s.tickets[j].serverName == t.serverName:
      count = count + 1
      if oldest < 0 or s.tickets[j].issuedMs < s.tickets[oldest].issuedMs: oldest = j
  if count >= s.perName and oldest >= 0: dropAt(s, oldest)
  elif s.tickets.len >= s.total and oldestAll >= 0: dropAt(s, oldestAll)
  reserveTicket(s)
  s.tickets.add t[]
  release(s.lock)

proc takeFrom(s: var MemoryStore; serverName: string; nowMs: int64; t: var SessionTicket): bool =
  result = false
  if not s.initialized: return
  acquire(s.lock)
  var i = 0
  while i < s.tickets.len:                       # drop the expired ones on the way
    if s.tickets[i].issuedMs + int64(s.tickets[i].lifetime) * 1000 <= nowMs: dropAt(s, i)
    else: i = i + 1
  var best = -1
  for j in 0 ..< s.tickets.len:
    if s.tickets[j].serverName == serverName and
       (best < 0 or s.tickets[j].issuedMs >= s.tickets[best].issuedMs):   # a tie: the last stored
      best = j
  if best >= 0:
    t = s.tickets[best]
    dropAt(s, best)
    result = true
  release(s.lock)

proc storePut(ctx: nil pointer; t: ptr SessionTicket) {.nimcall.} =
  let s = cast[nil ptr MemoryStore](ctx)
  if s == nil or t.ticket.len == 0 or t.ticket.len > MaxTicketLen: return
  putIn(s[], t)

proc storeTake(ctx: nil pointer; serverName: string; nowMs: int64; t: var SessionTicket): bool {.nimcall.} =
  let s = cast[nil ptr MemoryStore](ctx)
  result = s != nil and takeFrom(s[], serverName, nowMs, t)

proc memoryStore*(s: ptr MemoryStore): SessionStore =
  SessionStore(put: storePut, take: storeTake, ctx: s)

# --------------------------------------------------------- keyed ticketer

proc newKey(source: EntropySource; k: var array[32, byte]; id: var uint32): bool =
  var bytes = default(array[36, byte])
  if not randomFill(source, ptrOf(bytes), bytes.len): return false
  copyMem(addr k[0], addr bytes[0], 32)
  id = (uint32(bytes[32]) shl 24) or (uint32(bytes[33]) shl 16) or
       (uint32(bytes[34]) shl 8) or uint32(bytes[35])
  wipeBytes(ptrOf(bytes), bytes.len)
  result = true

proc nowOf(t: KeyedTicketer): int64 =
  let f = t.clock
  result = if f != nil: f() else: unixMs()

proc initKeyedTicketer*(t: var KeyedTicketer; rotateEverySec = 43200;
                       clock: TicketClock = nil; entropy: EntropySource = nil): bool =
  ## One owner; retain its address until no callback can use it. Failed entropy
  ## leaves an initialized but disabled ticketer; release it normally.
  if t.initialized: return false
  initLock(t.lock)
  t.initialized = true
  t.entropy = entropy
  t.hasCurrent = newKey(entropy, t.cur, t.curId)
  t.hasPrev = false
  t.rotateMs = int64(max(0, rotateEverySec)) * 1000
  t.clock = clock
  t.lastMs = nowOf(t)
  result = t.hasCurrent

proc rotateLocked(t: ptr KeyedTicketer): bool =
  var fresh = default(array[32, byte])
  var identity = 0'u32
  if not newKey(t.entropy, fresh, identity): return false
  wipeBytes(ptrOf(t.prev), t.prev.len)
  t.prev = t.cur
  t.prevId = t.curId
  t.hasPrev = t.hasCurrent
  t.cur = fresh
  t.curId = identity
  t.hasCurrent = true
  wipeBytes(ptrOf(fresh), fresh.len)
  t.lastMs = nowOf(t[])
  result = true

proc rotateIfDue(t: ptr KeyedTicketer): bool =
  if not t.hasCurrent or (t.rotateMs > 0 and nowOf(t[]) - t.lastMs >= t.rotateMs):
    return rotateLocked(t)
  result = true

proc rotate*(t: var KeyedTicketer): bool =
  ## False preserves the old keys. No ticket is sealed using failed entropy.
  if not t.initialized: return false
  acquire(t.lock)
  result = rotateLocked(addr t)
  release(t.lock)

proc release*(t: var KeyedTicketer) =
  ## Call only after all configurations/connections using it have drained.
  if not t.initialized: return
  wipeBytes(ptrOf(t.cur), t.cur.len)
  wipeBytes(ptrOf(t.prev), t.prev.len)
  deinitLock(t.lock)
  t = default(KeyedTicketer)

proc putStr8(w: var Writer; s: string) =
  put8(w, s.len)
  putStr(w, s)

proc readStr8(r: var Reader): string =
  var v = vec8(r)
  result = newString(v.left)
  for i in 0 ..< v.left: result[i] = char(v.p[v.pos + i])

proc ticketSeal(ctx: nil pointer; st: ptr SessionState; outp: var seq[byte]): bool {.nimcall.} =
  result = false
  let t = cast[nil ptr KeyedTicketer](ctx)
  if t == nil or not t.initialized or st.alpn.len > 255 or st.serverName.len > 255 or st.clientLeaf.len > MaxClientLeaf or
     st.scope.len > 255:
    return
  var body = newSeq[byte](TicketHead + 1 + 2 + 1 + 48 + 8 + 8 + 12 + 2 + 512 + 2 + st.clientLeaf.len + 1 + st.scope.len + AeadTagLen)
  var w = initWriter(bytesOf(body), TicketHead, body.len - AeadTagLen - TicketHead)
  put8(w, StateVersion)
  put16(w, code(st.suite))
  put8(w, st.psk.n)
  putBytes(w, cast[Bytes](unsafeAddr st.psk.b[0]), st.psk.n)
  put32(w, int(st.issuedMs shr 32))
  put32(w, int(st.issuedMs and 0xffffffff))
  put32(w, int(st.authMs shr 32))
  put32(w, int(st.authMs and 0xffffffff))
  put32(w, int(st.lifetime))
  put32(w, int(st.ageAdd))
  put32(w, int(st.maxEarlyData))
  putStr8(w, st.alpn)
  putStr8(w, st.serverName)
  put16(w, st.clientLeaf.len)
  if st.clientLeaf.len > 0: putBytes(w, cast[Bytes](unsafeAddr st.clientLeaf[0]), st.clientLeaf.len)
  put8(w, st.scope.len)
  if st.scope.len > 0: putBytes(w, cast[Bytes](unsafeAddr st.scope[0]), st.scope.len)
  if not w.ok:
    wipeBytes(bytesOf(body), body.len)
    return
  let n = w.pos - TicketHead
  var key = default(array[32, byte])
  acquire(t.lock)
  if not rotateIfDue(t):
    release(t.lock)
    wipeBytes(bytesOf(body), body.len)
    return
  key = t.cur
  let id = t.curId
  release(t.lock)
  body[0] = byte(id shr 24)
  body[1] = byte((id shr 16) and 0xff)
  body[2] = byte((id shr 8) and 0xff)
  body[3] = byte(id and 0xff)
  if not randomFill(t.entropy, at(bytesOf(body), 4), AeadNonceLen):
    wipeBytes(ptrOf(key), key.len)
    wipeBytes(bytesOf(body), body.len)
    return
  var a = default(Aead)
  if init(a, aeadAes256Gcm, ptrOf(key), 32):
    result = sealInPlace(a, at(bytesOf(body), 4), at(bytesOf(body), TicketHead), n,
                         at(bytesOf(body), TicketHead + n), bytesOf(body), 4)
  clear(a)
  wipeBytes(addr key[0], key.len)
  if result:
    body.setLen(TicketHead + n + AeadTagLen)
    outp = body
  else:
    wipeBytes(addr body[0], body.len)            # the plaintext state, never sent

proc readState(body: var seq[byte]; clen: int; st: var SessionState): bool =
  result = false
  var r = initReader(bytesOf(body), TicketHead, clen)
  if u8(r) != StateVersion: return
  var s = suiteAes128Gcm
  if not suiteOf(u16(r), s): return
  st = default(SessionState)
  st.suite = s
  let pn = u8(r)
  if pn > 48 or pn == 0: return
  var ps = sub(r, pn)
  if not ps.ok: return
  st.psk.n = pn
  copyMem(addr st.psk.b[0], ps.here, pn)
  let hi = u32(r)
  let lo = u32(r)
  st.issuedMs = int64((uint64(hi) shl 32) or uint64(lo))
  let ahi = u32(r)
  let alo = u32(r)
  st.authMs = int64((uint64(ahi) shl 32) or uint64(alo))
  st.lifetime = u32(r)
  st.ageAdd = u32(r)
  st.maxEarlyData = u32(r)
  st.alpn = readStr8(r)
  st.serverName = readStr8(r)
  var cl = vec16(r)
  if cl.left > 0:
    st.clientLeaf = newSeq[byte](cl.left)
    copyMem(addr st.clientLeaf[0], cl.here, cl.left)
    skip(cl, cl.left)
  var sc = vec8(r)
  if sc.left > 0:
    st.scope = newSeq[byte](sc.left)
    copyMem(addr st.scope[0], sc.here, sc.left)
    skip(sc, sc.left)
  result = r.ok and r.atEnd


proc ticketOpen(ctx: nil pointer; ticket: Bytes; n: int; st: var SessionState): bool {.nimcall.} =
  result = false
  let t = cast[nil ptr KeyedTicketer](ctx)
  if t == nil or not t.initialized or n < TicketHead + 1 + AeadTagLen or n > MaxTicketLen: return
  let id = (uint32(ticket[0]) shl 24) or (uint32(ticket[1]) shl 16) or (uint32(ticket[2]) shl 8) or uint32(ticket[3])
  var key = default(array[32, byte])
  var known = false
  acquire(t.lock)
  if not rotateIfDue(t):
    release(t.lock)
    return
  if id == t.curId:
    key = t.cur
    known = true
  elif t.hasPrev and id == t.prevId:
    key = t.prev
    known = true
  release(t.lock)
  if not known: return
  var body = newSeq[byte](n)
  copyMem(addr body[0], ticket, n)
  let clen = n - TicketHead - AeadTagLen
  var a = default(Aead)
  var ok = init(a, aeadAes256Gcm, ptrOf(key), 32) and
    openInPlace(a, at(bytesOf(body), 4), at(bytesOf(body), TicketHead), clen,
                at(bytesOf(body), TicketHead + clen), bytesOf(body), 4)
  clear(a)
  wipeBytes(addr key[0], key.len)
  if ok: result = readState(body, clen, st)
  wipeBytes(addr body[0], body.len)              # the plaintext state, whatever it held

proc keyedTicketer*(t: ptr KeyedTicketer): Ticketer =
  Ticketer(seal: ticketSeal, open: ticketOpen, ctx: t)

# ---------------------------------------------------------- memory replay

proc initMemoryReplay*(m: var MemoryReplay; slots = 65536) =
  ## Address-stable owner; release only after borrowed callbacks have drained.
  if m.initialized: return
  initLock(m.lock)
  m.initialized = true
  m.slots = newSeq[ReplaySlot](max(16, slots))

proc release*(m: var MemoryReplay) =
  if not m.initialized: return
  if m.slots.len > 0: wipeBytes(addr m.slots[0], m.slots.len * sizeof(ReplaySlot))
  m.slots = @[]
  deinitLock(m.lock)
  m = default(MemoryReplay)

proc replayFirstUse(ctx: nil pointer; id: Bytes; n: int; nowMs, ttlMs: int64): bool {.nimcall.} =
  result = false
  let m = cast[nil ptr MemoryReplay](ctx)
  if m == nil or not m.initialized or m.slots.len == 0: return
  var d = default(array[32, byte])
  var h = default(Hash)
  init(h, hashSha256)
  discard update(h, id, n)
  final(h, ptrOf(d))
  let start = int(((uint64(d[0]) shl 24) or (uint64(d[1]) shl 16) or (uint64(d[2]) shl 8) or uint64(d[3])) mod
                  uint64(m.slots.len))
  acquire(m.lock)
  var free = -1
  var seen = false
  var i = 0
  while i < 16:                             # a short probe: full of live ones means "refuse"
    let j = (start + i) mod m.slots.len
    let live = m.slots[j].expiresMs > nowMs
    var same = live
    if same:
      for k in 0 ..< 16:
        if m.slots[j].key[k] != d[k]: same = false
    if same:
      seen = true
      break
    if not live and free < 0: free = j
    i = i + 1
  if not seen and free >= 0:
    for k in 0 ..< 16: m.slots[free].key[k] = d[k]
    m.slots[free].expiresMs = nowMs + ttlMs
    result = true
  release(m.lock)

proc memoryReplay*(m: ptr MemoryReplay): AntiReplay =
  AntiReplay(firstUse: replayFirstUse, ctx: m)
