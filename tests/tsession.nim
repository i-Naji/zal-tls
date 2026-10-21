{.feature: "assumeSync".}
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/keys/schedule
import zal_tls/config/session
import hexutil

# The client's ticket store: single use, newest first, a few per name, expiry.
var store = default(MemoryStore)
initMemoryStore(store, 2)
let ss = memoryStore(addr store)
proc ticketFor(name: string; tag: byte; issued: int64; life: uint32): SessionTicket =
  result = default(SessionTicket)
  result.ticket = @[tag, tag, tag]
  result.serverName = name
  result.issuedMs = issued
  result.lifetime = life
var a = ticketFor("a.example", 1, 1000, 60)
var b = ticketFor("a.example", 2, 2000, 60)
var c = ticketFor("a.example", 3, 3000, 60)
var d = ticketFor("b.example", 4, 1000, 1)
ss.put(ss.ctx, addr a)
ss.put(ss.ctx, addr b)
ss.put(ss.ctx, addr c)                            # two per name: the oldest goes
ss.put(ss.ctx, addr d)
var got = default(SessionTicket)
expect(ss.take(ss.ctx, "a.example", 5000, got) and got.ticket[0] == 3, "newest first")
expect(ss.take(ss.ctx, "a.example", 5000, got) and got.ticket[0] == 2, "then the next")
expect(not ss.take(ss.ctx, "a.example", 5000, got), "used once, the oldest was dropped")
expect(not ss.take(ss.ctx, "b.example", 3000, got), "expired (1 s lifetime)")
# Tickets from the same millisecond: the last stored is the newest.
var e = ticketFor("c.example", 5, 1000, 60)
var f = ticketFor("c.example", 6, 1000, 60)
ss.put(ss.ctx, addr e)
ss.put(ss.ctx, addr f)
expect(ss.take(ss.ctx, "c.example", 2000, got) and got.ticket[0] == 6, "a tie: the last stored")
echo "PASS memory store: single use, newest first, a limit per name, expiry"

# Bounded against a server that sends many or big tickets, for many names:
# a total limit (the oldest go), tickets over MaxTicketLen refused, the
# expired ones dropped when a ticket is stored.
var small = default(MemoryStore)
initMemoryStore(small, 2, 5)
let sm = memoryStore(addr small)
for i in 0 ..< 20:
  var t = ticketFor("n" & $i & ".example", byte(i), int64(1000 + i), 3600)
  sm.put(sm.ctx, addr t)
expect(ticketCount(small) == 5, "five at most: " & $ticketCount(small))
var g = default(SessionTicket)
expect(not sm.take(sm.ctx, "n0.example", 2000, g) and sm.take(sm.ctx, "n19.example", 2000, g), "the oldest went")
var big = ticketFor("big.example", 1, 1000, 3600)
big.ticket = newSeq[byte](MaxTicketLen + 1)
sm.put(sm.ctx, addr big)
expect(not sm.take(sm.ctx, "big.example", 2000, g), "a ticket over the limit is not kept")
var stale = ticketFor("x.example", 1, 1000, 1)
var fresh = ticketFor("y.example", 2, 5000, 3600)
var only = default(MemoryStore)
initMemoryStore(only, 2, 100)
let om = memoryStore(addr only)
om.put(om.ctx, addr stale)
om.put(om.ctx, addr fresh)                      # at 5000 the first has expired
expect(ticketCount(only) == 1, "an expired ticket dropped when another is stored")
echo "PASS memory store: a total limit, big tickets refused, expired ones dropped"

# The server's ticketer: sealed state opens; tampering, and keys two rotations old, do not.
var tk = default(KeyedTicketer)
assert initKeyedTicketer(tk)
let tt = keyedTicketer(addr tk)
var st = default(SessionState)
st.psk.n = 32
for i in 0 ..< 32: st.psk.b[i] = byte(i)
st.suite = suiteAes256Gcm
st.alpn = "h2"
st.serverName = "test.example"
st.issuedMs = 1234567
st.lifetime = 7200
st.ageAdd = 0xdeadbeef'u32
st.maxEarlyData = 16384
var sealed: seq[byte] = @[]
expect(tt.seal(tt.ctx, addr st, sealed) and sealed.len > 32, "sealed")
var back = default(SessionState)
expect(tt.open(tt.ctx, bytesOf(sealed), sealed.len, back), "opened")
expect(back.psk.n == 32 and back.psk.b[31] == 31 and back.suite == suiteAes256Gcm and back.alpn == "h2" and
       back.serverName == "test.example" and back.issuedMs == 1234567 and back.lifetime == 7200 and
       back.ageAdd == 0xdeadbeef'u32 and back.maxEarlyData == 16384, "the state round-trips")
var bad = sealed
bad[bad.len - 1] = bad[bad.len - 1] xor 1
expect(not tt.open(tt.ctx, bytesOf(bad), bad.len, back), "tampered: refused")
assert rotate(tk)
expect(tt.open(tt.ctx, bytesOf(sealed), sealed.len, back), "one rotation: the previous key still opens")
assert rotate(tk)
expect(not tt.open(tt.ctx, bytesOf(sealed), sealed.len, back), "two rotations: refused")
var short = @[1'u8, 2, 3]
expect(not tt.open(tt.ctx, bytesOf(short), short.len, back), "garbage: refused")
echo "PASS keyed ticketer: seal/open, tamper, rotation"

# Anti-replay: an identity's first use only, within its time to live.
var ar = default(MemoryReplay)
initMemoryReplay(ar, 1024)
let rp = memoryReplay(addr ar)
var id1 = @[1'u8, 2, 3, 4]
var id2 = @[5'u8, 6, 7, 8]
expect(rp.firstUse(rp.ctx, bytesOf(id1), id1.len, 1000, 10_000), "first use")
expect(not rp.firstUse(rp.ctx, bytesOf(id1), id1.len, 2000, 10_000), "a replay")
expect(rp.firstUse(rp.ctx, bytesOf(id2), id2.len, 2000, 10_000), "another identity")
expect(rp.firstUse(rp.ctx, bytesOf(id1), id1.len, 20_000, 10_000), "after its time to live: new again")
echo "PASS anti-replay: first use only, within the window"

# The keyed ticketer rotates its key on its own (rotateEverySec): a ticket
# opens under its key and the next one, not later.
var gTickNow = 1_000_000'i64
proc tickClock(): int64 {.nimcall.} = gTickNow
block:
  var kt = default(KeyedTicketer)
  assert initKeyedTicketer(kt, rotateEverySec = 10, clock = tickClock)
  let tk = keyedTicketer(addr kt)
  var st = default(SessionState)
  st.suite = suiteAes128Gcm
  st.psk.n = 32
  st.lifetime = 60
  var ta: seq[byte] = @[]
  var tb: seq[byte] = @[]
  var tc: seq[byte] = @[]
  expect(tk.seal(tk.ctx, addr st, ta), "seal a")
  gTickNow = gTickNow + 11_000
  expect(tk.seal(tk.ctx, addr st, tb), "seal b")
  var newKey = false
  for i in 0 .. 3: newKey = newKey or ta[i] != tb[i]
  expect(newKey, "a new key after 10 s")
  var back = default(SessionState)
  expect(tk.open(tk.ctx, bytesOf(ta), ta.len, back), "a opens under the previous key")
  gTickNow = gTickNow + 11_000
  expect(tk.seal(tk.ctx, addr st, tc), "seal c")
  expect(not tk.open(tk.ctx, bytesOf(ta), ta.len, back), "a no longer opens (two rotations)")
  expect(tk.open(tk.ctx, bytesOf(tb), tb.len, back), "b still opens")
echo "PASS keyed ticketer: the key rotates on its own"

# A ticket carries the client's identity (its certificate) when there is one.
block:
  var kt = default(KeyedTicketer)
  assert initKeyedTicketer(kt)
  let tk = keyedTicketer(addr kt)
  var st = default(SessionState)
  st.suite = suiteAes128Gcm
  st.psk.n = 32
  st.lifetime = 60
  st.clientLeaf = newSeq[byte](1500)
  for i in 0 ..< 1500: st.clientLeaf[i] = byte(i and 0xff)
  var sealed: seq[byte] = @[]
  expect(tk.seal(tk.ctx, addr st, sealed), "seal with a client certificate")
  var back = default(SessionState)
  expect(tk.open(tk.ctx, bytesOf(sealed), sealed.len, back) and back.clientLeaf == st.clientLeaf, "opened with it")
echo "PASS tickets carry the client's certificate"

# Default and repeated release must never touch an uninitialized native lock.
release(store)
release(store)
assert ticketCount(store) == 0
ss.put(ss.ctx, addr a)
assert not ss.take(ss.ctx, "a.example", 5000, got)
release(small)
release(only)
release(ar)
release(ar)
assert not rp.firstUse(rp.ctx, bytesOf(id1), id1.len, 0, 1000)
release(tk)
release(tk)
var emptyStore = default(MemoryStore)
var emptyReplay = default(MemoryReplay)
release(emptyStore)
release(emptyReplay)
for cycle in 0 ..< 100:
  initMemoryStore(emptyStore, total = 4)
  initMemoryReplay(emptyReplay, slots = 16)
  let callbacks = memoryStore(addr emptyStore)
  a.psk.n = 32
  a.psk.b[0] = byte(cycle)
  callbacks.put(callbacks.ctx, addr a)
  callbacks.put(callbacks.ctx, addr b)
  assert callbacks.take(callbacks.ctx, "a.example", 5000, got)
  assert callbacks.take(callbacks.ctx, "a.example", 5000, got)
  assert got.psk.n == 32 and got.psk.b[0] == byte(cycle)
  release(emptyStore)
  release(emptyReplay)
echo "PASS session owners release, reject after release and repeat 100 cycles"

# Growth transfers ticket owners and wipes abandoned PSK slots without changing
# live keys. Continue through eviction to exercise shifting and growth together.
block:
  var growing = default(MemoryStore)
  initMemoryStore(growing, perName = 1, total = 37)
  let callbacks = memoryStore(addr growing)
  for i in 0 ..< 100:
    var ticket = default(SessionTicket)
    ticket.serverName = "host-" & $i
    ticket.ticket = @[byte(i)]
    ticket.issuedMs = 1000 + int64(i)
    ticket.lifetime = 60
    ticket.psk.n = 32
    for j in 0 ..< 32: ticket.psk.b[j] = byte(i xor j)
    callbacks.put(callbacks.ctx, addr ticket)
    wipe(ticket.psk)
  assert ticketCount(growing) == 37
  for i in 0 ..< 100:
    var ticket = default(SessionTicket)
    let found = callbacks.take(callbacks.ctx, "host-" & $i, 5000, ticket)
    assert found == (i >= 63)
    if found:
      assert ticket.ticket == @[byte(i)] and ticket.psk.n == 32
      for j in 0 ..< 32: assert ticket.psk.b[j] == byte(i xor j)
    wipe(ticket.psk)
  assert ticketCount(growing) == 0
  release(growing)
echo "PASS secret-preserving ticket growth, bounded eviction and cleanup"
