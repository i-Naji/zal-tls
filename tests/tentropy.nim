## Entropy providers may fail after partially filling output: never proceed.
import std/[syncio, assertions]
import zal_tls/common
import zal_tls/crypto/[sig, x509, rand]
import zal_tls/keys/schedule
import zal_tls/config/config
import zal_tls/private/core/[conn, client, server]

import zal_tls/wire/consts
import loophelp

proc failRandom(p: Bytes; n: int): bool {.nimcall.} =
  for i in 0 ..< n: p[i] = 0x42
  result = false

var bytes = default(array[32, byte])
assert not randomFill(failRandom, ptrOf(bytes), bytes.len)
for b in bytes: assert b == 0
proc slurp(path: string): string =
  try: result = readFile(path)
  except: quit "fixture unreadable"

var rootCerts: seq[Cert] = @[]
assert certsPem(slurp("tests/data/root.pem"), rootCerts) == 1
let roots = newRoots()
assert roots != nil
assert addRoot(roots, rootCerts[0])
var ck = default(CertifiedKey)
assert loadCertifiedKey(slurp("tests/data/leaf.pem") & slurp("tests/data/inter.pem"),
                        slurp("tests/data/leaf.key"), ck) == ""
var cc = defaultClientConfig(roots)
var sc = defaultServerConfig()
sc.resolver = singleCert(addr ck)
var a, b: Side
var ab, ba: seq[byte]
initSide(a)
cc.rand = failRandom
assert initClient(a.c, addr cc, "test.example")
discard turn(a, ab)
assert a.failed == alInternalError and not a.ready
release(a.c)
cc.rand = nil
sc.rand = failRandom
initSide(a)
initSide(b)
ab = @[]
ba = @[]
assert initClient(a.c, addr cc, "test.example")
assert initServer(b.c, addr sc)
run(a, b, ab, ba, 7)
assert b.failed == alInternalError and not a.ready and not b.ready
release(a.c)
release(b.c)
release(ck)
release(roots)
for cert in rootCerts: release(cert)
echo "PASS entropy failure: partial bytes wiped, client and server fail closed"

# ECH must not publish a public key for predictable or partial entropy.
let ech = newEchKey(1, "public.example", entropy = failRandom)
assert ech.config.len == 0
for b in ech.priv: assert b == 0
var disabled = default(KeyedTicketer)
assert not initKeyedTicketer(disabled, entropy = failRandom)
var state = default(SessionState)
state.psk.n = 32
state.lifetime = 60
var output: seq[byte] = @[]
let dead = keyedTicketer(addr disabled)
let sealDead = dead.seal
assert sealDead != nil
assert not sealDead(dead.ctx, addr state, output)
release(disabled)
release(disabled)

var denyEntropy = false
proc entropy(p: Bytes; n: int): bool {.nimcall.} =
  if denyEntropy: return failRandom(p, n)
  result = randomBytes(p, n)
var live = default(KeyedTicketer)
assert initKeyedTicketer(live, entropy = entropy)
let provider = keyedTicketer(addr live)
let sealLive = provider.seal
let openLive = provider.open
assert sealLive != nil and openLive != nil
assert sealLive(provider.ctx, addr state, output)
var saved = output
output = @[]
denyEntropy = true
assert not sealLive(provider.ctx, addr state, output) # nonce generation
assert output.len == 0
assert not rotate(live) # failed rotation must preserve previous valid keys
denyEntropy = false
var opened = default(SessionState)
assert openLive(provider.ctx, bytesOf(saved), saved.len, opened)
wipe(opened.psk)
wipe(state.psk)
release(live)
release(live)
echo "PASS entropy failure: ECH key, ticket key, ticket nonce, key rotation and repeated release"
