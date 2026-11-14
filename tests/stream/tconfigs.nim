## The configuration constructors of `zal_tls`: what they refuse, and a
## client configuration built from a trust store that outlives the store.
import std/[assertions, syncio]
import zal_net
import zal_tls
from zal_tls/crypto/x509 import Cert, newRoots, addRoot, certsPem, release

type Shared = ref object
  config: ServerConfig
  done: Event
  line: string

proc text(path: string): string =
  try: result = readFile(path)
  except: quit "missing TLS fixture: " & path

proc refusesServer(chain, key: string; alpn: seq[string] = @[]): bool =
  result = false
  try: discard newServerConfig(chain, key, alpn)
  except ErrorCode as error: result = error == ValueError

proc refusesClient(trust: TrustSource; alpn: seq[string] = @[]): bool =
  result = false
  try: discard newClientConfig(trust, alpn)
  except ErrorCode as error: result = error == ValueError

proc echoLine(listener: ptr Listener; shared: Shared) {.passive.} =
  try:
    var c = accept(listener[], afterMs(5000))
    c.renew afterMs(5000)
    c.secure(shared.config)
    shared.line = c.readLine()
    c.write shared.line & "\n"
  except ErrorCode as error:
    echo "server: ", error
  setEvent(addr shared.done)

proc fromStore(): ClientConfig {.raises.} =
  ## A configuration from a store the caller lets go of right after.
  var certs: seq[Cert] = @[]
  assert certsPem(text("tests/data/root.pem"), certs) == 1
  let roots = newRoots()
  if roots == nil: quit "no trust store"
  assert addRoot(roots, certs[0])
  release(certs[0])
  result = newClientConfig(storeTrust(roots))
  release(roots)

proc talk(config: ClientConfig; port: uint16) {.passive, raises.} =
  var c = connect(config, "127.0.0.1", port, "test.example", afterMs(5000))
  c.write "stored\n"
  assert c.readLine(afterMs(5000)) == "stored"

proc refusesHost(config: ClientConfig): bool {.passive.} =
  result = false
  try: discard connect(config, "bad\0host", 1, dl = afterMs(5000))
  except ErrorCode as error: result = error == ValueError

proc main() {.passive.} =
  try:
    let chain = text("tests/data/leaf.pem") & text("tests/data/inter.pem")
    let key = text("tests/data/leaf.key")
    let root = text("tests/data/root.pem")
    assert refusesServer("", "")
    assert refusesServer(text("tests/data/leaf.pem"), text("tests/data/rsa.key")), "a key from another certificate"
    assert refusesServer(chain, key, @[""]), "an empty protocol name"
    assert refusesClient(pemTrust(""))
    assert refusesClient(pemTrust("not a certificate"))
    assert refusesClient(pemTrust(root), @[""])

    let shared = Shared(config: newServerConfig(chain, key))
    var listener = listen(0, "127.0.0.1")
    let stored = fromStore()
    assert trySpawnTask(echoLine(addr listener, shared))
    talk(stored, listener.port)
    assert wait(addr shared.done, afterMs(5000)) == wrReady
    assert shared.line == "stored"
    close listener

    assert refusesHost(stored)
    echo "PASS TLS configurations: bad keys, chains, trust and protocol names refused, a store kept by its configuration"
  except ErrorCode as error:
    echo "unexpected error ", error
    assert false

assert runMain(main())
