## tlsecho <port> <chain.pem> <key.pem>
## A TLS echo server: `serve` hands each connection to `echoClient`, which
## secures it and sends back what it reads.
import std/[syncio, cmdline]
import zal_net
import zal_tls

type Context = ref object
  config: ServerConfig

proc report(ctx: Context; error: ErrorCode) = echo "connection: ", error

proc echoClient(c: var Conn; ctx: Context) {.passive, raises.} =
  c.secure(ctx.config, afterMs(10_000))
  var bytes = default(array[16_384, byte])
  while true:
    let count = c.read(bytes)
    if count == 0:
      break
    c.write bytes.toOpenArray(0, count - 1)
  c.shutdownWrite()

proc main(ctx: sink Context; port: uint16) {.passive.} =
  try:
    var listener = listen(port, "127.0.0.1")
    echo "TLS echo on 127.0.0.1:", listener.port
    flushFile(stdout)
    serve(listener, echoClient, ctx, report)
    close listener
  except ErrorCode as error:
    echo "server: ", error

if paramCount() != 3:
  quit "usage: tlsecho <port> <chain.pem> <key.pem>"
var portNumber = 0
for digit in paramStr(1):
  if digit < '0' or digit > '9': quit "invalid port"
  portNumber = portNumber * 10 + ord(digit) - ord('0')
  if portNumber > 65535: quit "invalid port"
try:
  let serverConfig = newServerConfig(readFile(paramStr(2)), readFile(paramStr(3)))
  let ctx = Context(config: serverConfig)
  if not runMain(main(ctx, uint16(portNumber))): quit "runtime entry rejected"
except ErrorCode as error:
  quit "configuration: " & $error
