## application_tlsecho <port> <chain.pem> <key.pem>
import std/[syncio, cmdline]
import zal_net
import zal_tls as tls

type Context = ref object
  config: tls.ServerConfig

proc report(ctx: Context; error: ErrorCode) = echo "connection: ", error

proc echoClient(connection: TcpStream; ctx: Context) {.passive, raises.} =
  var transport: nil TcpStream = connection
  let stream = tls.wrapOwned(ctx.config, transport)
  defer: stream.close()
  var bytes = default(array[16_384, byte])
  while true:
    let count = stream.read(bytes)
    if count == 0:
      break
    stream.write(bytes.toOpenArray(0, count - 1))

proc main(ctx: sink Context; port: uint16) {.passive.} =
  try:
    let listener = listen(port, "127.0.0.1")
    defer: listener.close()
    echo "TLS echo on 127.0.0.1:", listener.port
    flushFile(stdout)
    serve(listener, echoClient, ctx, report)
  except ErrorCode as error:
    echo "server: ", error

if paramCount() != 3:
  quit "usage: application_tlsecho <port> <chain.pem> <key.pem>"
var portNumber = 0
for digit in paramStr(1):
  if digit < '0' or digit > '9': quit "invalid port"
  portNumber = portNumber * 10 + ord(digit) - ord('0')
  if portNumber > 65535: quit "invalid port"
try:
  let config = tls.newServerConfig(readFile(paramStr(2)), readFile(paramStr(3)))
  let ctx = Context(config: config)
  if not runMain(main(ctx, uint16(portNumber))): quit "runtime entry rejected"
except ErrorCode as error:
  quit "configuration: " & $error
