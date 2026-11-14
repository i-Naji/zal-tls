## TLS over a layer of your own. The layer counts the bytes that cross the
## socket, `secure` goes on top of it, and the program reads and writes
## plaintext on the same `Conn`.
##   customstream <host> <port> [root.pem] [server-name]
##
## A layer is a context pointer, a `StreamOps` table and a release proc,
## put on a connection with `install` before its first read. It owns the
## socket from then on and closes it in the release proc, which runs once,
## when the connection closes or goes out of scope.
import std/[cmdline, syncio]
import zal_net
import zal_net/raw/tcp as rawtcp
import zal_tls

type
  Metered = object
    tcp: rawtcp.TcpStream
    received, sent: int
  MeteredPtr = ptr Metered

proc readMetered(ctx: pointer; buf: pointer; count: int; until: Deadline;
                 tok: nil CancelToken): int {.nimcall, passive.} =
  let m = cast[MeteredPtr](ctx)
  result = recvInto(addr m.tcp, buf, count, until, tok)
  if result > 0: m.received += result

proc writeMetered(ctx: pointer; buf: pointer; count: int; until: Deadline;
                  tok: nil CancelToken): int {.nimcall, passive.} =
  let m = cast[MeteredPtr](ctx)
  result = sendFrom(addr m.tcp, buf, count, until, tok)
  if result > 0: m.sent += result

proc endWrite(ctx: pointer) {.nimcall.} =
  let m = cast[MeteredPtr](ctx)
  shutdownWrite(addr m.tcp)

proc wake(ctx: pointer) {.nimcall.} =
  let m = cast[MeteredPtr](ctx)
  interrupt(addr m.tcp)

proc releaseMetered(ctx: pointer) {.nimcall.} =
  let m = cast[MeteredPtr](ctx)
  close(addr m.tcp)
  echo "\nsocket bytes: sent=", m.sent, " received=", m.received
  dealloc(m)

let operations = StreamOps(recv: readMetered, send: writeMetered,
                           shutdownWrite: endWrite, interrupt: wake)

proc meter(c: var Conn) =
  ## Hand the socket to a new metering layer.
  let m = cast[MeteredPtr](alloc0(sizeof(Metered)))
  var fd = releaseDescriptor(c)
  if not adoptTcp(addr m.tcp, fd, 0): quit "cannot adopt the socket"
  install(c, m, unsafeAddr operations, releaseMetered)

proc fetch(config: ClientConfig; host: string; port: uint16; name: string) {.passive, raises.} =
  var c = connect(host, port, afterMs(10_000))
  c.renew afterMs(30_000)
  meter(c)
  c.secure(config, name)
  c.write "GET / HTTP/1.1\r\nHost: " & name & "\r\nConnection: close\r\n\r\n"
  var response = default(array[4096, byte])
  while true:
    let count = c.read(response)
    if count == 0: break
    for i in 0 ..< count: stdout.write char(response[i])

proc main(host, name: string; port: uint16; trustFile: string; succeeded: ptr bool) {.passive.} =
  try:
    var trust = systemTrust()
    if trustFile.len > 0:
      try: trust = pemTrust(readFile(trustFile))
      except: quit "cannot read trust file"
    let config = newClientConfig(trust, @["http/1.1"])
    fetch(config, host, port, name)
    succeeded[] = true
  except ErrorCode as error:
    echo "\nfailed: ", error

if paramCount() < 2: quit "usage: customstream <host> <port> [root.pem] [server-name]"
var remotePort = 0
for digit in paramStr(2):
  if digit < '0' or digit > '9' or remotePort > 6553: quit "invalid port"
  remotePort = remotePort * 10 + ord(digit) - ord('0')
if remotePort < 1 or remotePort > 65535: quit "invalid port"
let trustFile = if paramCount() >= 3: paramStr(3) else: ""
let name = if paramCount() >= 4: paramStr(4) else: paramStr(1)
var succeeded = false
if not runMain(main(paramStr(1), name, uint16(remotePort), trustFile, addr succeeded)):
  quit "runtime entry rejected"
if not succeeded: quit 1
