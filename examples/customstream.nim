## TLS over a caller-owned stream adapter. Counts transport bytes without copying.
##   customstream <host> <port> [root.pem] [server-name]
## The TCP owner and operation table remain stable until TLS has closed.
import std/[cmdline, syncio]
import zal_net/raw
import zal_net/net/transport
import zal_net/unsafe/streamview
import zal_net/rt/cancel as cancellation
import zal_tls/raw
import zal_tls/common
import zal_tls/trust/roots

type
  MeteredStream = object
    tcp: TcpStream
    received, sent: int
  MeteredStreamPtr = ptr MeteredStream

proc readMetered(ctx: pointer; buf: pointer; count: int; until: Deadline;
                 tok: nil cancellation.CancelToken): int {.passive.} =
  let owner = cast[MeteredStreamPtr](ctx)
  result = recvInto(addr owner.tcp, buf, count, until, tok)
  if result > 0: owner.received = owner.received + result

proc writeMetered(ctx: pointer; buf: pointer; count: int; until: Deadline;
                  tok: nil cancellation.CancelToken): int {.passive.} =
  let owner = cast[MeteredStreamPtr](ctx)
  result = sendFrom(addr owner.tcp, buf, count, until, tok)
  if result > 0: owner.sent = owner.sent + result

proc endWrite(ctx: pointer) =
  let owner = cast[MeteredStreamPtr](ctx)
  shutdownWrite(addr owner.tcp)
proc cancel(ctx: pointer) =
  let owner = cast[MeteredStreamPtr](ctx)
  interrupt(addr owner.tcp)
proc finish(ctx: pointer): int {.passive.} =
  let owner = cast[MeteredStreamPtr](ctx)
  close(addr owner.tcp)
  result = 0

var operations = StreamOps(recv: readMetered, send: writeMetered,
  shutdownWrite: endWrite, interrupt: cancel)
var cfg = default(ClientConfig)
var host = ""
var name = ""
var remotePort = 0
var succeeded = false

proc fetch() {.passive.} =
  var owner = MeteredStream(tcp: connect(host, uint16(remotePort)))
  var tls = default(TlsStream)
  if owner.tcp.isOpen:
    let transport = unsafeBorrowStream(addr owner, addr operations)
    let status = unsafeWrapClient(addr tls, transport, addr cfg, name)
    if status == 0:
      var request = "GET / HTTP/1.1\r\nHost: " & name & "\r\nConnection: close\r\n\r\n"
      if sendFrom(addr tls, textBytes(request), request.len) == request.len:
        var response = default(array[4096, byte])
        while true:
          let count = recvInto(addr tls, addr response[0], response.len)
          if count <= 0:
            succeeded = count == 0
            break
          for i in 0 ..< count: stdout.write char(response[i])
    else:
      echo "TLS handshake failed: ", status
  close(addr tls)
  # wrapClient borrowed the transport; its owner still needs explicit close.
  close(addr owner.tcp)
  echo "\nTransport bytes: sent=", owner.sent, " received=", owner.received
  stopBlockingPool()
  while not joinBlockingPool(): parkUntil(afterMs(1))
  requestStop()

if paramCount() < 2: quit "usage: customstream <host> <port> [root.pem] [server-name]"
host = paramStr(1)
name = if paramCount() >= 4: paramStr(4) else: host
for digit in paramStr(2):
  if digit < '0' or digit > '9' or remotePort > 6553: quit "invalid port"
  remotePort = remotePort * 10 + ord(digit) - ord('0')
if remotePort < 1 or remotePort > 65535: quit "invalid port"
var trust: nil Roots = nil
if paramCount() >= 3:
  var pem = ""
  try: pem = readFile(paramStr(3))
  except: quit "cannot read trust file"
  var certificates: seq[Cert] = @[]
  if certsPem(pem, certificates) == 0: quit "empty trust file"
  let store = newRoots()
  if store == nil: quit "cannot allocate trust store"
  for certificate in certificates:
    if not addRoot(store, certificate): quit "cannot add trust anchor"
    release(certificate)
  trust = store
else:
  trust = systemRoots()
if trust == nil: quit "no trust anchors"
cfg = defaultClientConfig(trust)
cfg.alpn = @["http/1.1"]
initRuntime()
spawnTask fetch()
drainRuntime()
release(trust)
if not succeeded: quit 1
