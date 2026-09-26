## Public record owners: fragmented flights, metadata, transfer-free I/O and cleanup.
import std/[assertions, syncio]
import zal_tls/raw
import zal_tls/record as records
import zal_tls/common

proc textFile(path: string): string =
  try: result = readFile(path)
  except: result = ""
proc consume(s: var seq[byte]; n: int) =
  assert n >= 0 and n <= s.len
  var i = n
  while i < s.len:
    s[i - n] = s[i]
    i = i + 1
  s.setLen(s.len - n)
proc feed(wire, input: var seq[byte]) =
  if wire.len > 0:
    input.add wire[0]
    consume(wire, 1)
proc drive(c: records.TlsConnPtr; input, wire: var seq[byte]) =
  var output = default(array[7, byte])
  var status = default(StepResult)
  let event = records.step(c, bytesOf(input), input.len, ptrOf(output), output.len, status)
  assert event != stFailed, $status.alert
  consume(input, status.consumed)
  for i in 0 ..< status.outLen: wire.add output[i]

var key = default(CertifiedKey)
assert loadCertifiedKey(textFile("tests/data/leaf.pem") & textFile("tests/data/inter.pem"),
                        textFile("tests/data/leaf.key"), key) == ""
var certs: seq[Cert] = @[]
assert certsPem(textFile("tests/data/root.pem"), certs) == 1
let roots = newRoots()
assert roots != nil
assert addRoot(roots, certs[0])
var ccfg = defaultClientConfig(roots)
var scfg = defaultServerConfig()
ccfg.alpn = @["test"]
scfg.alpn = @["test"]
scfg.resolver = singleCert(addr key)
var client = default(records.TlsConn)
var server = default(records.TlsConn)
records.release(addr client)
assert records.initClient(addr client, addr ccfg, "test.example")
assert not records.initClient(addr client, addr ccfg, "test.example")
assert records.initServer(addr server, addr scfg)
var toClient, toServer, clientInput, serverInput: seq[byte] = @[]
var count = 0
while not records.isReady(addr client) or not records.isReady(addr server):
  assert count < 20_000
  feed(toClient, clientInput)
  drive(addr client, clientInput, toServer)
  feed(toServer, serverInput)
  drive(addr server, serverInput, toClient)
  count = count + 1
assert records.alpn(addr client) == "test"
assert records.peerLeafDer(addr client).len > 0
assert not records.resumed(addr client)
var recordBuffer = default(array[64, byte])
assert records.sealApp(addr client, ptrOf(recordBuffer), -1, 1) == 0
assert records.sealApp(addr client, ptrOf(recordBuffer), 0, -1) == 0
assert records.close(addr client, ptrOf(recordBuffer), 0) == 0
assert records.close(addr client, ptrOf(recordBuffer), 7) == 0
let closeSize = records.close(addr client, ptrOf(recordBuffer), recordBuffer.len)
assert closeSize > 0
assert records.close(addr client, ptrOf(recordBuffer), recordBuffer.len) == 0
var closeEvent = default(StepResult)
assert records.step(addr server, ptrOf(recordBuffer), closeSize, ptrOf(recordBuffer), 0, closeEvent) == stPeerClosed
records.release(addr client)
records.release(addr server)
records.release(addr client)
assert not records.isReady(addr client)
release(key)
release(roots)
for cert in certs: release(cert)
echo "PASS opaque public record owners and fragmented handshake"
