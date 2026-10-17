## zal-tls as a `std/streamio` TlsEngine: the stream core moves the bytes,
## AWS-LC seals and opens the records.
##
## ```nim
## let config = newClientConfig(systemTrust(), alpn = @["http/1.1"])
## let (r, w) = connect("example.com:443", request, tls = newTlsEngine(config))
## ```

import std/streamio
import zal_tls/common
import zal_tls/record as records
import zal_tls/config/owned
import zal_tls/crypto/rand

export streamio.TlsEngine, ClientConfigRef

const
  InCap = 2 * (RecordHeaderLen + MaxCiphertext)
  OutCap = RecordHeaderLen + MaxCiphertext + 64

type
  Conn = object
    c: records.TlsConn
    inb: seq[byte]            ## network bytes `step` has not consumed
    head, tail: int

  ZalTlsEngine* = ref object of TlsEngine
    config: ClientConfigRef
    serverName: string
    conn: Conn
    outb: seq[byte]           ## one step's output
    sealed: string            ## records waiting for `recordsOut`
    app: string               ## plaintext waiting for `appOut`
    pendingLimit: int
    started, ready, peerClosed, closeSent, failed: bool
    alert*: int               ## after a failure: the alert sent ...
    reason*: string           ## ... and why

proc `=destroy`(o: var Conn) =
  records.release(addr o.c)
  if o.inb.len > 0: wipeBytes(addr o.inb[0], o.inb.len)

proc addBytes(dest: var string; src: pointer; n: int) =
  if n > 0:
    let old = dest.len
    copyMem(beginStore(dest, old + n, old), src, n)
    endStore(dest)

proc newTlsEngine*(config: ClientConfigRef; serverName = ""; pendingLimit = 0): ZalTlsEngine {.raises.} =
  ## An engine for one connection, trusting what `config` trusts. A
  ## `serverName` replaces the address host for SNI and verification.
  ## A positive pendingLimit bounds each output queue. The caller must drain
  ## both queues and retry unconsumed input. std/streamio requires the default.
  if pendingLimit < 0 or (pendingLimit > 0 and pendingLimit < OutCap):
    raise BadOperation
  ZalTlsEngine(config: config, serverName: serverName,
               conn: Conn(c: default(records.TlsConn), inb: newSeq[byte](InCap), head: 0, tail: 0),
               outb: newSeq[byte](OutCap), sealed: "", app: "", pendingLimit: pendingLimit,
               started: false, ready: false, peerClosed: false, closeSent: false,
               failed: false, alert: 0, reason: "")

proc put(e: ZalTlsEngine; n: int) {.inline.} =
  if n > 0: e.sealed.addBytes(addr e.outb[0], n)

proc control(e: ZalTlsEngine) =
  # What the connection owes before any application data: a key update the
  # peer asked for, or one of our own.
  var m = records.takeControl(addr e.conn.c, bytesOf(e.outb), e.outb.len)
  if m == 0 and records.keyUpdateDue(addr e.conn.c):
    m = records.keyUpdate(addr e.conn.c, false, bytesOf(e.outb), e.outb.len)
  put(e, m)

proc drive(e: ZalTlsEngine) {.raises.} =
  # Leave incomplete records in place; compact only when the input is full.
  while true:
    if e.pendingLimit > 0 and
        (e.app.len > e.pendingLimit - MaxPlaintext or
         e.sealed.len > e.pendingLimit - OutCap): return
    var r = default(StepResult)
    let st = records.step(addr e.conn.c, at(bytesOf(e.conn.inb), e.conn.head), e.conn.tail - e.conn.head,
                          bytesOf(e.outb), e.outb.len, r)
    put(e, r.outLen)
    case st
    of stAppData, stEarlyData:
      if r.len > 0: e.app.addBytes(addr e.conn.inb[e.conn.head + r.off], r.len)
    of stReady: e.ready = true
    of stPeerClosed, stClosed: e.peerClosed = true
    of stFailed:
      e.failed = true
      e.alert = r.alert
      e.reason = r.reason
    of stNeedInput, stSend: discard
    if r.consumed > 0:
      e.conn.head += r.consumed
      if e.conn.head == e.conn.tail:
        e.conn.head = 0
        e.conn.tail = 0
    if st == stFailed: raise ProtocolError
    if st in {stNeedInput, stPeerClosed, stClosed}: return
    if r.consumed == 0 and r.outLen == 0 and st != stReady: return

method start*(e: ZalTlsEngine; host: string) {.raises.} =
  if e.started: raise BadOperation
  let name = if e.serverName.len > 0: e.serverName else: host
  if not records.initClient(addr e.conn.c, unsafeBorrowConfig(e.config), name):
    raise BadOperation
  e.started = true
  drive(e)

method recordsIn*(e: ZalTlsEngine; src: openArray[char]; used: var int) {.raises.} =
  used = 0
  if not e.started or e.failed: raise BadOperation
  if e.peerClosed: return
  drive(e)
  while used < src.len and not e.peerClosed:
    if e.conn.tail == e.conn.inb.len and e.conn.head > 0:
      let rest = e.conn.tail - e.conn.head
      moveMem(addr e.conn.inb[0], addr e.conn.inb[e.conn.head], rest)
      e.conn.head = 0
      e.conn.tail = rest
    let n = min(src.len - used, e.conn.inb.len - e.conn.tail)
    if n == 0: break
    copyMem(addr e.conn.inb[e.conn.tail], addr src[used], n)
    e.conn.tail += n
    used += n
    drive(e)

method recordsOut*(e: ZalTlsEngine; dest: var string) {.raises.} =
  if e.started and not e.failed: drive(e)
  if e.ready and not e.failed and not e.closeSent and
      (e.pendingLimit == 0 or e.sealed.len <= e.pendingLimit - OutCap): control(e)
  if e.sealed.len > 0:
    if dest.len == 0: dest = move e.sealed
    else: dest.add e.sealed
    e.sealed = ""

method appIn*(e: ZalTlsEngine; src: openArray[char]; used: var int) {.raises.} =
  used = 0
  if not e.ready or e.closeSent or e.failed: raise BadOperation
  while used < src.len:
    if e.pendingLimit > 0 and e.sealed.len > e.pendingLimit - OutCap: return
    control(e)
    let room = if e.pendingLimit == 0: MaxPlaintext else: e.pendingLimit - e.sealed.len - RecordHeaderLen - 17
    let n = min(min(MaxPlaintext, room), src.len - used)
    if n <= 0: return
    copyMem(addr e.outb[RecordHeaderLen], addr src[used], n)
    let m = records.sealApp(addr e.conn.c, bytesOf(e.outb), 0, n)
    if m == 0:
      e.failed = true
      raise ProtocolError
    put(e, m)
    used += n

method appOut*(e: ZalTlsEngine; dest: var string) {.raises.} =
  if e.started and not e.failed: drive(e)
  if e.app.len > 0:
    if dest.len == 0: dest = move e.app
    else: dest.add e.app
    e.app = ""

method close*(e: ZalTlsEngine) {.raises.} =
  if e.ready and not e.closeSent and not e.failed:
    if e.pendingLimit > 0 and e.sealed.len > e.pendingLimit - OutCap:
      raise BadOperation
    control(e)
    put(e, records.close(addr e.conn.c, bytesOf(e.outb), e.outb.len))
    e.closeSent = true

method isConnected*(e: ZalTlsEngine): bool = e.ready and not e.failed

method isPeerClosed*(e: ZalTlsEngine): bool = e.peerClosed

proc alpn*(e: ZalTlsEngine): string = records.alpn(addr e.conn.c)
  ## The protocol the server picked; "" for none.
