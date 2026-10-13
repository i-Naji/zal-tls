## TLS over a zal-net TCP connection, as a `DuplexStream`: `connectTls`
## or `acceptTls`, then `recvInto`, `sendFrom`, `shutdownWrite`, `close`,
## so zal-net's `copy`, `relay` and `BufReader` work over TLS as they
## are. The procs take `ptr TlsStream` (`TlsStreamPtr`): a stream holds its
## buffers and TLS state. Keep it alive until I/O finishes; one reader and
## one writer may share it.
##
## ```nim
## var s = default(TlsStream)
## if connectTls("example.com", 443, addr cfg, addr s) == 0:
##   discard sendFrom(addr s, addr req[0], req.len)
##   let n = recvInto(addr s, addr buf[0], buf.len)
##   close(addr s)
## ```
##
## Only the writer seals records (application data, the key update the
## peer asked for, our own, close_notify), so they reach the socket in the
## order their sequence numbers say; the reader only opens.

import std/[atomics, ticketlocks]
import zal_tls/private/kernelkeys
import zal_tls/private/streamlease
import zal_tls/common
import zal_tls/errors
export TlsFailed, TlsEof, TlsTruncated, TlsEarlyNotSent, TlsEchRejected, TlsClosed, tlsAlert
import zal_tls/private/core/[conn, client, server]

import zal_tls/keys/schedule
import zal_tls/private/writergate
import zal_tls/raw/ktls
import zal_tls/config/config
import zal_tls/record/protect
import zal_tls/crypto/rand
import zal_tls/wire/consts
import zal_net/rt, zal_net/raw/io, zal_net/rt/[sync, time, cancel, waits]
import zal_net/raw/tcp
import zal_net/raw/fdops
import zal_net/net/transport
import zal_net/unsafe/streamview
import zal_net/buffers

const
  InCap = 2 * (RecordHeaderLen + MaxCiphertext) + 1024
  OutCap = RecordHeaderLen + MaxPlaintext + 1 + 16 + 64
  CtlCap = 128
  CloseWaitMs = 5_000    ## how long a close waits to send close_notify
  DefaultHandshakeMs* = 30_000
  KtlsCheckBytes = 64 shl 20       ## kTLS: how often the kernel's send sequence is read
  KtlsSmallRead = 64               ## kTLS: reads smaller than this go through inb

type
  TlsStream* = object
    stateLock: TicketLock
    initialized: bool
    transport: StreamView
    transportOwner: nil Transport
    customTransport: bool
    ownsTransport: bool
    tcp: TcpStream
    conn: TlsConn
    inb: array[InCap, byte]
    inLen: int
    pendOff, pendLen: int        ## decrypted data not yet delivered (it lies in inb) ...
    pendUsed: int                ## ... and the input bytes to drop once it is
    outb: array[OutCap, byte]    ## the writer's
    rdOut: array[CtlCap, byte]   ## the reader's step output (an alert)
    ctl: array[CtlCap, byte]     ## sealed records waiting for the socket (close_notify)
    ctlLen: int
    writer: WriterGate
    shutdownAfter: bool          ## end the TCP sending side once `ctl` is out
    flushDone: Event             ## completion published after the task stops accessing s
    failed: int                  ## the first error (0: none)
    peerClosed: bool
    ktx, krx: bool             ## the kernel seals / opens the records (useKtls)
    rxWanted: bool               ## hand reading to the kernel at the next record boundary
    kClosePending: bool          ## kTLS: close_notify still to send
    kSent: int                   ## kTLS: bytes since the send sequence was last read
    early: RawBuf                ## server: 0-RTT data taken during the handshake (replayable) ...
    earlyAt: int                 ## ... delivered first, from here
    background: BackgroundLease  ## borrowed context retained by queued flushes

  TlsStreamPtr* = ptr TlsStream

proc lockState(s: TlsStreamPtr) = s.stateLock.acquire()
proc unlockState(s: TlsStreamPtr) = s.stateLock.release()

template lockedState(s: TlsStreamPtr; operation: untyped): untyped =
  ## Only bounded, synchronous protocol transitions belong inside this block.
  block:
    lockState(s)
    let lockedResult = operation
    unlockState(s)
    lockedResult

proc markClosedState(s: TlsStreamPtr) =
  lockState(s)
  markWriteClosed(s.conn)
  unlockState(s)

proc writerActive(s: TlsStreamPtr): bool = writerHeld(addr s.writer)
proc failureCode(s: TlsStreamPtr): int = atomicLoad(s.failed, moAcquire)

proc earlyBytes*(s: TlsStreamPtr): int =
  ## Server: how many bytes came as 0-RTT (replayable): the first ones
  ## `recvInto` gives; no read returns them with later bytes.
  s.early.len

proc transportOpen(s: TlsStreamPtr): bool =
  s.initialized and (if s.customTransport: isOpen(s.transport) else: s.tcp.isOpen)

proc flushPending(s: TlsStreamPtr): bool {.inline.} =
  s.initialized and not isSet(addr s.flushDone)

proc initState(s: TlsStreamPtr) =
  s[] = default(TlsStream)
  setEvent(addr s.flushDone)
  s.initialized = true

proc finishFlush(s: TlsStreamPtr) =
  # Copy the borrowed hook before publishing completion. A waiter may dispose
  # or reuse the raw stream as soon as setEvent releases its lock. The event
  # resumes claimed waiters using their own nodes, without further s access.
  let lease = s.background
  setEvent(addr s.flushDone)
  release(lease)

proc setBackgroundLease*(s: TlsStreamPtr; lease: BackgroundLease): bool =
  ## Internal owner integration; never replace a lease while a flush uses it.
  if flushPending(s): return false
  s.background = lease
  result = true

proc releaseState(s: TlsStreamPtr) =
  free(s.early)
  release(s.conn)
  wipeBytes(addr s.inb[0], InCap)
  wipeBytes(addr s.outb[0], OutCap)
  wipeBytes(addr s.rdOut[0], CtlCap)
  wipeBytes(addr s.ctl[0], CtlCap)

proc closeNow*(s: TlsStreamPtr): bool =
  ## Quiescent, nonblocking disposal without close_notify. Caller has finished
  ## every borrower. False preserves the owner if a writer/flush still uses it
  ## or a transferred custom transport lacks synchronous disposal.
  if not s.initialized: return true
  if writerActive(s) or flushPending(s): return false
  if s.customTransport and s.ownsTransport:
    let owner = s.transportOwner
    if owner != nil and dispose(owner) != 0: return false
  elif not s.customTransport:
    close(addr s.tcp)
  releaseState(s)
  s.transport = default(StreamView)
  s.transportOwner = nil
  s.initialized = false
  s.background = default(BackgroundLease)
  result = true

proc isOpen*(s: TlsStream): bool =
  s.initialized and s.failed == 0 and
    (if s.customTransport: isOpen(s.transport) else: s.tcp.isOpen)

# Keep native TCP I/O in the protocol caller's passive frame. Retained and
# custom transports keep their public callback path.
template readTransport(s: TlsStreamPtr; p: pointer; n: int; deadline: Deadline;
                       tok: nil CancelToken = nil): int =
  block:
    let owner = s.transportOwner
    if owner != nil: recvInto(owner, p, n, deadline, tok)
    elif s.customTransport: recvInto(s.transport, p, n, deadline, tok)
    else:
      var transferred = 0
      fdRecvInline(nativeHandle(s.tcp), s.tcp.timeoutMs, p, n, deadline, transferred, tok)
      transferred

template writeTransport(s: TlsStreamPtr; p: pointer; n: int; deadline: Deadline;
                        tok: nil CancelToken = nil): int =
  block:
    let owner = s.transportOwner
    if owner != nil: sendFrom(owner, p, n, deadline, tok)
    elif s.customTransport: sendFrom(s.transport, p, n, deadline, tok)
    else:
      var transferred = 0
      fdSendInline(nativeHandle(s.tcp), s.tcp.timeoutMs, p, n, deadline, transferred, tok)
      transferred

proc endTransport(s: TlsStreamPtr) =
  if s.customTransport: shutdownWrite(s.transport)
  else: shutdownWrite(addr s.tcp)

proc dropInput(s: TlsStreamPtr; n: int) =
  if n <= 0: return
  let rest = s.inLen - n
  if rest > 0: moveMem(addr s.inb[0], addr s.inb[n], rest)
  s.inLen = rest

proc writeRaw(s: TlsStreamPtr; p: Bytes; n: int; deadline: Deadline;
              tok: nil CancelToken = nil): int {.passive.} =
  ## All n bytes to the socket: 0, or the failing result.
  var off = 0
  while off < n:
    let k = writeTransport(s, at(p, off), n - off, deadline, tok)
    if k <= 0: return (if k < 0: k else: -1)
    off = off + k
  result = 0

proc giveWriter(s: TlsStreamPtr) =
  giveWriter(addr s.writer)

proc queueCtl(s: TlsStreamPtr; p: Bytes; n: int): bool =
  s.stateLock.acquire()
  defer: s.stateLock.release()
  if s.ctlLen + n > CtlCap: return false
  copyMem(addr s.ctl[s.ctlLen], p, n)
  s.ctlLen = s.ctlLen + n
  result = true

proc controlLength(s: TlsStreamPtr): int = lockedState(s, s.ctlLen)

proc flushCtl(s: TlsStreamPtr; deadline: Deadline; tok: nil CancelToken = nil): int {.passive.} =
  result = 0
  while true:
    var batch = default(array[CtlCap, byte])
    s.stateLock.acquire()
    let n = s.ctlLen
    if n > 0: copyMem(addr batch[0], addr s.ctl[0], n)
    s.ctlLen = 0
    let finish = n == 0 and s.shutdownAfter
    if finish: s.shutdownAfter = false
    s.stateLock.release()
    if n == 0:
      if finish: endTransport(s)
      break
    result = writeRaw(s, ptrOf(batch), n, deadline, tok)
    if result < 0: return

proc owedRecords(s: TlsStreamPtr; deadline: Deadline; tok: nil CancelToken = nil): int {.passive.} =
  ## The writer, before sealing data: queued records, the key update the
  ## peer asked for, ours when the key has sealed enough; nothing parks
  ## between the last of these and the caller's seal.
  result = 0
  while true:
    if controlLength(s) > 0:
      result = flushCtl(s, deadline, tok)
    else:
      var m = lockedState(s, takeControl(s.conn, ptrOf(s.outb), OutCap))
      if m == 0 and lockedState(s, keyUpdateDue(s.conn)): m = lockedState(s, keyUpdate(s.conn, false, ptrOf(s.outb), OutCap))
      if m == 0: return
      result = writeRaw(s, ptrOf(s.outb), m, deadline, tok)
    if result < 0: return

proc fail(s: TlsStreamPtr; code: int): int =
  var expected = 0
  discard atomicCompareExchange(s.failed, expected, code, moAcquireRelease, moAcquire)
  result = code

proc sendEarly(s: TlsStreamPtr; p: pointer; n: int; deadline: Deadline;
               tok: nil CancelToken = nil): int {.passive.} =
  ## Client: `p[0 ..< n]` as 0-RTT records right after the ClientHello, as
  ## far as the ticket allows: the bytes sent so (the rest goes after the
  ## handshake), or a failure.
  result = 0
  let src = cast[Bytes](p)
  while result < n:
    let k = min(MaxPlaintext, n - result)
    copyMem(addr s.outb[RecordHeaderLen], addr src[result], k)
    let m = sealEarly(s.conn, ptrOf(s.outb), 0, k)
    if m == 0: break                              # over the ticket's limit: after the handshake
    let w = writeRaw(s, ptrOf(s.outb), m, deadline, tok)
    if w < 0: return fail(s, w)
    result = result + k

proc handshake(s: TlsStreamPtr; deadline: Deadline; earlyP: nil pointer; earlyLen: int;
               earlySent: var int; tok: nil CancelToken = nil): int {.passive.} =
  ## The handshake; a client's 0-RTT data (`earlyP`, `earlyLen`) goes right
  ## after its ClientHello when the ticket allows, `earlySent` bytes of it.
  var r = default(StepResult)
  var triedEarly = false
  while true:
    if cancelled(tok): return fail(s, ECancelled)
    let st = lockedState(s, step(s.conn, ptrOf(s.inb), s.inLen, ptrOf(s.outb), OutCap, r))
    if st == stEarlyData:
      # Server: 0-RTT taken, kept for the application (before its input moves).
      append(s.early, at(ptrOf(s.inb), r.off), r.len)
    dropInput(s, r.consumed)
    case st
    of stSend:
      let w = writeRaw(s, ptrOf(s.outb), r.outLen, deadline, tok)
      if w < 0: return fail(s, w)
      let ep = earlyP
      if not triedEarly and ep != nil and earlyLen > 0 and s.conn.earlyWrite:
        triedEarly = true
        let k = sendEarly(s, ep, earlyLen, deadline, tok)
        if k < 0: return k
        earlySent = k
    of stNeedInput:
      if s.inLen == InCap: return fail(s, TlsFailed - alInternalError)
      let n = readTransport(s, addr s.inb[s.inLen], InCap - s.inLen, deadline, tok)
      if n == 0: return fail(s, TlsEof)
      if n < 0: return fail(s, n)
      s.inLen = s.inLen + n
    of stReady:
      return 0
    of stFailed:
      if r.outLen > 0: discard writeRaw(s, ptrOf(s.outb), r.outLen, deadline, tok)
      # (The client's own ech_required: `echRejected` is set only then.)
      if s.conn.role == roleClient and s.conn.echRejected and r.alert == alEchRequired:
        return fail(s, TlsEchRejected)
      return fail(s, TlsFailed - r.alert)
    of stPeerClosed, stClosed:
      return fail(s, TlsEof)
    of stEarlyData:
      discard                                     # kept above
    of stAppData:
      return fail(s, TlsFailed - alUnexpectedMessage)   # not before stReady

proc sealApplication(s: TlsStreamPtr; p: pointer; size: int): int =
  s.stateLock.acquire()
  defer: s.stateLock.release()
  if s.ctlLen > 0 or replyDue(s.conn) or keyUpdateDue(s.conn): return -1
  copyMem(addr s.outb[RecordHeaderLen], p, size)
  result = sealApp(s.conn, ptrOf(s.outb), 0, size)

proc sendFrom*(s: TlsStreamPtr; p: pointer; n: int; deadline = never;
               tok: nil CancelToken = nil): int {.passive.}

proc connectTls*(host: string; port: uint16; cfg: ClientConfigPtr; s: TlsStreamPtr;
                 serverName = ""; deadline = never; timeoutMs = 10_000;
                 handshakeMs = DefaultHandshakeMs; earlyData: nil pointer = nil; earlyLen = 0;
                 tok: nil CancelToken = nil): int {.passive.} =
  ## Connect to host:port and run the handshake (verifying `serverName`,
  ## or `host` when it is ""), within `handshakeMs` and `deadline`: 0,
  ## a negative TCP/resolver result (including IoTimedOut), or
  ## TlsFailed - alert / TlsEof. With the configuration's session store the
  ## connection resumes when it holds a ticket (`s.conn.resumed`).
  ## `earlyData`: the first bytes to send. As 0-RTT right after the
  ## ClientHello when a ticket allows (`cfg.earlyData`) — replayable by an
  ## attacker: idempotent requests only — or, where the server refuses them
  ## or no ticket fits, after the handshake; either way the server's
  ## application reads them once (`s.conn.earlyAccepted`: as 0-RTT). When
  ## the server refused them and chose another protocol than the ticket's,
  ## they are not sent again: `TlsEarlyNotSent`, the connection up.
  ## With ECH configs (`cfg.echConfigs`) the server may refuse ECH:
  ## `TlsEchRejected` once it proved to be the public name's, and the
  ## configs to retry with are `echRetryConfigs(s)` (empty: it takes
  ## no ECH now), there until `close`. Configs that cannot be used fail at
  ## once (TlsFailed - internal_error): no hello with the name in clear.
  if s.initialized: return ResourceBusy
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  let connectionCode = connectInto(addr s.tcp, host, port, timeoutMs, tok = tok, deadline = deadline)
  if connectionCode != 0: return fail(s, connectionCode)
  if not initClient(s.conn, cfg, if serverName.len > 0: serverName else: host):
    return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), earlyData, earlyLen, sent, tok)
  let ed = earlyData
  if result != 0 or ed == nil or earlyLen <= 0: return
  if s.conn.earlyRejected and s.conn.earlyAlpnChanged: return TlsEarlyNotSent   # (4.2.10)
  var off = if s.conn.earlyAccepted: sent else: 0  # refused 0-RTT is sent again
  let src = cast[Bytes](ed)
  while off < earlyLen:
    let k = sendFrom(s, addr src[off], earlyLen - off, deadline, tok)
    if k <= 0: return (if k < 0: k else: fail(s, TlsFailed - alInternalError))
    off = off + k

proc acceptTls*(s: TlsStreamPtr; tcp: TcpStreamPtr; cfg: ServerConfigPtr; deadline = never;
                handshakeMs = DefaultHandshakeMs; tok: nil CancelToken = nil): int {.passive.} =
  ## Take over an accepted connection (tcp is left closed: its descriptor
  ## now belongs to `s`) and run the server handshake within `handshakeMs`
  ## and `deadline`: 0 or a failure as for `connectTls`. With a ticketer the
  ## server resumes and issues tickets; 0-RTT it takes (`maxEarlyData`,
  ## `s.conn.earlyAccepted`) is what `recvInto` gives first — replayable.
  if s.initialized: return ResourceBusy
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.tcp = takeTcp(tcp)
  if not initServer(s.conn, cfg): return fail(s, TlsFailed - alInternalError)
  var none = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, none, tok)

proc takeClient*(s: TlsStreamPtr; tcp: TcpStreamPtr; cfg: ClientConfigPtr;
                 serverName: string; deadline = never;
                 handshakeMs = DefaultHandshakeMs; tok: nil CancelToken = nil): int {.passive.} =
  ## Transfer an already-connected quiescent TCP owner and use direct I/O.
  ## Pre-initialization rejection preserves tcp; started handshakes consume it.
  if s.initialized: return ResourceBusy
  if not tcp[].isOpen: return ResourceClosed
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.tcp = takeTcp(tcp)
  if not initClient(s.conn, cfg, serverName): return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, sent, tok)

proc unsafeWrapClient*(s: TlsStreamPtr; underlying: StreamView; cfg: ClientConfigPtr;
                 serverName: string; deadline = never;
                 handshakeMs = DefaultHandshakeMs; tok: nil CancelToken = nil): int {.passive.} =
  ## Borrow a transport. It must outlive s and every pending TLS operation.
  ## On failure, close(s) releases TLS state but does not close the transport.
  if s.initialized: return ResourceBusy
  if not isOpen(underlying): return ResourceClosed
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.customTransport = true
  s.transport = underlying
  if not initClient(s.conn, cfg, serverName): return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, sent, tok)

proc unsafeWrapServer*(s: TlsStreamPtr; underlying: StreamView; cfg: ServerConfigPtr;
                 deadline = never; handshakeMs = DefaultHandshakeMs;
                 tok: nil CancelToken = nil): int {.passive.} =
  ## Borrow an accepted transport; close(s) does not close its owner.
  if s.initialized: return ResourceBusy
  if not isOpen(underlying): return ResourceClosed
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.customTransport = true
  s.transport = underlying
  if not initServer(s.conn, cfg): return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, sent, tok)

proc wrapClient*(s: TlsStreamPtr; underlying: Transport; cfg: ClientConfigPtr;
                 serverName: string; deadline = never;
                 handshakeMs = DefaultHandshakeMs; tok: nil CancelToken = nil): int {.passive.} =
  if s.initialized: return ResourceBusy
  if not isOpen(underlying): return ResourceClosed
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.customTransport = true
  s.transportOwner = underlying
  s.transport = borrow(underlying)
  if not initClient(s.conn, cfg, serverName): return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, sent, tok)

proc wrapServer*(s: TlsStreamPtr; underlying: Transport; cfg: ServerConfigPtr;
                 deadline = never; handshakeMs = DefaultHandshakeMs;
                 tok: nil CancelToken = nil): int {.passive.} =
  if s.initialized: return ResourceBusy
  if not isOpen(underlying): return ResourceClosed
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  initState(s)
  s.customTransport = true
  s.transportOwner = underlying
  s.transport = borrow(underlying)
  if not initServer(s.conn, cfg): return fail(s, TlsFailed - alInternalError)
  var sent = 0
  result = handshake(s, earlier(deadline, afterMs(handshakeMs)), nil, 0, sent, tok)

proc takeClient*(s: TlsStreamPtr; underlying: Transport; cfg: ClientConfigPtr;
                 serverName: string; deadline = never;
                 handshakeMs = DefaultHandshakeMs; tok: nil CancelToken = nil): int {.passive.} =
  if s.initialized: return ResourceBusy
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  let moved = takeTransport(underlying)
  let taken = moved.value
  if taken == nil: return moved.code
  result = wrapClient(s, taken, cfg, serverName, deadline, handshakeMs, tok)
  if s.initialized: s.ownsTransport = true
  else: discard dispose(taken)

proc takeServer*(s: TlsStreamPtr; underlying: Transport; cfg: ServerConfigPtr;
                 deadline = never; handshakeMs = DefaultHandshakeMs;
                 tok: nil CancelToken = nil): int {.passive.} =
  if s.initialized: return ResourceBusy
  retain(tok)
  defer: release(tok)
  if cancelled(tok): return ECancelled
  let moved = takeTransport(underlying)
  let taken = moved.value
  if taken == nil: return moved.code
  result = wrapServer(s, taken, cfg, deadline, handshakeMs, tok)
  if s.initialized: s.ownsTransport = true
  else: discard dispose(taken)

proc kernelRecv(s: TlsStreamPtr; p: pointer; n: int; deadline: Deadline;
                tok: nil CancelToken = nil): int {.passive.} =
  ## kTLS reading: application data straight into p; control records
  ## handled here (a KeyUpdate: new kernel keys; close_notify: the end). A
  ## read smaller than a control record goes through `inb` (idle under
  ## kTLS; what does not fit p waits there): an alert must come whole.
  var res = 0
  let small = n < KtlsSmallRead
  while true:
    if cancelled(tok): return ECancelled
    var t = 0
    let dst = if small: cast[pointer](addr s.inb[0]) else: p
    let k = ktlsRecv(nativeHandle(s.tcp), dst, (if small: InCap else: n), t)
    if k > 0:
      if t == 23:
        if lockedState(s, hasPartialHandshake(s.conn)): return fail(s, TlsFailed - alUnexpectedMessage)   # a message cut (5.1)
        if not small: return k
        let m = min(n, k)
        copyMem(p, addr s.inb[0], m)
        if k > m:
          s.pendOff = m
          s.pendLen = k - m
          s.pendUsed = 0
        return m
      if t == 22:
        let h = lockedState(s, handshakeRecord(s.conn, cast[Bytes](dst), k))
        if h != 0: return fail(s, TlsFailed - h)
        if lockedState(s, takeReadKeyChange(s.conn)):
          let r = lockedState(s, installKernelKeys(s.conn, nativeHandle(s.tcp), false))
          if r != 0: return fail(s, r)            # a kernel without TLS 1.3 rekey
        continue
      if lockedState(s, hasPartialHandshake(s.conn)): return fail(s, TlsFailed - alUnexpectedMessage)
      if t == 21:
        let b = cast[Bytes](dst)
        if k >= 2 and int(b[1]) == alCloseNotify:
          s.peerClosed = true
          return 0
        if k >= 2 and int(b[1]) == 90: continue   # user_canceled
        return fail(s, TlsFailed - (if k >= 2: int(b[1]) else: alDecodeError))
      return fail(s, TlsFailed - alUnexpectedMessage)
    if k == 0: return fail(s, TlsTruncated)
    if k != KtlsAgain: return fail(s, k)
    parkIo(nativeHandle(s.tcp), {evRead}, limit(s.tcp.timeoutMs, deadline), res, tok)
    if res <= 0: return (if res < 0: res else: IoTimedOut)

proc recordRest(s: TlsStreamPtr): int =
  ## Bytes still missing from the record at the start of inb (a header
  ## first): what may be read while reading moves to the kernel.
  if s.inLen < RecordHeaderLen: return RecordHeaderLen - s.inLen
  let n = RecordHeaderLen + ((int(s.inb[3]) shl 8) or int(s.inb[4]))
  result = max(0, n - s.inLen)

proc recvInto*(s: TlsStreamPtr; p: pointer; n: int; deadline = never;
               tok: nil CancelToken = nil): int {.passive.} =
  ## Up to n bytes of application data: > 0 bytes, 0 at close_notify, or a
  ## failure (TlsTruncated when TCP ended without close_notify).
  if n < 0: return InvalidInput
  if n == 0: return 0
  if not s.initialized: return ResourceClosed
  retain(tok)
  defer: release(tok)
  ioCheckpoint(min(n, MaxPlaintext))
  if not s.initialized: return ResourceClosed
  if deadline <= monoNow(): return IoTimedOut
  if cancelled(tok): return ECancelled
  if s.earlyAt < s.early.len:                   # 0-RTT first, never with later bytes in one read
    let k = min(n, s.early.len - s.earlyAt)
    copyMem(p, at(base(s.early), s.earlyAt), k)
    s.earlyAt = s.earlyAt + k
    return k
  while true:
    ioCheckpoint(0)
    if deadline <= monoNow(): return IoTimedOut
    if cancelled(tok) or stopping(): return ECancelled
    if s.pendLen > 0:
      let k = min(n, s.pendLen)
      copyMem(p, addr s.inb[s.pendOff], k)
      s.pendOff = s.pendOff + k
      s.pendLen = s.pendLen - k
      if s.pendLen == 0: dropInput(s, s.pendUsed)
      return k
    if failureCode(s) != 0: return failureCode(s)
    if s.peerClosed: return 0
    if s.krx: return kernelRecv(s, p, n, deadline, tok)
    if s.rxWanted and s.inLen == 0:
      # A record boundary: the kernel opens the records from here on.
      s.rxWanted = false
      if lockedState(s, installKernelKeys(s.conn, nativeHandle(s.tcp), false)) == 0:
        s.krx = true
        continue
    var r = default(StepResult)
    let st = lockedState(s, step(s.conn, ptrOf(s.inb), s.inLen, ptrOf(s.rdOut), CtlCap, r))
    case st
    of stAppData, stEarlyData:
      s.pendOff = r.off
      s.pendLen = r.len
      s.pendUsed = r.consumed
    of stNeedInput, stReady:
      dropInput(s, r.consumed)
      if st == stNeedInput:
        if s.inLen == InCap: return fail(s, TlsFailed - alInternalError)
        # Before the kernel takes reading over: no byte past this record.
        let want = if s.rxWanted: recordRest(s) else: InCap - s.inLen
        let k = readTransport(s, addr s.inb[s.inLen], want, deadline, tok)
        if k == 0: return fail(s, TlsTruncated)
        if k < 0: return k                     # a timeout or error; the stream stays usable after a timeout
        s.inLen = s.inLen + k
    of stSend:
      # Nothing after the handshake is sent by the reader today; kept for the writer.
      dropInput(s, r.consumed)
      if not queueCtl(s, ptrOf(s.rdOut), r.outLen): return fail(s, TlsFailed - alInternalError)
    of stPeerClosed, stClosed:
      dropInput(s, r.consumed)
      s.peerClosed = true
      return 0
    of stFailed:
      dropInput(s, r.consumed)
      if r.outLen > 0 and not writerActive(s):
        if s.ktx:
          # The kernel seals now: our alert as its record (the one `step`
          # sealed has user-space keys the kernel moved past).
          var al = [2'u8, byte(r.alert)]
          discard ktlsSendRecord(nativeHandle(s.tcp), 21, ptrOf(al), 2)             # best effort
        else:
          if not s.customTransport: discard writeSome(nativeHandle(s.tcp), addr s.rdOut[0], r.outLen)       # best effort
      return fail(s, TlsFailed - r.alert)

proc kernelSendAll(s: TlsStreamPtr; ctype: int; p: Bytes; n: int; deadline: Deadline;
                   tok: nil CancelToken = nil): int {.passive.} =
  ## kTLS: one control record, waiting for room: 0 or the failure.
  var res = 0
  while true:
    if cancelled(tok): return ECancelled
    let k = ktlsSendRecord(nativeHandle(s.tcp), ctype, p, n)
    if k == n: return 0
    if k >= 0 or k != KtlsAgain: return (if k < 0: k else: -1)   # a control record goes whole
    parkIo(nativeHandle(s.tcp), {evWrite}, limit(s.tcp.timeoutMs, deadline), res, tok)
    if res <= 0: return (if res < 0: res else: IoTimedOut)

proc kernelKeyUpdate(s: TlsStreamPtr; deadline: Deadline;
                     tok: nil CancelToken = nil): int {.passive.} =
  ## kTLS: our KeyUpdate as a record, then the kernel's new send keys.
  var msg = [24'u8, 0, 0, 1, 0]
  result = kernelSendAll(s, 22, ptrOf(msg), msg.len, deadline, tok)
  if result == 0:
    if not lockedState(s, rollWriteKey(s.conn)): return TlsFailed - alInternalError
    result = lockedState(s, installKernelKeys(s.conn, nativeHandle(s.tcp), true))

template kernelPrepareInline(s: TlsStreamPtr; upcoming: int; deadline: Deadline;
                             tok: nil CancelToken; outcome: var int) =
  ## Run in the writer's existing passive frame. Only a due control record
  ## enters the cold KeyUpdate operation; ordinary payload creates no frame.
  block:
    outcome = 0
    var due = lockedState(s, replyDue(s.conn))
    s.kSent = s.kSent + upcoming
    if not due and (lockedState(s, keyUpdateInterval(s.conn)) > 0 or s.kSent >= KtlsCheckBytes):
      s.kSent = 0
      let limit = if lockedState(s, keyUpdateInterval(s.conn)) > 0: lockedState(s, keyUpdateInterval(s.conn)) else: KeyUpdateAfter
      let sq = ktlsTxSeq(nativeHandle(s.tcp), lockedState(s, suite(s.conn)))
      if sq < 0:
        outcome = int(sq)       # cannot safely decide key lifetime without it
      else:
        due = uint64(sq) >= limit
    if outcome == 0 and due:
      outcome = kernelKeyUpdate(s, deadline, tok)

proc kernelSend(s: TlsStreamPtr; p: pointer; n: int; deadline: Deadline;
                tok: nil CancelToken = nil): int {.passive.} =
  ## kTLS writing (the writer held): owed or due key updates, then plaintext.
  kernelPrepareInline(s, n, deadline, tok, result)
  if result != 0: return
  result = writeRaw(s, cast[Bytes](p), n, deadline, tok)
  if result == 0: result = n

proc sendFrom*(s: TlsStreamPtr; p: pointer; n: int; deadline = never;
               tok: nil CancelToken = nil): int {.passive.} =
  ## Up to 16384 bytes of p as one record (with kTLS: all n bytes): the
  ## count taken, TlsClosed after `shutdownWrite`, or a failure.
  if n < 0: return InvalidInput
  if n == 0: return 0
  if not s.initialized: return ResourceClosed
  if failureCode(s) != 0: return failureCode(s)
  if lockedState(s, writeClosed(s.conn)): return TlsClosed
  retain(tok)
  defer: release(tok)
  ioCheckpoint(min(n, MaxPlaintext))
  if not s.initialized: return ResourceClosed
  if failureCode(s) != 0: return failureCode(s)
  if cancelled(tok) or stopping(): return ECancelled
  if deadline <= monoNow(): return IoTimedOut
  if not takeWriter(addr s.writer, deadline, tok): return (if cancelled(tok): ECancelled else: IoTimedOut)
  if lockedState(s, writeClosed(s.conn)):                            # shut down while we waited for the writer
    giveWriter(s)
    return TlsClosed
  if s.ktx:
    result = kernelSend(s, p, n, deadline, tok)
    giveWriter(s)
    if result < 0: discard fail(s, result)
    return
  let k = min(n, MaxPlaintext)
  while true:
    result = owedRecords(s, deadline, tok)
    if result != 0: break
    let m = sealApplication(s, p, k)
    if m < 0: continue # A reader queued control work before this transition.
    if m == 0:
      result = TlsClosed
    else:
      result = writeRaw(s, ptrOf(s.outb), m, deadline, tok)
      if result == 0:
        result = flushCtl(s, deadline, tok)
        if result == 0: result = k
    break
  giveWriter(s)
  if result < 0 and result != TlsClosed: discard fail(s, result)

proc kernelClose(s: TlsStreamPtr; deadline: Deadline) {.passive.} =
  ## kTLS: close_notify as an alert record, then the half-close, only
  ## after it: the alert also closes the kernel's open record, which a FIN
  ## alone could overtake.
  let pending = lockedState(s, block:
    let value = s.kClosePending
    s.kClosePending = false
    value)
  if pending:
    var alert = [1'u8, 0]
    if kernelSendAll(s, 21, ptrOf(alert), 2, deadline) == 0: endTransport(s)

proc flushLater(s: TlsStreamPtr) {.passive.} =
  ## close_notify and the half-close that `shutdownWrite` could not send at
  ## once. Bounded by its deadlines: `close` waits for it.
  if takeWriter(addr s.writer, afterMs(CloseWaitMs)):
    if s.ktx: kernelClose(s, afterMs(CloseWaitMs))
    else: discard flushCtl(s, afterMs(CloseWaitMs))
    giveWriter(s)
  finishFlush(s)

proc scheduleFlush(s: TlsStreamPtr) =
  s.stateLock.acquire()
  if flushPending(s):
    s.stateLock.release()
    return
  retain(s.background)
  clearEvent(addr s.flushDone)
  s.stateLock.release()
  if not trySpawnCleanupTask(flushLater(s)):
    discard fail(s, ResourceClosed)
    finishFlush(s)

proc shutdownWrite*(s: TlsStreamPtr) =
  ## Queue close_notify under the protocol lock. The writer sends it after
  ## every earlier sealed record, without holding this lock across a wait.
  s.stateLock.acquire()
  if not s.initialized or failureCode(s) != 0 or writeClosed(s.conn):
    s.stateLock.release()
    return
  if s.ktx:
    markWriteClosed(s.conn)
    s.kClosePending = true
  else:
    var rec = default(array[64, byte])
    let n = close(s.conn, ptrOf(rec), rec.len)
    if n > 0:
      if s.ctlLen + n > CtlCap:
        s.stateLock.release()
        discard fail(s, TlsFailed - alInternalError)
        return
      copyMem(addr s.ctl[s.ctlLen], ptrOf(rec), n)
      s.ctlLen += n
    s.shutdownAfter = true
  s.stateLock.release()
  scheduleFlush(s)

proc interrupt*(s: TlsStreamPtr) =
  ## Wake whatever is parked on the stream; it fails.
  if not s.initialized: return
  if s.customTransport: interrupt(s.transport)
  else: interrupt(addr s.tcp)

proc close*(s: TlsStreamPtr) {.passive.} =
  ## close_notify (unless sent, or the stream failed: what was sent may be
  ## cut short), then free the TLS state and the socket.
  if not s.initialized: return
  if failureCode(s) != 0: markClosedState(s)
  if s.ktx and s.tcp.isOpen and not lockedState(s, writeClosed(s.conn)):
    markClosedState(s)
    discard lockedState(s, block:
      s.kClosePending = true
      true)
    if takeWriter(addr s.writer, afterMs(CloseWaitMs)):
      kernelClose(s, afterMs(CloseWaitMs))
      giveWriter(s)
  var rec = default(array[64, byte])
  let n = lockedState(s, close(s.conn, ptrOf(rec), rec.len))
  if n > 0: discard queueCtl(s, ptrOf(rec), n)
  if transportOpen(s) and takeWriter(addr s.writer, afterMs(CloseWaitMs)):
    discard flushCtl(s, afterMs(CloseWaitMs))
    giveWriter(s)
  while flushPending(s):
    discard wait(addr s.flushDone, afterMs(CloseWaitMs))
    if flushPending(s): yieldNow() # shutdown cancellation is not completion
  releaseState(s)
  if s.customTransport:
    let owner = s.transportOwner
    if s.ownsTransport and owner != nil: discard close(owner)
    s.transportOwner = nil
    s.transport = default(StreamView)
  else:
    close(addr s.tcp)
  s.initialized = false

proc useKtls*(s: TlsStreamPtr; rx = true): int =
  ## Hand the records to the kernel (Linux kTLS) after the handshake:
  ## sending at once, reading (with `rx`) from the next record boundary. 0,
  ## or why not (KtlsUnavailable, -errno): the stream then goes on in user
  ## space as before. A client of servers that send tickets right after the
  ## handshake may prefer rx = false.
  if s.customTransport: return NotSupported
  if not s.initialized or not lockedState(s, isReady(s.conn)) or failureCode(s) != 0: return TlsFailed - alInternalError
  if writerActive(s) or s.ctlLen > 0 or lockedState(s, writeClosed(s.conn)) or lockedState(s, replyDue(s.conn)): return -16   # EBUSY
  var tx = default(Secret)
  var rxs = default(Secret)
  var txSeq = 0'u64
  var rxSeq = 0'u64
  if not lockedState(s, exportSecrets(s.conn, tx, rxs, txSeq, rxSeq)): return TlsFailed - alInternalError
  wipe(rxs)
  result = ktlsAttach(nativeHandle(s.tcp))
  if result == 0: result = ktlsKeys(nativeHandle(s.tcp), true, lockedState(s, suite(s.conn)), tx, txSeq)
  wipe(tx)
  if result != 0: return
  s.ktx = true
  s.rxWanted = rx

# Read-only connection metadata; no handshake or traffic-key mutation escapes.
template recvInto*(s: TlsStreamPtr; buf: var openArray[byte]; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  recvInto(s, dataPtr(buf), buf.len, deadline, tok)

template sendFrom*(s: TlsStreamPtr; buf: openArray[byte]; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  sendFrom(s, dataPtr(buf), buf.len, deadline, tok)

proc isReady*(s: TlsStreamPtr): bool = s.initialized and lockedState(s, isReady(s.conn))
proc suite*(s: TlsStreamPtr): Suite = lockedState(s, suite(s.conn))
proc alpn*(s: TlsStreamPtr): string = lockedState(s, alpn(s.conn))
proc serverName*(s: TlsStreamPtr): string = lockedState(s, serverName(s.conn))
proc resumed*(s: TlsStreamPtr): bool = s.conn.resumed
proc retried*(s: TlsStreamPtr): bool = s.conn.retried
proc earlyAccepted*(s: TlsStreamPtr): bool = s.conn.earlyAccepted
proc earlyRejected*(s: TlsStreamPtr): bool = s.conn.earlyRejected
proc echAccepted*(s: TlsStreamPtr): bool = s.conn.echAccepted
proc hasPeerCertificate*(s: TlsStreamPtr): bool = s.conn.peerLeaf.len > 0
proc peerLeafDer*(s: TlsStreamPtr): seq[byte] = lockedState(s, peerLeafDer(s.conn))
proc echRetryConfigs*(s: TlsStreamPtr): seq[byte] = lockedState(s, echRetryConfigs(s.conn))
proc usesKernelWrite*(s: TlsStreamPtr): bool = s.ktx
proc usesKernelRead*(s: TlsStreamPtr): bool = s.krx
proc nativeHandle*(s: TlsStreamPtr): cint =
  ## Borrow the direct TCP handle. Custom transports have no native handle.
  if s.customTransport or not s.initialized: return -1
  result = nativeHandle(s.tcp)

# Advanced adapter shares private TLS control/ownership state.
include zal_tls/private/kernelsplice
