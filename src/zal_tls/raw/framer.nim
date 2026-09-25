## TLS records on zal-net's framed relay, in place. A direction whose
## source is a TLS side opens every complete record where it lies:
## application data becomes spans; a KeyUpdate rolls the read keys and
## owes a reply; close_notify is the clean end (TCP ending without it is a
## failure: truncation). A direction whose sink is a TLS side seals its
## spans where they lie, after the control records the connection owes (a
## reply, our own key update) put in the sink's prefix, and says
## close_notify when its source ends. Both directions of one TLS side share
## a `TlsTraffic` block: the connection's `TlsConn` after the handshake.

import std/atomics
import zal_tls/common
import zal_tls/private/core/[conn, client, server]
import zal_tls/private/kernelkeys
import zal_tls/config/config
export Step, StepResult
import zal_tls/crypto/aead
import zal_tls/keys/schedule
import zal_tls/record/protect
import zal_tls/wire/consts
import zal_tls/raw/ktls
import zal_net/relay

const
  TlsGeometry* = Geometry(head: RecordHeaderLen, tail: 1 + AeadTagLen, maxRecord: MaxPlaintext,
                          headRoom: RecordHeaderLen)
  MaxEmptyRecords = 32                   ## empty application records in a row tolerated

type
  TlsTraffic* = object
    ## One TLS side of a relay connection. Plain data: allocated per
    ## connection, freed when both framers holding it have closed.
    conn: TlsConn
    refs: int                            ## framers holding it (atomic)
    peerClosed*: bool                    ## close_notify arrived
    emptyRun: int
    kSent: int                           ## kTLS: bytes since the send sequence was read

  TlsSide* = nil TlsTrafficPtr
    ## A connection's TLS side: nil until a handshake succeeds. (An alias:
    ## `var nil ptr T` does not parse as a parameter type, c34.)

  TlsTrafficPtr* = ptr TlsTraffic

var liveTraffics: int                    # traffic blocks allocated (atomic)

proc liveTrafficBlocks*(): int =
  ## TLS sides currently allocated (a leak check for tests).
  atomicLoad(liveTraffics, moRelaxed)

proc newTraffic*(): TlsSide =
  ## A zeroed block (a `TlsConn` ready for initClient/initServer).
  result = cast[TlsSide](alloc0(sizeof(TlsTraffic)))
  discard atomicFetchAdd(liveTraffics, 1, moRelaxed)

proc releaseTraffic*(t: TlsTrafficPtr) =
  ## Free a block no framer holds (a handshake that failed).
  release(t.conn)
  dealloc(t)
  discard atomicFetchSub(liveTraffics, 1, moRelaxed)

proc initServerSide*(t: TlsTrafficPtr; cfg: ServerConfigPtr; earlyCapacity: uint32): bool =
  ## Initialize a fresh traffic block. Configuration outlives the handshake.
  result = initServer(t.conn, cfg)
  if result: t.conn.earlyCap = earlyCapacity

proc initClientSide*(t: TlsTrafficPtr; cfg: ClientConfigPtr; name: string): bool =
  result = initClient(t.conn, cfg, name)

proc stepSide*(t: TlsTrafficPtr; inp: Bytes; inLen: int; outp: Bytes;
               outCap: int; event: var StepResult): Step {.inline.} =
  result = step(t.conn, inp, inLen, outp, outCap, event)

proc openSideRecord*(t: TlsTrafficPtr; buf: Bytes; off, count: int;
                     typ, payloadOffset, payloadLen: var int): int {.inline.} =
  result = openIncomingRecord(t.conn, buf, off, count, typ, payloadOffset, payloadLen)

proc processSideHandshake*(t: TlsTrafficPtr; buf: Bytes; count: int): int =
  result = handshakeRecord(t.conn, buf, count)

proc resumed*(t: TlsTrafficPtr): bool = t.conn.resumed
proc earlyAccepted*(t: TlsTrafficPtr): bool = t.conn.earlyAccepted
proc echAccepted*(t: TlsTrafficPtr): bool = t.conn.echAccepted
proc serverName*(t: TlsTrafficPtr): string = serverName(t.conn)
proc peerLeafDer*(t: TlsTrafficPtr): seq[byte] = peerLeafDer(t.conn)
proc setKeyUpdateInterval*(t: TlsTrafficPtr; records: uint64): bool =
  result = setKeyUpdateInterval(t.conn, records)

proc sourceTraffic(d: DirectionPtr): TlsTrafficPtr {.inline.} = sourceState[TlsTrafficPtr](d)[]
proc sinkTraffic(d: DirectionPtr): TlsTrafficPtr {.inline.} = sinkState[TlsTrafficPtr](d)[]
proc bufOf(d: DirectionPtr): Bytes {.inline.} = buf(d)

proc tlsOpen(c: Conn; d: DirectionPtr): int =
  ## Every complete record in the window, opened in place. >0 spans; 0
  ## more bytes needed; InEof after close_notify; InFail.
  let t = sourceTraffic(d)
  d.nspans = 0
  d.bytes = 0
  if t.peerClosed: return InEof
  let b = bufOf(d)
  while d.nspans < MaxSpans:
    let n = recordLen(b, d.off, d.fill - d.off)
    if n == 0: break
    if n < 0 or int(b[d.off]) != ctApplicationData:
      recordFailure(t.conn, if n < 0: -n else: alUnexpectedMessage)
      return InFail
    var typ = 0
    var off = 0
    var len = 0
    let a = openIncomingRecord(t.conn, b, d.off, n, typ, off, len)
    if a != 0:
      recordFailure(t.conn, a)
      return InFail
    d.off = d.off + n
    if typ != ctHandshake and hasPartialHandshake(t.conn):
      recordFailure(t.conn, alUnexpectedMessage)      # a handshake message cut by another type (5.1)
      return InFail
    case typ
    of ctApplicationData:
      if len > 0:
        t.emptyRun = 0
        d.spans[d.nspans] = Span(off: off, len: len)
        d.nspans = d.nspans + 1
        d.bytes = d.bytes + len
      else:
        t.emptyRun = t.emptyRun + 1
        if t.emptyRun > MaxEmptyRecords: return InFail
    of ctHandshake:
      let h = handshakeRecord(t.conn, at(b, off), len)
      if h != 0:
        recordFailure(t.conn, h)
        return InFail
    of ctAlert:
      if len != 2: return InFail
      let desc = int(b[off + 1])
      if desc == alCloseNotify:
        t.peerClosed = true
        return (if d.nspans > 0: d.nspans else: InEof)
      if desc != 90:                           # user_canceled: close_notify follows
        recordFailure(t.conn, desc)
        return InFail
    else:
      return InFail
  result = d.nspans

proc tlsEnded(d: DirectionPtr): bool = sourceTraffic(d).peerClosed

proc tlsBoundary(d: DirectionPtr): bool =
  ## The stream may end here only after close_notify.
  sourceTraffic(d).peerClosed

proc tlsSeal(c: Conn; d: DirectionPtr): bool =
  ## The owed control records into the prefix, then every span sealed in
  ## place into one region (a record shorter than the source's, padding
  ## gone, is moved down to close the gap).
  let t = sinkTraffic(d)
  var n = takeControl(t.conn, at(ptrOf(d.pre), d.preLen), PreCap - d.preLen)
  if n == 0 and keyUpdateDue(t.conn):
    n = keyUpdate(t.conn, false, at(ptrOf(d.pre), d.preLen), PreCap - d.preLen)
  d.preLen = d.preLen + n
  let b = bufOf(d)
  var i = 0
  while i < d.nspans:
    let off = d.spans[i].off
    let len = d.spans[i].len
    let start = off - RecordHeaderLen
    if start < 0: return false
    let m = sealApp(t.conn, b, start, len)
    if m == 0: return false
    if i == 0:
      d.wOff = start
      d.wEnd = start + m
    elif start == d.wEnd:
      d.wEnd = d.wEnd + m
    else:
      if start < d.wEnd: return false
      moveMem(bufAt(d, d.wEnd), bufAt(d, start), m)
      d.wEnd = d.wEnd + m
    i = i + 1
  result = true

proc tlsFinish(c: Conn; d: DirectionPtr): bool =
  ## close_notify in the prefix before the half-close.
  let t = sinkTraffic(d)
  let n = close(t.conn, at(ptrOf(d.pre), d.preLen), PreCap - d.preLen)
  d.preLen = d.preLen + n
  result = true

proc drop(t: TlsTrafficPtr) =
  if atomicFetchSub(t.refs, 1, moAcquireRelease) == 1: releaseTraffic(t)

proc tlsCloseSource(d: DirectionPtr) =
  let t = sourceTraffic(d)
  sourceState[nil TlsTrafficPtr](d)[] = nil
  drop(t)

proc tlsCloseSink(d: DirectionPtr) =
  let t = sinkTraffic(d)
  sinkState[nil TlsTrafficPtr](d)[] = nil
  drop(t)

var tlsFramer* = FramerObj(geometry: TlsGeometry, open: tlsOpen, atBoundary: tlsBoundary, sourceEnded: tlsEnded,
                           seal: tlsSeal, closeSource: tlsCloseSource, closeSink: tlsCloseSink,
                           finish: tlsFinish)
  ## TLS 1.3 records, both ways.

proc useTls*(src, dst: DirectionPtr; t: TlsTrafficPtr) =
  ## `src` reads the TLS side's records, `dst` writes them; both hold `t`
  ## (freed when both have closed).
  src.srcFramer = addr tlsFramer
  sourceState[nil TlsTrafficPtr](src)[] = t
  dst.dstFramer = addr tlsFramer
  sinkState[nil TlsTrafficPtr](dst)[] = t
  atomicStore(t.refs, 2, moRelease)

# ------------------------------------------------------------------- kTLS

const
  KtlsGeometry* = Geometry(head: 0, tail: 0, maxRecord: MaxRecord, headRoom: 0)
  KtlsCheckBytes = 64 shl 20

proc kOpen(c: Conn; d: DirectionPtr): int =
  ## The kernel has opened the records: what is buffered is plaintext.
  let t = sourceTraffic(d)
  d.nspans = 0
  d.bytes = 0
  if d.fill > d.off:
    if hasPartialHandshake(t.conn):                       # a handshake message cut by data (5.1)
      recordFailure(t.conn, alUnexpectedMessage)
      return InFail
    d.spans[0] = Span(off: d.off, len: d.fill - d.off)
    d.nspans = 1
    d.bytes = d.fill - d.off
    d.off = d.fill
  elif t.peerClosed:
    return InEof
  result = d.nspans

const EIoLinux = 5

proc kReadFailed(c: Conn; d: DirectionPtr; err: int): int =
  ## A plain read failed. EIO: a control record is next (the kernel wants
  ## recvmsg): a KeyUpdate gives new kernel keys (and a reply owed),
  ## close_notify the clean end, data that raced in is kept for `open`.
  ## Anything else (a record the kernel refused: EBADMSG, EMSGSIZE; a
  ## reset) fails. `failAlert` says why where TLS does.
  let t = sourceTraffic(d)
  if err != EIoLinux:
    recordFailure(t.conn, if err == 74 or err == 90: alBadRecordMac else: 0)   # EBADMSG, EMSGSIZE
    return InFail
  if d.fill >= BufCap: return InFail
  var typ = 0
  let k = ktlsRecv(d.src, bufAt(d, d.fill), BufCap - d.fill, typ)
  if k <= 0: return InFail                       # KtlsAgain too: EIO promised a record
  let b = buf(d)
  if typ != ctHandshake and hasPartialHandshake(t.conn):
    recordFailure(t.conn, alUnexpectedMessage)       # a handshake message cut by another type (5.1)
    return InFail
  case typ
  of ctApplicationData:
    d.fill = d.fill + k
    result = InAgain
  of ctHandshake:
    let h = handshakeRecord(t.conn, at(b, d.fill), k)
    if h != 0:
      recordFailure(t.conn, h)
      return InFail
    if takeReadKeyChange(t.conn):
      if installKernelKeys(t.conn, d.src, false) != 0:
        recordFailure(t.conn, alInternalError)       # a kernel without TLS 1.3 rekey
        return InFail
    result = InAgain
  of ctAlert:
    if k < 2:
      recordFailure(t.conn, alDecodeError)
      return InFail
    let desc = int(b[d.fill + 1])
    if desc == alCloseNotify:
      t.peerClosed = true
      return InEof
    if desc == 90: return InAgain
    recordFailure(t.conn, desc, true)
    result = InFail
  else:
    recordFailure(t.conn, alUnexpectedMessage)
    result = InFail

proc kSeal(c: Conn; d: DirectionPtr): bool =
  ## The kernel seals: owed or due key updates into the prefix (sent by
  ## kWritePrefix), the spans into one region as they are.
  let t = sinkTraffic(d)
  var due = replyDue(t.conn)
  t.kSent = t.kSent + d.bytes
  if not due and (keyUpdateInterval(t.conn) > 0 or t.kSent >= KtlsCheckBytes):
    t.kSent = 0
    let limit = if keyUpdateInterval(t.conn) > 0: keyUpdateInterval(t.conn) else: KeyUpdateAfter
    let sq = ktlsTxSeq(d.dst, suite(t.conn))
    due = sq >= 0 and uint64(sq) >= limit
  if due and d.preLen + 7 <= PreCap:
    for x in [22'u8, 5, 24, 0, 0, 1, 0]:          # [type, length, KeyUpdate(update_not_requested)]
      d.pre[d.preLen] = x
      d.preLen = d.preLen + 1
  var i = 0
  while i < d.nspans:
    let off = d.spans[i].off
    let len = d.spans[i].len
    if i == 0:
      d.wOff = off
      d.wEnd = off + len
    elif off == d.wEnd:
      d.wEnd = d.wEnd + len
    else:
      if off < d.wEnd: return false
      moveMem(bufAt(d, d.wEnd), bufAt(d, off), len)
      d.wEnd = d.wEnd + len
    i = i + 1
  result = true

proc kWritePrefix(c: Conn; d: DirectionPtr): int =
  ## Each [type, length, bytes] entry of the prefix as its own kernel record;
  ## after our KeyUpdate, the kernel's new send keys.
  let t = sinkTraffic(d)
  while d.preAt < d.preLen:
    let typ = int(d.pre[d.preAt])
    let n = int(d.pre[d.preAt + 1])
    let k = ktlsSendRecord(d.dst, typ, addr d.pre[d.preAt + 2], n)
    if k == KtlsAgain: return InAgain
    if k != n: return InFail
    d.preAt = d.preAt + 2 + n
    if typ == ctHandshake:
      if not rollWriteKey(t.conn) or installKernelKeys(t.conn, d.dst, true) != 0:
        return InFail
  result = 1

proc kFinish(c: Conn; d: DirectionPtr): bool =
  ## close_notify as an alert record before the half-close.
  let t = sinkTraffic(d)
  markWriteClosed(t.conn)
  if d.preLen + 4 > PreCap: return false
  for x in [21'u8, 2, 1, 0]:
    d.pre[d.preLen] = x
    d.preLen = d.preLen + 1
  result = true

var ktlsFramer* = FramerObj(geometry: KtlsGeometry, open: kOpen, atBoundary: tlsBoundary, sourceEnded: tlsEnded,
                            seal: kSeal, closeSource: tlsCloseSource, closeSink: tlsCloseSink,
                            finish: kFinish, readFailed: kReadFailed, writePrefix: kWritePrefix)
  ## A TLS side whose records the kernel seals and opens (Linux kTLS).

const
  HandoverFallback* = -1   ## the kernel cannot take over here; user space goes on (nothing lost)
  HandoverFailed* = -2     ## a bad record, a fatal alert or a bad handshake message: fail
  KtlsHalfInstalled* = -10_000   ## the kernel opens the records but cannot seal them: fail

proc ktlsHandover*(d: DirectionPtr; t: TlsTrafficPtr): int =
  ## Before the kernel takes reading over: open the complete records
  ## buffered in `d` here (application data becomes spans, appended), and
  ## say how many bytes the next record still lacks (0: at a boundary, the
  ## kernel may start). `HandoverFallback`: more records than spans hold;
  ## the rest stays buffered, untouched, for the user-space framer.
  ## `HandoverFailed`: the connection must fail. After close_notify nothing
  ## more is read (RFC 8446 6.1).
  if d.fill == d.off: return 0
  let b = buf(d)
  while true:
    let avail = d.fill - d.off
    if avail == 0: return 0
    if t.peerClosed:
      d.off = d.fill                             # data after close_notify is ignored
      return 0
    let n = recordLen(b, d.off, avail)
    if n < 0: return HandoverFailed
    if n == 0:
      if avail < RecordHeaderLen: return RecordHeaderLen - avail
      return RecordHeaderLen + ((int(b[d.off + 3]) shl 8) or int(b[d.off + 4])) - avail
    if int(b[d.off]) != ctApplicationData: return HandoverFailed
    if d.nspans == MaxSpans: return HandoverFallback   # before opening it: nothing consumed
    var typ = 0
    var off = 0
    var len = 0
    let a = openIncomingRecord(t.conn, b, d.off, n, typ, off, len)
    if a != 0:
      recordFailure(t.conn, a)
      return HandoverFailed
    d.off = d.off + n
    if typ != ctHandshake and hasPartialHandshake(t.conn):
      recordFailure(t.conn, alUnexpectedMessage)     # a handshake message cut by another type (5.1)
      return HandoverFailed
    case typ
    of ctApplicationData:
      if len > 0:
        d.spans[d.nspans] = Span(off: off, len: len)
        d.nspans = d.nspans + 1
        d.bytes = d.bytes + len
    of ctHandshake:
      let h = handshakeRecord(t.conn, at(b, off), len)
      if h != 0:
        recordFailure(t.conn, h)
        return HandoverFailed
      discard takeReadKeyChange(t.conn)                # the kernel gets the current keys below
    of ctAlert:
      if len == 2 and int(b[off + 1]) == alCloseNotify: t.peerClosed = true
      elif not (len == 2 and int(b[off + 1]) == 90):
        recordFailure(t.conn, if len == 2: int(b[off + 1]) else: alDecodeError, len == 2)
        return HandoverFailed
    else:
      recordFailure(t.conn, alUnexpectedMessage)
      return HandoverFailed

proc useKtlsFramer*(src, dst: DirectionPtr; t: TlsTrafficPtr; fd: cint): int =
  ## The kernel's keys on `fd` (the TLS side: `src` reads it, `dst` writes
  ## it; the ULP already attached: `ktlsAttach`) from where the connection
  ## stands (call after `ktlsHandover` says 0), and the kTLS framer on both.
  ## 0; -errno when the kernel took nothing (user space may go on:
  ## `useTls`); `KtlsHalfInstalled` when it opens but cannot seal (the
  ## connection must fail). Reading first: a failure there leaves nothing.
  var tx = default(Secret)
  var rx = default(Secret)
  var txSeq = 0'u64
  var rxSeq = 0'u64
  if not exportSecrets(t.conn, tx, rx, txSeq, rxSeq): return -22
  result = ktlsKeys(fd, false, suite(t.conn), rx, rxSeq)
  if result == 0:
    result = ktlsKeys(fd, true, suite(t.conn), tx, txSeq)
    if result != 0: result = KtlsHalfInstalled
  wipe(tx)
  wipe(rx)
  if result != 0: return
  src.srcFramer = addr ktlsFramer
  sourceState[nil TlsTrafficPtr](src)[] = t
  dst.dstFramer = addr ktlsFramer
  sinkState[nil TlsTrafficPtr](dst)[] = t
  atomicStore(t.refs, 2, moRelease)
