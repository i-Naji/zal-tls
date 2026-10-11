from zal_net/io import IoResult, ioResult
## Retained TLS owners. Forwarding keeps the reference in the
## caller's passive frame. Configurations and friendly TCP transports are
## retained through handshake, I/O, background flushing and final cleanup.
import zal_net/[rt, errors, buffers], zal_net/rt/[sync, cancel]
import zal_net/ownership, zal_net/foundation/tcp, zal_net/net/tcpview, zal_net/net/transport, zal_net/raw/tcp
import zal_net/unsafe/refcontext
import zal_tls/config/[owned, config]
import zal_tls/raw/stream
import zal_tls/private/streamlease
import std/[atomics, ticketlocks]
when not defined(release):
  import std/atomics
  var liveOwners: int
  proc liveTlsOwners*(): int = atomicLoad(liveOwners, moRelaxed)

export ownership, owned

type
  TlsConnObj = object
    stream: TlsStream
    life: OwnerLife
    client: nil ClientConfigRef
    server: nil ServerConfigRef
    tcp: nil TcpConnRef
    flushHold: nil TlsConnRef       ## temporary self-reference while flush runs
    ownerLock: TicketLock
    backgroundCount: int
    cleanup: bool                  ## retaining close task has been admitted
    readFailure, writeFailure: IoFailure
    when not defined(release):
      counted: bool
  TlsConnRef* = ref TlsConnObj
  TlsConnResult* = object
    value*: nil TlsConnRef
    code*: int

proc `=destroy`(owner: var TlsConnObj) =
  ## No borrower, flush or cleanup can remain: each retains the wrapper.
  discard closeNow(addr owner.stream)
  owner.client = nil
  owner.server = nil
  owner.tcp = nil
  owner.flushHold = nil
  when not defined(release):
    if owner.counted: discard atomicFetchSub(liveOwners, 1, moRelaxed)

proc newOwner(): TlsConnRef =
  result = TlsConnRef()
  when not defined(release):
    result.counted = true
    discard atomicFetchAdd(liveOwners, 1, moRelaxed)
  initOwnerLife(result.life)

proc rawStream(owner: TlsConnRef): TlsStreamPtr {.inline.} = addr owner.stream
proc gate(owner: TlsConnRef): ptr OwnerLife {.inline.} = addr owner.life
proc state*(owner: TlsConnRef): OwnerState {.inline.} = state(owner.life)
proc finishControl(owner: TlsConnRef)
proc nativeHandle*(owner: TlsConnRef): cint =
  if beginControl(owner.life) != 0: return -1
  result = nativeHandle(rawStream(owner))
  finishControl(owner)

proc negotiatedProtocol*(owner: TlsConnRef; value: var string): int =
  ## Copy ALPN into caller-owned storage; no handshake-local view escapes.
  result = beginControl(owner.life)
  if result != 0: return
  value = alpn(rawStream(owner))
  finishControl(owner)

proc lastReadFailure*(owner: TlsConnRef): IoFailure =
  owner.ownerLock.acquire()
  result = owner.readFailure
  owner.ownerLock.release()
proc lastWriteFailure*(owner: TlsConnRef): IoFailure =
  owner.ownerLock.acquire()
  result = owner.writeFailure
  owner.ownerLock.release()

proc recordRead*(owner: TlsConnRef; code: int; transferred = 0) =
  owner.ownerLock.acquire()
  owner.readFailure = IoFailure(code: code, transferred: transferred)
  owner.ownerLock.release()

proc recordWrite*(owner: TlsConnRef; code: int; transferred = 0) =
  owner.ownerLock.acquire()
  owner.writeFailure = IoFailure(code: code, transferred: transferred)
  owner.ownerLock.release()

proc detachResources(owner: TlsConnRef) =
  owner.client = nil
  owner.server = nil
  owner.tcp = nil
  markClosed(owner.life)

proc disposeRejectedClose(owner: TlsConnRef) =
  if not atomicLoad(owner.cleanup, moAcquire) and claimOwnerCleanup(owner.life):
    if closeNow(rawStream(owner)): detachResources(owner)
    else: releaseCleanupClaim(owner.life)

proc finishControl(owner: TlsConnRef) =
  endControl(owner.life)
  signalIdle(owner.life)
  disposeRejectedClose(owner)

proc acquireBackground(context: pointer) {.nimcall.} =
  let owner = cast[TlsConnRef](context)
  owner.ownerLock.acquire()
  if owner.backgroundCount == 0: owner.flushHold = owner
  inc owner.backgroundCount
  owner.ownerLock.release()

proc dropBackground(context: pointer) {.nimcall.} =
  let owner = cast[TlsConnRef](context)
  owner.ownerLock.acquire()
  dec owner.backgroundCount
  if owner.backgroundCount == 0: owner.flushHold = nil
  owner.ownerLock.release()
  disposeRejectedClose(owner)

proc initialized(owner: TlsConnRef; code: int): TlsConnResult =
  result = default(TlsConnResult)
  result.code = code
  if code == 0:
    discard setBackgroundLease(rawStream(owner), BackgroundLease(
      context: borrowRefContext(owner), acquire: acquireBackground, drop: dropBackground))
    result.value = owner
  else:
    discard closeNow(rawStream(owner))
    detachResources(owner)

proc constructionAllowed(): int =
  if stopping(): return ResourceClosed
  result = 0

proc attach(owner: TlsConnRef; cfg: ClientConfigRef): ClientConfigPtr =
  owner.client = cfg
  unsafeBorrowConfig(cfg)

proc attach(owner: TlsConnRef; cfg: ServerConfigRef): ServerConfigPtr =
  owner.server = cfg
  unsafeBorrowConfig(cfg)

template connectTlsConn*(cfg: ClientConfigRef; host: string; port: uint16;
                         serverName = ""; deadline: Deadline = never;
                         timeoutMs = 10_000; handshakeMs = DefaultHandshakeMs;
                         tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let configuration = cfg
      let owner = newOwner()
      let name = host
      let code = connectTls(name, port, attach(owner, configuration), rawStream(owner),
                            serverName, deadline, timeoutMs, handshakeMs, tok=tok)
      outcome = initialized(owner, code)
    outcome

template borrowTlsClient*(cfg: ClientConfigRef; underlying: Transport; serverName: string;
                          deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                          tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let owner = newOwner()
      let code = wrapClient(rawStream(owner), underlying, attach(owner, cfg), serverName,
                            deadline, handshakeMs, tok)
      outcome = initialized(owner, code)
    outcome

template borrowTlsServer*(cfg: ServerConfigRef; underlying: Transport;
                          deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                          tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let owner = newOwner()
      let code = wrapServer(rawStream(owner), underlying, attach(owner, cfg),
                            deadline, handshakeMs, tok)
      outcome = initialized(owner, code)
    outcome

proc retainTcp(owner: TlsConnRef; tcp: TcpConnRef): Transport =
  owner.tcp = tcp
  tcpTransport(tcp)

template borrowTlsClient*(cfg: ClientConfigRef; tcp: TcpConnRef; serverName: string;
                          deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                          tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let owner = newOwner()
      let held = tcp
      let code = wrapClient(rawStream(owner), retainTcp(owner, held), attach(owner, cfg),
                            serverName, deadline, handshakeMs, tok)
      outcome = initialized(owner, code)
    outcome

template borrowTlsServer*(cfg: ServerConfigRef; tcp: TcpConnRef;
                          deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                          tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let owner = newOwner()
      let held = tcp
      let code = wrapServer(rawStream(owner), retainTcp(owner, held), attach(owner, cfg),
                            deadline, handshakeMs, tok)
      outcome = initialized(owner, code)
    outcome

template takeTlsServer*(cfg: ServerConfigRef; view: Transport;
                        deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                        tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      if canTransfer(view) != 0: outcome.code = canTransfer(view)
      else:
        let owner = newOwner()
        let code = takeServer(rawStream(owner), view, attach(owner, cfg),
                              deadline, handshakeMs, tok)
        outcome = initialized(owner, code)
    outcome

template takeTlsClient*(cfg: ClientConfigRef; view: Transport; serverName: string;
                        deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                        tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      if canTransfer(view) != 0: outcome.code = canTransfer(view)
      else:
        let owner = newOwner()
        let code = takeClient(rawStream(owner), view, attach(owner, cfg), serverName,
                              deadline, handshakeMs, tok)
        outcome = initialized(owner, code)
    outcome

template takeTlsServer*(cfg: ServerConfigRef; tcp: var nil TcpConnRef;
                        deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                        tok: nil CancelToken = nil): TlsConnResult =
  ## Rejection preserves tcp; admission consumes it even on failure.
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let held = tcp
      if held == nil: outcome.code = ResourceClosed
      elif not quiescent(held): outcome.code = ResourceBusy
      elif cancelled(tok): outcome.code = ECancelled
      else:
        let owner = newOwner()
        var raw = default(TcpStream)
        let moved = takeRawTcp(held, raw)
        if moved != 0: outcome.code = moved
        else:
          let code = acceptTls(rawStream(owner), addr raw, attach(owner, cfg),
                               deadline, handshakeMs, tok)
          # Admission transferred ownership. A later cancellation releases
          # the descriptor here if the raw constructor did not consume it.
          if raw.isOpen: close(addr raw)
          tcp = nil
          outcome = initialized(owner, code)
    outcome

template takeTlsClient*(cfg: ClientConfigRef; tcp: var nil TcpConnRef; serverName: string;
                        deadline: Deadline = never; handshakeMs = DefaultHandshakeMs;
                        tok: nil CancelToken = nil): TlsConnResult =
  block:
    var outcome = default(TlsConnResult)
    outcome.code = constructionAllowed()
    if outcome.code == 0:
      let held = tcp
      if held == nil: outcome.code = ResourceClosed
      elif not quiescent(held): outcome.code = ResourceBusy
      elif cancelled(tok): outcome.code = ECancelled
      else:
        let owner = newOwner()
        var raw = default(TcpStream)
        let moved = takeRawTcp(held, raw)
        if moved != 0: outcome.code = moved
        else:
          let code = takeClient(rawStream(owner), addr raw, attach(owner, cfg), serverName,
                                deadline, handshakeMs, tok)
          # Admission transferred ownership. A later cancellation releases
          # the descriptor here if the raw constructor did not consume it.
          if raw.isOpen: close(addr raw)
          tcp = nil
          outcome = initialized(owner, code)
    outcome

proc beginOperation(owner: TlsConnRef; write: bool): int =
  if stopping(): return ResourceClosed
  result = beginBorrow(owner.life, write)

proc endOperation(owner: TlsConnRef; write: bool) =
  endBorrow(owner.life, write)
  signalIdle(owner.life)
  disposeRejectedClose(owner)

template recvInto*(owner: TlsConnRef; p: pointer; n: int; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  block:
    let held = owner
    var count = beginOperation(held, false)
    if count == 0:
      defer: endOperation(held, false)
      count = recvInto(rawStream(held), p, n, deadline, tok)
      if count < 0 and state(held) == ownerClosing: count = ResourceClosed
    count

template sendFrom*(owner: TlsConnRef; p: pointer; n: int; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  block:
    let held = owner
    var count = beginOperation(held, true)
    if count == 0:
      defer: endOperation(held, true)
      count = sendFrom(rawStream(held), p, n, deadline, tok)
      if count < 0 and state(held) == ownerClosing: count = ResourceClosed
    count

template recvInto*(owner: TlsConnRef; bytes: var openArray[byte]; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  recvInto(owner, dataPtr(bytes), bytes.len, deadline, tok)

template sendFrom*(owner: TlsConnRef; bytes: openArray[byte]; deadline: Deadline = never;
                   tok: nil CancelToken = nil): int =
  sendFrom(owner, dataPtr(bytes), bytes.len, deadline, tok)

proc shutdownWrite*(owner: TlsConnRef): int =
  result = beginControl(owner.life)
  if result != 0: return
  shutdownWrite(rawStream(owner))
  finishControl(owner)

proc interrupt*(owner: TlsConnRef): int =
  result = beginControl(owner.life)
  if result != 0: return
  interrupt(rawStream(owner))
  finishControl(owner)

proc closeNow*(owner: TlsConnRef): int =
  if state(owner) == ownerClosed: return 0
  result = beginClose(owner.life, true, true)
  if result != 0: return ResourceBusy
  if not closeNow(rawStream(owner)):
    reopenRejectedClose(owner.life)
    return ResourceBusy
  finishInterrupt(owner.life)
  detachResources(owner)
  result = 0

proc drainAndClose(owner: sink TlsConnRef) {.passive.} =
  while not claimOwnerCleanup(owner.life):
    drainBorrowers(gate(owner))
    yieldNow()
  close(rawStream(owner))
  detachResources(owner)

proc startClose(owner: TlsConnRef): int =
  result = beginClose(owner.life, true)
  if result == ResourceClosed: return 0
  if result != 0: return
  atomicStore(owner.cleanup, true, moRelease)
  if not isIdle(owner.life): interrupt(rawStream(owner))
  finishInterrupt(owner.life)
  if not trySpawnCleanupTask(drainAndClose(owner)):
    atomicStore(owner.cleanup, false, moRelease)
    interrupt(rawStream(owner))
    disposeRejectedClose(owner)

template close*(owner: TlsConnRef; deadline: Deadline = never): int =
  block:
    let held = owner
    var code = startClose(held)
    if code == 0: code = drainClose(gate(held), deadline)
    code


template writeAllInto*(owner: TlsConnRef; p: pointer; n: int;
                       deadline: Deadline; tok: nil CancelToken; output: var IoResult) =
  block:
    let held = owner
    let source = p
    let size = n
    let until: Deadline = deadline
    let token: nil CancelToken = tok
    retain(token)
    defer: release(token)
    var sent = 0
    var code = beginOperation(held, true)
    if code == 0:
      defer: endOperation(held, true)
      if size < 0: code = InvalidInput
      while sent < size:
        let position = offset(bytesPtr(source), sent)
        var count = 0
        count = sendFrom(rawStream(held), position, size - sent, until, token)
        if count <= 0:
          code = if count < 0: count else: NoProgress
          break
        sent += count
    recordWrite(held, code, sent)
    output = ioResult(sent, code)

proc writeAll*(owner: TlsConnRef; p: pointer; n: int;
               deadline: Deadline = never; tok: nil CancelToken = nil): IoResult {.passive.} =
  result = default(IoResult)
  writeAllInto(owner, p, n, deadline, tok, result)

template writeAll*(owner: TlsConnRef; buffer: openArray[byte];
                   deadline: Deadline = never; cancel: nil CancelToken = nil): IoResult =
  block:
    let held = owner
    let bytes: openArray[byte] = buffer
    writeAll(held, dataPtr(bytes), bytes.len, deadline, cancel)

proc transferStatus*(owner: TlsConnRef): int =
  if state(owner) != ownerOpen: return ResourceClosed
  if atomicLoad(owner.cleanup, moAcquire) or not isIdle(owner.life): return ResourceBusy
  result = 0
