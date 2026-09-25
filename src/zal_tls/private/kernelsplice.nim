# Included by raw/stream: its private TLS writer gate owns the entire pump.
# Exported only through the explicit raw/splice adapter, never the default import.
import zal_net/raw/fdops

type KernelCopyStats* = object
  bytes*: int64                  ## application bytes delivered to the TLS peer
  kernelBytes*: int64            ## delivered through socket -> pipe -> kTLS
  fallbackBytes*: int64          ## delivered from an ordinary userspace buffer
  error*: int                    ## 0 EOF; otherwise package/OS failure

when defined(linux):
  {.compile: "../private/nt_splice.c".}
  proc splicePipe(fds: ptr cint): cint {.importc: "nt_splice_pipe".}
  proc spliceMove(source, destination: cint; count: clong): clong {.importc: "nt_splice_move".}
  proc spliceOutput(source, destination: cint; count: clong): clong {.importc: "nt_splice_output".}
  proc closePipe(fd: cint) {.importc: "nt_splice_close".}
  when defined(ntSpliceSequenceFaultTest):
    {.passC: "-DNT_KTLS_FAULT_TEST".}
  when defined(ntSpliceFaultTest):
    {.passC: "-DNT_SPLICE_FAULT_TEST".}

when defined(linux):
  proc kernelBufferedCopy(source: TcpStreamPtr; destination: TlsStreamPtr;
                          pipe: cint; remaining: int; deadline: Deadline;
                          tok: nil CancelToken): KernelCopyStats {.passive.} =
    result = KernelCopyStats()
    var buffer = default(array[65536, byte])
    var pending = remaining
    var sinceYield = 0
    while true:
      if cancelled(tok):
        result.error = ECancelled
        return
      var count = 0
      if pending > 0:
        count = readSome(pipe, addr buffer[0], min(pending, buffer.len))
        if count > 0: pending = pending - count
      else:
        fdRecvInline(nativeHandle(source), source.timeoutMs, addr buffer[0], buffer.len, deadline, count, tok)
        if count == 0: return
      if count <= 0:
        result.error = if count < 0: count else: -1
        return
      var offset = 0
      while offset < count:
        if failureCode(destination) != 0 or lockedState(destination, writeClosed(destination.conn)):
          result.error = if failureCode(destination) != 0: failureCode(destination) else: TlsClosed
          return
        var prepared = 0
        kernelPrepareInline(destination, count - offset, deadline, tok, prepared)
        if prepared != 0:
          result.error = fail(destination, prepared)
          return
        var sent = 0
        fdSendInline(nativeHandle(destination.tcp), destination.tcp.timeoutMs,
                     addr buffer[offset], count - offset, deadline, sent, tok)
        if sent <= 0:
          result.error = if sent < 0: sent else: -1
          return
        offset = offset + sent
        result.bytes = result.bytes + sent
        result.fallbackBytes = result.fallbackBytes + sent
        sinceYield = sinceYield + sent
        if sinceYield >= 1048576:
          sinceYield = 0
          yieldNow()

proc copyToKernel*(source: TcpStreamPtr; destination: TlsStreamPtr;
                   deadline = never; tok: nil CancelToken = nil): KernelCopyStats {.passive.} =
  ## Optional Linux TCP -> established kTLS TX pump. Borrow both stable owners
  ## until return, with no competing source reader. Holds the TLS writer gate;
  ## the admitted reader may process control records. Does not half-close.
  ## Requires prior successful useKtls(); never installs keys automatically.
  ## Unsupported splice drains already-consumed pipe bytes before buffering.
  ## Cancellation/deadline returns delivered counts; consumed undelivered bytes
  ## are discarded with the pipe. Kernel-managed record sequences stay usable.
  result = KernelCopyStats()
  when not defined(linux):
    result.error = KtlsUnavailable
  else:
    if not source[].isOpen or not destination.initialized:
      result.error = ResourceClosed
      return
    if destination.customTransport or not destination.ktx:
      result.error = NotSupported
      return
    if nativeHandle(source) == nativeHandle(destination.tcp):
      result.error = InvalidInput
      return
    if failureCode(destination) != 0:
      result.error = failureCode(destination)
      return
    if lockedState(destination, writeClosed(destination.conn)):
      result.error = TlsClosed
      return
    retain(tok)
    defer: release(tok)
    if not takeWriter(addr destination.writer, deadline, tok):
      result.error = if cancelled(tok): ECancelled else: IoTimedOut
      return
    defer: giveWriter(destination)
    if lockedState(destination, writeClosed(destination.conn)):
      result.error = TlsClosed
      return
    var pipe = [-1.cint, -1.cint]
    let created = int(splicePipe(addr pipe[0]))
    var buffered = created != 0
    defer:
      closePipe(pipe[0])
      closePipe(pipe[1])
    var inPipe = 0
    var sinceYield = 0
    var ready = 0
    # The cold fallback frame owns its buffer for the rest of this operation.
    # It is entered only on unsupported descriptors/platform splice refusal.
    while true:
      if cancelled(tok):
        result.error = ECancelled
        return
      if failureCode(destination) != 0 or lockedState(destination, writeClosed(destination.conn)):
        result.error = if failureCode(destination) != 0: failureCode(destination) else: TlsClosed
        return
      if buffered:
        let cold = kernelBufferedCopy(source, destination, pipe[0], inPipe, deadline, tok)
        result.bytes = result.bytes + cold.bytes
        result.fallbackBytes = result.fallbackBytes + cold.bytes
        result.error = cold.error
        return
      if inPipe == 0:
        let count = int(spliceMove(nativeHandle(source), pipe[1], 65536))
        if count == 0: return
        if count > 0:
          inPipe = count
        elif count == -22 or count == -38 or count == -95:
          buffered = true
          continue
        elif count == -11:
          parkIo(nativeHandle(source), {evRead}, limit(source.timeoutMs, deadline), ready, tok)
          if ready <= 0:
            result.error = if ready < 0: ready else: IoTimedOut
            return
          continue
        else:
          result.error = count
          return
      # Complete due control records and rekey before any application bytes.
      # At most one pipe chunk goes out before the next sequence check.
      var prepared = 0
      kernelPrepareInline(destination, inPipe, deadline, tok, prepared)
      if prepared != 0:
        result.error = fail(destination, prepared)
        return
      let count = int(spliceOutput(pipe[0], nativeHandle(destination.tcp), clong(inPipe)))
      if count > 0:
        inPipe = inPipe - count
        result.bytes = result.bytes + count
        result.kernelBytes = result.kernelBytes + count
        sinceYield = sinceYield + count
        if sinceYield >= 1048576:
          sinceYield = 0
          yieldNow()
      elif count == -22 or count == -38 or count == -95:
        buffered = true
      elif count == -11:
        parkIo(nativeHandle(destination.tcp), {evWrite}, limit(destination.tcp.timeoutMs, deadline), ready, tok)
        if ready <= 0:
          result.error = if ready < 0: ready else: IoTimedOut
          return
      else:
        result.error = fail(destination, if count < 0: count else: -1)
        return

when defined(linux):
  proc readBoundary(s: TlsStreamPtr): bool =
    s.earlyAt >= s.early.len and s.pendLen == 0 and s.inLen == 0 and
      not lockedState(s, hasPartialHandshake(s.conn))

  proc activateKernelRead(s: TlsStreamPtr): bool =
    if s.krx: return true
    if not s.rxWanted or not readBoundary(s): return false
    s.rxWanted = false
    if lockedState(s, installKernelKeys(s.conn, nativeHandle(s.tcp), false)) != 0: return false
    s.krx = true
    result = true

  proc kernelReceiveBuffered(source: TlsStreamPtr; destination: TcpStreamPtr;
                             pipe: cint; remaining: int; finish, forceRead: bool;
                             deadline: Deadline; tok: nil CancelToken): KernelCopyStats {.passive.} =
    ## Cold handover/control/fallback: preserve pending application bytes before
    ## returning to splice. A control read may deliver one application record.
    result = KernelCopyStats()
    var buffer = default(array[65536, byte])
    var pending = remaining
    var mustRead = forceRead
    var sinceYield = 0
    while true:
      if cancelled(tok):
        result.error = ECancelled
        return
      var count = 0
      if pending > 0:
        count = readSome(pipe, addr buffer[0], min(pending, buffer.len))
        if count > 0: pending = pending - count
      else:
        if not finish and not mustRead and readBoundary(source) and activateKernelRead(source): return
        mustRead = false
        count = recvInto(source, addr buffer[0], buffer.len, deadline, tok)
        if count == 0: return
      if count <= 0:
        result.error = if count < 0: count else: -1
        return
      var offset = 0
      while offset < count:
        var sent = 0
        fdSendInline(nativeHandle(destination), destination.timeoutMs,
                     addr buffer[offset], count - offset, deadline, sent, tok)
        if sent <= 0:
          result.error = if sent < 0: sent else: -1
          return
        offset = offset + sent
        result.bytes = result.bytes + sent
        result.fallbackBytes = result.fallbackBytes + sent
        sinceYield = sinceYield + sent
        if sinceYield >= 1048576:
          sinceYield = 0
          yieldNow()

proc copyFromKernel*(source: TlsStreamPtr; destination: TcpStreamPtr;
                     deadline = never; tok: nil CancelToken = nil): KernelCopyStats {.passive.} =
  ## Optional established kTLS RX -> TCP pump. Requires prior useKtls(rx=true).
  ## Drains already-buffered/early bytes before handover. Control records remain
  ## authenticated and rekey through the TLS reader; bare TCP EOF is truncation.
  ## Unsupported RX/splice falls back without losing consumed pipe bytes.
  ## Borrow both stable owners with no competing reader/source or writer/sink.
  result = KernelCopyStats()
  when not defined(linux):
    result.error = KtlsUnavailable
  else:
    if not source.initialized or not destination[].isOpen:
      result.error = ResourceClosed
      return
    if source.customTransport or (not source.krx and not source.rxWanted):
      result.error = NotSupported
      return
    if nativeHandle(source.tcp) == nativeHandle(destination):
      result.error = InvalidInput
      return
    retain(tok)
    defer: release(tok)
    var pipe = [-1.cint, -1.cint]
    let created = int(splicePipe(addr pipe[0]))
    var buffered = created != 0
    defer:
      closePipe(pipe[0])
      closePipe(pipe[1])
    var inPipe = 0
    var sinceYield = 0
    var ready = 0
    while true:
      if cancelled(tok):
        result.error = ECancelled
        return
      if failureCode(source) != 0:
        result.error = failureCode(source)
        return
      if source.peerClosed: return
      if buffered or not readBoundary(source) or not activateKernelRead(source):
        let cold = kernelReceiveBuffered(source, destination, pipe[0], inPipe, buffered, false, deadline, tok)
        result.bytes = result.bytes + cold.bytes
        result.fallbackBytes = result.fallbackBytes + cold.bytes
        if cold.error != 0 or buffered or source.peerClosed:
          result.error = cold.error
          return
        continue
      if inPipe == 0:
        let count = int(spliceMove(nativeHandle(source.tcp), pipe[1], 65536))
        if count == 0:
          result.error = fail(source, TlsTruncated)
          return
        if count > 0:
          inPipe = count
        elif count == -5:                 # EIO: an authenticated control record
          let cold = kernelReceiveBuffered(source, destination, pipe[0], 0, false, true, deadline, tok)
          result.bytes = result.bytes + cold.bytes
          result.fallbackBytes = result.fallbackBytes + cold.bytes
          if cold.error != 0:
            result.error = cold.error
            return
          continue
        elif count == -22 or count == -38 or count == -95:
          buffered = true
          continue
        elif count == -11:
          parkIo(nativeHandle(source.tcp), {evRead}, limit(source.tcp.timeoutMs, deadline), ready, tok)
          if ready <= 0:
            result.error = if ready < 0: ready else: IoTimedOut
            return
          continue
        else:
          result.error = fail(source, count)
          return
      let count = int(spliceOutput(pipe[0], nativeHandle(destination), clong(inPipe)))
      if count > 0:
        inPipe = inPipe - count
        result.bytes = result.bytes + count
        result.kernelBytes = result.kernelBytes + count
        sinceYield = sinceYield + count
        if sinceYield >= 1048576:
          sinceYield = 0
          yieldNow()
      elif count == -22 or count == -38 or count == -95:
        buffered = true
      elif count == -11:
        parkIo(nativeHandle(destination), {evWrite}, limit(destination.timeoutMs, deadline), ready, tok)
        if ready <= 0:
          result.error = if ready < 0: ready else: IoTimedOut
          return
      else:
        result.error = if count < 0: count else: -1
        return

type
  KernelRelayStats* = object
    toTls*, fromTls*: KernelCopyStats
  KernelRelayState = object
    completed: Event
    fromTls: KernelCopyStats

proc kernelReturn(plain: TcpStreamPtr; tls: TlsStreamPtr; state: ptr KernelRelayState;
                  deadline: Deadline; tok: nil CancelToken) {.passive.} =
  let copied = copyFromKernel(tls, plain, deadline, tok)
  if copied.error == 0:
    shutdownWrite(plain)
  else:
    interrupt(plain)
    interrupt(tls)
  state.fromTls = copied
  setEvent(addr state.completed)    # final state access before its caller frees it

proc relayKernel*(plain: TcpStreamPtr; tls: TlsStreamPtr; deadline = never;
                  tok: nil CancelToken = nil): KernelRelayStats {.passive.} =
  ## Explicit Linux kTLS relay after useKtls(rx=true). Stable raw owners stay
  ## borrowed; one reader/writer per side. Authenticated EOF forwards half-close.
  ## Failure/cancellation interrupts both sides and drains both tasks. Deadline
  ## is absolute; stream operation timeouts still apply. No idle reset promise.
  result = KernelRelayStats()
  when not defined(linux):
    result.toTls.error = KtlsUnavailable
    result.fromTls.error = KtlsUnavailable
  else:
    if not tls.initialized or not plain[].isOpen:
      result.toTls.error = ResourceClosed
      result.fromTls.error = ResourceClosed
      return
    if tls.customTransport or not tls.ktx or (not tls.krx and not tls.rxWanted):
      result.toTls.error = NotSupported
      result.fromTls.error = NotSupported
      return
    if nativeHandle(plain) == nativeHandle(tls.tcp):
      result.toTls.error = InvalidInput
      result.fromTls.error = InvalidInput
      return
    retain(tok)
    defer: release(tok)
    if cancelled(tok):
      result.toTls.error = ECancelled
      result.fromTls.error = ECancelled
      return
    # One operation-owned allocation, never a payload or per-iteration frame.
    let state = cast[ptr KernelRelayState](alloc0(sizeof(KernelRelayState)))
    if not trySpawnTask(kernelReturn(plain, tls, state, deadline, tok)):
      dealloc(state)
      result.toTls.error = ECancelled
      result.fromTls.error = ECancelled
      return
    result.toTls = copyToKernel(plain, tls, deadline, tok)
    if result.toTls.error == 0:
      shutdownWrite(tls)
    else:
      interrupt(plain)
      interrupt(tls)
    # Once a child owns state, cancellation cannot bypass its acknowledgement.
    discard wait(addr state.completed, never)
    result.fromTls = state.fromTls
    dealloc(state)
