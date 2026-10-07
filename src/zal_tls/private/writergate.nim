## Serializes application and control-record writes without holding a lock
## across transport waits. The containing stream must outlive every waiter.
import std/atomics
import zal_net/rt
import zal_net/rt/[sync, cancel]

type WriterGate* = object
  held: bool
  available: Notify

proc writerHeld*(gate: ptr WriterGate): bool {.sync.} =
  {.cast(assumeSync).}:
    result = atomicLoad(gate.held, moAcquire)

proc tryTakeWriter*(gate: ptr WriterGate): bool {.sync.} =
  {.cast(assumeSync).}:
    var expected = false
    result = atomicCompareExchange(gate.held, expected, true, moAcquireRelease, moAcquire)

proc waitWriter*(gate: ptr WriterGate; deadline: Deadline;
                 tok: nil CancelToken = nil): WaitResult {.passive, sync.} =
  {.cast(assumeSync).}:
    result = wait(addr gate.available, deadline, tok)

proc takeWriter*(gate: ptr WriterGate; deadline: Deadline;
                 tok: nil CancelToken = nil): bool {.passive, sync.} =
  {.cast(assumeSync).}:
    while not cancelled(tok) and not stopping() and monoNow() < deadline:
      if tryTakeWriter(gate): return true
      # A release between the failed claim and this wait remains observable.
      # A stale permit only causes a retry; it never grants writer admission.
      if waitWriter(gate, deadline, tok) != wrReady: return false
    result = false

proc giveWriter*(gate: ptr WriterGate) {.sync.} =
  {.cast(assumeSync).}:
    atomicStore(gate.held, false, moRelease)
    notifyOne(addr gate.available, coalesce=true)
