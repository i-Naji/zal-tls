## Writer release remains visible even before a contender registers its wait.
import std/[assertions, atomics, syncio]
import zal_net/rt
import zal_net/rt/[sync, cancel]
import zal_tls/private/writergate

var gate: WriterGate
var inside, completed, operations: int
var done: Event

proc contender() {.passive.} =
  for iteration in 0..<500:
    assert takeWriter(addr gate, afterMs(5000))
    assert atomicFetchAdd(inside, 1, moAcquireRelease) == 0
    yieldNow() # Keep admission across suspension, including worker migration.
    discard atomicFetchAdd(operations, 1, moRelaxed)
    assert atomicFetchSub(inside, 1, moAcquireRelease) == 1
    giveWriter(addr gate)
  if atomicFetchAdd(completed, 1, moAcquireRelease) == 7:
    setEvent(addr done)

proc exercise() {.passive.} =
  assert tryTakeWriter(addr gate)
  assert not tryTakeWriter(addr gate)
  # Force the exact failed-claim -> release -> wait interleaving. A Notify
  # broadcast would be lost here because no waiter was registered yet.
  giveWriter(addr gate)
  assert waitWriter(addr gate, afterMs(100)) == wrReady
  assert tryTakeWriter(addr gate)
  assert waitWriter(addr gate, afterMs(20)) == wrTimedOut,
    "a consumed wake is not duplicated"
  let tok = newCancelToken()
  cancel(tok)
  assert not takeWriter(addr gate, afterMs(100), tok)
  release(tok)
  giveWriter(addr gate)
  for child in 0..<8: assert trySpawnTask(contender())
  assert wait(addr done, afterMs(20000)) == wrReady
  assert operations == 4000 and inside == 0 and not writerHeld(addr gate)
  for iteration in 0..<1000:
    assert tryTakeWriter(addr gate)
    giveWriter(addr gate)
  assert waitWriter(addr gate, afterMs(100)) == wrReady
  assert waitWriter(addr gate, afterMs(20)) == wrTimedOut,
    "uncontended releases retain one permit, not an unbounded counter"
  requestStop()

initRuntime()
startConn(exercise())
drainRuntime()
assert runtimeFinished()
echo "PASS writer wake-before-wait, coalescing, cancellation and 4000 contended writes"
