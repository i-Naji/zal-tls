## A borrowed lifetime hook for library-owned background flushes. The context
## remains stable while installed. Acquire/drop retain the shared stream state;
## acquire keeps that context alive until the matching drop, without blocking.
type BackgroundLease* = object
  context*: nil pointer
  acquire*, drop*: nil proc (context: pointer) {.nimcall.}

proc retain*(lease: BackgroundLease) =
  let context = lease.context
  let callback = lease.acquire
  if context != nil and callback != nil: callback(context)

proc release*(lease: BackgroundLease) =
  let context = lease.context
  let callback = lease.drop
  if context != nil and callback != nil: callback(context)
