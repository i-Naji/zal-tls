## Owned byte storage for protocol state; always wiped before release.
import zal_tls/common
import zal_tls/crypto/rand
import std/syncio

type
  RawBuf* = object
    ## A growable byte buffer outside the managed heap (plain data).
    p*: nil Bytes
    len*, cap*: int

  BufferAllocator* = proc (size: int): nil pointer {.nimcall.}
    ## Test seam: successful allocations must be compatible with dealloc.

proc allocateBuffer(size: int): nil pointer = cast[nil pointer](alloc(size))


proc base*(b: var RawBuf): Bytes =
  ## The buffer (allocated on first use).
  let p = b.p
  if p != nil: return p
  let q = cast[Bytes](alloc(512))
  b.p = q
  b.cap = 512
  result = q

proc tryGrow*(b: var RawBuf; n: int; allocate: BufferAllocator = allocateBuffer): nil Bytes =
  ## Nil for invalid/overflowing dimensions. Failure leaves storage unchanged.
  if n < 0 or b.len < 0 or b.cap < 0 or b.len > b.cap: return nil
  if b.len > high(int) - n: return nil
  let need = b.len + n
  let p = b.p
  if p == nil and b.len != 0: return nil
  if p != nil and need <= b.cap: return p
  var cap = need
  if b.cap <= high(int) div 2: cap = max(cap, b.cap * 2)
  if cap < 512: cap = 512
  # realloc may free the previous allocation before we can wipe it. Growth is
  # protocol/control storage, never the established application-record path.
  let q = cast[nil Bytes](allocate(cap))
  if q == nil: return nil
  if p != nil:
    if b.len > 0: copyMem(q, p, b.len)
    wipeBytes(p, b.cap)
    dealloc(p)
  b.p = q
  b.cap = cap
  result = q

proc grow*(b: var RawBuf; n: int): Bytes =
  ## Room for `n` more bytes. Internal misuse fails closed before copying.
  let p = tryGrow(b, n)
  if p == nil: quit "zal-tls: invalid buffer growth"
  result = p

proc append*(b: var RawBuf; src: Bytes; n: int) =
  if n <= 0: return
  let p = grow(b, n)
  copyMem(addr p[b.len], src, n)
  b.len = b.len + n

proc free*(b: var RawBuf) =
  let p = b.p
  if p != nil:
    wipeBytes(p, b.cap)
    dealloc(p)
  b.p = nil
  b.len = 0
  b.cap = 0
