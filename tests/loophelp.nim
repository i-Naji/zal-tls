## Two connections joined through memory, for the loop, negative and fuzz
## tests: each side has an input buffer (bytes received, not yet consumed)
## and sends into a queue the other side is fed from.

import std/syncio
import zal_tls/common
import zal_tls/private/core/conn

type
  Side* = object
    c*: TlsConn
    inb*: seq[byte]
    inLen*: int
    outb*: seq[byte]
    ready*, peerClosed*: bool
    failed*: int              ## the alert once stFailed, else -1
    reason*: string
    app*: seq[byte]           ## application data received

proc initSide*(s: var Side) =
  s.inb = newSeq[byte](1 shl 18)
  s.inLen = 0
  s.outb = newSeq[byte](1 shl 17)
  s.ready = false
  s.peerClosed = false
  s.failed = -1
  s.reason = ""
  s.app = @[]

proc dropFront*(q: var seq[byte]; n: int) =
  var rest = newSeq[byte](q.len - n)
  for i in 0 ..< rest.len: rest[i] = q[n + i]
  q = rest

proc feed*(s: var Side; q: var seq[byte]; chunk: int) =
  ## Move up to `chunk` bytes from the queue into s's input.
  let n = min(chunk, min(q.len, s.inb.len - s.inLen))
  for i in 0 ..< n: s.inb[s.inLen + i] = q[i]
  s.inLen = s.inLen + n
  if n > 0: dropFront(q, n)

proc turn*(s: var Side; q: var seq[byte]): bool =
  ## One `step`; what it sends goes to q. True when anything happened.
  if s.failed >= 0: return false
  var r = default(StepResult)
  let st = step(s.c, bytesOf(s.inb), s.inLen, bytesOf(s.outb), s.outb.len, r)
  result = r.consumed > 0 or r.outLen > 0
  case st
  of stAppData, stEarlyData:
    for i in r.off ..< r.off + r.len: s.app.add s.inb[i]
    result = true
  of stReady:
    s.ready = true
    result = true
  of stPeerClosed, stClosed:
    if not s.peerClosed: result = true
    s.peerClosed = true
  of stFailed:
    s.failed = r.alert
    s.reason = r.reason
    result = true
  else: discard
  for i in 0 ..< r.outLen: q.add s.outb[i]
  if r.consumed > 0:
    let rest = s.inLen - r.consumed
    if rest > 0: moveMem(addr s.inb[0], addr s.inb[r.consumed], rest)
    s.inLen = rest

proc run*(a, b: var Side; ab, ba: var seq[byte]; chunk: int) =
  ## Turn both sides until nothing moves; `chunk` bytes are delivered per turn.
  var idle = 0
  var turns = 0
  while idle < 3 and turns < 2_000_000:
    turns = turns + 1
    feed(b, ab, chunk)
    feed(a, ba, chunk)
    var moved = turn(a, ab)
    if turn(b, ba): moved = true
    if ab.len > 0 or ba.len > 0: moved = true
    if moved: idle = 0
    else: idle = idle + 1

proc sendApp*(s: var Side; q: var seq[byte]; data: seq[byte]; recSize: int): bool =
  ## `data` as application records of up to `recSize` bytes, into q, after
  ## the control records the connection owes (a key update the peer asked for).
  result = true
  var ctl = newSeq[byte](64)
  let m = takeControl(s.c, bytesOf(ctl), ctl.len)
  for j in 0 ..< m: q.add ctl[j]
  var i = 0
  while i < data.len:
    let n = min(recSize, data.len - i)
    var buf = newSeq[byte](5 + n + 1 + 16)
    for j in 0 ..< n: buf[5 + j] = data[i + j]
    let m = sealApp(s.c, bytesOf(buf), 0, n)
    if m != buf.len: return false
    for x in buf: q.add x
    i = i + n

proc pattern*(n: int; seed: int): seq[byte] =
  result = newSeq[byte](n)
  var x = uint32(seed) * 2654435761'u32 + 1
  for i in 0 ..< n:
    x = x xor (x shl 13)
    x = x xor (x shr 17)
    x = x xor (x shl 5)
    result[i] = byte(x and 0xff)
