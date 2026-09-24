## Bounds-checked big-endian readers and writers over caller buffers. A
## read or write past the end yields zero / writes nothing and clears `ok`
## for good, so a parser checks `ok` once at the end.

import zal_tls/common

type
  Reader* = object
    p*: Bytes
    pos*, stop*: int
    ok*: bool

  Writer* = object
    p*: Bytes
    pos*, cap*: int
    ok*: bool

proc initReader*(p: Bytes; off, len: int): Reader =
  let valid = off >= 0 and len >= 0 and off <= high(int) - len
  Reader(p: p, pos: (if valid: off else: 0), stop: (if valid: off + len else: 0), ok: valid)

proc left*(r: Reader): int {.inline.} = r.stop - r.pos
proc atEnd*(r: Reader): bool {.inline.} = r.pos == r.stop
proc here*(r: Reader): Bytes {.inline.} =
  ## The address of the next byte (valid at the end too: nothing is read).
  cast[Bytes](addr r.p[r.pos])

proc take(r: var Reader; n: int): bool {.inline.} =
  if not r.ok or n < 0 or r.stop - r.pos < n:
    r.ok = false
    r.pos = r.stop
    return false
  result = true

proc u8*(r: var Reader): int =
  if not take(r, 1): return 0
  result = int(r.p[r.pos])
  r.pos = r.pos + 1

proc u16*(r: var Reader): int =
  if not take(r, 2): return 0
  result = (int(r.p[r.pos]) shl 8) or int(r.p[r.pos + 1])
  r.pos = r.pos + 2

proc u24*(r: var Reader): int =
  if not take(r, 3): return 0
  result = (int(r.p[r.pos]) shl 16) or (int(r.p[r.pos + 1]) shl 8) or int(r.p[r.pos + 2])
  r.pos = r.pos + 3

proc u32*(r: var Reader): uint32 =
  if not take(r, 4): return 0
  result = (uint32(r.p[r.pos]) shl 24) or (uint32(r.p[r.pos + 1]) shl 16) or
           (uint32(r.p[r.pos + 2]) shl 8) or uint32(r.p[r.pos + 3])
  r.pos = r.pos + 4

proc skip*(r: var Reader; n: int) =
  if take(r, n): r.pos = r.pos + n

proc sub*(r: var Reader; n: int): Reader =
  ## The next `n` bytes as their own reader (consumed here).
  if not take(r, n): return Reader(p: r.p, pos: r.stop, stop: r.stop, ok: false)
  result = Reader(p: r.p, pos: r.pos, stop: r.pos + n, ok: true)
  r.pos = r.pos + n

proc vec8*(r: var Reader): Reader =
  let n = u8(r)
  result = sub(r, n)

proc vec16*(r: var Reader): Reader =
  let n = u16(r)
  result = sub(r, n)

proc vec24*(r: var Reader): Reader =
  let n = u24(r)
  result = sub(r, n)

proc initWriter*(p: Bytes; off, len: int): Writer =
  ## `len` writable bytes beginning at `off`, as for initReader.
  let valid = off >= 0 and len >= 0 and off <= high(int) - len
  Writer(p: p, pos: (if valid: off else: 0), cap: (if valid: off + len else: 0), ok: valid)

proc room(w: var Writer; n: int): bool {.inline.} =
  if not w.ok or n < 0 or w.cap - w.pos < n:
    w.ok = false
    return false
  result = true

proc put8*(w: var Writer; v: int) =
  if room(w, 1):
    w.p[w.pos] = byte(v and 0xff)
    w.pos = w.pos + 1

proc put16*(w: var Writer; v: int) =
  if room(w, 2):
    w.p[w.pos] = byte((v shr 8) and 0xff)
    w.p[w.pos + 1] = byte(v and 0xff)
    w.pos = w.pos + 2

proc put24*(w: var Writer; v: int) =
  if room(w, 3):
    w.p[w.pos] = byte((v shr 16) and 0xff)
    w.p[w.pos + 1] = byte((v shr 8) and 0xff)
    w.p[w.pos + 2] = byte(v and 0xff)
    w.pos = w.pos + 3

proc put32*(w: var Writer; v: int) =
  if room(w, 4):
    put16(w, (v shr 16) and 0xffff)
    put16(w, v and 0xffff)

proc putBytes*(w: var Writer; src: Bytes; n: int) =
  if n > 0 and room(w, n):
    copyMem(addr w.p[w.pos], src, n)
    w.pos = w.pos + n

proc begin8*(w: var Writer): int =
  ## Reserve a one-byte length field; its offset, for `finish8`.
  result = w.pos
  put8(w, 0)

proc begin16*(w: var Writer): int =
  result = w.pos
  put16(w, 0)

proc begin24*(w: var Writer): int =
  result = w.pos
  put24(w, 0)

proc finish8*(w: var Writer; at: int) =
  ## Patch the length field at `at` with the bytes written since it.
  let n = w.pos - at - 1
  if w.ok and n <= 0xff: w.p[at] = byte(n)
  else: w.ok = false

proc finish16*(w: var Writer; at: int) =
  let n = w.pos - at - 2
  if w.ok and n <= 0xffff:
    w.p[at] = byte(n shr 8)
    w.p[at + 1] = byte(n and 0xff)
  else: w.ok = false

proc finish24*(w: var Writer; at: int) =
  let n = w.pos - at - 3
  if w.ok and n <= 0xffffff:
    w.p[at] = byte(n shr 16)
    w.p[at + 1] = byte((n shr 8) and 0xff)
    w.p[at + 2] = byte(n and 0xff)
  else: w.ok = false

proc putStr*(w: var Writer; s: string) =
  ## The bytes of `s` (no length).
  var i = 0
  while i < s.len:
    put8(w, ord(s[i]))
    i = i + 1
