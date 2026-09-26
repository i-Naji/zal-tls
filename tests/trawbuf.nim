import std/[assertions, syncio]
import zal_tls/private/rawbuf

var calls = 0
proc refuse(size: int): nil pointer =
  calls = calls + 1
  result = nil

var b = default(RawBuf)
assert tryGrow(b, -1) == nil
assert b.p == nil and b.cap == 0
let first = grow(b, 4)
first[0] = 42
b.len = 1
assert tryGrow(b, high(int)) == nil
assert tryGrow(b, 512, refuse) == nil
assert calls == 1 and b.p == first and b.len == 1 and b.cap == 512
assert first[0] == 42
let second = grow(b, 512)
assert second[0] == 42 and b.cap >= 513
free(b)
free(b)
assert b.p == nil and b.len == 0 and b.cap == 0
echo "PASS RawBuf overflow, unchanged state on allocation failure and repeated free"
