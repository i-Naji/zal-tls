## Hex helpers for the test vectors.

import std/syncio

proc nibble(c: char): int =
  if c >= '0' and c <= '9': ord(c) - ord('0')
  elif c >= 'a' and c <= 'f': ord(c) - ord('a') + 10
  elif c >= 'A' and c <= 'F': ord(c) - ord('A') + 10
  else: -1

proc hex*(s: string): seq[byte] =
  result = @[]
  var i = 0
  while i + 1 < s.len:
    result.add byte(nibble(s[i]) * 16 + nibble(s[i + 1]))
    i = i + 2

proc toHex*(b: openArray[byte]): string =
  const digits = "0123456789abcdef"
  result = ""
  for x in b:
    result.add digits[int(x shr 4)]
    result.add digits[int(x and 15)]

proc ua*(b: var seq[byte]): ptr UncheckedArray[byte] =
  ## The address of b[0] (b must not be empty).
  cast[ptr UncheckedArray[byte]](addr b[0])

proc expect*(cond: bool; what: string) =
  ## An assert that names what failed (Nimony's assert prints no location).
  if not cond:
    echo "FAILED: ", what
    quit 1
