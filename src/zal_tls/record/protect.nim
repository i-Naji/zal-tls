## TLS 1.3 record protection (RFC 8446 section 5), in place: a record is
## sealed where its plaintext sits (the 5-byte header before it, the inner
## content type, padding and the tag after it) and opened where it arrived.

import zal_tls/common
import zal_tls/crypto/[aead, rand]
import zal_tls/keys/schedule
import zal_tls/wire/[bytes, consts]

const
  RecordHeaderLen* = 5
  MaxPlaintext* = 16384
  MaxCiphertext* = 16384 + 256

type
  Protection* = object
    ## One direction's keys. Owns an `Aead`: never copy it.
    suite*: Suite
    aead*: Aead
    iv*: array[12, byte]
    seq*: uint64
    live*: bool

proc clear*(p: var Protection) =
  clear(p.aead)
  wipeBytes(addr p.iv[0], p.iv.len)
  p.seq = 0
  p.live = false

proc install*(p: var Protection; suite: Suite; secret: Secret): bool =
  ## Key this direction from a traffic secret; the sequence number restarts.
  clear(p)
  p.suite = suite
  var key = default(array[32, byte])
  result = trafficKeys(suite, secret, ptrOf(key), ptrOf(p.iv)) and
    init(p.aead, aeadOf(suite), ptrOf(key), keyLen(aeadOf(suite)))
  wipeBytes(addr key[0], key.len)
  p.live = result

proc nonce(p: Protection; n: var array[12, byte]) =
  ## iv XOR the 64-bit sequence number, big-endian, right-aligned (5.3).
  n = p.iv
  var i = 0
  while i < 8:
    n[4 + i] = n[4 + i] xor byte((p.seq shr uint64(8 * (7 - i))) and 0xff)
    i = i + 1

proc writePlainHeader*(buf: Bytes; off: int; ctype, len: int; first: bool) =
  ## An unprotected record's header: legacy_record_version is 0x0301 for
  ## the first ClientHello, 0x0303 otherwise.
  buf[off] = byte(ctype)
  buf[off + 1] = 3
  buf[off + 2] = byte(if first: 1 else: 3)
  buf[off + 3] = byte(len shr 8)
  buf[off + 4] = byte(len and 0xff)

proc recordLen*(buf: Bytes; off, avail: int): int =
  ## The whole record's length once `avail` bytes hold it; 0 when more are
  ## needed; minus the alert to send for a bad header.
  if avail < RecordHeaderLen: return 0
  let ct = int(buf[off])
  if ct < ctChangeCipherSpec or ct > ctApplicationData: return -alUnexpectedMessage
  let n = (int(buf[off + 3]) shl 8) or int(buf[off + 4])
  if n > MaxCiphertext: return -alRecordOverflow
  if n == 0: return -alDecodeError               # no TLS 1.3 record is empty
  if avail < RecordHeaderLen + n: return 0
  result = RecordHeaderLen + n

proc sealRecord*(p: var Protection; buf: Bytes; off, len: int;
                 ctype: int; pad: int): int =
  ## Protect the plaintext at buf[off+5 ..< off+5+len]: writes the header at
  ## `off`, the inner type and `pad` zeros after the plaintext, then the
  ## tag. The record's length, or 0 (no keys, too long, sequence spent).
  let inner = len + 1 + pad
  if not p.live or len < 0 or pad < 0 or inner > MaxPlaintext + 1 or p.seq == high(uint64):
    return 0
  let body = off + RecordHeaderLen
  buf[body + len] = byte(ctype)
  var i = 0
  while i < pad:
    buf[body + len + 1 + i] = 0
    i = i + 1
  let total = inner + AeadTagLen
  buf[off] = byte(ctApplicationData)
  buf[off + 1] = 3
  buf[off + 2] = 3
  buf[off + 3] = byte(total shr 8)
  buf[off + 4] = byte(total and 0xff)
  var n = default(array[12, byte])
  nonce(p, n)
  if not sealInPlace(p.aead, ptrOf(n), at(buf, body), inner, at(buf, body + inner), at(buf, off),
                     RecordHeaderLen):
    return 0
  p.seq = p.seq + 1
  result = RecordHeaderLen + total

proc openRecord*(p: var Protection; buf: Bytes; off, recLen: int;
                 ctype, payOff, payLen: var int): int =
  ## Decrypt the record at `off` in place and strip its padding: 0 and the
  ## inner type and content, or the alert to send.
  if not p.live or p.seq == high(uint64): return alInternalError
  if recLen < RecordHeaderLen + 1 + AeadTagLen or recLen > RecordHeaderLen + MaxCiphertext:
    return alBadRecordMac
  let body = off + RecordHeaderLen
  let inner = recLen - RecordHeaderLen - AeadTagLen
  if inner > MaxPlaintext + 1: return alRecordOverflow   # content, type and padding (5.4)
  var n = default(array[12, byte])
  nonce(p, n)
  if not openInPlace(p.aead, ptrOf(n), at(buf, body), inner, at(buf, body + inner), at(buf, off),
                     RecordHeaderLen):
    return alBadRecordMac
  p.seq = p.seq + 1
  var i = body + inner - 1
  while i >= body and buf[i] == 0: i = i - 1
  if i < body: return alUnexpectedMessage        # no content type
  ctype = int(buf[i])
  payOff = body
  payLen = i - body
  result = 0
