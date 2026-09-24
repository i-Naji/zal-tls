## Peek at a ClientHello before choosing how to answer it (rustls'
## Acceptor): SNI, ALPN, suites, groups, key shares, signature schemes. The
## hook for SNI routing and for protocols that hand the connection off.

import zal_tls/common
import zal_tls/record/protect
import zal_tls/wire/[consts, messages]

const MaxHelloLen* = 65536

proc readClientHello*(inp: Bytes; inLen: int; v: var HelloView; recLen: var int;
                      msg: var seq[byte]): int =
  ## Look at the ClientHello at inp[0 ..] without consuming anything:
  ## 0 = more bytes are needed; > 0 = the length of the records that hold
  ## it (also in `recLen`), `v` filled and the message itself in `msg`
  ## (`v`'s offsets count from its first byte; with several records it is
  ## the only place they are contiguous); < 0 = minus the alert to send.
  recLen = 0
  msg = @[]
  var pos = 0
  var gathered: seq[byte] = @[]
  while true:
    let n = recordLen(inp, pos, inLen - pos)
    if n <= 0: return n
    if int(inp[pos]) != ctHandshake: return -alUnexpectedMessage
    let payLen = n - RecordHeaderLen
    if payLen > MaxPlaintext: return -alRecordOverflow
    if pos == 0 and payLen >= 4:
      if int(inp[5]) != htClientHello: return -alUnexpectedMessage
      let mlen = (int(inp[6]) shl 16) or (int(inp[7]) shl 8) or int(inp[8])
      if mlen + 4 > MaxHelloLen: return -alDecodeError
      if mlen + 4 == payLen:
        let a = parseClientHello(at(inp, 5), payLen, v)
        if a != 0: return -a
        msg = newSeq[byte](payLen)
        copyMem(addr msg[0], addr inp[5], payLen)
        recLen = n
        return n
      if mlen + 4 < payLen: return -alUnexpectedMessage   # nothing may follow it yet
    for i in 0 ..< payLen: gathered.add inp[pos + RecordHeaderLen + i]
    pos = pos + n
    if gathered.len >= 4:
      if int(gathered[0]) != htClientHello: return -alUnexpectedMessage
      let mlen = (int(gathered[1]) shl 16) or (int(gathered[2]) shl 8) or int(gathered[3])
      if mlen + 4 > MaxHelloLen: return -alDecodeError
      if gathered.len > mlen + 4: return -alUnexpectedMessage
      if gathered.len == mlen + 4:
        let a = parseClientHello(bytesOf(gathered), gathered.len, v)
        if a != 0: return -a
        msg = gathered
        recLen = pos
        return pos
