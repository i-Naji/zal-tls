import zal_net/net/endpointdial
## TLS handshakes on a zal-net relay connection, inline in the caller's
## passive frame (like Kage's `receiveRequest`): the peer's records land in
## one direction's buffer, our flights are built in the other's, and the
## parks are the relay's own. Records that arrive with the handshake's last
## flight stay in place for the framer; 0-RTT a server takes becomes the
## direction's first spans (relayed first; `tlsReadPlain` starts with it).
## Tickets a client gets are stored through its configuration. On success the TLS framer is on
## that side's two directions already (so `failConn` frees the TLS state
## too); `useKtls` may hand it to the kernel; `tlsReadPlain` reads a
## protocol header first.
##
## ```nim
## proc serveConn(fd: cint; srv: ptr MyServer) {.passive.} =
##   let c = newConn(srv.timeoutMs)
##   if c == nil: (lingerRst(fd); return)
##   c.fd = fd
##   var t: TlsSide = nil
##   var ok = false
##   tlsAccept(c, addr srv.tls, t, ok)
##   if not ok: (failConn(c, "tls"); return)
##   dialEndpointInline(srv.upstream, true, 10_000, c.up)
##   if c.up < 0: (failConn(c, "upstream"); return)    # frees the TLS side too
##   c.a.dst = c.up
##   c.b.src = c.up
##   c.b.dst = c.fd
##   startPumps(c)
## ```

import zal_tls/common

import zal_tls/config/config
import zal_tls/raw/[framer, ktls]
import zal_tls/record/protect
import zal_net/rt
import zal_net/raw/io
import zal_net/relay
export framer

const
  HsWindow = 1 shl 16         ## a handshake read takes at most this: room stays for what follows
  HsOutRoom = 16384 + 512     ## the tail of `into`'s buffer where flights are built (drained in pieces)
  RelayEarlyRoom = BufCap - HeadRoom - HsOutRoom - HsWindow - 2 * (RecordHeaderLen + MaxCiphertext)

proc relayEarlyCap*(): int {.inline.} =
  ## 0-RTT a relay's server side holds at most (its tickets promise no
  ## more, and a ticket that promised more gets its 0-RTT refused).
  max(1, RelayEarlyRoom)

proc dirBuf(d: DirectionPtr): Bytes {.inline.} = buf(d)

template tlsHandshake*(c: Conn; t: TlsTrafficPtr; sock: cint; into: DirectionPtr; ok: var bool) =
  ## Drive t's handshake on `sock`: its records land in `into` (whose
  ## source it becomes, fresh: nothing buffered); our flights are built in
  ## that buffer's tail, which reads leave alone, and go out in pieces.
  ## Within the connection's timeout.
  block:
    ok = false
    let hsIn = into
    let hsOutDir = into
    hsIn.src = sock
    let hsOut = BufCap - HsOutRoom
    let hsDeadline = afterMs(c.timeoutMs)
    var hsRes = 0
    var hsR = default(StepResult)
    hsIn.nspans = 0
    hsIn.bytes = 0
    while ensurePayload(hsIn):
      let hsBase = hsIn.off
      let hsSt = stepSide(t, at(dirBuf(hsIn), hsIn.off), hsIn.fill - hsIn.off,
                      at(dirBuf(hsOutDir), hsOut), BufCap - hsOut, hsR)
      hsIn.off = hsIn.off + hsR.consumed
      if hsSt == stEarlyData:
        # 0-RTT the server took: decrypted in place, relayed first. One
        # span: each record's plaintext moves down to the end of the last
        # (over the record headers and tags between), however many records.
        if hsIn.nspans == 0:
          hsIn.spans[0] = Span(off: hsBase + hsR.off, len: hsR.len)
          hsIn.nspans = 1
        else:
          let hsEnd = hsIn.spans[0].off + hsIn.spans[0].len
          if hsR.len > 0: moveMem(bufAt(hsIn, hsEnd), bufAt(hsIn, hsBase + hsR.off), hsR.len)
          hsIn.spans[0].len = hsIn.spans[0].len + hsR.len
        hsIn.bytes = hsIn.bytes + hsR.len
      elif hsSt == stSend:
        var hsSent = false
        sendAll(c, sock, bufAt(hsOutDir, hsOut), hsR.outLen, hsRes, hsSent)
        if not hsSent: break
      elif hsSt == stNeedInput:
        if hsIn.off == hsIn.fill and hsIn.nspans == 0:   # (0-RTT spans stay where they are)
          hsIn.off = HeadRoom
          hsIn.fill = HeadRoom
        # One read of what is there, at most HsWindow (the records that
        # follow the handshake stay small enough to finish in place).
        let hsRoom = min(hsOut - hsIn.fill, HsWindow)
        if hsRoom <= 0: break
        let hsN = readSome(hsIn.src, bufAt(hsIn, hsIn.fill), hsRoom)
        if hsN > 0:
          touchIo(addr c.lastIo)
          hsIn.fill = hsIn.fill + hsN
        elif hsN == IoAgain:
          parkPoll(hsIn.src, {evRead}, hsDeadline, hsRes)
          if hsRes <= 0: break
        else:
          break
      elif hsSt == stReady:
        ok = true
        break
      elif hsSt == stFailed:
        if hsR.outLen > 0:
          var hsSent = false
          sendAll(c, sock, bufAt(hsOutDir, hsOut), hsR.outLen, hsRes, hsSent)
        break
      else:
        break                                  # the peer closed, or data before the handshake ended

template tlsAccept*(c: Conn; cfg: ServerConfigPtr; t: var TlsSide; ok: var bool) =
  ## The server handshake on c.fd: records into c.a (flights from its
  ## buffer's tail). On success `t` is the TLS side, already on c.a (reading) and
  ## c.b (writing); on failure it is nil. Either way the connection is the
  ## caller's (`failConn` frees the TLS side with it).
  block:
    ok = false
    t = nil
    let taT = newTraffic()
    if taT != nil:
      let taIn = addr c.a
      let taOut = addr c.b
      if initServerSide(taT, cfg, uint32(relayEarlyCap())):
        tlsHandshake(c, taT, c.fd, taIn, ok)
      if ok:
        t = taT
        useTls(taIn, taOut, taT)              # held by the connection now: failConn frees it
      else: releaseTraffic(taT)

template tlsConnect*(c: Conn; sock: cint; into, outof: DirectionPtr; cfg: ClientConfigPtr; name: string;
                     t: var TlsSide; ok: var bool) =
  ## The client handshake on `sock` (usually c.up) to `name`: records into
  ## `into` (usually addr c.b, fresh; flights from its buffer's tail), so
  ## what `outof` (usually addr c.a) holds — a request read first — stays. On success `t` is the TLS side, already on
  ## `into` (reading) and `outof` (writing).
  block:
    ok = false
    t = nil
    let tcT = newTraffic()
    if tcT != nil:
      let tcIn = into
      let tcOut = outof
      if initClientSide(tcT, cfg, name):
        tlsHandshake(c, tcT, sock, tcIn, ok)
      if ok:
        t = tcT
        useTls(tcIn, tcOut, tcT)              # held by the connection now: failConn frees it
      else: releaseTraffic(tcT)

type
  KtlsOutcome* = enum
    ktlsKernel      ## the kernel seals and opens the records
    ktlsUser        ## no kTLS here: the user-space framer goes on (as `useTls`)
    ktlsFailed      ## the records buffered were bad, or the kernel could not take both
                    ## directions: fail the connection (`failConn`)

template useKtls*(c: Conn; reader, writer: DirectionPtr; t: TlsTrafficPtr; sock: cint;
                  outcome: var KtlsOutcome) =
  ## After tlsAccept / tlsConnect: hand the TLS side's records to the
  ## kernel (Linux kTLS); `reader` reads that side, `writer` writes it (as
  ## for `useTls`). The kernel's TLS layer first (where there is none,
  ## `ktlsUser` at once); then the records already buffered in `reader` are
  ## opened here (their data goes first), reading up to the next record
  ## boundary only; then the kernel's keys and `ktlsFramer`. `ktlsUser`
  ## also when that cannot be done without loss (too many small records
  ## buffered, no room to finish one): the user-space framer goes on.
  block:
    outcome = ktlsUser
    let kuSrc = reader
    let kuDst = writer
    let kuDeadline = afterMs(c.timeoutMs)
    var kuRes = 0
    var kuGo = ktlsAttach(sock) == 0
    while kuGo:
      let kuNeed = ktlsHandover(kuSrc, t)
      if kuNeed == HandoverFailed:
        outcome = ktlsFailed
        kuGo = false
        break
      if kuNeed < 0:
        kuGo = false                            # user space goes on from here
        break
      if kuNeed == 0: break
      if kuSrc.fill + kuNeed > BufCap:
        kuGo = false                            # no room to finish the record here: user space
        break
      let kuN = readSome(kuSrc.src, bufAt(kuSrc, kuSrc.fill), kuNeed)
      if kuN > 0:
        kuSrc.fill = kuSrc.fill + kuN
      elif kuN == IoAgain:
        parkPoll(kuSrc.src, {evRead}, kuDeadline, kuRes)
        if kuRes <= 0:
          outcome = ktlsFailed
          kuGo = false
          break
      else:
        outcome = ktlsFailed                    # the peer ended or failed inside a record
        kuGo = false
        break
    if kuGo:
      let kuRc = useKtlsFramer(kuSrc, kuDst, t, sock)
      if kuRc == 0: outcome = ktlsKernel
      elif kuRc == KtlsHalfInstalled: outcome = ktlsFailed
    if outcome == ktlsUser: useTls(kuSrc, kuDst, t)

template tlsReadPlain*(c: Conn; t: TlsTrafficPtr; want: int; plainOff, plainLen: var int; ok: var bool) =
  ## After tlsAccept, for a protocol that reads a header over TLS (a
  ## Trojan-style request): open c.a's records until at least `want` bytes
  ## of plaintext lie together at c.a.buf[plainOff ..< plainOff + plainLen]
  ## (records' payloads are moved together). Parse the header there, then
  ## hand the rest to the relay with `restAsSpan`.
  block:
    ok = false
    plainOff = 0
    plainLen = 0
    let rpD = addr c.a
    let rpB = dirBuf(rpD)
    let rpDeadline = afterMs(c.timeoutMs)
    var rpEnd = -1
    var rpRes = 0
    # 0-RTT the handshake kept (spans, in order): the start of the plaintext.
    var rpI = 0
    while rpI < rpD.nspans:
      let rpS = rpD.spans[rpI]
      if rpEnd < 0:
        plainOff = rpS.off
        rpEnd = rpS.off + rpS.len
      else:
        moveMem(bufAt(rpD, rpEnd), bufAt(rpD, rpS.off), rpS.len)
        rpEnd = rpEnd + rpS.len
      rpI = rpI + 1
    rpD.nspans = 0
    rpD.bytes = 0
    while true:
      if rpEnd >= 0 and rpEnd - plainOff >= want:
        ok = true
        break
      let rpN = recordLen(rpB, rpD.off, rpD.fill - rpD.off)
      if rpN < 0: break
      if rpN == 0:
        let rpRoom = min(BufCap - rpD.fill, HsWindow)
        if rpRoom <= 0: break
        let rpK = readSome(rpD.src, bufAt(rpD, rpD.fill), rpRoom)
        if rpK > 0: rpD.fill = rpD.fill + rpK
        elif rpK == IoAgain:
          parkPoll(rpD.src, {evRead}, rpDeadline, rpRes)
          if rpRes <= 0: break
        else: break
        continue
      if int(rpB[rpD.off]) != 23: break
      var rpTyp = 0
      var rpOff = 0
      var rpLen = 0
      if openSideRecord(t, rpB, rpD.off, rpN, rpTyp, rpOff, rpLen) != 0: break
      rpD.off = rpD.off + rpN
      if rpTyp == 23:
        if rpLen > 0:
          if rpEnd < 0:
            plainOff = rpOff
            rpEnd = rpOff + rpLen
          else:
            moveMem(bufAt(rpD, rpEnd), bufAt(rpD, rpOff), rpLen)
            rpEnd = rpEnd + rpLen
      elif rpTyp == 22:
        if processSideHandshake(t, at(rpB, rpOff), rpLen) != 0: break
      else:
        break                                  # an alert before the header
    if rpEnd >= 0: plainLen = rpEnd - plainOff

proc restAsSpan*(d: DirectionPtr; off, len: int) =
  ## Plaintext at d.buf[off ..< off + len] (after a header `tlsReadPlain`
  ## gave) becomes the direction's first span: the relay sends it first.
  d.nspans = 0
  d.bytes = 0
  if len > 0:
    d.spans[0] = Span(off: off, len: len)
    d.nspans = 1
    d.bytes = len
