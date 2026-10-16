## Record-oriented TLS without socket I/O. Keep each owner at a stable address
## until release. Configurations are borrowed for the entire connection lifetime.
## Handshake state and traffic-key mutation are private to the implementation.
import zal_tls/common
import zal_tls/config/config
import zal_tls/keys/schedule
import zal_tls/wire/consts
import zal_tls/record/protect
export RecordHeaderLen, MaxPlaintext, MaxCiphertext
import zal_tls/private/core/conn as implementation
import zal_tls/private/core/client as clientCore
import zal_tls/private/core/server as serverCore
export Step, StepResult

type
  TlsConn* = object
    connection: implementation.TlsConn
    initialized: bool
  TlsConnPtr* = ptr TlsConn

proc initClient*(c: TlsConnPtr; cfg: ClientConfigPtr; serverName: string): bool =
  if c.initialized: return false
  result = clientCore.initClient(c.connection, cfg, serverName)
  if result: c.initialized = true
  else: implementation.release(c.connection)

proc initServer*(c: TlsConnPtr; cfg: ServerConfigPtr): bool =
  if c.initialized: return false
  result = serverCore.initServer(c.connection, cfg)
  if result: c.initialized = true
  else: implementation.release(c.connection)

proc release*(c: TlsConnPtr) =
  ## Default and repeated release are safe; pending operations must be finished.
  if not c.initialized: return
  implementation.release(c.connection)
  c[] = default(TlsConn)

proc step*(c: TlsConnPtr; inp: Bytes; inLen: int; outp: Bytes; outCap: int;
           r: var StepResult): Step {.inline.} =
  ## Consume only r.consumed input bytes. Output and plaintext borrow the
  ## supplied buffers until the next call. Drain stSend before providing input.
  if not c.initialized:
    r = default(StepResult)
    return stClosed
  if inLen < 0 or outCap < 0:
    r = default(StepResult)
    r.alert = alInternalError
    r.reason = "negative input length or output capacity"
    return stFailed
  result = implementation.step(c.connection, inp, inLen, outp, outCap, r)

proc sealApp*(c: TlsConnPtr; buf: Bytes; off, len: int): int {.inline.} =
  ## Buffer must include TLS header and tag room. Returns full record length.
  if not c.initialized or off < 0 or len < 0 or off > high(int) - MaxCiphertext - RecordHeaderLen: return 0
  result = implementation.sealApp(c.connection, buf, off, len)
proc sealEarly*(c: TlsConnPtr; buf: Bytes; off, len: int): int {.inline.} =
  if not c.initialized or off < 0 or len < 0 or off > high(int) - MaxCiphertext - RecordHeaderLen: return 0
  result = implementation.sealEarly(c.connection, buf, off, len)
proc keyUpdate*(c: TlsConnPtr; requestPeer: bool; outp: Bytes; outCap: int): int {.inline.} =
  if not c.initialized: return 0
  result = implementation.keyUpdate(c.connection, requestPeer, outp, outCap)
proc keyUpdateDue*(c: TlsConnPtr): bool {.inline.} =
  result = c.initialized and implementation.keyUpdateDue(c.connection)
proc takeControl*(c: TlsConnPtr; outp: Bytes; outCap: int): int {.inline.} =
  if not c.initialized: return 0
  result = implementation.takeControl(c.connection, outp, outCap)
proc replyDue*(c: TlsConnPtr): bool {.inline.} =
  result = c.initialized and implementation.replyDue(c.connection)
proc close*(c: TlsConnPtr; outp: Bytes; outCap: int): int {.inline.} =
  ## Produce close_notify; the owner still needs release after output is sent.
  if not c.initialized: return 0
  result = implementation.close(c.connection, outp, outCap)
proc isReady*(c: TlsConnPtr): bool {.inline.} =
  result = c.initialized and implementation.isReady(c.connection)
proc alpn*(c: TlsConnPtr): string = implementation.alpn(c.connection)
proc serverName*(c: TlsConnPtr): string = implementation.serverName(c.connection)
proc suite*(c: TlsConnPtr): Suite = implementation.suite(c.connection)
proc resumed*(c: TlsConnPtr): bool = c.connection.resumed
proc retried*(c: TlsConnPtr): bool = c.connection.retried
proc earlyAccepted*(c: TlsConnPtr): bool = c.connection.earlyAccepted
proc earlyRejected*(c: TlsConnPtr): bool = c.connection.earlyRejected
proc echAccepted*(c: TlsConnPtr): bool = c.connection.echAccepted
proc echRetryConfigs*(c: TlsConnPtr): seq[byte] = implementation.echRetryConfigs(c.connection)
proc peerLeafDer*(c: TlsConnPtr): seq[byte] = implementation.peerLeafDer(c.connection)
proc exportKeyingMaterial*(c: TlsConnPtr; label: string; context: Bytes; ctxLen: int;
                          outp: Bytes; outLen: int): bool =
  result = c.initialized and ctxLen >= 0 and outLen >= 0 and implementation.exportKeyingMaterial(c.connection, label, context, ctxLen, outp, outLen)
