## Included by private/core/conn. Address-stable connection and handshake storage.
type
  Step* = enum
    stNeedInput    ## read more bytes, then call again with them after the unconsumed rest
    stSend         ## send outp[0 ..< r.outLen], then call again
    stAppData      ## application data at inp[r.off ..< r.off + r.len] (decrypted in place)
    stEarlyData    ## server: 0-RTT data, same shape (replayable)
    stReady        ## the handshake is complete (once)
    stPeerClosed   ## the peer sent close_notify: no more data will come
    stClosed       ## both sides closed
    stFailed       ## r.alert and r.reason; outp[0 ..< r.outLen] is our alert, if any

  StepResult* = object
    consumed*: int
    outLen*: int
    off*, len*: int
    alert*: int
    reason*: string

  Role* = enum
    roleClient, roleServer

  ConnState* = enum
    csStart, csWaitSh, csWaitEe, csWaitCertCr, csWaitCv, csWaitFinished,
    ssStart, ssWaitCh2, ssWaitEoed, ssWaitClientCert, ssWaitClientCv, ssWaitFinished,
    stateConnected, stateFailed

  HandshakeState* = object
    ## What the handshake needs and the traffic does not: one block, freed
    ## (and wiped) when the handshake ends.
    tr256*, tr384*: Hash               ## the transcript (both until the suite is known)
    alg*: HashAlg
    algKnown*: bool
    sched*: Schedule
    keys*: array[4, KxKey]             ## client: the key shares sent
    nkeys*: int
    clientRandom*: array[32, byte]
    sessionId*: array[32, byte]
    sessionIdLen*: int
    ch*: RawBuf                        ## client: our ClientHello (what we offered)
    stage*: RawBuf                     ## handshake messages waiting to become records
    outb*: RawBuf                      ## records waiting to be sent
    outSent*: int
    hrr*: bool                         ## a HelloRetryRequest was sent or received
    hrrGroup*, hrrSuite*: int
    cookie*: RawBuf
    ccsSent*: bool
    peerKey*: nil PublicKey            ## client: the server's leaf key
    certRequested*: bool               ## the server asked for a client certificate (both sides)
    clientLeafPending*: RawBuf         ## server: the client's certificate until its CertificateVerify
    certReqCtx*: RawBuf
    echOffered*, echRejected*, echHrrAccepted*: bool   ## client: ECH offered; refused; accepted at a retry
    echRetryPending*: RawBuf           ## client: a refusing server's retry configs, until its Finished
    echCtx*: HpkeCtx                   ## client: the HPKE sender (kept for a second hello)
    echConfigId*, echMaxNameLen*, echPayloadLen*: int
    echPublicName*: array[256, byte]
    echPublicNameLen*: int
    greaseOn*: bool                    ## client: a GREASE ECH extension sent
    echSrvAccepted*, echSrvRejected*: bool   ## server: the inner hello opened / ECH offered and refused
    outerRandom*: array[32, byte]      ## client: the outer hello's random
    chOuter*: RawBuf                   ## client: the outer hello, until the server says which counts
    trOuter256*, trOuter384*: Hash     ## ... and its transcript
    clientCk*: nil CertifiedKeyPtr    ## client: the certificate presented (nil: an empty Certificate) ...
    clientScheme*: SigScheme           ## ... and its CertificateVerify's scheme
    skipEarly*: bool                   ## server: 0-RTT data was offered and is being skipped
    earlySkipped*: int                 ## ... bytes of it so far
    psk*: Secret                       ## the PSK offered (client) or accepted (server)
    pskSuite*: Suite                   ## ... the ticket's suite
    pskIssuedMs*: int64                ## client: the ticket's arrival, for its age
    pskAgeAdd*: uint32
    pskOffered*, pskAccepted*: bool
    earlyOffered*: bool                ## client: early_data sent in the ClientHello
    earlyMax*: uint32                  ## early data allowed (the ticket's)
    earlySent*: int                    ## ... sent (client) or received (server) so far
    earlySkipMax*: uint32              ## server: the opened ticket's promise (skipped as far, if refused)
    authMs*: int64                     ## server: the full handshake's time (resumed: the ticket's)
    earlyAlpn*: array[256, byte]       ## client: the ticket's ALPN (0-RTT is for that protocol)
    earlyAlpnLen*: int

  TlsConn* = object
    ## One connection. Plain data: embeddable in a connection block; `release`
    ## frees what it owns.
    wire*: nil HandshakeWirePtr        ## borrowed; nil selects TLS records
    role*: Role
    state*: ConnState
    cs*: Suite
    rd*, wr*: Protection
    rdSecret*, wrSecret*: Secret       ## the current application traffic secrets
    exporter*, resumption*: Secret
    hs*: nil HandshakeStatePtr
    ccfg*: nil ClientConfigPtr
    scfg*: nil ServerConfigPtr
    onStart*: nil proc (c: TlsConnPtr; hs: HandshakeStatePtr): int {.nimcall.}
    onMsg*: nil proc (c: TlsConnPtr; hs: HandshakeStatePtr; typ: int;
                      msg: Bytes; len: int): int {.nimcall.}
    msg*: RawBuf                       ## handshake message reassembly
    maxMsg*: int
    keyChanged*: bool                  ## read keys changed: the record must end here
    appWrite*: bool                    ## the write keys are application keys
    readyPending*, ready*: bool
    retried*: bool                     ## the handshake went through a HelloRetryRequest
    resumed*: bool                     ## a PSK (ticket) was accepted: no certificate this time
    earlyWrite*: bool                  ## client: `sealEarly` may seal 0-RTT data now
    earlyAccepted*, earlyRejected*: bool  ## the server took the 0-RTT data / skipped it (resend it) ...
    earlyAlpnChanged*: bool            ## ... for another protocol than the ticket's: do not resend it
    echAccepted*, echRejected*: bool   ## the server took the client's ECH / refused it (client: only once
                                       ## the refusing server's Finished is verified; ech_required sent)
    echRetry*: RawBuf                  ## client: the retry_configs of a refusing server, authenticated
    rdClosed*, wrClosed*: bool
    failAlert*: int
    failReceived*: bool
    replyOwed*: bool                   ## the peer asked for a key update: `takeControl` sends it
    ccsSeen*: int                      ## change_cipher_spec records dropped so far
    earlyCap*: uint32                  ## server: the most 0-RTT this connection can hold (0: no
                                       ## limit of its own; a relay's buffer has one)
    keyUpdateEvery*: uint64            ## records per write key before our own key update (0: KeyUpdateAfter)
    keyUpdatesIn*, keyUpdatesOut*: int ## the peer's key updates taken, ours sent (write keys rolled)
    emptyRun*: int                     ## empty application records in a row
    alpnBuf*: array[256, byte]
    alpnLen*: int
    nameBuf*: array[256, byte]
    nameLen*: int
    peerLeaf*: RawBuf

  TlsConnPtr* = ptr TlsConn
  HandshakeStatePtr* = ptr HandshakeState
