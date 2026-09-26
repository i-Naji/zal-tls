#!/bin/sh
# Interop with the OpenSSL command-line tool and curl, both roles:
#   1. OpenSSL's s_server (every suite, group and signature scheme; a
#      HelloRetryRequest) <- our tlsget;
#   2. our tlsecho (http mode) <- OpenSSL's s_client (every suite and group),
#      with a key update from s_client;
#   3. our tlsecho <- curl;
#   3b. resumption and 0-RTT both ways (tlsget/s_server, s_client/tlsecho, curl);
#   3c. client certificates both ways (s_client, s_server -Verify, curl);
#   3d. Encrypted Client Hello both ways with Go's crypto/tls (tests/goech;
#       skipped without go): accepted, a stale config refused with the
#       retry configs, through a HelloRetryRequest, GREASE (every tlsget
#       above sends GREASE ECH too: s_server ignores it);
#   4. the relay: curl and s_client through tlsterm to a plain HTTP server,
#      curl through tlsorig and tlsterm (and with NET=1 tlsorig to a real site);
#   5. with NET=1: tlsget with the system roots against a few real sites.
# Needs the programs from scripts/test.sh (build/test/loops).
#   OPENSSL=/opt/homebrew/bin/openssl  BE=loops  NET=1  GOECH=goech-binary  tests/interop.sh
set -u
cd "$(dirname "$0")/.."
O=${OPENSSL:-/opt/homebrew/bin/openssl}
[ -x "$O" ] || O=openssl
BE=${BE:-loops}
B=${BUILD_DIR:-build/test}/$BE
D=tests/data
TMP=${TMPDIR:-/tmp}/zal-tls-interop.$$
mkdir -p "$TMP"
cat $D/leaf.pem $D/inter.pem > "$TMP/chain.pem"
PORT=$((20000 + $$ % 20000))
TLS_GROUPS="X25519 P-256"
"$O" list -tls-groups 2>/dev/null | tr ':' '\n' | grep -q X25519MLKEM768 && TLS_GROUPS="$TLS_GROUPS X25519MLKEM768"
pass=0; fail=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; [ -n "${2:-}" ] && sed 's/^/     /' "$2" | head -5; fail=$((fail + 1)); }
wait_port() {
  i=0
  while [ $i -lt 50 ]; do
    if (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null; then return 0; fi
    nc -z 127.0.0.1 "$1" 2>/dev/null && return 0
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

# 1. s_server <- tlsget
server_case() {  # name, s_server options...
  name=$1; shift
  PORT=$((PORT + 1))
  "$O" s_server -quiet -accept $PORT -www -tls1_3 "$@" >"$TMP/srv.log" 2>&1 &
  spid=$!
  wait_port $PORT
  if "$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 >"$TMP/get.log" 2>&1 &&
     grep -q "HTTP/1.0 200" "$TMP/get.log"; then ok "s_server $name"; else bad "s_server $name" "$TMP/get.log"; fi
  kill $spid 2>/dev/null; wait $spid 2>/dev/null
}
for s in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  server_case "$s" -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key -ciphersuites $s
done
for g in $TLS_GROUPS; do
  server_case "group $g" -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key -groups $g
done
server_case "ECDSA P-384 leaf" -cert $D/leaf-p384.pem -cert_chain $D/inter.pem -key $D/p384.key
server_case "RSA-PSS leaf" -cert $D/leaf-rsa.pem -cert_chain $D/inter.pem -key $D/rsa.key
server_case "Ed25519 leaf" -cert $D/leaf-ed25519.pem -cert_chain $D/inter.pem -key $D/ed25519.key
server_case "HelloRetryRequest (P-256 only)" -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key -groups P-256
if grep -q "hrr=yes" "$TMP/get.log"; then ok "  ... and it was a HelloRetryRequest"; else bad "  ... no HelloRetryRequest seen" "$TMP/get.log"; fi
server_case "middlebox compat off" -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key -no_middlebox

# 2. tlsecho <- s_client
PORT=$((PORT + 1))
EP=$PORT
"$B/tlsecho" $EP "$TMP/chain.pem" $D/leaf.key http >"$TMP/echo.log" 2>&1 &
epid=$!
wait_port $PORT
client_case() {  # name, s_client options...
  name=$1; shift
  printf 'GET / HTTP/1.1\r\nHost: test.example\r\n\r\n' |
    "$O" s_client -connect 127.0.0.1:$PORT -servername test.example -CAfile $D/root.pem \
      -verify_return_error -tls1_3 -ign_eof "$@" >"$TMP/cli.log" 2>&1
  if grep -q "HTTP/1.1 200 OK" "$TMP/cli.log" && grep -q "Verify return code: 0" "$TMP/cli.log"; then
    ok "s_client $name"; else bad "s_client $name" "$TMP/cli.log"; fi
}
for s in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  client_case "$s" -ciphersuites $s
done
for g in $TLS_GROUPS; do client_case "group $g" -groups $g; done
client_case "HelloRetryRequest (a P-384 share we lack, then P-256)" -groups P-384:P-256 -msg
if grep -qi "cf 21 ad 74" "$TMP/cli.log"; then ok "  ... and it was a HelloRetryRequest"; else bad "  ... no HelloRetryRequest seen"; fi
client_case "ALPN http/1.1" -alpn http/1.1
# A key update requested by s_client in the middle of the request.
(printf 'GET / HT'; sleep 0.3; printf 'K\n'; sleep 0.3; printf 'TP/1.1\r\nHost: t\r\n\r\n'; sleep 1) |
  "$O" s_client -connect 127.0.0.1:$PORT -servername test.example -CAfile $D/root.pem -tls1_3 \
    >"$TMP/ku.log" 2>&1
if grep -q "KEYUPDATE" "$TMP/ku.log" && grep -q "HTTP/1.1 200 OK" "$TMP/ku.log"; then ok "s_client key update"
else bad "s_client key update" "$TMP/ku.log"; fi

# 2b. Linux: the same through a kTLS server (records in the kernel), with a
#     key update; and our kTLS client against s_server, every suite. The
#     kernel's TLS: loaded (or built in) when tcp_available_ulp lists it.
KTLS=0
if [ "$(uname)" = Linux ]; then
  modprobe tls 2>/dev/null
  grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null && KTLS=1
fi
if [ $KTLS = 1 ]; then
  for s in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    PORT=$((PORT + 1))
    "$O" s_server -quiet -accept $PORT -www -tls1_3 -cert $D/leaf.pem -cert_chain $D/inter.pem \
      -key $D/leaf.key -ciphersuites $s >"$TMP/ksrv.log" 2>&1 &
    spid=$!
    wait_port $PORT
    if "$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 --ktls >"$TMP/kget.log" 2>&1 &&
       grep -q "HTTP/1.0 200" "$TMP/kget.log" && grep -q "ktls=yes" "$TMP/kget.log"; then ok "s_server $s <- kTLS client"
    else bad "s_server $s <- kTLS client" "$TMP/kget.log"; fi
    kill $spid 2>/dev/null; wait $spid 2>/dev/null
  done
elif [ "$(uname)" = Linux ]; then
  echo "skip kTLS cases: no tls in /proc/sys/net/ipv4/tcp_available_ulp"
fi
if [ $KTLS = 1 ]; then
  PORT=$((PORT + 1)); KP=$PORT
  "$B/tlsecho" $KP "$TMP/chain.pem" $D/leaf.key http ktls >"$TMP/kecho.log" 2>&1 &
  kpid=$!
  wait_port $KP
  (printf 'GET / HT'; sleep 0.3; printf 'K\n'; sleep 0.3; printf 'TP/1.1\r\nHost: t\r\n\r\n'; sleep 1) |
    "$O" s_client -connect 127.0.0.1:$KP -servername test.example -CAfile $D/root.pem -tls1_3 \
      >"$TMP/kku.log" 2>&1
  if grep -q "KEYUPDATE" "$TMP/kku.log" && grep -q "HTTP/1.1 200 OK" "$TMP/kku.log"; then ok "s_client -> kTLS server, key update"
  else bad "s_client -> kTLS server, key update" "$TMP/kku.log"; fi
  kill $kpid 2>/dev/null; wait $kpid 2>/dev/null
fi

# 3. tlsecho <- curl
if curl -s --cacert $D/root.pem --resolve test.example:$EP:127.0.0.1 \
     https://test.example:$EP/ -o "$TMP/curl.out" -w '%{http_code}' >"$TMP/curl.code" 2>"$TMP/curl.err" &&
   [ "$(cat "$TMP/curl.code")" = 200 ] && grep -q ok "$TMP/curl.out"; then ok "curl"
else bad "curl" "$TMP/curl.err"; fi
kill $epid 2>/dev/null; wait $epid 2>/dev/null

# 3b. Resumption and 0-RTT, both roles: s_server (tickets, -early_data) <-
#     tlsget --again / --early; our tlsecho (tickets, 0-RTT) <- s_client
#     -sess_out / -sess_in / -early_data, and curl fetching twice.
PORT=$((PORT + 1))
"$O" s_server -quiet -accept $PORT -www -tls1_3 -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key \
  >"$TMP/rsrv.log" 2>&1 &
spid=$!
wait_port $PORT
"$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 --again >"$TMP/r1.log" 2>&1
if [ "$(grep -c 'HTTP/1.0 200' "$TMP/r1.log")" = 2 ] && grep -q "resumed=yes" "$TMP/r1.log"; then
  ok "s_server <- tlsget: the second connection resumed"
else bad "s_server <- tlsget: the second connection resumed" "$TMP/r1.log"; fi
kill $spid 2>/dev/null; wait $spid 2>/dev/null
# 0-RTT: s_server answers it with -www only from OpenSSL 3.2 on.
PORT=$((PORT + 1))
"$O" s_server -quiet -accept $PORT -www -tls1_3 -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key \
  -early_data >"$TMP/rsrv2.log" 2>&1 &
spid=$!
if wait_port $PORT; then
  "$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 --early >"$TMP/r2.log" 2>&1
  if [ "$(grep -c 'HTTP/1.0 200' "$TMP/r2.log")" = 2 ] && grep -q "resumed=yes early=yes" "$TMP/r2.log"; then
    ok "s_server <- tlsget: 0-RTT accepted"
  else bad "s_server <- tlsget: 0-RTT accepted" "$TMP/r2.log"; fi
else
  echo "skip s_server 0-RTT: $(head -1 "$TMP/rsrv2.log")"
fi
kill $spid 2>/dev/null; wait $spid 2>/dev/null
PORT=$((PORT + 1)); RP=$PORT
"$B/tlsecho" $RP "$TMP/chain.pem" $D/leaf.key http early >"$TMP/recho.log" 2>&1 &
rpid=$!
wait_port $RP
REQ='GET / HTTP/1.1\r\nHost: test.example\r\n\r\n'
sclient() { "$O" s_client -connect 127.0.0.1:$RP -servername test.example -CAfile $D/root.pem -tls1_3 -ign_eof "$@"; }
printf "$REQ" | sclient -sess_out "$TMP/sess1.pem" >"$TMP/rc1.log" 2>&1
printf "$REQ" | sclient -sess_in "$TMP/sess1.pem" -sess_out "$TMP/sess2.pem" >"$TMP/rc2.log" 2>&1
if grep -q "Reused, TLSv1.3" "$TMP/rc2.log" && grep -q "ok resumed=yes" "$TMP/rc2.log"; then
  ok "s_client -sess_in -> tlsecho: resumed"
else bad "s_client -sess_in -> tlsecho: resumed" "$TMP/rc2.log"; fi
printf "$REQ" > "$TMP/early.txt"
sclient -sess_in "$TMP/sess2.pem" -early_data "$TMP/early.txt" </dev/null >"$TMP/rc3.log" 2>&1
if grep -q "Early data was accepted" "$TMP/rc3.log" && grep -q "ok resumed=yes early=yes" "$TMP/rc3.log"; then
  ok "s_client -early_data -> tlsecho: 0-RTT accepted"
else bad "s_client -early_data -> tlsecho: 0-RTT accepted" "$TMP/rc3.log"; fi
# ... the same ticket again: resumed, its early data refused (once per ticket;
# s_client does not send refused early data again).
sclient -sess_in "$TMP/sess2.pem" -early_data "$TMP/early.txt" </dev/null >"$TMP/rc4.log" 2>&1
if grep -q "Early data was rejected" "$TMP/rc4.log" && grep -q "Reused, TLSv1.3" "$TMP/rc4.log"; then
  ok "s_client, the same ticket again: 0-RTT refused, resumed"
else bad "s_client, the same ticket again: 0-RTT refused, resumed" "$TMP/rc4.log"; fi
if curl -V | grep -q SecureTransport; then
  echo "skip curl resumption (SecureTransport curl keeps no TLS 1.3 tickets)"
else
  curl -s --cacert $D/root.pem --resolve test.example:$RP:127.0.0.1 -H 'Connection: close' \
    https://test.example:$RP/a https://test.example:$RP/b >"$TMP/rcurl.out" 2>"$TMP/rcurl.err"
  if grep -q "ok resumed=no" "$TMP/rcurl.out" && grep -q "ok resumed=yes" "$TMP/rcurl.out"; then ok "curl: the second request resumed"
  else bad "curl: the second request resumed" "$TMP/rcurl.out"; fi
fi
kill $rpid 2>/dev/null; wait $rpid 2>/dev/null

# 3c. Client certificates both ways: tlsecho requiring one (from our client
#     CA) <- s_client with and without; s_server -Verify <- tlsget with and
#     without; curl with one.
PORT=$((PORT + 1)); CP=$PORT
"$B/tlsecho" $CP "$TMP/chain.pem" $D/leaf.key http clientca=$D/cauth-root.pem >"$TMP/cecho.log" 2>&1 &
cpid=$!
wait_port $CP
printf 'GET / HTTP/1.1\r\nHost: test.example\r\n\r\n' |
  "$O" s_client -connect 127.0.0.1:$CP -servername test.example -CAfile $D/root.pem -tls1_3 -ign_eof \
    -cert $D/cauth.pem -key $D/cauth.key >"$TMP/m1.log" 2>&1
if grep -q "ok resumed=no early=no client=yes" "$TMP/m1.log"; then ok "s_client -cert -> tlsecho (required)"
else bad "s_client -cert -> tlsecho (required)" "$TMP/m1.log"; fi
printf 'GET / HTTP/1.1\r\nHost: test.example\r\n\r\n' |
  "$O" s_client -connect 127.0.0.1:$CP -servername test.example -CAfile $D/root.pem -tls1_3 -ign_eof \
    >"$TMP/m2.log" 2>&1
if grep -qi "alert certificate required" "$TMP/m2.log" && ! grep -q "ok resumed" "$TMP/m2.log"; then
  ok "s_client without a certificate: certificate_required"
else bad "s_client without a certificate: certificate_required" "$TMP/m2.log"; fi
if curl -V | grep -q SecureTransport; then
  echo "skip curl --cert (SecureTransport curl takes no PEM key)"
else
  curl -s --cacert $D/root.pem --cert $D/cauth.pem --key $D/cauth.key --resolve test.example:$CP:127.0.0.1 \
    https://test.example:$CP/ >"$TMP/mc.out" 2>"$TMP/mc.err"
  if grep -q "client=yes" "$TMP/mc.out"; then ok "curl --cert -> tlsecho (required)"
  else bad "curl --cert -> tlsecho (required)" "$TMP/mc.err"; fi
fi
kill $cpid 2>/dev/null; wait $cpid 2>/dev/null
PORT=$((PORT + 1))
"$O" s_server -quiet -accept $PORT -www -tls1_3 -cert $D/leaf.pem -cert_chain $D/inter.pem -key $D/leaf.key \
  -Verify 1 -verify_return_error -CAfile $D/cauth-root.pem >"$TMP/msrv.log" 2>&1 &
spid=$!
wait_port $PORT
"$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 --cert $D/cauth.pem --key $D/cauth.key \
  >"$TMP/m3.log" 2>&1
if grep -q "HTTP/1.0 200" "$TMP/m3.log"; then ok "s_server -Verify <- tlsget --cert"
else bad "s_server -Verify <- tlsget --cert" "$TMP/m3.log"; fi
"$B/tlsget" test.example $PORT / --ca $D/root.pem --connect 127.0.0.1 >"$TMP/m4.log" 2>&1
if ! grep -q "HTTP/1.0 200" "$TMP/m4.log"; then ok "s_server -Verify <- tlsget without: refused"
else bad "s_server -Verify <- tlsget without: refused" "$TMP/m4.log"; fi
kill $spid 2>/dev/null; wait $spid 2>/dev/null

# 3d. ECH with Go (crypto/tls, RFC 9849): Go's client -> tlsecho with ECH
#     keys (accepted; a stale config: rejected with our retry configs;
#     through a HelloRetryRequest); tlsget -> Go's server (accepted; a stale
#     config: rejected, then accepted with the retry configs; through a
#     HelloRetryRequest; GREASE: a normal handshake).
G=${GOECH:-}                                   # a prebuilt tests/goech (no Go here)
if [ -z "$G" ] && command -v go >/dev/null 2>&1 && (cd tests/goech && go build -o "$TMP/goech" .) 2>"$TMP/gobuild.log"
then G="$TMP/goech"; fi
if [ -n "$G" ] && [ -x "$G" ]; then
  cat $D/other.pem $D/inter.pem > "$TMP/other.pem"
  "$G" genlist "$TMP/stale.hex" 1
  for mode in plain hrr; do
    PORT=$((PORT + 1)); EP=$PORT
    extra=""; [ $mode = hrr ] && extra=p256
    "$B/tlsecho" $EP "$TMP/chain.pem" $D/leaf.key http $extra ech=other.example:"$TMP/ours.hex" \
      alt=other.example:"$TMP/other.pem":$D/other.key >"$TMP/eecho.log" 2>&1 &
    epid=$!
    wait_port $EP
    goarg=""; [ $mode = hrr ] && goarg=hrr
    "$G" client $EP "$TMP/ours.hex" $D/root.pem test.example $goarg >"$TMP/e1.log" 2>&1
    if grep -q "ech=yes name=test.example" "$TMP/e1.log" && grep -q "^ech=true" "$TMP/e1.log"; then
      ok "go client ($mode) -> tlsecho: ECH accepted"
    else bad "go client ($mode) -> tlsecho: ECH accepted" "$TMP/e1.log"; fi
    if [ $mode = plain ]; then
      "$G" client $EP "$TMP/stale.hex" $D/root.pem test.example >"$TMP/e2.log" 2>&1
      if grep -q "^rejected retry=$(cat "$TMP/ours.hex")\$" "$TMP/e2.log"; then
        ok "go client, a stale config -> tlsecho: rejected, our retry configs"
      else bad "go client, a stale config -> tlsecho: rejected, our retry configs" "$TMP/e2.log"; fi
    fi
    kill $epid 2>/dev/null; wait $epid 2>/dev/null
    PORT=$((PORT + 1)); GP=$PORT
    "$G" server $GP "$TMP/go.hex" "$TMP/chain.pem" $D/leaf.key "$TMP/other.pem" $D/other.key $goarg \
      >"$TMP/gsrv.log" 2>&1 &
    gpid=$!
    wait_port $GP
    "$B/tlsget" test.example $GP / --ca $D/root.pem --connect 127.0.0.1 --ech "$TMP/go.hex" >"$TMP/e3.log" 2>&1
    want="hrr=no"; [ $mode = hrr ] && want="hrr=yes"
    if grep -q "sni=test.example ech=true" "$TMP/e3.log" && grep -q "$want.*ech=yes" "$TMP/e3.log"; then
      ok "tlsget -> go server ($mode): ECH accepted"
    else bad "tlsget -> go server ($mode): ECH accepted" "$TMP/e3.log"; fi
    if [ $mode = plain ]; then
      "$B/tlsget" test.example $GP / --ca $D/root.pem --connect 127.0.0.1 --ech "$TMP/stale.hex" >"$TMP/e4.log" 2>&1
      if grep -q "ECH rejected, retry configs $(cat "$TMP/go.hex")\$" "$TMP/e4.log" &&
         grep -q "sni=test.example ech=true" "$TMP/e4.log"; then
        ok "tlsget, a stale config -> go server: rejected, then accepted with the retry configs"
      else bad "tlsget, a stale config -> go server: rejected, then accepted with the retry configs" "$TMP/e4.log"; fi
      "$B/tlsget" test.example $GP / --ca $D/root.pem --connect 127.0.0.1 >"$TMP/e5.log" 2>&1
      if grep -q "sni=test.example ech=false" "$TMP/e5.log"; then ok "tlsget (GREASE ECH) -> go server"
      else bad "tlsget (GREASE ECH) -> go server" "$TMP/e5.log"; fi
    fi
    kill $gpid 2>/dev/null; wait $gpid 2>/dev/null
  done
else
  echo "skip ECH with Go (no go, or it did not build: $(head -1 "$TMP/gobuild.log" 2>/dev/null))"
fi

# 4. The relay: tlsterm (TLS in, plain out) and tlsorig (plain in, TLS out)
#    in front of a plain HTTP server.
if command -v python3 >/dev/null 2>&1 && [ -x "$B/tlsterm" ] && [ -x "$B/tlsorig" ]; then
  mkdir -p "$TMP/www"
  echo "relayed through zal-tls" > "$TMP/www/hello.txt"
  HP=$((PORT + 1)); TP=$((PORT + 2)); OP=$((PORT + 3)); PORT=$OP
  python3 -m http.server $HP --bind 127.0.0.1 --directory "$TMP/www" >"$TMP/http.log" 2>&1 &
  hpid=$!
  "$B/tlsterm" $TP "$TMP/chain.pem" $D/leaf.key 127.0.0.1:$HP >"$TMP/term.log" 2>&1 &
  tpid=$!
  "$B/tlsorig" $OP 127.0.0.1:$TP test.example $D/root.pem >"$TMP/orig.log" 2>&1 &
  opid=$!
  wait_port $HP; wait_port $TP; wait_port $OP
  if curl -s --cacert $D/root.pem --resolve test.example:$TP:127.0.0.1 \
       https://test.example:$TP/hello.txt 2>"$TMP/c1.err" | grep -q "relayed through"; then ok "curl -> tlsterm -> http"
  else bad "curl -> tlsterm -> http" "$TMP/c1.err"; fi
  printf 'GET /hello.txt HTTP/1.0\r\n\r\n' |
    "$O" s_client -connect 127.0.0.1:$TP -servername test.example -CAfile $D/root.pem \
      -verify_return_error -tls1_3 -ign_eof >"$TMP/c2.log" 2>&1
  if grep -q "relayed through" "$TMP/c2.log"; then ok "s_client -> tlsterm -> http"
  else bad "s_client -> tlsterm -> http" "$TMP/c2.log"; fi
  if curl -s http://127.0.0.1:$OP/hello.txt 2>"$TMP/c3.err" | grep -q "relayed through"; then
    ok "curl -> tlsorig -> tlsterm -> http"
  else bad "curl -> tlsorig -> tlsterm -> http" "$TMP/c3.err"; fi
  kill $hpid $tpid $opid 2>/dev/null; wait $hpid $tpid $opid 2>/dev/null
  if [ "${NET:-0}" = 1 ]; then
    OP=$((PORT + 1)); PORT=$OP
    "$B/tlsorig" $OP www.cloudflare.com:443 www.cloudflare.com >"$TMP/orig2.log" 2>&1 &
    opid=$!
    wait_port $OP
    if curl -s -o /dev/null -w '%{http_code}' -H 'Host: www.cloudflare.com' http://127.0.0.1:$OP/ \
         >"$TMP/c4.code" 2>&1 && grep -q '^[23]' "$TMP/c4.code"; then ok "curl -> tlsorig -> www.cloudflare.com"
    else bad "curl -> tlsorig -> www.cloudflare.com" "$TMP/c4.code"; fi
    kill $opid 2>/dev/null; wait $opid 2>/dev/null
  fi
fi

# 5. Real sites.
if [ "${NET:-0}" = 1 ]; then
  for h in www.cloudflare.com www.google.com github.com; do
    if "$B/tlsget" $h 443 / >"$TMP/net.log" 2>&1 && grep -q "HTTP/1.1" "$TMP/net.log"; then ok "net $h"
    else bad "net $h" "$TMP/net.log"; fi
  done
fi
rm -rf "$TMP"
echo "interop: $pass ok, $fail failed"
[ $fail = 0 ]
