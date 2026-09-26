#!/bin/sh
# Test PKI for client certificates (mTLS): a client CA (its key is not
# kept) -> "client.example" leaves on one P-256 key (cauth.key, kept: the
# tests sign with it): cauth.pem (clientAuth), cauth-expired.pem (expired
# 2025), cauth-server.pem (serverAuth only: not for a client),
# cauth-short.pem (expires 2026-10-01), cauth-big.pem (300 names, ~6.7 KB) and
# cauth-huge.pem (450 names, ~10 KB): client certificates in tickets. Needs the
# OpenSSL 3.4+ command-line tool (-not_before/-not_after).
# The outputs are committed; rerun only to replace them.
set -eu
cd "$(dirname "$0")"
O=${OPENSSL:-/opt/homebrew/bin/openssl}
NB=20260101000000Z NA=20360101000000Z
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out cauth-root.key
$O req -x509 -new -key cauth-root.key -subj /CN=zal-tls-test-client-ca -not_before $NB -not_after $NA \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out cauth-root.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out cauth.key
$O req -new -key cauth.key -subj /CN=client.example -out cauth.csr
leaf() {  # out, extendedKeyUsage, not_before, not_after[, names]
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$2" > cauth.ext
  if [ -n "${5:-}" ]; then
    printf 'subjectAltName=' >> cauth.ext
    i=0; while [ $i -lt "$5" ]; do [ $i -gt 0 ] && printf ',' >> cauth.ext; printf 'DNS:c%03d.client.example' $i >> cauth.ext; i=$((i + 1)); done
    printf '\n' >> cauth.ext
  fi
  $O x509 -req -in cauth.csr -CA cauth-root.pem -CAkey cauth-root.key -not_before $3 -not_after $4 \
    -extfile cauth.ext -out "$1"
}
leaf cauth.pem clientAuth $NB $NA
leaf cauth-expired.pem clientAuth 20240101000000Z 20250101000000Z
leaf cauth-server.pem serverAuth $NB $NA
leaf cauth-short.pem clientAuth $NB 20261001000000Z
leaf cauth-big.pem clientAuth $NB $NA 300
leaf cauth-huge.pem clientAuth $NB $NA 450
rm -f cauth.csr cauth.ext cauth-root.key cauth-root.srl
