#!/bin/sh
# Test PKI for tsig: root CA -> intermediate CA -> leaf "test.example",
# P-256 throughout, valid 2026-01-01 .. 2036-01-01; plus leaves with P-384,
# RSA and Ed25519 keys, and other.example for SNI. Needs the OpenSSL 3.4+
# command-line tool (-not_before/-not_after).
# The outputs are committed; rerun only to replace them.
set -eu
cd "$(dirname "$0")"
O=${OPENSSL:-/opt/homebrew/bin/openssl}
NB=20260101000000Z NA=20360101000000Z
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key
$O req -x509 -new -key root.key -subj /CN=zal-tls-test-root -not_before $NB -not_after $NA \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out root.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter.key
$O req -new -key inter.key -subj /CN=zal-tls-test-intermediate -out inter.csr
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > inter.ext
$O x509 -req -in inter.csr -CA root.pem -CAkey root.key -not_before $NB -not_after $NA \
  -extfile inter.ext -out inter.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
$O req -new -key leaf.key -subj /CN=test.example -out leaf.csr
printf 'subjectAltName=DNS:test.example\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > leaf.ext
$O x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -not_before $NB -not_after $NA \
  -extfile leaf.ext -out leaf.pem
# A leaf valid only for client authentication (never as a server).
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out client.key
$O req -new -key client.key -subj /CN=client.example -out client.csr
printf 'subjectAltName=DNS:client.example\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
$O x509 -req -in client.csr -CA inter.pem -CAkey inter.key -not_before $NB -not_after $NA \
  -extfile client.ext -out client.pem
# A leaf naming test.example only in its subject CN (no SAN): must not match.
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out cnonly.key
$O req -new -key cnonly.key -subj /CN=test.example -out cnonly.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > cnonly.ext
$O x509 -req -in cnonly.csr -CA inter.pem -CAkey inter.key -not_before $NB -not_after $NA \
  -extfile cnonly.ext -out cnonly.pem
$O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out p384.key
$O genpkey -algorithm ED25519 -out ed25519.key
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out other.key
# Leaves for test.example with the other key types (tloop: every scheme), and
# one for other.example / *.wild.example (SNI).
for k in p384 rsa ed25519; do
  $O req -new -key $k.key -subj /CN=test.example -out $k.csr
  $O x509 -req -in $k.csr -CA inter.pem -CAkey inter.key -not_before $NB -not_after $NA \
    -extfile leaf.ext -out leaf-$k.pem
done
$O req -new -key other.key -subj /CN=other.example -out other.csr
printf 'subjectAltName=DNS:other.example,DNS:*.wild.example\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > other.ext
$O x509 -req -in other.csr -CA inter.pem -CAkey inter.key -not_before $NB -not_after $NA \
  -extfile other.ext -out other.pem
# Signatures over "hello" that a scheme check must refuse: RSA PKCS#1 v1.5
# (TLS 1.3 allows only PSS) and ECDSA P-384 with SHA-256 (no such scheme).
printf hello > hello.txt
$O dgst -sha256 -sign rsa.key -out rsa-v15.sig hello.txt
$O dgst -sha256 -sign p384.key -out p384-sha256.sig hello.txt
rm -f hello.txt
rm -f inter.csr leaf.csr client.csr cnonly.csr inter.ext leaf.ext client.ext cnonly.ext \
  p384.csr rsa.csr ed25519.csr other.csr other.ext \
  root.key inter.key client.key cnonly.key root.srl inter.srl
