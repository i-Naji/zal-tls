import std/[syncio, assertions]
import zal_tls/crypto/[sig, x509]
import hexutil

proc slurpText(path: string): string =
  try: result = readFile(path)
  except: result = ""

# RFC 8032 section 7.1, test 1: Ed25519 over the empty message.
var edPub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
var edSig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
var empty = newSeq[byte](1)
let ek = publicKeyEd25519(ua(edPub))
if ek == nil: quit "tsig: no Ed25519 key"
assert verify(sigEd25519, ek, ua(empty), 0, ua(edSig), edSig.len)
edSig[0] = edSig[0] xor 1
assert not verify(sigEd25519, ek, ua(empty), 0, ua(edSig), edSig.len)
release(ek)
echo "PASS ed25519: RFC 8032 test 1, tamper refused"

# RFC 6979 A.2.5: ECDSA P-256, SHA-256, "sample" (r, s as DER).
var pt = hex("0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
var der = hex("3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
var sample = hex("73616d706c65")
let pk = publicKeyP256(ua(pt))
if pk == nil: quit "tsig: no P-256 key"
assert verify(sigEcdsaP256Sha256, pk, ua(sample), sample.len, ua(der), der.len)
release(pk)
echo "PASS ecdsa p-256: RFC 6979 A.2.5"

# RSA-PSS and ECDSA: sign, verify, tamper.
var msg = hex("68656c6c6f")
var s = newSeq[byte](512)
var n = 0
let rsa = privateKeyPem(slurpText("tests/data/rsa.key"))
if rsa == nil: quit "tsig: cannot read rsa.key"
assert sign(sigRsaPssSha256, rsa, ua(msg), msg.len, ua(s), s.len, n) and n == 256
assert verify(sigRsaPssSha256, rsa, ua(msg), msg.len, ua(s), n)   # an RSA private key verifies too
s[5] = s[5] xor 1
assert not verify(sigRsaPssSha256, rsa, ua(msg), msg.len, ua(s), n)
release(rsa)
let ecPriv = privateKeyPem(slurpText("tests/data/leaf.key"))
if ecPriv == nil: quit "tsig: cannot read leaf.key"
assert sign(sigEcdsaP256Sha256, ecPriv, ua(msg), msg.len, ua(s), s.len, n)
release(ecPriv)
var leafOnly: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/leaf.pem"), leafOnly) == 1
let leafPub = publicKey(leafOnly[0])
if leafPub == nil: quit "tsig: no leaf key"
assert verify(sigEcdsaP256Sha256, leafPub, ua(msg), msg.len, ua(s), n)
s[5] = s[5] xor 1
assert not verify(sigEcdsaP256Sha256, leafPub, ua(msg), msg.len, ua(s), n)
release(leafPub)
release(leafOnly[0])
echo "PASS sign: RSA-PSS and ECDSA sign and verify (the leaf certificate's key), tamper refused"

# X.509: chain to the test root, names, time.
var roots0: seq[Cert] = @[]
var inter: seq[Cert] = @[]
var leaf: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/root.pem"), roots0) == 1
assert certsPem(slurpText("tests/data/inter.pem"), inter) == 1
assert certsPem(slurpText("tests/data/leaf.pem"), leaf) == 1
let r = newRoots()
if r == nil: quit "tsig: no store"
assert addRoot(r, roots0[0])
const Y2030 = 1893456000'i64            # 2030-01-01
const Y2040 = 2208988800'i64            # 2040-01-01
const Y2025 = 1735689600'i64            # 2025-01-01
assert verifyChain(r, leaf[0], inter, "test.example", Y2030) == vrOk
assert verifyChain(r, leaf[0], inter, "other.example", Y2030) == vrBadName
assert verifyChain(r, leaf[0], inter, "test.example", Y2040) == vrExpired
assert verifyChain(r, leaf[0], inter, "test.example", Y2025) == vrNotYetValid
var noInter: seq[Cert] = @[]
assert verifyChain(r, leaf[0], noInter, "test.example", Y2030) == vrUnknownIssuer
var cnOnly: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/cnonly.pem"), cnOnly) == 1
assert verifyChain(r, cnOnly[0], inter, "test.example", Y2030) == vrBadName   # CN alone never names a host
assert verifyChain(r, leaf[0], inter, "test.example\0evil", Y2030) != vrOk    # a NUL in the name: refused
var client: seq[Cert] = @[]
assert certsPem(slurpText("tests/data/client.pem"), client) == 1
assert verifyChain(r, client[0], inter, "client.example", Y2030) == vrBadPurpose   # not a server's
assert verifyChain(r, client[0], inter, "", Y2030, cpClient) == vrOk
assert verifyChain(r, leaf[0], inter, "", Y2030, cpClient) == vrBadPurpose        # not a client's
let empty0 = newRoots()
if empty0 == nil: quit "tsig: no store"
assert verifyChain(empty0, roots0[0], noInter, "", Y2030) == vrUnknownIssuer     # a self-signed leaf
release(empty0)
release(client[0])
release(cnOnly[0])
release(r)
release(leaf[0])
release(inter[0])
release(roots0[0])
echo "PASS x509: chain ok, wrong name, expired, not yet valid, missing intermediate, CN only, NUL in name, purpose, self-signed leaf"

# A scheme must match its key: TLS 1.3 has no RSA PKCS#1 v1.5 and no ECDSA
# P-384 with SHA-256 (signatures made by tests/data/mkcerts.sh).
proc slurpBytes(path: string): seq[byte] =
  let t = slurpText(path)
  result = newSeq[byte](t.len)
  var i = 0
  while i < t.len:
    result[i] = byte(t[i])
    i = i + 1
var hello = hex("68656c6c6f")
var v15 = slurpBytes("tests/data/rsa-v15.sig")
var s384 = slurpBytes("tests/data/p384-sha256.sig")
let rsaK = privateKeyPem(slurpText("tests/data/rsa.key"))
let p384K = privateKeyPem(slurpText("tests/data/p384.key"))
if rsaK == nil or p384K == nil: quit "tsig: cannot read the keys"
assert not verify(sigEcdsaP256Sha256, rsaK, ua(hello), hello.len, ua(v15), v15.len)
assert not verify(sigRsaPssSha256, rsaK, ua(hello), hello.len, ua(v15), v15.len)
assert not verify(sigEcdsaP256Sha256, p384K, ua(hello), hello.len, ua(s384), s384.len)
var sigBuf = newSeq[byte](512)
var outLen = 0
assert not sign(sigEcdsaP256Sha256, rsaK, ua(hello), hello.len, ua(sigBuf), sigBuf.len, outLen)
assert not sign(sigEcdsaP256Sha256, p384K, ua(hello), hello.len, ua(sigBuf), sigBuf.len, outLen)
assert not sign(sigRsaPssSha256, p384K, ua(hello), hello.len, ua(sigBuf), sigBuf.len, outLen)
assert sign(sigEcdsaP384Sha384, p384K, ua(hello), hello.len, ua(sigBuf), sigBuf.len, outLen)
assert verify(sigEcdsaP384Sha384, p384K, ua(hello), hello.len, ua(sigBuf), outLen)
release(rsaK)
release(p384K)
echo "PASS sig: schemes must match their keys (v1.5, P-384/SHA-256 refused)"
