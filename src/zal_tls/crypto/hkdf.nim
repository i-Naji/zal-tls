## HMAC and HKDF (RFC 5869) from AWS-LC, over SHA-256 or SHA-384.

import zal_tls/common
import zal_tls/crypto/[awslc, hash]

type EvpMd {.importc: "EVP_MD", header: "<openssl/digest.h>", incompleteStruct.} = object

proc EVP_sha256(): ptr EvpMd {.importc, header: "<openssl/digest.h>".}
proc EVP_sha384(): ptr EvpMd {.importc, header: "<openssl/digest.h>".}
proc HMAC(md: ptr EvpMd; key: pointer; keyLen: csize_t; data: pointer; dataLen: csize_t;
          outp: pointer; outLen: ptr cuint): nil pointer {.importc, header: "<openssl/hmac.h>".}
proc HKDF_extract(outKey: pointer; outLen: ptr csize_t; md: ptr EvpMd; secret: pointer; secretLen: csize_t;
                  salt: pointer; saltLen: csize_t): cint {.importc, header: "<openssl/hkdf.h>".}
proc HKDF_expand(outKey: pointer; outLen: csize_t; md: ptr EvpMd; prk: pointer; prkLen: csize_t;
                 info: pointer; infoLen: csize_t): cint {.importc, header: "<openssl/hkdf.h>".}

proc md(alg: HashAlg): ptr EvpMd =
  case alg
  of hashSha256: EVP_sha256()
  of hashSha384: EVP_sha384()

proc hmac*(alg: HashAlg; key: Bytes; keyLen: int;
           data: Bytes; dataLen: int; outp: Bytes): bool =
  ## `digestLen(alg)` bytes of HMAC at `outp`.
  ## Negative input lengths are rejected without modifying output.
  if keyLen < 0 or dataLen < 0: return false
  var n: cuint = 0
  result = HMAC(md(alg), key, csize_t(keyLen), data, csize_t(dataLen), outp, addr n) != nil and
    int(n) == digestLen(alg)

proc hkdfExtract*(alg: HashAlg; salt: Bytes; saltLen: int;
                  ikm: Bytes; ikmLen: int; prk: Bytes): bool =
  ## The pseudorandom key (`digestLen(alg)` bytes) at `prk`.
  if saltLen < 0 or ikmLen < 0: return false
  var n: csize_t = 0
  result = HKDF_extract(prk, addr n, md(alg), ikm, csize_t(ikmLen), salt, csize_t(saltLen)) == 1 and
    int(n) == digestLen(alg)

proc hkdfExpand*(alg: HashAlg; prk: Bytes; prkLen: int;
                 info: Bytes; infoLen: int;
                 outp: Bytes; outLen: int): bool =
  ## RFC 5869 permits at most 255 digest blocks. Invalid dimensions cause no
  ## writes; zero output succeeds without invoking crypto.
  if prkLen < 0 or infoLen < 0 or outLen < 0: return false
  if outLen > 255 * digestLen(alg): return false
  if outLen == 0: return true
  result = HKDF_expand(outp, csize_t(outLen), md(alg), prk, csize_t(prkLen), info, csize_t(infoLen)) == 1
