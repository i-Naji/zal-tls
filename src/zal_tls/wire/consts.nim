## TLS 1.3 protocol numbers (RFC 8446), and the maps between them and the
## crypto layer's groups and signature schemes.

import zal_tls/crypto/[kx, sig]

const
  # Content types (5.1).
  ctChangeCipherSpec* = 20
  ctAlert* = 21
  ctHandshake* = 22
  ctApplicationData* = 23

  # Handshake message types (4).
  htClientHello* = 1
  htServerHello* = 2
  htNewSessionTicket* = 4
  htEndOfEarlyData* = 5
  htEncryptedExtensions* = 8
  htCertificate* = 11
  htCertificateRequest* = 13
  htCertificateVerify* = 15
  htFinished* = 20
  htKeyUpdate* = 24
  htMessageHash* = 254

  # Extension types (4.2).
  extServerName* = 0
  extSupportedGroups* = 10
  extSignatureAlgorithms* = 13
  extAlpn* = 16
  extPreSharedKey* = 41
  extEarlyData* = 42
  extSupportedVersions* = 43
  extCookie* = 44
  extPskKeyExchangeModes* = 45
  extCertificateAuthorities* = 47
  extSignatureAlgorithmsCert* = 50
  extKeyShare* = 51
  extQuicTransportParameters* = 57
  extEch* = 0xfe0d
  extEchOuterExtensions* = 0xfd00

  # Alert descriptions (6).
  alCloseNotify* = 0
  alUnexpectedMessage* = 10
  alBadRecordMac* = 20
  alRecordOverflow* = 22
  alHandshakeFailure* = 40
  alBadCertificate* = 42
  alUnsupportedCertificate* = 43
  alCertificateExpired* = 45
  alCertificateUnknown* = 46
  alIllegalParameter* = 47
  alUnknownCa* = 48
  alDecodeError* = 50
  alDecryptError* = 51
  alProtocolVersion* = 70
  alInsufficientSecurity* = 71
  alInternalError* = 80
  alMissingExtension* = 109
  alUnsupportedExtension* = 110
  alUnrecognizedName* = 112
  alCertificateRequired* = 116
  alNoApplicationProtocol* = 120
  alEchRequired* = 121

  Tls13* = 0x0304
  Tls12* = 0x0303

  # The HelloRetryRequest's fixed random: SHA-256("HelloRetryRequest") (4.1.3).
  HrrRandom*: array[32, byte] = [0xcf'u8, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
    0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c]
  # The last 8 bytes of a ServerHello.random that negotiated TLS 1.2 / 1.1
  # or below (4.1.3): a TLS 1.3 client must refuse them.
  Downgrade12*: array[8, byte] = [0x44'u8, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01]
  Downgrade11*: array[8, byte] = [0x44'u8, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00]

proc groupCode*(g: KxGroup): int =
  case g
  of kxX25519: 0x001d
  of kxSecp256r1: 0x0017
  of kxX25519MlKem768: 0x11ec

proc groupOf*(code: int; g: var KxGroup): bool =
  result = true
  case code
  of 0x001d: g = kxX25519
  of 0x0017: g = kxSecp256r1
  of 0x11ec: g = kxX25519MlKem768
  else: result = false

proc schemeOf*(code: int; s: var SigScheme): bool =
  result = false
  for x in [sigEcdsaP256Sha256, sigEcdsaP384Sha384, sigRsaPssSha256, sigRsaPssSha384, sigEd25519]:
    if int(sig.code(x)) == code:
      s = x
      return true
