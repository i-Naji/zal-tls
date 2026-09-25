/* kTLS (Linux): the kernel's side of zal-tls io/ktls.nim. Only built on Linux.
   The kernel's ABI (linux/tls.h) is copied here, so any kernel headers do:
   the layouts and numbers are fixed; kernels without a cipher or TLS 1.3
   refuse at setsockopt (-EINVAL), not at compile time. */
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define NT_SOL_TLS 282
#define NT_TCP_ULP 31
#define NT_TLS_TX 1
#define NT_TLS_RX 2
#define NT_TLS_SET_RECORD_TYPE 1
#define NT_TLS_GET_RECORD_TYPE 2
#define NT_TLS_1_3_VERSION 0x0304
#define NT_CIPHER_AES_GCM_128 51
#define NT_CIPHER_AES_GCM_256 52
#define NT_CIPHER_CHACHA20_POLY1305 54
#define NT_AGAIN (-11)          /* "try again": one value for EAGAIN and EWOULDBLOCK */

struct nt_crypto_info { unsigned short version, cipher_type; };
struct nt_aes_gcm_128 { struct nt_crypto_info info; unsigned char iv[8], key[16], salt[4], rec_seq[8]; };
struct nt_aes_gcm_256 { struct nt_crypto_info info; unsigned char iv[8], key[32], salt[4], rec_seq[8]; };
struct nt_chacha20 { struct nt_crypto_info info; unsigned char iv[12], key[32], rec_seq[8]; };

/* The ABI copies complete traffic keys; these stack copies must survive
 * neither return nor optimizer dead-store elimination. */
static void clear_secret(void *memory, size_t length) {
  volatile unsigned char *bytes = (volatile unsigned char *)memory;
  while (length--) *bytes++ = 0;
}

#ifdef NT_KTLS_FAULT_TEST
static int reject_sequence;
void nt_test_reject_tx_sequence(void) { __atomic_store_n(&reject_sequence, 1, __ATOMIC_SEQ_CST); }
#endif

static int err(void) { return (errno == EAGAIN || errno == EWOULDBLOCK) ? NT_AGAIN : -errno; }

int nt_ktls_ulp(int fd) {
  return setsockopt(fd, IPPROTO_TCP, NT_TCP_ULP, "tls", sizeof("tls")) == 0 ? 0 : -errno;
}

static void put_seq(unsigned char *out, unsigned long long seq) {
  for (int i = 7; i >= 0; i--) { out[i] = (unsigned char)(seq & 0xff); seq >>= 8; }
}

/* cipher: 0 AES-128-GCM, 1 AES-256-GCM, 2 ChaCha20-Poly1305; iv: the 12-byte TLS 1.3 IV. */
int nt_ktls_set(int fd, int tx, int cipher, const unsigned char *key, const unsigned char *iv,
                unsigned long long seq) {
  int dir = tx ? NT_TLS_TX : NT_TLS_RX;
  int r;
  if (cipher == 0) {
    struct nt_aes_gcm_128 ci;
    memset(&ci, 0, sizeof ci);
    ci.info.version = NT_TLS_1_3_VERSION;
    ci.info.cipher_type = NT_CIPHER_AES_GCM_128;
    memcpy(ci.salt, iv, 4);
    memcpy(ci.iv, iv + 4, 8);
    memcpy(ci.key, key, 16);
    put_seq(ci.rec_seq, seq);
    r = setsockopt(fd, NT_SOL_TLS, dir, &ci, sizeof ci);
    clear_secret(&ci, sizeof ci);
  } else if (cipher == 1) {
    struct nt_aes_gcm_256 ci;
    memset(&ci, 0, sizeof ci);
    ci.info.version = NT_TLS_1_3_VERSION;
    ci.info.cipher_type = NT_CIPHER_AES_GCM_256;
    memcpy(ci.salt, iv, 4);
    memcpy(ci.iv, iv + 4, 8);
    memcpy(ci.key, key, 32);
    put_seq(ci.rec_seq, seq);
    r = setsockopt(fd, NT_SOL_TLS, dir, &ci, sizeof ci);
    clear_secret(&ci, sizeof ci);
  } else {
    struct nt_chacha20 ci;
    memset(&ci, 0, sizeof ci);
    ci.info.version = NT_TLS_1_3_VERSION;
    ci.info.cipher_type = NT_CIPHER_CHACHA20_POLY1305;
    memcpy(ci.iv, iv, 12);
    memcpy(ci.key, key, 32);
    put_seq(ci.rec_seq, seq);
    r = setsockopt(fd, NT_SOL_TLS, dir, &ci, sizeof ci);
    clear_secret(&ci, sizeof ci);
  }
  return r == 0 ? 0 : -errno;
}

/* One record of `type` (a control record: handshake, alert), non-blocking. */
int nt_ktls_send(int fd, int type, const void *p, int n) {
  char cbuf[CMSG_SPACE(sizeof(unsigned char))];
  struct iovec iov = { (void *)p, (size_t)n };
  struct msghdr m;
  memset(&m, 0, sizeof m);
  memset(cbuf, 0, sizeof cbuf);
  m.msg_iov = &iov;
  m.msg_iovlen = 1;
  m.msg_control = cbuf;
  m.msg_controllen = sizeof cbuf;
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = NT_SOL_TLS;
  c->cmsg_type = NT_TLS_SET_RECORD_TYPE;
  c->cmsg_len = CMSG_LEN(sizeof(unsigned char));
  *CMSG_DATA(c) = (unsigned char)type;
  ssize_t r = sendmsg(fd, &m, MSG_DONTWAIT | MSG_NOSIGNAL);
  return r >= 0 ? (int)r : err();
}

/* Bytes of one record's plaintext and its type (23 when the kernel gives none),
   non-blocking: >0, 0 at EOF, NT_AGAIN (nothing yet), -errno. */
int nt_ktls_recv(int fd, void *p, int n, int *type) {
  char cbuf[CMSG_SPACE(sizeof(unsigned char))];
  struct iovec iov = { p, (size_t)n };
  struct msghdr m;
  memset(&m, 0, sizeof m);
  m.msg_iov = &iov;
  m.msg_iovlen = 1;
  m.msg_control = cbuf;
  m.msg_controllen = sizeof cbuf;
  ssize_t r = recvmsg(fd, &m, MSG_DONTWAIT);
  if (r < 0) return err();
  *type = 23;
  struct cmsghdr *c = CMSG_FIRSTHDR(&m);
  if (c && c->cmsg_level == NT_SOL_TLS && c->cmsg_type == NT_TLS_GET_RECORD_TYPE)
    *type = *CMSG_DATA(c);
  return (int)r;
}

/* The kernel's next send sequence number (for our own key updates), or -errno.
   The kernel wants exactly the connection's cipher's layout (0, 1, 2 as above). */
long long nt_ktls_tx_seq(int fd, int cipher) {
#ifdef NT_KTLS_FAULT_TEST
  if (__atomic_exchange_n(&reject_sequence, 0, __ATOMIC_SEQ_CST)) return -EIO;
#endif
  unsigned char buf[sizeof(struct nt_aes_gcm_256)];
  socklen_t len;
  size_t at;
  if (cipher == 0) { len = sizeof(struct nt_aes_gcm_128); at = offsetof(struct nt_aes_gcm_128, rec_seq); }
  else if (cipher == 1) { len = sizeof(struct nt_aes_gcm_256); at = offsetof(struct nt_aes_gcm_256, rec_seq); }
  else { len = sizeof(struct nt_chacha20); at = offsetof(struct nt_chacha20, rec_seq); }
  memset(buf, 0, sizeof buf);
  if (getsockopt(fd, NT_SOL_TLS, NT_TLS_TX, buf, &len) != 0) {
    int error = errno;
    clear_secret(buf, sizeof buf);
    return -error;
  }
  if (len < at + 8) {
    clear_secret(buf, sizeof buf);
    return -EINVAL;
  }
  unsigned long long s = 0;
  for (int i = 0; i < 8; i++) s = (s << 8) | buf[at + i];
  clear_secret(buf, sizeof buf);
  return (long long)s;
}
