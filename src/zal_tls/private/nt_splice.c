/* Optional Linux kTLS transport pump. TLS state and keys stay in Nim. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int nt_splice_pipe(int fds[2]) {
  if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0) return 0;
  if (errno != ENOSYS) return -errno;
  if (pipe(fds) != 0) return -errno;
  for (int i = 0; i < 2; ++i) {
    if (fcntl(fds[i], F_SETFL, O_NONBLOCK) < 0 ||
        fcntl(fds[i], F_SETFD, FD_CLOEXEC) < 0) {
      int error = errno;
      close(fds[0]); close(fds[1]);
      fds[0] = fds[1] = -1;
      return -error;
    }
  }
  return 0;
}

long nt_splice_move(int source, int destination, long length) {
  long count;
  do count = splice(source, NULL, destination, NULL, (size_t)length,
                   SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
  while (count < 0 && errno == EINTR);
  return count >= 0 ? count : -errno;
}

#ifdef NT_SPLICE_FAULT_TEST
static int reject_output;
void nt_test_reject_splice_output(void) { __atomic_store_n(&reject_output, 1, __ATOMIC_SEQ_CST); }
int nt_test_splice_rejection_pending(void) { return __atomic_load_n(&reject_output, __ATOMIC_SEQ_CST); }
#endif

long nt_splice_output(int source, int destination, long length) {
#ifdef NT_SPLICE_FAULT_TEST
  if (__atomic_exchange_n(&reject_output, 0, __ATOMIC_SEQ_CST)) return -EINVAL;
#endif
  return nt_splice_move(source, destination, length);
}

void nt_splice_close(int fd) { if (fd >= 0) (void)close(fd); }
