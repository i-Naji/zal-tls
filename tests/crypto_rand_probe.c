/* Test-only RAND interception. The dedicated build redirects RAND_bytes
   with a C preprocessor define; the shipping library has no test hooks. */
#undef RAND_bytes
#include <openssl/rand.h>
#include <string.h>

static int fail_next, calls;

void tls_arm_entropy_failure(void) {
  fail_next = 1;
  calls = 0;
}

int tls_entropy_calls(void) { return calls; }

int tls_test_random(unsigned char *output, size_t length) {
  ++calls;
  if (fail_next) {
    fail_next = 0;
    /* Keep an unguarded negative-size regression safe to diagnose. */
    if (length <= 32) memset(output, 0x42, length);
    return 0;
  }
  return RAND_bytes(output, length);
}
