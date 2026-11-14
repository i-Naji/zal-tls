#!/bin/sh
# Native Linux feature lane. Refuses to count unavailable kTLS as a pass.
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = Linux ] || { echo 'kTLS feature lane requires native Linux' >&2; exit 2; }
BASE_FLAGS=${NIMFLAGS:---mm:atomicArc -d:release}
BASE_DIR=${BUILD_DIR:-build/ktls}
for feature in base Control Preloaded Cancel Truncate Fallback Sequence; do
  flags=$BASE_FLAGS
  tests=tkernelrelay
  case "$feature" in
    base) tests='tktls tktlsbounds tkernelsplice tkernelrelay' ;;
    Fallback) flags="$flags -d:ntSpliceFaultTest"; tests=tkernelsplice ;;
    Sequence) flags="$flags -d:ntSpliceSequenceFaultTest"; tests=tkernelsplice ;;
    *) flags="$flags -d:ntSplice${feature}Test" ;;
  esac
  # KEEP=1 leaves the programs in $BASE_DIR/$feature/ktls. The tester drops
  # what a passing test prints, so each runs once more here for its PASS and
  # SKIP lines.
  NIMFLAGS="$flags" TESTS="$tests" BUILD_DIR="$BASE_DIR/$feature" KEEP=1 sh scripts/test.sh
  for test in $tests; do
    for workers in ${WORKERS:-1}; do
      program="$BASE_DIR/$feature/ktls/$test"
      log="$program.w$workers.out"
      ZAL_WORKERS=$workers "$program" >"$log" 2>&1 || { cat "$log" >&2; echo "FAIL $feature $test workers=$workers: $log" >&2; exit 1; }
      if grep -q '^SKIP' "$log"; then
        echo "FAIL unavailable native capability: $log" >&2; exit 1
      fi
      grep -q '^PASS' "$log" || { echo "FAIL missing feature result: $log" >&2; exit 1; }
    done
  done
done
