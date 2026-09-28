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
  NIMFLAGS="$flags" TESTS="$tests" BUILD_DIR="$BASE_DIR/$feature" sh scripts/test.sh
  for backend in runtime; do
    for test in $tests; do
      for workers in ${WORKERS:-1}; do
        log="$BASE_DIR/$feature/$backend/$test.w$workers.out"
        if grep -q '^SKIP' "$log"; then
          echo "FAIL unavailable native capability: $log" >&2; exit 1
        fi
        grep -q '^PASS' "$log" || { echo "FAIL missing feature result: $log" >&2; exit 1; }
      done
    done
  done
done
