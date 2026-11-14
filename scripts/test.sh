#!/bin/sh
# Builds zal-net's tools/tester.nim and hands over to it; see that file for the rules.
# SUITE=fast|full|stress|platform, TESTS="tests/stream wire/tbytes tloop", WORKERS="1 4".
# KEEP=1 keeps every program and its cache under BUILD_DIR.
set -eu
cd "$(dirname "$0")/.."
NIMONY=${NIMONY:-nimony}
BUILD_DIR=${BUILD_DIR:-build/test}
# The compiler builds zal-net's plugins in their own directory: give it a path that stays valid there.
ZAL_NET_DIR=$(CDPATH= cd -- "${ZAL_NET_DIR:-../zal-net}" && pwd)
AWSLC=$(CDPATH= cd -- "${AWSLC:-build/aws-lc/install}" && pwd)
export ZAL_NET_DIR AWSLC
mkdir -p "$BUILD_DIR"
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
TESTER=$BUILD_DIR/tester
if [ ! -x "$TESTER" ] || [ "$ZAL_NET_DIR/tools/tester.nim" -nt "$TESTER" ]; then
  XDG_CACHE_HOME="$BUILD_DIR/c-cache" "$NIMONY" c --ff --nimcache:"$BUILD_DIR/cache-tester" \
    -o:"$TESTER" "$ZAL_NET_DIR/tools/tester.nim" >"$BUILD_DIR/tester.log" 2>&1 || { cat "$BUILD_DIR/tester.log" >&2; exit 1; }
fi
set -- --nimony:"$NIMONY" --build:"$BUILD_DIR" --workers:"${WORKERS:-1}"
if [ "${KEEP:-0}" = 1 ]; then set -- "$@" --keep; fi
for flag in ${NIMFLAGS:-}; do set -- "$@" --flag:"$flag"; done
if [ "${SANITIZE:-0}" = 1 ]; then
  # UBSan otherwise recovers and lets a failing sanitizer run print "ok".
  export UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1}
  for flag in --passC:-fsanitize=address,undefined --passC:-DMI_TRACK_ASAN=1 --passC:-fno-omit-frame-pointer --passL:-fsanitize=address,undefined; do
    set -- "$@" --flag:"$flag"
  done
fi
if [ -n "${TESTS:-}" ]; then
  # A path, a category/tname, or a bare test name.
  for t in $(printf '%s' "$TESTS" | tr ',' ' '); do
    if [ -e "$t" ]; then set -- "$@" "$t"
    elif [ -e "tests/$t.nim" ]; then set -- "$@" "tests/$t.nim"
    else set -- "$@" tests/*/"$t".nim; fi
  done
  exec "$TESTER" "$@"
fi
case "${SUITE:-fast}" in
  full) exec "$TESTER" "$@" tests examples ;;
  *) exec "$TESTER" "$@" --suite:"${SUITE:-fast}" ;;
esac
