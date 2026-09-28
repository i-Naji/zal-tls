#!/bin/sh
# SUITE=fast|full|stress|platform; TESTS selects individual cases.
set -eu
cd "$(dirname "$0")/.."
NIMONY=${NIMONY:-nimony}
WORKERS=${WORKERS:-"1"}
BUILD_DIR=${BUILD_DIR:-build/test}
ZAL_NET_DIR=${ZAL_NET_DIR:-../zal-net}
AWSLC=${AWSLC:-build/aws-lc/install}
set -- --path:src --path:"$ZAL_NET_DIR/src" --passC:"-I$AWSLC/include" --passL:"$AWSLC/lib/libcrypto.a" ${NIMFLAGS:-}
if [ "$(uname)" = Linux ]; then set -- "$@" --passL:-lpthread; fi
if [ "${SANITIZE:-0}" = 1 ]; then
  # UBSan otherwise recovers and lets a failing sanitizer run print "ok".
  export UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1}
  set -- "$@" --passC:-fsanitize=address,undefined --passC:-DMI_TRACK_ASAN=1 --passC:-fno-omit-frame-pointer --passL:-fsanitize=address,undefined
fi
mkdir -p "$BUILD_DIR"
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
if [ -z "${TESTS:-${ONLY:-}}" ]; then
  case "${SUITE:-fast}" in
    fast) TESTS="tbytes taead thash tconfig trecordapi thandshake ttlsref tapplicationtls tcryptobounds twritergate" ;;
    full) ;;
    stress) TESTS="tmemory tfuzz" ;;
    platform) TESTS="tktls tktlsbounds tkernelsplice tkernelrelay" ;;
    *) echo "unknown SUITE (fast, full, stress, platform)" >&2; exit 2 ;;
  esac
fi
fail=0
prune_case() {
  if [ "${PRUNE_CASE_CACHES:-0}" = 1 ]; then
    rm -rf "$BUILD_DIR/$be/cache-$name" "$BUILD_DIR/$be/c-cache-$name"
  fi
}
for be in runtime; do
  flag="--mm:atomicArc -d:useMimalloc"
  mkdir -p "$BUILD_DIR/$be"
  selected=$(printf '%s' "${TESTS:-${ONLY:-}}" | tr ',' ' ')
  if [ -n "$selected" ]; then srcs=$(for t in $selected; do printf 'tests/%s.nim ' "$t"; done)
  else srcs="tests/t*.nim examples/*.nim"; fi
  for src in $srcs; do
    name=$(basename "$src" .nim)
    out="$BUILD_DIR/$be/$name"
    if ! XDG_CACHE_HOME="$BUILD_DIR/$be/c-cache-$name" "$NIMONY" c --ff $flag "$@" --nimcache:"$BUILD_DIR/$be/cache-$name" -o:"$out" "$src" >"$out.log" 2>&1; then
      echo "FAIL build $be $name (see $out.log)"; fail=1; continue
    fi
    case "$src" in examples/*) echo "ok   build $be $name"; prune_case; continue;; esac
    case_failed=0
    for w in $WORKERS; do
      if ZAL_WORKERS=$w "$out" >"$out.w$w.out" 2>&1; then echo "ok   $be $name workers=$w"
      else echo "FAIL $be $name workers=$w (see $out.w$w.out)"; fail=1; case_failed=1; fi
    done
    if [ "$case_failed" = 0 ]; then prune_case; fi
  done
done
exit $fail
