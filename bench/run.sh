#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NIMONY=${NIMONY:-nimony}
ZAL_NET_DIR=${ZAL_NET_DIR:-../zal-net}
AWSLC=${AWSLC:-build/aws-lc/install}
BUILD_DIR=${BUILD_DIR:-build/bench}
WORKERS=${WORKERS:-"1 4"}
RUNS=${RUNS:-5}
mkdir -p "$BUILD_DIR"
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
set -- --ff --mm:atomicArc -d:useMimalloc -d:release -d:benchTls \
  --path:src --path:"$ZAL_NET_DIR/src" --passC:"-I$AWSLC/include" \
  --passL:"$AWSLC/lib/libcrypto.a" ${NIMFLAGS:-}
if [ "$(uname)" = Linux ]; then set -- "$@" --passL:-lpthread; fi
XDG_CACHE_HOME="$BUILD_DIR/c-cache-connections" "$NIMONY" c "$@" \
  --nimcache:"$BUILD_DIR/cache-connections" -o:"$BUILD_DIR/connections" \
  "$ZAL_NET_DIR/bench/connections.nim" >"$BUILD_DIR/connections-build.log" 2>&1 || {
    cat "$BUILD_DIR/connections-build.log" >&2
    exit 1
  }
printf 'revision=%s compiler=%s\n' "$(git rev-parse HEAD)" "$NIMONY"
uname -sm
for workers in $WORKERS; do
  run=0
  while [ "$run" -lt "$RUNS" ]; do
    ZAL_WORKERS=$workers "$BUILD_DIR/connections"
    run=$((run + 1))
  done
done
