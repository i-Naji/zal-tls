#!/bin/sh
# AWS-LC static libcrypto, pinned by
# ci/aws-lc.ref, built with CMake (no libssl, Go or Perl) and installed under
# <dir>/install (include/, lib/libcrypto.a). Safe to run again.
#   scripts/awslc-setup.sh [dir]     default build/aws-lc
#   CC=<compiler>                    e.g. musl-gcc for static Linux builds
#   JOBS=8  AWSLC_CMAKE_FLAGS="..."  (e.g. -DCMAKE_TOOLCHAIN_FILE=...)
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
set -- "${1:-$HERE/build/aws-lc}" $(cat "$HERE/ci/aws-lc.ref")
DIR=$1 TAG=$2 COMMIT=$3    # $4: the release tarball's SHA-256 (awslc-setup.ps1)
mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
if [ ! -d "$DIR/src/.git" ]; then
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$TAG" https://github.com/aws/aws-lc.git "$DIR/src"
fi
head=$(git -C "$DIR/src" rev-parse HEAD)
if [ "$head" != "$COMMIT" ]; then
  git -C "$DIR/src" fetch -q --depth 1 origin tag "$TAG"
  git -C "$DIR/src" checkout -q "$TAG"
  head=$(git -C "$DIR/src" rev-parse HEAD)
fi
if [ "$head" != "$COMMIT" ]; then
  echo "awslc-setup: $TAG is $head, expected $COMMIT" >&2
  exit 1
fi
# A build directory remembers its compiler: another CC or other flags start afresh.
cfg="CC=${CC:-} FLAGS=${AWSLC_CMAKE_FLAGS:-}"
if [ -f "$DIR/build/nn-config" ] && [ "$(cat "$DIR/build/nn-config")" != "$cfg" ]; then
  rm -rf "$DIR/build" "$DIR/install"
fi
cmake -S "$DIR/src" -B "$DIR/build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$DIR/install" -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DBUILD_LIBSSL=OFF \
  -DDISABLE_GO=ON -DDISABLE_PERL=ON -DBUILD_SHARED_LIBS=OFF \
  ${AWSLC_CMAKE_FLAGS:-} >"$DIR/cmake.log" 2>&1 || { tail -20 "$DIR/cmake.log" >&2; exit 1; }
cmake --build "$DIR/build" -j "${JOBS:-8}" >"$DIR/build.log" 2>&1 || { tail -20 "$DIR/build.log" >&2; exit 1; }
cmake --install "$DIR/build" >"$DIR/install.log" 2>&1
printf '%s' "$cfg" > "$DIR/build/nn-config"
echo "awslc-setup: $TAG in $DIR/install"
