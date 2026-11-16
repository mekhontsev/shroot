#!/usr/bin/env sh
set -eu
test "$#" -ge 1
src=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
build=$1
shift
cmake -S "$src/../.." -B "$build" -G Ninja "$@"
cmake --build "$build" --target shroot-cli bootstrap supervisor run service image \
    --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
