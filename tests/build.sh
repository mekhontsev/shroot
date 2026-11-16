#!/usr/bin/env sh
set -eu
if [ "$#" -lt 1 ]; then
    printf 'Usage: %s BUILD_DIRECTORY [CMAKE_OPTIONS...]\n' "$0" >&2
    exit 2
fi
src=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
build=$1
shift
cmake -S "$src" -B "$build" -G Ninja -DSHROOT_BUILD_TESTS=ON "$@"
cmake --build "$build" --target shroot-check-fixtures --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
ctest --test-dir "$build" --output-on-failure
