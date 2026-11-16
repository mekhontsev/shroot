#!/usr/bin/env sh
set -eu
test "$#" = 1
src=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
runtime="$src/../src"
mkdir -p "$1"
sh "$src/compile-host.sh" \
    -DMD_NO_START -DMD_USE_LIBC -std=c17 -O2 -Wall -Wextra -Werror \
    "$src/test_domain.c" "$runtime/event_wait.c" "$runtime/raw.c" \
    "$runtime/memory.c" "$runtime/raw.S" -o "$1/md-domain-test"
