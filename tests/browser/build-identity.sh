#!/usr/bin/env sh
set -eu
test "$#" = 1
src=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
mkdir -p "$1"
sh "$src/../compile-host.sh" \
    -std=c17 -O2 -Wall -Wextra -Werror -iquote "$src/../../src" \
    "$src/../../src/guest_identity.c" "$src/../../src/user_namespace.c" \
    "$src/../../src/namespace_identity.c" "$src/test_identity.c" -o "$1/md-browser-identity"
