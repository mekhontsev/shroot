#!/usr/bin/env sh
set -eu
cc=${CC:-clang}
case "$("$cc" -dumpmachine)" in
    aarch64*android*) set -- --target=aarch64-linux-android34 "$@" ;;
    aarch64*) ;;
    *) printf 'Native controls require an ARM64 compiler: %s\n' "$cc" >&2; exit 2 ;;
esac
exec "$cc" -static -Wl,-z,noexecstack -Wl,-z,max-page-size=16384 "$@"
