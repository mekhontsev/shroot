#!/usr/bin/env sh
set -eu
test "$#" = 3
src=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
sysroot=$(CDPATH= cd -- "$1" && pwd)
out=$(CDPATH= cd -- "$2" && pwd)
work=$(CDPATH= cd -- "$3" && pwd)
cc=${CC:-clang}
crt=$sysroot/usr/lib/aarch64-linux-gnu
guest_cc() {
    "$cc" --target=aarch64-linux-gnu --sysroot="$sysroot" -isystem "$sysroot/usr/include/aarch64-linux-gnu" \
        -fuse-ld=lld -std=c17 -O2 -Wall -Wextra -Werror -fPIC -nostdlib -pie \
        "$crt/Scrt1.o" "$crt/crti.o" "$@" "$crt/crtn.o" \
        -L"$crt" -L"$sysroot/lib/aarch64-linux-gnu" -l:libc.so.6 -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1
}
if [ -f "$sysroot/usr/include/X11/Xlib.h" ]; then
    guest_cc "$src/test_x11_desktop.c" -l:libX11.so.6 -o "$out/md-x11-desktop"
fi
if [ -f "$sysroot/usr/include/dbus-1.0/dbus/dbus.h" ]; then
    guest_cc -I"$sysroot/usr/include/dbus-1.0" -I"$crt/dbus-1.0/include" \
        "$src/test_xfce_session.c" -l:libdbus-1.so.3 -o "$out/md-xfce-session"
fi
if [ -f "$sysroot/usr/include/wayland-client.h" ]; then
    protocol=$sysroot/usr/share/wayland-protocols/stable/xdg-shell/xdg-shell.xml
    wayland-scanner client-header "$protocol" "$work/xdg-shell-client-protocol.h"
    wayland-scanner private-code "$protocol" "$work/xdg-shell-protocol.c"
    guest_cc -I"$work" "$src/test_wayland.c" "$work/xdg-shell-protocol.c" \
        -l:libwayland-client.so.0 -o "$out/md-wayland-fixture"
fi
