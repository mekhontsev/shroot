#!/usr/bin/env python3
"""Opt-in smoke test against an authenticated, running Termux:X11 display."""
import argparse
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", help="Shroot name or absolute store containing xdpyinfo and xev")
    parser.add_argument("--cli", default="shroot")
    parser.add_argument("--library")
    parser.add_argument("--xdotool", default="xdotool")
    parser.add_argument("--display", required=True, type=int)
    parser.add_argument("--authority", type=Path, required=True)
    args = parser.parse_args()
    display = ":" + str(args.display)
    address = "/tmp/.X11-unix/X" + str(args.display)
    endpoint = str(Path(os.environ["TMPDIR"]) / ".X11-unix" / ("X" + str(args.display)))
    host = dict(os.environ, DISPLAY=display, XAUTHORITY=str(args.authority.resolve(strict=True)))
    with tempfile.TemporaryDirectory(prefix="shroot-xauth-") as directory:
        shutil.copyfile(args.authority, Path(directory) / "cookie")
        command = [args.cli, *(["--library", args.library] if args.library else []),
                   "exec", args.environment, "--env", "DISPLAY=" + display,
                   "--env", "XAUTHORITY=/tmp/shroot-test-xauth/cookie",
                   "--bind-ro-create", directory, "/tmp/shroot-test-xauth",
                   "--socket-path", address, endpoint, "--socket-abstract", address, endpoint, "--"]
        info = subprocess.check_output([*command, "/usr/bin/xdpyinfo"], timeout=15)
        assert b"version number:" in info and display.encode() in info
        title = "shroot-xev-" + str(os.getpid())
        window = subprocess.Popen([*command, "/usr/bin/xev", "-name", title],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            def xdo(*words):
                return subprocess.check_output([args.xdotool, *words], env=host, timeout=15)
            wid = xdo("search", "--sync", "--onlyvisible", "--name", "^" + title + "$").splitlines()[0]
            xdo("windowfocus", "--sync", wid, "mousemove", "--window", wid, "10", "10",
                "click", "1", "key", "a")
            events = (b"MapNotify", b"ButtonPress", b"KeyPress", b"keysym 0x61, a")
            output = bytearray()
            deadline = time.monotonic() + 15
            with selectors.DefaultSelector() as ready:
                ready.register(window.stdout, selectors.EVENT_READ)
                while not all(event in output for event in events):
                    if not ready.select(max(0, deadline-time.monotonic())):
                        raise AssertionError(("Missing guest input", output[-4096:]))
                    chunk = os.read(window.stdout.fileno(), 8192)
                    if not chunk or len(output) > 1024 * 1024:
                        raise AssertionError(("Unexpected guest output", output[-4096:]))
                    output.extend(chunk)
        finally:
            window.terminate()
            window.communicate(timeout=15)
        print("PASS Termux:X11: guest connected, window mapped, button and key received")


if __name__ == "__main__":
    main()
