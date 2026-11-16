#!/usr/bin/env python3
"""Run an existing native fixture with disposable paths and bounded cleanup."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=90)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command or args.timeout <= 0:
        parser.error('a command and positive timeout are required')
    command[0] = str(Path(command[0]).resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='shroot-test-') as scratch:
        command = [item.replace('@WORK@', scratch) for item in command]
        environment = dict(os.environ, TMPDIR=scratch)
        process = subprocess.Popen(command, cwd=scratch, env=environment, start_new_session=True)
        try:
            return process.wait(timeout=args.timeout)
        finally:
            # Fixtures may fork before an assertion or deadline terminates them.
            # Only the private test process group is eligible for cleanup.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


if __name__ == '__main__':
    raise SystemExit(main())
