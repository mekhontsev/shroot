#!/usr/bin/env python3
"""Run an existing native fixture with disposable paths and bounded cleanup."""
import argparse
from pathlib import Path
from executors.local import LocalExecutor
from fixture_executor import deadline_seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=deadline_seconds, default=90)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command or args.timeout <= 0:
        parser.error('a command and positive timeout are required')
    command[0] = str(Path(command[0]).resolve(strict=True))
    executor = LocalExecutor(Path.cwd(), 'component')
    try:
        command = [item.replace('@WORK@', executor.root) for item in command]
        result = executor.run(command, args.timeout, on_line=lambda line: print(line, end='', flush=True))
        return result['exitCode']
    finally:
        executor.close()


if __name__ == '__main__':
    raise SystemExit(main())
