#!/usr/bin/env python3
"""Native client integration; no Android application or automation service."""
import argparse
import json
import os
import resource
import select
import signal
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
from client_fixture import archive_fixture


def owner_lifetime(command):
    reader, owner = socket.socketpair()
    process = None
    try:
        process = subprocess.Popen(command + ['--owner-fd', str(owner.fileno()), '--', '/bin/client-guest', 'hold'],
                                   pass_fds=(owner.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        owner.close()
        assert select.select([process.stdout], [], [], 30)[0], 'guest did not start'
        assert os.read(process.stdout.fileno(), 6) == b'ready\n'
        assert not select.select([reader], [], [], 0)[0], 'owner FD closed before tree exit'
        process.terminate()
        output, error = process.communicate(timeout=30)
        assert process.returncode in (128 + signal.SIGTERM, -signal.SIGTERM), error
        assert select.select([reader], [], [], 5)[0], 'owner FD survived tree exit'
        assert reader.recv(1) == b''
    finally:
        owner.close(); reader.close()
        if process and process.poll() is None:
            process.kill(); process.communicate(timeout=15)


def parent_lifetime(cli, instance):
    launcher = ('import os, subprocess, sys; '
                'child = subprocess.Popen(sys.argv[1:2] + ["--parent-pid", str(os.getpid())] + sys.argv[2:]); '
                'sys.stdin.buffer.read(1)')
    process = subprocess.Popen([sys.executable, '-c', launcher, *cli, 'exec', str(instance),
                                '--', '/bin/client-guest', 'hold'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        # EVENT_WAIT: the guest acknowledges startup before its frontend exits.
        assert select.select([process.stdout], [], [], 30)[0], 'guest did not start'
        assert process.stdout.read(12) == b'ready\nready\n'
        process.kill()
        output, _ = process.communicate(timeout=30)
        assert process.returncode == -signal.SIGKILL
        assert output == b'', output
        # EOF verifies that the guest tree released the inherited output pipe.
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--consumer", type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    prefix = args.prefix.resolve() if args.prefix else None
    runtime = prefix / "libexec/shroot" if prefix else build
    with tempfile.TemporaryDirectory(prefix="shroot-client-", dir=build) as directory:
        root = Path(directory)
        archive = root / "rootfs.tar"
        archive_fixture(build, archive)
        subprocess.run([str(build / "test_client_integration"), str(runtime), str(archive), str(root)],
                       check=True, timeout=180)
        cli = [str(prefix / "bin/shroot")] if prefix else [str(build / "shroot"), "--runtime", str(build)]
        image = root / "cli-image"
        instance = root / "cli-instance"
        subprocess.run(cli + ["rootfs", str(archive), str(image)], check=True, timeout=30)
        subprocess.run(cli + ["create", str(image), str(instance)], check=True, timeout=30)
        result = subprocess.run(cli + ["inspect", str(instance)], check=True, text=True,
                                capture_output=True, timeout=30)
        assert json.loads(result.stdout)["format"] == 17
        if args.consumer:
            result = subprocess.run([str(args.consumer.resolve()), str(runtime), str(instance)],
                                    check=True, text=True, capture_output=True, timeout=30)
            assert json.loads(result.stdout)["format"] == 17
        subprocess.run(cli + ["exec", str(instance), "--env", "LIBSHROOT_TEST=retained ' value",
                              "--cwd", "/", "--hostname", "client-test", "--", "/bin/client-guest",
                              "spaces ' ; $(false)"], check=True, timeout=30)
        result = subprocess.run(cli + ["exec", str(instance), "--", "/bin/client-guest", "exit42"],
                                timeout=30)
        assert result.returncode == 42
        attachment = root / 'attachment'
        attachment.mkdir()
        (attachment / 'token').write_text('read-only')
        native_tmpfile = json.loads(subprocess.check_output(
            [str(build / 'client-guest'), 'native-tmpfile', str(attachment)],
            text=True, timeout=30))
        assert len(native_tmpfile) == 2 and all(isinstance(value, int) for value in native_tmpfile)
        print(f'Native attachment O_TMPFILE errno (ordinary/exclusive): {native_tmpfile}', flush=True)
        for entry in ('0', '1'):
            launches = [cli + ['exec', str(instance)],
                        [str(runtime / 'libshroot_guest_run.so'), '--store', str(instance)]]
            for owner, launch in enumerate(launches):
                target = f'/readonly-{entry}-{owner}'
                for repeat in range(2):
                    subprocess.run(launch + ['--bind-ro-create', str(attachment), target,
                                            '--env', 'SHROOT_MACHINE_ENTRY=' + entry,
                                            '--', '/bin/client-guest', 'readonly-bind', target],
                                   check=True, timeout=30)
                subprocess.run(launch + ['--bind-create', str(attachment), '/native',
                                        '--env', 'SHROOT_MACHINE_ENTRY=' + entry,
                                        '--', '/bin/client-guest', 'native-tmpfile', '/native',
                                        *map(str, native_tmpfile)],
                               check=True, timeout=30)
        parent_lifetime(cli, instance)
        for command in ([*cli, 'exec', str(instance)], [str(runtime / 'libshroot_guest_run.so'), '--store', str(instance)]):
            subprocess.run(command + ['--env', 'PATH=/custom:/bin', '--path-prefix', '/integration',
                                     '--', '/bin/client-guest', 'path', '/integration:/custom:/bin'],
                           check=True, timeout=30)
            owner_lifetime(command)
        for parent in ('1', '0', '-1', 'invalid', '2147483648'):
            result = subprocess.run(cli + ['--parent-pid', parent, 'format'], capture_output=True, timeout=10)
            assert result.returncode == 125, result
        with socket.socket() as port:
            port.bind(('127.0.0.1', 0))
            publication = f'127.0.0.1:{port.getsockname()[1]}:8080'
        result = subprocess.run(cli + ['exec', str(instance), '--network', 'bridge',
                                '--dns', '192.0.2.53',
                                '--subnet', '192.0.2.0/24', '--subnet', '2001:db8::/64',
                                '--gateway', '192.0.2.1', '--gateway', '2001:db8::1',
                                '--ip', '192.0.2.2', '--ip6', '2001:db8::2',
                                '--publish', publication,
                                '--', '/bin/client-guest', 'exit42'], timeout=30)
        assert result.returncode == 42
        limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        for entry in ('0', '1'):
            subprocess.run(cli + ["exec", str(instance), "--network", "routed",
                                  "--env", "SHROOT_MACHINE_ENTRY=" + entry,
                                  "--", "/bin/client-guest", "limits"], check=True, timeout=30,
                           preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (128, 4096)))
            assert resource.getrlimit(resource.RLIMIT_NOFILE) == limits
        for store in (instance, image):
            subprocess.run(cli + ["remove", str(store)], check=True, timeout=30)
        print("PASS CLI: public API operations, launch arguments and guest exit status")


if __name__ == "__main__":
    main()
