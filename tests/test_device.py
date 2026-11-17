#!/usr/bin/env python3
"""Run prepared userspace through the shared Android executor fixtures."""
import argparse
from fixture_executor import FixtureExecutor
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--config", type=Path, default=Path.home() / ".codex/config.toml")
    parser.add_argument("--server")
    parser.add_argument("--packages", action="store_true", help="Observe actual dpkg transactions and known shell limits")
    parser.add_argument("--native-build", type=Path, help="Exact packaged fixture build (required for User)")
    parser.add_argument("--output", type=Path)
    FixtureExecutor.add_argument(parser, android_only=True)
    args = parser.parse_args()
    manifest = json.loads((args.build / "manifest.json").read_text())
    archive = args.build / Path(next(p["file"] for p in manifest["packages"] if p["name"] == "gzip")).name
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(archive)]))) as package:
        package_links = [member for member in package.getmembers() if member.islnk()]
        uncompress = next(member for member in package.getmembers() if member.name.endswith("/uncompress"))
        gunzip = next(member for member in package.getmembers() if member.name.endswith("/gunzip"))
    if args.executor == 'app' and args.native_build is None:
        parser.error('--executor app requires --native-build matching the installed fixture APK')
    output = args.output or args.build / ('results-' + args.executor)
    executor = FixtureExecutor.connect(output, args.executor, 'prepared', config=args.config, server=args.server)
    root = executor.root
    results = {**executor.state, "manifest": manifest,
               "directory": root, "checks": []}

    def command(value):
        return executor.execute(value, 210, capture=True)

    def check(name, value, code=0, contains=None, limitation=False):
        result = command(value)
        fragments = [] if contains is None else contains if isinstance(contains, list) else [contains]
        ok = result["exitCode"] == code and all(fragment in result["output"] for fragment in fragments)
        results["checks"].append({"name": name, "passed": ok, "limitation": limitation, "command": value,
                                  "exitCode": result["exitCode"], "output": result["output"],
                                  "fixtureLimitations": [line[6:] for line in result["output"].splitlines()
                                                         if line.startswith("LIMIT ")]})
        print(("LIMIT " if ok and limitation else "PASS " if ok else "FAIL ") + name + "\n" + result["output"], flush=True)
        if not ok:
            raise RuntimeError("Fixture check failed: " + name)
        return result

    try:
        executor.upload(args.build / "bundle.tar.gz", root + "/bundle.tar.gz")
        check("extract without package installation", "tar -xzf " + root + "/bundle.tar.gz -C " + root)
        if args.executor == 'app':
            # Android executes immutable APK ELF files, not writable imported copies.
            for target in ['libshroot_guest_' + name + '.so' for name in ('supervisor', 'bootstrap', 'run', 'service', 'image')] + \
                    ['md-command-test', 'md-capabilities-test', 'md-lifecycle-test', 'md-sockets-test']:
                packaged = ('libshroot_guest_capabilities.so' if target == 'md-capabilities-test' else
                            'libshroot_guest_prepared_' + target[3:].replace('-', '_') + '.so'
                            if target.startswith('md-') else target)
                source = args.native_build / ('libshroot_guest_capabilities.so' if target == 'md-capabilities-test' else target)
                remote = root + '/' + target
                executor.upload(source, remote, packaged_name=packaged)
                check('admit immutable ' + target, shlex.join(['ln', '-sf', executor.native_path(remote), remote]))
        launch = ("env PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp TMPDIR=/tmp LANG=C "
                  + root + "/libshroot_guest_supervisor.so " + root + "/libshroot_guest_bootstrap.so " + root + "/rootfs ")
        check("selected Android identity", "id -u", contains=str(executor.uid) + '\n')
        check("kernel identity", "uname -a", contains="aarch64")
        check("page size observation", "getconf PAGE_SIZE")
        check("prepared executable and loader ownership", "timeout 30 " + root
              + "/md-command-test " + root + "/prepared-images",
              contains="PASS prepared command:")
        check("optional kernel capabilities do not disable ordinary shell", "timeout 30 " + root
              + "/md-capabilities-test " + root + "/libshroot_guest_supervisor.so " + root + "/libshroot_guest_bootstrap.so",
              contains="PASS capability isolation")
        # Copy outside the source first, then move inside the executor's root.
        # Relative dirfd operations outside that root remain deliberately rejected.
        check("prepare immutable rootfs import source", "cp -a " + root + "/rootfs " + root + "/prepared-rootfs")
        check("place import source inside laboratory root", "mv " + root + "/prepared-rootfs " + root + "/rootfs/prepared-rootfs")
        check("offline prepared rootfs import, rollback and source integrity",
              "timeout 180 " + launch + "/usr/bin/md-import-fixture /tmp/md-import-tests "
              + "/prepared-rootfs /tmp/imported-rootfs",
              contains=["PASS prepared Debian rootfs import:",
                        "PASS import: three deterministic SIGKILL boundaries",
                        "PASS offline import fixture (not execution from the imported namespace)"])
        namespace = ("env PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/tmp TMPDIR=/tmp LANG=C "
                     + root + "/libshroot_guest_run.so --store " + root + "/rootfs/tmp/imported-rootfs -- ")
        check("import independent second guest store", "timeout 180 " + root
              + "/libshroot_guest_service.so --import " + root + "/rootfs/prepared-rootfs " + root + "/second-store",
              contains="Imported entries=")
        for store, marker in [(root + "/rootfs/tmp/imported-rootfs", "first"), (root + "/second-store", "second")]:
            check("distinct guest root " + marker, "timeout 30 " + root + "/libshroot_guest_run.so --store "
                  + store + " -- /bin/sh -c " + shlex.quote("printf " + marker + " > /etc/md-environment"))
        check("namespace process-tree ownership and cancellation", "timeout 150 " + root
              + "/md-lifecycle-test " + root + "/libshroot_guest_run.so " + root + "/rootfs/tmp/imported-rootfs "
              + root + "/second-store",
              contains=["PASS lifecycle: double-fork/setsid descendant uses namespace after root exit",
                        "PASS lifecycle: TERM escalation",
                        "PASS lifecycle: frontend SIGKILL",
                        "PASS lifecycle: namespace owner failure",
                        "PASS lifecycle: launch failures and final ECHILD"])
        check("stock Debian shell executing from inode namespace", "timeout 45 " + namespace + "/bin/dash -c "
              + shlex.quote("/bin/cat /etc/md-guest-fixture | /usr/bin/wc -c"), contains="12\n")
        check("namespace syscalls, shared inode semantics and fork/exec", "timeout 60 " + namespace
              + "/usr/bin/md-namespace-fixture",
              contains=["PASS namespace exec preserves cwd, real umask and open-unlinked FD",
                        "PASS namespace syscalls: atomic open, hard links, stat/statx, mmap/flock, symlinks and directory cursors"])
        for backend, prefix in [("direct", launch), ("namespace", namespace)]:
            check(backend + " large exec vectors and proc image", "timeout 120 " + prefix
                  + "/usr/bin/md-arguments-fixture",
                  contains=["PASS 32768 arguments", "PASS exec limits"])
            check(backend + " proc descriptor aliases", "timeout 60 " + prefix
                  + "/usr/bin/md-proc-fixture /tmp/md-proc-" + backend + " " + backend,
                  contains=["PASS proc: file aliases", "PASS proc: posix_spawn", "PASS proc: renamed directory",
                            "PASS proc: native pipe descriptors", "PASS proc: inherited open-unlinked",
                            "PASS proc: deleted inode remains accessible"])
        probe = command("timeout 15 " + root + "/md-sockets-test probe " + root + "/rootfs")
        assert probe['exitCode'] in (0, 77), probe
        results['nativePathnameSockets'] = probe
        for backend in ["direct", "namespace"]:
            check(backend + " abstract Unix sockets and descriptor exchange", "timeout 60 " + root
                  + "/md-sockets-test " + backend + " " + root + "/rootfs abstract",
                  contains=["PASS sockets: stream/seqpacket/datagram",
                            "PASS sockets: binary abstract names",
                            "PASS sockets: native permission/type failures",
                            "PASS sockets: descriptor counts unchanged"])
        check("namespace state survives a fresh service", "timeout 30 " + namespace
              + "/usr/bin/stat /tmp/ns-moved/child", contains="Size: 0")
        check("explicit Unix routes survive exec and environment replacement", "timeout 60 " + root
              + "/md-sockets-test routes " + root + "/rootfs",
              contains="PASS socket routes: independent connections, shell/exec/env-i, credentials, SCM_RIGHTS and shared mmap")
        check("namespace signal, stack and exec regressions", "timeout 90 " + namespace
              + "/usr/bin/md-exec-fixture", contains=["PASS posix_spawn file actions, cwd and full signal mask", "PASS 64 execs"])
        check("namespace path and descriptor extended attributes", "timeout 45 " + namespace
              + "/usr/bin/md-xattrs-fixture /tmp/md-ns-xattrs",
              contains="PASS xattrs: binary values, path/FD identity, flags, permissions, symlinks and errors")
        check("direct-backend extended attributes", "timeout 30 " + launch
              + "/usr/bin/md-xattrs-fixture /tmp/md-direct-xattrs native",
              contains="PASS xattrs: binary values, path/FD identity, flags, permissions, symlinks and errors")
        check("direct strict attribute copy retains SELinux denial", "timeout 30 " + launch
              + "/bin/cp --preserve=xattr /tmp/md-direct-xattrs/archive-source /tmp/md-direct-xattrs/copied",
              code=1, contains=["setting attribute 'security.selinux'", "Permission denied"], limitation=True)
        check("namespace strict attribute copy excludes backing SELinux label", "timeout 30 " + namespace
              + "/bin/cp --preserve=xattr /tmp/md-ns-xattrs/archive-source /tmp/md-ns-xattrs/copied")
        check("namespace copied attributes persist", "timeout 30 " + namespace
              + "/usr/bin/md-xattrs-fixture /tmp/md-ns-xattrs/copied verify", contains="PASS copied/archive xattrs")
        check("namespace coreutils archive-mode copy", "timeout 30 " + namespace
              + "/bin/cp -a /tmp/md-ns-xattrs/archive-source /tmp/md-ns-xattrs/copied-best-effort")
        check("namespace archive-mode copied attributes persist", "timeout 30 " + namespace
              + "/usr/bin/md-xattrs-fixture /tmp/md-ns-xattrs/copied-best-effort verify", contains="PASS copied/archive xattrs")
        check("namespace tar stores extended attributes", "timeout 30 " + namespace
              + "/bin/tar --xattrs --xattrs-include='user.*' -cf /tmp/md-xattrs.tar -C /tmp/md-ns-xattrs archive-source")
        check("namespace prepare archive extraction", "timeout 30 " + namespace + "/bin/mkdir /tmp/md-xattrs-out")
        check("namespace tar restores extended attributes", "timeout 30 " + namespace
              + "/bin/tar --xattrs --xattrs-include='user.*' -xf /tmp/md-xattrs.tar -C /tmp/md-xattrs-out")
        check("namespace archived attributes persist", "timeout 30 " + namespace
              + "/usr/bin/md-xattrs-fixture /tmp/md-xattrs-out/archive-source verify", contains="PASS copied/archive xattrs")
        if args.packages:
            check("prepare namespace dpkg database", "timeout 30 " + namespace + "/bin/mkdir -p /tmp/md-dpkg")
            check("namespace dpkg installation", "timeout 60 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --force-not-root --install /tmp/md-package-fixture.deb")
            check("namespace dpkg committed status", "timeout 30 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --status md-package-fixture",
                  contains=["Status: install ok installed", "Version: 1.0"])
            check("namespace dpkg upgrade", "timeout 60 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --force-not-root --install /tmp/md-package-update.deb")
            check("namespace upgraded database committed", "timeout 30 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --status md-package-fixture",
                  contains=["Status: install ok installed", "Version: 2.0"])
            check("namespace upgraded payload and maintainer script", "timeout 30 " + namespace
                  + "/bin/cat /usr/share/md-package-fixture/value /usr/share/md-package-fixture/configured",
                  contains=["package-value-v2\n", "configured-v2\n"])
            check("namespace writes do not modify direct rootfs", "timeout 30 " + launch
                  + "/bin/dash -c " + shlex.quote("test ! -e /usr/share/md-package-fixture"))
            check("namespace dpkg purge", "timeout 60 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --force-not-root --purge md-package-fixture")
            check("namespace package absent from committed database", "timeout 30 " + namespace
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --status md-package-fixture", code=1,
                  contains="is not installed")
            check("namespace removed payload and postrm marker", "timeout 30 " + namespace
                  + "/bin/dash -c " + shlex.quote("test ! -e /usr/share/md-package-fixture"))
            check("namespace official gzip archive extraction", "timeout 60 " + namespace
                  + "/usr/bin/dpkg-deb --extract /tmp/md-hardlinks.deb /tmp/md-gzip")
            one = shlex.quote("/tmp/md-gzip/" + gunzip.name.removeprefix("./"))
            two = shlex.quote("/tmp/md-gzip/" + uncompress.name.removeprefix("./"))
            identity = ('a=$(/usr/bin/stat -c %d:%i ' + one + '); b=$(/usr/bin/stat -c %d:%i ' + two + '); test "$a" = "$b"'
                if uncompress.islnk() else 'test -L ' + two + '; test "$(readlink ' + two + ')" = ' + shlex.quote(uncompress.linkname))
            assert uncompress.islnk() or uncompress.issym()
            check("namespace archive preserves declared link type", "timeout 30 " + namespace + "/bin/dash -c "
                  + shlex.quote("set -eu; test -f " + one + "; " + identity))
        check("Debian identity", "timeout 20 " + launch + "/usr/bin/id -u", contains=str(executor.uid) + '\n')
        check("Debian shell and child cat", "timeout 20 " + launch + "/bin/dash -c "
              + shlex.quote("/bin/cat /etc/md-guest-fixture"), contains="guest-value\n")
        check("pipeline and fork/exec", "timeout 20 " + launch + "/bin/dash -c "
              + shlex.quote("/bin/cat /etc/md-guest-fixture | /usr/bin/wc -c"), contains="12\n")
        check("guest regression fixture", "timeout 30 " + launch + "/usr/bin/md-fixture",
              contains="PASS inherited Unix socket")
        check("exec inheritance and signal/pointer regressions", "timeout 30 " + launch + "/usr/bin/md-exec-fixture",
              contains="PASS 64 execs")
        check("file metadata and notifications", "timeout 20 " + launch + "/usr/bin/md-files-fixture",
              contains="PASS atomic rename flags and inotify namespace mapping")
        check("isolated inode model, descriptor coherence and crash recovery", "timeout 45 " + launch
              + "/usr/bin/md-inodes-fixture /tmp/md-inode-store",
              contains=["PASS 11 deterministic SIGKILL recovery boundaries",
                        "PASS 12 hierarchy SIGKILL boundaries",
                    "PASS inode-store fixture (hierarchical model, not guest syscall integration)"])
        check("filesystem service transport, native FD transfer and failure boundaries", "timeout 60 " + launch
              + "/usr/bin/md-rpc-fixture /tmp/md-fs-service",
              contains=["PASS nested signal-handler RPC during pending outer call; errno unchanged",
                        "PASS directory RPC: paging, shared dup/fork/exec cursor, service restart, cookies and concurrent readers",
                        "PASS server death after commit is UNCONFIRMED, no replay; namespace recovered",
                        "PASS filesystem service fixture (explicit RPC, not guest syscall integration)"])
        check("statx translation inside coreutils", "timeout 20 " + launch
              + "/usr/bin/stat /etc/md-guest-fixture", contains="Size: 12")
        check("shell vfork child", "timeout 20 " + launch + "/bin/dash /usr/bin/md-script", code=23,
              contains="guest-value\n")
        link_control = command("ln " + root + "/rootfs/etc/md-guest-fixture " + root + "/host-hard-link")
        assert link_control['exitCode'] == 0 or (link_control['exitCode'] == 1 and 'Permission denied' in link_control['output']), link_control
        hardlinks = link_control['exitCode'] == 0
        results['nativeHardlinks'] = link_control
        if args.packages:
            version = next(p["version"] for p in manifest["packages"] if p["name"] == "dpkg").split(":")[-1]
            check("Debian package manager identity", "timeout 20 " + launch + "/usr/bin/dpkg --version",
                  contains=version + " (arm64)")
            check("package metadata and decompression", "timeout 20 " + launch
                  + "/usr/bin/dpkg-deb --info /tmp/md-package-fixture.deb", contains="Package: md-package-fixture")
            check("prepare isolated dpkg database", "timeout 20 " + launch + "/bin/mkdir -p /tmp/md-dpkg")
            check("dpkg setting transaction", "timeout 20 " + launch
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --force-not-root --add-architecture armhf")
            check("direct dpkg transaction follows native hard-link capability", "timeout 20 " + launch
                  + "/usr/bin/dpkg --admindir=/tmp/md-dpkg --force-not-root --install /tmp/md-package-fixture.deb",
                  code=0 if hardlinks else 2,
                  contains=None if hardlinks else "error creating new backup file '/tmp/md-dpkg/status-old': Permission denied",
                  limitation=not hardlinks)
            check("direct postinst execution", "timeout 20 " + launch
                  + "/bin/cat /usr/share/md-package-fixture/configured", contains="configured\n")
            check("direct dpkg commit matches native capability", "timeout 20 " + launch + "/bin/dash -c "
                  + shlex.quote("test -s /tmp/md-dpkg/status" if hardlinks else
                                "test ! -s /tmp/md-dpkg/status && test -s /tmp/md-dpkg/status-new"), limitation=not hardlinks)
            check("official gzip archive retains declared link semantics", "timeout 20 " + launch
                  + "/usr/bin/dpkg-deb --extract /tmp/md-hardlinks.deb /tmp/md-hardlinks",
                  code=2 if package_links and not hardlinks else 0,
                  contains="Cannot hard link" if package_links and not hardlinks else None,
                  limitation=bool(package_links) and not hardlinks)
        check("missing executable", "timeout 20 " + launch + "/usr/bin/not-installed", code=127)
        check("child exit status", "timeout 20 " + launch + "/bin/dash -c 'exit 42'", code=42)
        # Cancellation bound for a deliberately nonterminating guest, not a settling delay.
        check("bounded cancellation of running guest", "timeout -s TERM 1 " + launch
              + "/bin/dash -c 'while :; do :; done'", code=124)
        check("executor remains usable after cancellation", "timeout 20 " + launch
              + "/bin/cat /etc/md-guest-fixture", contains="guest-value\n")
    finally:
        try:
            check("remove isolated fixture files", 'cd "$HOME" && rm -rf -- ' + shlex.quote(root))
        finally:
            try:
                executor.close()
            finally:
                results['executor'] = executor.evidence
                (output / "device-results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
