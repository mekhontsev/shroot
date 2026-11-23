# Shroot Test Guide

Start with the native suite for runtime changes. Use a distribution workflow
when the assertion depends on a real application, service, or graphical session.
The [distribution matrix](validation-matrix.md) records what was actually run.

## Standalone Native Checks

On the target ARM64 host, configure, build and run the suite from the checkout:

```sh
tests/build.sh build -DCMAKE_BUILD_TYPE=RelWithDebInfo
```

For a configured test build, select just the work you need:

```sh
cmake --build build --target shroot-check-fixtures -j 4
ctest --test-dir build -LE benchmark --output-on-failure
ctest --test-dir build --rerun-failed --output-on-failure
```

| CTest selection | Scope |
| --- | --- |
| `-L component` | Native resource, policy, signal, storage and image contracts |
| `-L integration` | Native integration checks, including environment and import workflows |
| `-L packaging` | Bundle validation and dependency preparation |
| `-L benchmark` | Checkpoint timings; run without competing builds or workloads |
| No selection | All registered tests, including benchmarks |

Use CMake, Ninja, a C compiler and Python 3.11+. Archive checks use `zstd`;
local HTTPS tests use OpenSSL. The standalone suite needs no Android
application, privileged service or public container registry. Run cross-built
fixtures on the target, not the build host. `TMPDIR` selects the writable
workspace for management, bundle and nested fixtures; the build supplies
the binaries and need not be writable by the guest.

[CI](../embedding.md#continuous-integration) runs on ARM64 Linux and cross-builds
Android artifacts. `tests/audit_bundle.py` inspects an archive without executing
it; `tests/test_bundle.py BUILD --prefix INSTALLATION` tests a relocated install
on the target. A production acceptance run uses a separate
`SHROOT_BUILD_TESTS=OFF` installation.

In Termux, `python tests/test_termux_upgrade.py OLD.deb NEW.deb ALPINE_ROOTFS.tar.gz`
installs both packages with APT in a temporary installation root. It runs Alpine
before and after the upgrade and checks its catalog identity and a guest file.
The two package versions must sort in ascending Debian version order. The
host package database and the user's environment library are not used.

### Qualified Hosts

The host coverage below spans component, management, runtime, transport and
packaging contracts, including native/kernel-profile admission and applicable
signal-checkpoint controls.

| Host | Execution identity | Kernel / page size | Additional verified workflows |
| --- | --- | --- | --- |
| Raspberry Pi 5, Debian 13 | UID/GID 1000, no effective capabilities or inherited seccomp | 6.18.60+rpt-rpi-2712 / 16 KiB | Installed production API/CLI, independent CMake consumer, stripped archive audit, stock Alpine 3.23.8 with `apk update`, Debian trixie with `dpkg --audit` and `apt-get update`, stock k3s with network policies, Traefik ingress, PVC and server restart |
| Android, Termux | UID/GID 10601, `untrusted_app_27`, no effective capabilities, inherited seccomp | 6.12.23-android16 / 4 KiB | Shared standalone native test set; not MagicDesk's Zygote identity or Shell |

Android uses Clang and bundled static dependencies. The Pi uses GCC, system
SQLite and dynamic runtime helpers. Static-only installed-bundle checks are not
registered for that configuration. Stock Alpine and Debian execute successfully with both builds in
Base and lazy-SVC modes, sharing the same installed stores without copies.

Linux package checks include logical guest root, shell execution, hardlinks and
file IO; lazy-SVC completion is observed. This is not the full distribution
GUI/container matrix or a performance comparison. The `linux-5.15` profile tests
capability fallbacks on these hosts, not a real 5.15 kernel. Executing stock musl
applications alone does not qualify a musl-hosted runtime; that build is covered
separately below.

### Nested Runtime

`test_nested_runtime.py BUILD --case nested` creates disposable outer and inner
stores using the same helper binaries. All four Base/lazy combinations cover
startup, fork/exec/wait, exit status, arguments, environment, hardlink/symlink
metadata and descriptor isolation. `--depth 3` extends this to eight combinations
and 24 launches. Both depths pass on the Android Termux host above.

In the distribution test, Alpine hosts Debian. All 272 native functional cases
completed from Debian across the full run and focused rechecks, including FIFO
and two-layer OCI import into Debian's inode-backed temporary directory. The
glibc runtime starts a third guest for debugger and signal tests. The recursive
case adds a fourth guest and checks all 12 launches across the four innermost
Base/lazy combinations. The 272 cases do not all run in the fourth guest.

These are functional results, not first-level timing guarantees. The RPC
fixture completed 10,000 consecutive descriptor exchanges in one run (465 s
for the fixture). Fourth-level launches took 37-68 s each; qualification used
longer test deadlines and a longer filesystem-worker startup deadline in the
measurement build. These checks do not cover nested execution on 16 KiB pages
or the full distribution GUI/container matrix.

Alpine 3.23.8 running inside the Android-hosted runtime builds Shroot with GCC
15.2 and its stock musl toolchain. The standalone checks cover the
installed/relocated bundle, netlink descriptor admission, Base/lazy nested
launches, debugger and signal controls. The outer runtime keeps the Termux UID;
guest root is logical. This covers a musl-built supervisor and worker, not only
musl applications running under an Android-built runtime.

`--case debugger` exercises the same C scenarios used by
`test_debugger_runtime.py`: syscall-info mutation, signal interruption of
metadata/poll/epoll calls, seccomp TRACE and number changes, SYSEMU, pending
interrupts, pidfd descriptor copies, foreign proc-FD reopen, service admission
and nondestructive signal-queue inspection. `proc-thread` checks leader/thread
proc aliases, fdinfo and cwd after independently splitting CLONE_FILES and
CLONE_FS ownership. Foreign proc-FD directory traversal also preserves mounted
providers, including `/dev/fd`, instead of exposing their physical carriers.
TRACE controls include filter
installation with live peers through both APIs: each original call must publish
one event and exit even when admission requires internal preparation.
`--native-control` also executes
these scenarios directly on the host. `--case signals` reuses the signal-delivery
and machine-context fixtures under Base and lazy entry, including ignored signals
and interrupts during native signal-frame construction. Machine-context groups
(`frame`, `alias`, `native`, `kernel`) retain all 77 alias cases and the native
frame controls. CTest registers
`nested_debugger_*`, `nested_signals_*` and `nested_nested`; these supplement, not
replace, ordinary runtime and ELF tests. Debugger and signal names separate Base
(`0`) from lazy (`1`) so a failed variant can be repeated independently.
Debugger TRACE cases also accept `--scenario seccomp-trace:openat` (or
`install`, `getpid`, `getuid`, `getpgid`, `sigmask`, `skip`); signal interruption
accepts `syscall-signal:stat`, `:poll` and `:epoll`. The recursive driver runs
all groups with the same assertions, variants and 32 signal iterations per syscall.
CTest discovers these scenario names from the runner and registers each separately,
so one failure neither prevents later scenarios nor requires replaying earlier ones.

`--depth` counts the runtimes created by the recursive fixture, not runtimes
already enclosing it. Plan the total depth explicitly: inside Debian hosted by
Alpine, `--depth 1` exercises level three; the default adds levels three and four.
`ctest --test-dir build -LE 'benchmark|recursive'` separates ordinary contracts from this extra
recursion, then `test_nested_runtime.py BUILD --case nested --depth N` checks the
chosen additional levels. This is a test-plan choice, not a runtime depth limit.

For deep qualification under an outer process-tree observer, the local component,
signal-checkpoint and nested runners accept `--external-watchdog`. This replaces
their command wall timeout, not protocol deadlines or expected results. It does
not pass a depth, option or environment variable to the program under test.
The outer runner records elapsed time, checks progress across the owned process
tree, and handles cancellation; lack of output alone is not evidence of a hang.
Ordinary runs keep their runner timeouts.

## Fixture Transports

Shared resource, runtime, OCI service and headless-browser runners default to
`--executor local`. They keep the caller's real UID and host restrictions, use
an explicit native build and disposable fixture directories, and need no MCP
configuration. Assertions, Base/lazy entry selection and host-kernel profiles
are shared with the MagicDesk executors. An installed store must be supplied
explicitly; local tests never select a global distribution.

```sh
python tests/test_resources.py build --executor local --case supervisor-state
python tests/test_watch_runtime.py build --executor local
python tests/test_oci_services.py build/results --build build --python /path/to/oci-layout
```

Build the fixtures used by the chosen workload; `shroot-check-fixtures` builds
the CTest set, not every optional application probe. Local evidence records UID,
groups, kernel, page size, SELinux context and effective capabilities. A Termux
run establishes that actual Android identity, not MagicDesk's different Zygote
domain, Shell, or ordinary Linux. Native streaming uses pipes; it does not loop
through a console, network log relay or file previews.

External transports are opt-in modules selected by `SHROOT_TEST_ADAPTER`.
They implement `executor(output, mode, prefix, config=None, server=None)` and
reuse the same guest assertions. Shroot never searches for another checkout or
silently substitutes execution identity. Its local executor needs no adapter.

MagicDesk owns its adapter and graphical, installer and APK-specific drivers in
[`tests/shroot`](https://github.com/mekhontsev/magicdesk/tree/develop/tests/shroot).
To run an engine fixture with that adapter from this checkout:

```sh
export PYTHONPATH=/path/to/magicdesk-android/tests/shroot
export APP_TESTS="$PYTHONPATH"
export SHROOT_SOURCE="$PWD"
export SHROOT_TEST_ADAPTER=magicdesk_executor
export SHROOT_TEST_EXECUTOR=shell  # or app with a matching fixture APK
python tests/test_resources.py /path/to/exact/native/build --case supervisor-state
```

The adapter reads the existing MCP configuration (`~/.codex/config.toml`) without
modifying it. `app` invokes the debug APK's real Zygote identity and verifies the
exact packaged helper hashes; `shell` verifies UID 2000 and the shell SELinux
domain. App artifacts use an app-UID console and authenticated, SHA-256-checked
loopback file transfer; this adapter requires the runner on the same device and
does not use `run-as`. On-device service tests use a loopback log channel. Graphical checks
still require MagicDesk and its graphics/placement services; a local headless
browser pass does not qualify Android presentation or audio.

Commands using `$APP_TESTS` run the application-owned drivers from that
directory. Other `tests/` paths refer to this native repository.

## Choose A Suite

| Contract | Guide |
| --- | --- |
| Per-recipe qualification by executor and entry mode | [Distribution validation matrix](validation-matrix.md) |
| Bubblewrap, namespaces, credentials and application filters | [Namespace fixtures](namespaces.md) |
| SteamOS, X11/Wayland desktops, audio and GPU | [Desktop workflows](desktop-workflows.md) |
| OCI images, mounts, filesystem operations and watches | [Filesystem workflows](filesystem-workflows.md) |
| GDB, strace and matched performance measurements | [Developer workflows](developer-workflows.md) |
| Entry contracts, stock musl/glibc workloads and native/PRoot comparisons | [Cooperative entry](cooperative-entry.md), [runtime contract](../cooperative-entry.md) |
| Init systems and distribution boot | [Init matrix](init-matrix.md) |
| Browser workload and sandbox evidence | [Browser fixtures](browser/README.md) |
| Kernel seccomp/ptrace controls | [Sandbox controls](sandbox-research.md) |
| Shared regression under real Android application and shell identities | [Host execution identities](host-execution.md) |
| Lazy machine-code entry, signal boundaries and Go stress | [Lazy SVC entry](svc-rewriting.md) |
| Native namespace admission and restricted brokers | [Isolation controls](chromium-isolation.md) |
| Descriptor custody, publication and resource teardown | [Resource verification](../resource-tests.md) |

### Network Fixtures

Use [network fixtures](network-workflows.md) for launch profiles, k3s,
container port publication, DHCP and firewall tests. For proc, cgroups,
signals and descriptor lifecycle, use [process fixtures](process-workflows.md).

### Installer Acceptance

[Installer acceptance](https://github.com/mekhontsev/magicdesk/blob/develop/tests/shroot/recipe-workflows.md#installer-acceptance) exercises the
packaged application, default catalog and ordinary interactive recipe.

### Named Environment Workflows

[Environment workflows](https://github.com/mekhontsev/magicdesk/blob/develop/tests/shroot/recipe-workflows.md#named-environment-workflows) cover
independent instances, files, graphical clients, backup and recovery.

### Prepared Runtime Fixtures

[Prepared rootfs fixtures](https://github.com/mekhontsev/magicdesk/blob/develop/tests/shroot/recipe-workflows.md#prepared-rootfs-fixtures) run
stock userspace and graphical workloads from authenticated packages.

### Graphics Adaptation (Paused)

KWin and Weston package changes belong to the [MagicDesk recipe tests](https://github.com/mekhontsev/magicdesk/blob/develop/tests/shroot/compositor-adaptation.md), not the Shroot runtime.

## Evidence Rules

- Guest assertions are shared across executor identities. App-UID launchers
  establish the real Zygote context; they do not define a separate Shroot ABI
  or weaker expected results. `k3s_fixture.py` and `test_proc_inspection.py`
  run unchanged under either executor. Proc inspection covers dumpable and
  protected tasks, absolute and dirfd-relative reads, and stable process start
  identity. `--busy` exercises an active task; `--fifo` exercises a task parked
  in FIFO open while its observer has not yet opened the peer.
- Record the APK/helper identity, image source, executor UID and firmware/kernel.
  A staged helper validates that helper, not APK packaging or installer delivery.
- Keep native controls, Shroot component tests and real-application workflows
  distinct. An exit code alone does not prove a rendered page, audible output,
  container connectivity or complete browser isolation.
- Wait for the exact operation's completion and cleanup. A deadline is a failure
  bound, not evidence of readiness. Retain bounded logs and reproducible inputs
  in test artifacts rather than adding each run to this guide.
  `FixtureExecutor` carries each command's deadline through its selected
  transport, including full-output capture. Long commands do not change the
  shared client's defaults; a transport timeout never replays the command.
- Run destructive or failure-injection cases in disposable stores. Preserve the
  user's active sessions and use the agreed display for graphical checks.
- Unsupported hardware, unavailable native authority and an implementation
  failure are different results. Do not weaken assertions or silently disable a
  client's sandbox to obtain a pass.

## Kernel Profiles

Use a native build configured with `-DSHROOT_BUILD_TESTS=ON`. The
`linux-5.15` profile removes newer host capabilities from the supervisor and its
workers, without putting a denial filter around the guest or disabling lazy SVC.
It needs neither root nor a phone reboot. Existing Linux sessions are unchanged.

```sh
python tests/test_resources.py BUILD --case kernel-baseline
python tests/test_resources.py BUILD --case fs-results --kernel-profile linux-5.15
python tests/test_watch_runtime.py BUILD --kernel-profile linux-5.15
python tests/test_systemd.py --build BUILD --store STORE --kernel-profile linux-5.15 --machine-entry
SHROOT_TEST_KERNEL_PROFILE=linux-5.15 python tests/test_clone3.py --build BUILD --name ENVIRONMENT
```

`kernel-baseline` always compares both profiles and both syscall entry modes.
Other commands select one profile; omit it or select `native` for the ordinary
host. The environment form applies to runners using the shared `Suite` launcher,
including prepared-distribution workflows. Stock native controls stay native.
For a standalone host component, use the device-side
`libshroot_guest_kernel_baseline.so --host NATIVE-FIXTURE ...`; do not wrap a
whole Shroot launch in that command, because its descendants inherit the filter.

Reports retain the real kernel and verified profile separately. The runner
checks fixture support and records each observed profile activation; guest output
remains usable as JSON or text. A missing profile is a failure, not a silent
modern-kernel pass. Release binaries contain no profile hooks. See the
[scope and limits](../kernel-compatibility.md#host-kernel-profiles): this
tests missing host APIs, not old-kernel scheduling, SELinux or all native guest
semantics. It does not replace testing on a real 5.15 device.
