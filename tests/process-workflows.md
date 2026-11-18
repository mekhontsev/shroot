# Process And Resource Fixtures

Select a [fixture executor](README.md#fixture-transports) and a disposable store.
For native, model-level assertions use [resource verification](../resource-tests.md).

## Process Limits And Providers

`test_resources.py BUILD --case cgroup` runs the native ownership model and
isolated guest cgroup tests in Base and lazy modes. It covers controller
publication/retirement, policy validation, hierarchical PID limits, threads,
clone3 target admission, zombie/reap accounting, poll notifications, sampled
CPU/RSS and cgroup namespaces. Repeat with `--kernel-profile linux-5.15` for
capability-fallback coverage; this is not a substitute for a physical 5.15 kernel.
CPU quotas, cpuset affinity and memory limits are retained policies, not enforced
controls. `memory.events`/`.local` must remain quiet after the initial read and
retire on group/controller removal. These tests keep that boundary explicit.

`test_kmsg.py BUILD STORE --machine-entry` (or `--base`) verifies the private
kernel-message device's record ABI, cursors, poll/blocking delivery, overrun and
permissions. It does not read host logs or claim OOM observation.
`test_proc_policy.py` covers private proc inventories and advisory kernel-policy
values through original and newly mounted proc views, including denied writers
and explicitly rejected strict overcommit. Repeat supported fixtures with
`--kernel-profile linux-5.15` to exercise capability fallbacks.

## Thread Identity And Owner Death

`test_thread_identity_runtime.py BUILD STORE [FIXTURE] --debuggers` checks libc
thread identities and multi-threaded setuid/setgid/setgroups, including strace
both inside and outside a PID namespace. The store must contain strace and GDB.
`--executor app|shell` selects the Android identity; without a prebuilt fixture,
the test compiles against that store's libc. `--case robust` independently checks
ten cases both directly and inside a logical PID namespace: list registration/
query, owner death after thread/process exit, SIGKILL, leader/nonleader exec,
childless and real-child waits, thread-specific waits, native SIGCHLD readers
and subreaper adoption. Wait coverage includes WNOWAIT, NULL waitid output and
stop/continue events. `--native-control --executor shell` builds a static fixture
and runs the same assertions directly under Android before the Shroot variants.
It distinguishes kernel limitations without weakening the managed-path checks;
libc accepting a robust attribute alone is not a pass.
`test_resources.py BUILD --case robust-futex --executor app|shell` tests the
cleanup cursor and retained-address-space executor independently of libc:
atomic owner replacement, sleeping-waiter wakeup, exit/SIGKILL/exec, private
child reaping, coalesced/directed SIGCHLD and subreaper adoption, including
concurrently blocked signalfd/waitpid readers and non-leader parent borrowing.
The same native signal queues supply those readers after retirement. Cleanup
faults retain the application's SIGSEGV disposition; malformed-list walks yield
bounded progress turns without accepting another cleanup over unfinished work.
The fixture uses `task_retained`, `task_robust` and `task_child_reap`, not its own
implementation of those operations. The runtime uses these same owners; the
separate libc fixture verifies their integration with distribution mutexes.
The supervisor-state suite checks filtered-wait selection, cancellation of
NULL-output waitid probes when their shared buffer pool is exhausted, shared
checkpoint ownership for parked signal waits, and retirement admission while
the parent or its children still have terminal events to complete. Memory-repair
stops are retained across every quiescence owner and replayed exactly once.
Provider-wait checks distinguish repeatable direct/IO preparation from committed
effects, partial transfers and splice. `test_mount_api.py` also uses libc reads
under signals without SA_RESTART while refreshing an already-open mount table;
Python's automatic EINTR retry cannot mask that assertion.
Signal information remains native while stopped and is translated separately
for debugger observation and delivery to the target.
Compile the fixture with both stock glibc and musl: `--pid-futex` also checks
explicit PI rejection at either mutex attribute selection or initialization,
followed by contended ordinary mutexes, including with `dumpable=0`.

## Guest Credentials And Executable Policy

`test_setid.py BUILD STORE [--base | --machine-entry]` builds a small ELF and two
competing shared libraries inside a disposable store with Python and a C
compiler. It checks stored setuid/setgid metadata through initial entry, path
exec, descriptor exec and an unlinked executable, without `--admit-elf`.
Assertions cover real/effective/saved/filesystem IDs, auxv, `AT_SECURE`, actual
loader rejection of an untrusted `LD_LIBRARY_PATH`, `no_new_privs`, ptrace,
unmapped user-namespace owners, `nosuid`, ignored script bits and failed exec.
Tests use stock libraries with default lazy entry or explicit Base. This is
guest credential behavior, not Android privilege or
complete kernel-equivalent isolation. The browser fixture separately verifies
stock Chromium's set-ID sandbox and its no-new-privileges rejection.

`test_nproc.py BUILD STORE` verifies per-real-UID process/thread quotas, shared
thread limits, fork copies, unreaped children, UID-change/exec admission,
protected memory, seccomp denial and `/proc/*/limits`, both directly and in a
private PID/mount namespace. `test_rtkit.py BUILD STORE` starts the distribution's
unmodified RTKit daemon with its original chroot, identity and NPROC limit,
checks the canary/watchdog threads and D-Bus responses, then releases the owned
processes. `test_os_boot.py --build BUILD --store STORE --rtkit` additionally checks the
packaged service unit through a real systemd boot, restart and stop. RTKit's
ability to obtain native realtime scheduling is a separate Android permission,
not a success implied by daemon readiness.

`test_readonly_exec.py BUILD STORE` creates fresh executable leaves, then checks
first exec, `/proc/self/exe` reexec, file-watch registration and mutation denials
on the base mount, a bind, a tmpfs bind and a read-only tmpfs superblock. This
guards systemd generator sandboxes against representation changes being mistaken
for guest writes. `test_os_boot.py` also rejects generator failures even when
systemd reaches its default target.

Root desktop recipes use an owned XDG autostart profile to omit the unnecessary
XFCE authentication agent. Packaged files and user overrides remain intact;
ordinary-user sessions retain their distribution configuration. GUI checks reject
the known empty PolicyKit error dialog as well as lost X11 authorization.

## Descriptor And Wait Semantics

`test_filtered_fd.py BUILD STORE` compiles a small fixture with the guest's own
compiler and runs Base/lazy controls. Its application filter kills gettid,
clone and sendmsg, and constrains openat's original PC and flags. It checks
protected stdio metadata, CLOEXEC, read/mmap/close and single-effect O_EXCL.
The optional installed `file` utility is reported separately when unavailable.

`test_epoll_runtime.py --build BUILD --store STORE --trace --machine-entry`
includes exclusive FIFO/signalfd subscriptions, aliases, invalid mask/MOD
requests, retirement and application-filter coverage. The OCI nginx fixture
checks 1, 2 and automatic worker counts over routed TCP, repeated HTTP requests
and shutdown in the server's own signal domain; `--base`, `--machine-entry`
and `--kernel-profile linux-5.15` select independent admission checks.

The epoll fixture also runs mixed/native readiness, signal masks, shared-table races and denied
retirement through guest strace. Cold-admission cases add a first virtual interest
to an already-blocked finite or infinite epoll wait, including protected callers
and epoll_pwait2. Native-ready cases cover one-shot consumption, invalid output
pointers and argument-sensitive application filters. `--base` selects the same
cases without lazy entry. `test_debugger_runtime.py` also accepts
`--machine-entry`; `--case strace-detach-socket` verifies that detaching does not
need data to arrive on a blocked socket. These regressions cover common Base
owners, not just SVC publication.
