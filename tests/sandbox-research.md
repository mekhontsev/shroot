# Seccomp And Ptrace Controls

These native fixtures isolate kernel behavior under the selected shell executor.
They are not a second production backend or a browser-certification suite.
Production Shroot uses selective TRACE/USER_NOTIF interception; application
SIGSYS handlers and alternate stacks belong to the application. See the
[interception contract](../interception.md) and
[production browser workflows](browser/README.md).

- [Reproduction](#reproduction)
- [Policy Boundaries](#policy-boundaries)
- [Userspace Policy Cost](#userspace-policy-cost)
- [Selective Ptrace Hybrid](#selective-ptrace-hybrid)
- [Signal-Neutral Checkpoints](#signal-neutral-checkpoints)
- [Real Browser Boundaries](#real-browser-boundaries)
- [Primary References](#primary-references)

## Reproduction

Use a disposable prepared glibc store and an immutable staged runtime:

```sh
python tests/build_prepared.py BUILD --native-build NATIVE_BUILD
python "$APP_TESTS/test_sandbox.py" BUILD \
  --runtime IMMUTABLE_STAGED_HELPERS --store DISPOSABLE_GLIBC_STORE
sh tests/build-hybrid-fixture.sh BUILD
python "$APP_TESTS/test_hybrid.py" BUILD --runs 50
```

The runners record device/kernel identity, actual UID, helper hashes, output
and cleanup. Synthetic-policy controls affect owned child processes only.
A completed observation suite is not a passing arbitrary-browser workload.
`test_notifications.py` supplies separate notification-lifecycle controls.

## Policy Boundaries

| Control | Meaning |
| --- | --- |
| TRAP versus ERRNO; multiple TRAP filters | Kernel action precedence and data-cookie selection are not a runtime policy choice |
| USER_NOTIF with application ERRNO/TRAP/KILL | A denial must win without executing the external operation |
| Listener loss | Notified calls fail; they must not become unmediated host operations |
| Cooperative SIGSYS and blocked SIGSYS | Signal ownership, alternate stacks and masks are part of the application ABI |
| Replay at a different instruction address | Instruction-pointer filters can produce a different decision |
| Native namespace creation | Host capability evidence is separate from logical Shroot namespaces |
| Direct filesystem RPC | An external broker is an authority boundary, not automatically confined by its caller's seccomp filter |

Do not use observations from the in-process TRAP controls as claims about the
current runtime. In particular, reserving SIGSYS/altstack and bypassing an
application's open denial are not its supported execution contract.

Copied arguments, thread identity, filter inheritance and original call-site
semantics matter independently. A guest-writable secret or caller-supplied
syscall/PC is not trusted authorization. An external broker must also account
for alternate RPC paths, inherited descriptors and raw host access; successful
filter installation alone does not establish complete confinement.

## Userspace Policy Cost

`test_seccomp_entry` compares installed kernel policies with workload-scoped
userspace evaluation through the shared `seccomp_program` interpreter and
read-only `md_seccomp_view`. The installed-policy mode exercises production
publication and lazy SVC; the explicit userspace mode is a prototype limited to
the measured calls, not a process-wide sandbox. Neither measures browser speed.

Build with `SHROOT_BUILD_TESTS=ON`, then supply two raw AArch64
`sock_filter` arrays captured from guest `seccomp`/`prctl` installation:

```sh
cmake --build BUILD --target test_seccomp_entry
python tests/test_seccomp_entry.py BUILD FILE_FILTER FD_FILTER \
  --rounds 5 --executor shell
python tests/test_seccomp_entry.py APK_BUILD FILE_FILTER FD_FILTER \
  --rounds 5 --executor app
```

The App executor requires a fixture APK containing the exact helpers in
`APK_BUILD`. Inputs must permit the measured operations: `FILE_FILTER` allows
`newfstatat`, `openat` and `close`; `FD_FILTER` allows `fstat` and `close`.
Both must deny `renameat` with ERRNO. The runner records their SHA-256 hashes.
Do not infer a browser process role from a filter's filename.

Each launch installs the exact filter in a disposable child as a kernel oracle.
The child checks ERRNO and, when selected by the input policy, TRAP from
`process_vm_readv`, including original PC, syscall number, architecture and
data. The userspace path independently checks the rename denial without
executing it. Unsupported userspace actions fail explicitly, never become ALLOW.

The same timed loops compare native/kernel-filter, Base/kernel-filter,
lazy/kernel-filter, lazy/userspace-policy and lazy/no-policy modes. The last
two are deliberately limited to the measured calls and the denial control;
libc startup and unrelated calls are **not** covered by a virtual guest filter.
Kernel-filter modes install the real policy and exercise production admission,
including eligible direct entry after publication.
Separate instrumented controls check actual cooperative completions; timing
runs omit instrumentation. Rounds alternate forward/reverse mode order,
with CPU-frequency evidence outside each command and no affinity/frequency lock.
Native here means an Android native fixture, not a prepared chroot benchmark.

The matched Shell and User measurements with Chromium 149 filters are
`495f84bfa6af4c05aa15ea8d9b66d538` and `4bf747776a154aba97e113b6511d274b`
under `build/seccomp-entry-results`. They retain filter hashes, mode order and
CPU observations; they are not whole-browser timings.

### Integration Boundary

Use the production policy tests for filter publication, inheritance, TSYNC,
action precedence and original instruction-pointer semantics. The userspace-only
benchmark qualifies none of these. For a real browser, require a sandboxed
launch, correct output and a filtered completion in a process with a published
policy. A nonzero completion count establishes use of the path, not a browser
throughput figure. See the [entry contract](../cooperative-entry.md) and
[browser fixtures](browser/README.md).

## Selective Ptrace Hybrid

`test_hybrid.c` is a bounded static native control. It uses USER_NOTIF for
selected operations and TRACE for register/exec changes, with ordinary
`PTRACE_CONT` between them. Single-stepping is a signal-delivery test control,
not its normal execution mechanism.

Its supervisor owns only its child tree through SEIZE/EXITKILL and event-driven
signalfd/notification observation. Thread-specific INTERRUPT cancels the exact
pending notification. Process-directed SIGSTOP does not provide that identity.

The fixture checks:

- Original ERRNO/TRAP/KILL decisions, nested application SIGSYS and an
  application-owned alternate stack.
- Register-only exec redirection, including after dumpability is disabled.
- ARM64 `orig_x0` rechecking: replacing x0 alone is not equivalent to a fresh
  entry through the original SVC instruction.
- Protected parent/fork-child memory access through bounded instruction-only
  copies, without changing dumpability or using the parent's memory FD for
  a replacement address space.
- Cancellation, copied pathname validation, original-site replay and ADDFD
  publication for a fresh kernel-validated request.
- Concurrent TSYNC denial after copying but before replay.
- Signal masks, original PC/result/siginfo, nested calls and kernel-owned
  EINTR/SA_RESTART behavior.
- Rejection of a second native tracer. Guest debugger compatibility is a
  separate [Shroot contract](../debugging.md).

Temporary copies are untrusted input. No stale notification ID authorizes work.
Cancellation before an external operation is not permission to replay a mutation
whose completion is unknown. The fixture's known code sites and bounded mappings
do not establish arbitrary exec, signal or process-lifetime compatibility.

## Signal-Neutral Checkpoints

The common `task_checkpoint` owner serves normal bootstrap control markers
through selective TRACE or scoped SYSEMU. `task_call` owns native entry/exit
without a return BRK, and `signal_delivery` chains actual delivery stops without
service single-step. Build the controls with `SHROOT_BUILD_TESTS=ON`:

```sh
cmake --build BUILD --target test_signal_checkpoint
python tests/test_signal_checkpoint.py BUILD
```

The runner uses UID 2000 and records the kernel, fixture hash, controls, timings
and cleanup in `build/signal-checkpoints`. The bounded fixture compares BRK,
single-step, syscall entry/exit, seccomp TRACE and two SYSEMU conventions. It
also compares two ways to re-deliver retained real signals: injection at
syscall exit, and a supervisor-originated `tkill` using the retained signal's
own number. Neither replay variant reserves a carrier signal. Delivery stops
restore the original `siginfo` before returning the signal under the saved mask.

Observed on the test phone's Android 16 / Linux 6.12 kernel:

| Mechanism | Result | Boundary |
| --- | --- | --- |
| BRK and hardware single-step | A blocked or ignored SIGTRAP resets its action to SIG_DFL before the tracer sees it | Restoring only the mask cannot repair disposition; CLONE_SIGHAND peers observe the change too |
| Syscall entry/exit checkpoint | Preserves action and mask | Changing the syscall number to -1 at entry still encounters application seccomp; KILL for -1 defeats cancellation |
| Seccomp TRACE checkpoint | Preserves action and mask; cancellation at the TRACE stop also works with KILL for -1 | A subsequently installed KILL filter for the checkpoint call wins before TRACE; the supervisor cannot cancel a stop it never receives |
| PTRACE_SYSEMU checkpoint | Preserves action and mask; the marker is skipped before kernel seccomp, including KILL by number/IP and concurrent TSYNC | Must be scoped to owned service execution; real syscalls encountered there need native admission, not emulation |
| Retained signal sent externally | Preserves disposition, siginfo and native restart decisions when delivery stops are chained without executing userspace between them | Combined entry/seccomp/exit and native job-stop controls pass; regenerating retained job-control signals is not equivalent to keeping them pending in the kernel |

The fixture has 168 positive/control cases and 16 expected KILL-policy rejection
controls. Coverage includes installed/ignored and blocked/unblocked SIGTRAP,
shared dispositions, protected memory, existing pending standard signals and
`RLIMIT_SIGPENDING=0`. Exhausted kernel signal storage retains native loss of
queued sender metadata rather than pretending that the kernel stored it.
A shared progress marker verifies that replay stops do not execute the original
application continuation prematurely. These are native protocol tests, not
168 passing Shroot application workloads.

The additional SYSEMU controls cover:

- 32 strict-policy cases: syscall-number and IP-only KILL, KILL for -1,
  dumpable=0, and TSYNC installed by a sibling while the actor is stopped at
  its emulated entry. Negative controls resume the same marker natively and
  must terminate with SIGSYS.
- Six native-admission cases: original IP and arguments, exactly-once write,
  denial by syscall number or IP, and protected tasks.
- Ten real-signal cases: thread/process-directed SIGUSR1 and SIGTRAP, original
  siginfo, application PC/SP/x0/x7, alternate stack and native
  SIGSTOP/group-stop/LISTEN/SIGCONT. These signals stay in kernel custody until
  application context is restored; this is not the retained-signal replay test.
- Four interrupted-read cases: real handler and rt_sigreturn, EINTR versus
  SA_RESTART, and exactly-once read completion under the original filter.
  ARM64's signal-delivery stop exposes a provisional restart; the final
  SA_RESTART decision is checked in the handler's ucontext and IO result.
- Sixteen retained-signal replay cases: SYSEMU checkpoints replace single-step,
  and their resume queues the retained signal's own number. A real delivery
  stop installs its original siginfo, then requeues it under the service mask.
  Both signals are in kernel custody before restoring application context.
  Tests cover SIG_IGN, blocked delivery/sigtimedwait, handlers/altstack,
  preexisting standard signals, exact PC/SP/x0/x7 and strict seccomp.
- Sixteen native-entry replay cases: a real signal interrupts the original
  syscall without changing its number to -1. Entry and seccomp boundaries
  retain native write-once versus read EINTR/SA_RESTART behavior, original
  metadata and a protected tracee. The original call can complete before the
  handler, as with ordinary ptrace delivery. Integration must preserve that
  ownership, not replay the call.
- Four register-copy cases: an owned load/store sequence publishes x3-x18,
  including x7/x8 payloads, through SYSEMU. An interrupt exposes the hidden x7
  before restoring application registers. The marker is identified by exact
  IP, not a chosen syscall number. Its IP-specific KILL filter proves that
  an unarmed marker cannot execute payload x8 as a native syscall.

Six additional fault controls expose a separate limitation: an invalid source
in an owned userspace load resets ignored/blocked SIGSEGV before ptrace sees
the fault, even with a signal-neutral return checkpoint. The fixture records
this as `LIMIT`, not a transparent-copy pass. A native write/copy_from_user
control returns EFAULT without changing the same signal disposition. These
faulting fallback copies need kernel-mediated access, not just replacement of
their final BRK or a racy VMA precheck.

### Invalid-Pointer Copy Controls

Run the bounded copy investigation without the complete checkpoint matrix:

```sh
python tests/test_signal_checkpoint.py BUILD --copy-fault
```

It retains the six negative LDR controls and adds 72 native self-`process_vm`
read/write controls: installed, ignored and blocked SIGSEGV/SIGBUS; dumpable=0;
valid, inaccessible, unmapped, truncated-file and read-only mappings; and an
exact partial prefix at a protection boundary. On the tested Linux 6.12 device,
kernel copies preserve both dispositions and masks. Six filter scenarios then
deny `process_vm_readv/writev` and subsequently pipe `read/write`: neither is a
universal replacement inside application seccomp. These are native controls,
not integrated Shroot copy implementations or coverage of every kernel.

The same mode compares the production `guest_copy.S` with self-`process_vm` and
a pipe round trip, rotating five rounds of 32768 copies of 128 bytes. Reports
retain raw timings, medians and CPU-frequency context over the command envelope,
not per-thread execution frequency. The recorded fixture medians are 0.19 ms for
userspace, 6.8 ms for either `process_vm` direction and 8.4 ms for the pipe.
The roughly 0.2 microsecond extra cost per kernel copy excludes PID lookup and
adapter integration; it is not a measured whole-application slowdown.

No production path is changed by this experiment. The normal supervisor shield
already unblocks synchronous faults, but cannot protect an ignored disposition
or the caller-mask cooperative path. Existing task helpers share `CLONE_SIGHAND`,
so moving a load there does not isolate the damage. A reliable conditional path
would have to account for native mask/action changes and concurrent peers;
checking VMAs before a load or repairing a handler after the fault is insufficient.
Keep this limitation explicit rather than adding a per-copy kernel trip or a
separate helper lifecycle solely for this case.

### Combined Replay Protocol

The controls distinguish kernel-owned restart and job-control decisions from
register restoration. They check exact signal information, alternate stacks,
pending queues, EINTR/SA_RESTART and exactly-once IO. Negative controls insert
a userspace checkpoint between delivery stops or regenerate a cancelled CONT;
neither is equivalent to leaving the decision in kernel custody.

The [interception contract](../interception.md) and [debugger contract](../debugging.md)
describe production owners. Guest-requested single-step is a debugger operation,
not an internal completion marker. Use the benchmark CTest label for checkpoint
cost; for end-to-end effects, compare matched workloads as described in
[performance fixtures](developer-workflows.md#runtime-benchmarks).

## Real Browser Boundaries

Use [browser/README.md](browser/README.md) for stock Firefox/Chromium workloads.
It distinguishes automatic user/PID namespace startup, the explicitly selected
set-ID helper route, admission rejection and renderer-only diagnostics.
Renderer-only tests and version strings are not full-browser passes.

The [isolation controls](chromium-isolation.md) separately exercise native
namespace admission, a deliberately restricted read-only broker and
helper/protected-memory mechanics. Their reduced syscall surfaces must not be
confused with a general Linux execution environment or native sandbox equivalence.

## Primary References

- [Linux seccomp contract](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux 6.12 notification implementation](https://github.com/torvalds/linux/blob/v6.12/kernel/seccomp.c)
- [Firefox signal/filter integration](https://github.com/mozilla/gecko-dev/blob/master/security/sandbox/linux/Sandbox.cpp)
- [Chromium Linux sandbox](https://github.com/chromium/chromium/blob/main/sandbox/linux/README.md)
- [Android 16 common-kernel ptrace](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/kernel/ptrace.c)
- [ARM64 syscall arguments](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/arch/arm64/include/asm/syscall.h)
- [Kernel signal and ptrace-stop implementation](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/kernel/signal.c)
- [Syscall-stop signal injection](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/include/linux/ptrace.h)
- [ARM64 signal delivery](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/arch/arm64/kernel/signal.c)
- [ARM64 5.15 ptrace/SYSEMU ordering and x7](https://android.googlesource.com/kernel/common/+/refs/heads/android13-5.15/arch/arm64/kernel/ptrace.c)
- [ARM64 5.15 ptrace UAPI](https://android.googlesource.com/kernel/common/+/refs/heads/android13-5.15/arch/arm64/include/uapi/asm/ptrace.h)
- [Signal generation, job control and ptrace requeue](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/kernel/signal.c)
