# Embedding Shroot

`libshroot` is the native C management API. The `shroot` command is a client of
that API. Both use the same native storage, image and runtime owners; neither
requires Java, ART, an Android APK or an installed MagicDesk application.

## Process Boundary

The library contains only client management. It does not load the syscall
adapter, SQLite, the supervisor or a guest into its caller. Operations launch
an executable from an explicitly selected runtime directory. The image worker
uses the existing storage owners; guest launches replace that worker with the
existing runner and its supervised process tree.

`shroot_launch()` starts that complete execution unit. The supervisor owns the
filesystem worker's creation, readiness acknowledgement and shutdown; clients
do not start those threads separately or provide their scheduling. This keeps
internal thread topology outside the public contract. Submission and runtime
completion remain separate from application-specific readiness.

There is no resident management daemon or library-created background thread.
The private completion channel is used at operation admission and completion,
not for guest syscalls or data IO. Only the image worker gains this management
entry; supervisor, bootstrap and cooperative-entry dispatch remain unchanged.

The host's actual credentials remain authoritative. Library calls never select
another Android UID, invoke `su`, modify SELinux policy or implicitly attach
MagicDesk's command service. Each independent Android application must own its
runtime and private store. Logical guest credentials are not an outer security
boundary for hostile code.

## Build And Link

The same project builds `libshroot.so`, `libshroot.a` and `shroot`. Public
declarations are in [`include/shroot.h`](include/shroot.h); internal runtime
structures and SQLite schema are not public ABI. Android shared libraries use
an unversioned `.so` filename for APK packaging; ordinary Linux uses a versioned
SONAME. Static linking is also available to an application's JNI adapter.

```cmake
find_package(Shroot 1 CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE Shroot::shroot)
# Or Shroot::static; both publish the same public header.
```

`SHROOT_BUILD_RUNTIME=OFF` builds just the client library and CLI, without
downloading the native runtime's dependencies. Executing operations still
requires a compatible runtime bundle. `SHROOT_BUILD_TESTS=ON` adds client tests
and, when building the runtime, native fixtures. See the standalone consumer in
[`examples/client`](examples/client).

The library and runtime use the repository's [GPLv3 license](LICENSE). Linking
the library does not introduce an additional licensing exception.

## Objects And Ownership

- A context captures the explicit runtime directory. Keep that bundle immutable
  and available for the context's lifetime; do not replace helpers in place.
- A store selects a canonical host directory, not a global current distribution
  or an open SQLite connection. It does not lock or pin the directory's name;
  coordinate deletion, replacement and relocation with other callers. The
  existing native admission owner performs schema checks and locking when used.
- A job owns one child process, its pidfd and its completion channel. A submitted
  job is independent of the context and store objects.
- Contexts may be used concurrently. A job has one wait owner; another thread
  may signal or cancel it. Coordinate object destruction with all users.

Contexts outlive store handles. Close every completed job. Closing a running
job returns `-EBUSY`; it does not detach a process or silently kill its tree.
Destroying a context or store does not terminate previously submitted jobs.

All strings and IO descriptors passed to a submission are borrowed only until
that function returns. `NULL` IO inherits standard descriptors and the host
environment; an explicit descriptor value of `-1` means `/dev/null`. Guest
environment overrides are separate from the worker's host environment.
Unlisted inherited descriptors are closed before the worker begins storage
operations. Arguments are passed directly to `exec`, never through a shell.

The library does not alter its caller's cwd, umask, environment, credentials or
signal handlers/masks. The application must retain normal child reaping and must
not reap library-owned children through another `waitpid` owner. Submission
rejects `SIGCHLD=SIG_IGN` and `SA_NOCLDWAIT` instead of changing those settings.

## Completion And Cancellation

Submissions return zero or a negative errno. Success means a job was created,
not that import or guest startup completed. The worker receives admission only
after the client has retained its exact pidfd. A lost client before admission
does not authorize changes to storage.

Use the borrowed `shroot_job_fd()` with `poll`/`epoll`, then call
`shroot_job_wait(job, 1, &result)`. A blocking wait is available with zero as the
second argument. Drain output pipes while waiting: an output pipe's capacity
is not an output-storage service.

`shroot_result` separates an operation's negative errno from a process exit code
or terminating signal. Protocol corruption fails explicitly. Errors do not
depend on parsing human-readable stderr. Structured query output retains the
image worker's JSON/JSON-lines formats. A successful runtime `exec` closes the
completion channel, while the pidfd continues to track the runner's lifetime;
it is not a guest-application readiness notification.

`shroot_job_cancel()` sends SIGTERM through the retained pidfd. The existing
runner/guardian owns guest-tree cleanup. `shroot_job_signal()` supports explicit
signal forwarding, and `shroot_stop()` uses a validated live launch identifier.
Never treat a saved numeric PID as cancellation authority. Cancellation can
interrupt an import; existing staging recovery remains responsible for an
unpublished partial store. No new persisted format is introduced.

`SHROOT_EXEC` starts a new supervised tree in the selected store, not a command
inside another live tree. The API makes no claim of container-engine exec
semantics or extra guest isolation.

## Verification

Client tests cover concurrent callers, invalid completion records, literal
arguments, early and running cancellation, guest exit status, and preservation
of caller state. Runtime integration imports an archive with hardlinks and a
symlink, creates two instances, executes stock native guest programs, checks
descriptor isolation and descendant cleanup, and backs up/restores metadata.

```sh
ctest --test-dir build --output-on-failure
python3 tests/test_client_runtime.py build
```

These workflows run outside MagicDesk. Android app-UID execution has been checked
locally from Termux. Ordinary Linux, Raspberry Pi 5 and other page-size/device combinations
still require their own qualification; successful client tests alone do not
establish runtime compatibility there.
