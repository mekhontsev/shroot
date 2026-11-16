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

### SQLite Provider

`SHROOT_SQLITE` selects `bundled` (the default), `system`, or an existing CMake
target. The bundled source is pinned and hash-verified. System mode uses
`find_package(SQLite3)`. A parent project can share its own dependency:

```cmake
add_library(common_sqlite STATIC vendor/sqlite/sqlite3.c)
target_include_directories(common_sqlite PUBLIC vendor/sqlite)
target_compile_definitions(common_sqlite PRIVATE
    SQLITE_THREADSAFE=2 SQLITE_ENABLE_PREUPDATE_HOOK)
set(SHROOT_SQLITE common_sqlite)
add_subdirectory(shroot)
```

Shroot does not modify the supplied target or fetch another SQLite copy. Its
directory-anchored VFS remains a separate adapter using public SQLite APIs.
The required contract is SQLite >= 3.37, `THREADSAFE=1` or `2`, preupdate hooks,
compile-option diagnostics, Unix VFS, WAL, foreign keys, triggers, CHECK constraints,
integrity checks and authorizer support. Headers and required symbols are checked
by compilation/linking; runtime admission checks the loaded provider once, before opening persistent
databases. Incompatible providers fail explicitly, without a silent fallback or
a changed storage format. Each connection remains owned by one runtime thread.
For performance-sensitive builds, the bundled settings also disable SQLite's
global allocation statistics (`SQLITE_DEFAULT_MEMSTATUS=0`). An external provider
retains its own defaults; qualifying its semantics does not prove identical speed.

`SHROOT_STATIC_RUNTIME=ON` retains the self-contained executable bundle. Use
`OFF` for dynamic native runtime executables when supplying a shared SQLite:

```sh
cmake -S . -B build -DSHROOT_SQLITE=system -DSHROOT_STATIC_RUNTIME=OFF
```

Freestanding guest-entry images retain static linking in either mode. A shared
SQLite is reused as a library file, not as an embedding application's database
connection. The integrator owns its ABI, runtime lookup and distribution; Shroot
does not copy system libraries into the installation. Android's private framework
SQLite is not an application dependency. A static provider shares the build but
still contributes code to each executable that links it. `libshroot` itself has
no SQLite dependency in either configuration.

Run the same `database` and `client_runtime` tests for each shipped provider.
The standalone `tests/sqlite` project also accepts `SQLITE_AMALGAMATION`,
`SQLITE_KIND` and `SQLITE_FEATURES` to test a supplied target. `TEST_RUNTIME=ON`
embeds the complete Shroot project; otherwise it runs only the shared storage
contract fixture. `TEST_REJECTION=ON` verifies rejection before storage mutation.

## Objects And Ownership

- A context captures the explicit runtime directory. Keep that bundle immutable
  and available for the context's lifetime; do not replace helpers in place.
- A store selects a canonical host directory, not a global current distribution
  or an open SQLite connection. It does not lock or pin the directory's name;
  coordinate deletion, replacement and relocation with other callers. The
  existing native admission owner performs schema checks and locking when used.
- A library captures an absolute catalog directory, without creating it or
  opening its metadata in the embedding process. Named install, resolve, launch,
  backup/restore and prune use the [native catalog owner](library.md).
- A job owns one child process, its pidfd and its completion channel. A submitted
  job is independent of the context and store objects.
- Contexts may be used concurrently. A job has one wait owner; another thread
  may signal or cancel it. Coordinate object destruction with all users.

Contexts outlive store and library handles. Close every completed job. Closing a running
job returns `-EBUSY`; it does not detach a process or silently kill its tree.
Destroying a context, store or library does not terminate previously submitted jobs.

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
The native library suite adds catalog admission, shared image/layer dependencies,
relocation, recovery and named launch cancellation.

```sh
ctest --test-dir build --output-on-failure
python3 tests/test_client_runtime.py build
```

These workflows run outside MagicDesk. Android app-UID execution has been checked
locally from Termux. Ordinary Linux, Raspberry Pi 5 and other page-size/device combinations
still require their own qualification; successful client tests alone do not
establish runtime compatibility there.
