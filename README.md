# Shroot

**Run ARM64 Linux environments on Android and Linux, without root or a VM.**

Shroot is a native userspace runtime and environment manager. It runs stock
Linux programs on the host kernel and supplies filesystem, credential,
namespace and networking interfaces that the host does not expose to the caller.

Use the `shroot` CLI directly, or integrate the [`libshroot` C API](embedding.md)
into another project. Both use the same runtime, environment catalog and storage.

[Get started](#get-started) |
[Build](#build) |
[Embed](embedding.md) |
[Architecture](architecture.md) |
[Host tests](tests/README.md#qualified-hosts) |
[Distribution matrix](tests/validation-matrix.md)

## What It Runs

- **Linux distributions and packages:** stock glibc and musl, package managers,
  compilers, static programs and Go binaries.
- **Init systems and services:** systemd, OpenRC and runit, including guest PID 1
  and service lifecycle.
- **Containers and Kubernetes:** Docker, Podman, runc, LXC, systemd-nspawn,
  BuildKit and k3s, including multi-node networking and persistent volumes.
- **Desktop applications:** X11/Wayland desktops, Chromium, Firefox, VS Code,
  selected Flatpak/Snap applications and FUSE document portals.
- **Development tools:** GDB, LLDB, gdbserver, strace and QEMU's software emulator.
- **Recursive execution:** run Shroot inside Shroot with the same runtime
  binaries, without a special nesting mode.

These are supported workflows, not a claim that every package works on every
host. The [distribution matrix](tests/validation-matrix.md) records application
coverage by distribution, executor and entry mode, including outstanding limits.
[Host coverage](tests/README.md#qualified-hosts) includes Android on 4 KiB pages
and a Raspberry Pi 5 on 16 KiB pages. Those are distinct configurations.

## Get Started

Use an ARM64 Android or Linux host with **Linux 5.15 or newer** and executable
storage. Android application UIDs, Android Shell and ordinary unprivileged Linux
users run the same engine. Shroot checks the selected identity's actual
capabilities; it does not change SELinux or silently elevate privileges.
See [host requirements](architecture.md#execution-policy) and
[kernel compatibility](kernel-compatibility.md).

With a [built and installed bundle](#build), install an ARM64 environment from
an OCI registry and open its shell:

```sh
shroot install debian:stable --name debian
shroot login debian
```

Or import an ARM64 rootfs archive you already have:

```sh
shroot install alpine-rootfs.tar.gz --rootfs --name alpine
shroot exec alpine -- /bin/sh -c 'id; uname -a'
```

List environments, back one up, or restore it under another name:

```sh
shroot list
shroot backup alpine alpine.tar.zst
shroot restore alpine.tar.zst --name restored
```

`shroot --print-library` shows where environments live. To select another
catalog for one command, use `shroot --library DIR list`. The
[library guide](library.md) covers defaults, registry access, DNS and cleanup.
Backups preserve guest metadata, ownership and hardlinks; see
[images and storage](images.md) for formats and sharing rules.

## Lazy SVC

Shroot replaces eligible AArch64 syscall instructions in process memory when
they are first intercepted. Stock binaries need no rebuild, and files on disk
remain unchanged.

The common entry evaluates the guest's seccomp policy in its own thread, then
selects native execution, a direct result or a request to the shared resource
owners. Admitted calls use shared-memory channels; ptrace stops remain for
operations that actually need kernel task context. Ordinary native data IO
stays native.

Unsupported sites, unavailable policy views and debugger-owned execution retain
the Base seccomp/ptrace path. Base and lazy entry share syscall implementations
and resource ownership. See [cooperative entry](cooperative-entry.md) for admission,
signals, sandbox filters and performance controls.

## Recursive Execution

On Android, an ordinary Termux UID runs Alpine in Shroot. Alpine builds Shroot
with musl and uses it to launch Debian. The full native functional suite runs
from Debian: its glibc build starts a third guest for debugger and signal tests,
and a fourth for fork/exec/wait tests in all four Base/lazy SVC combinations of
the two innermost runtimes.

Each level has its own supervisor and store. No nesting mode or extra host
privileges are needed. Deep test runs use longer time limits; see
[recursive test coverage](tests/README.md#nested-runtime).

## Storage And Integration

Each environment has an inode-backed store. SQLite holds guest names, identity,
permissions and layer relationships; native files hold their data. Shared image
layers and copy-on-write environments do not depend on host hardlink or mount
privileges. Installed stores retain their identity across runtime updates.

`libshroot` manages installation, import, launch, cancellation, backup and cleanup.
Guest execution runs out of process: the library does not install signal
handlers or a syscall adapter into its host. Runtime thread topology stays
internal, and each launch retains its chosen identity and environment.

[MagicDesk](https://github.com/mekhontsev/magicdesk) uses Shroot for its Linux
environments on Android. It adds terminals, graphics, audio, file exchange and
automation. Other integrations can use the same native API and explicit host
connections.

## Boundaries

Host-enforced isolation is separate from Shroot's guest semantics. On Android,
a distinct application UID with private storage supplies the kernel-enforced
[application sandbox](https://source.android.com/docs/security/app-sandbox),
including UID, SELinux and seccomp protections for native processes. Guest root
does not grant host root or access to another application's private data.

Shroot itself shares the host kernel and supplies a supported subset of Linux
semantics. Its logical separation between environments sharing one host UID is
not a security boundary for hostile code. Guest permissions, mount policy,
supported Landlock rules and seccomp checks remain meaningful, but unadapted
calls and inherited descriptors retain that UID's host authority. Explicitly
shared files, connections and graphics sessions remain shared capabilities;
different host UIDs do not isolate clients of the same X11 server from one another.

Logical cgroups enforce pids limits and freezer state, but not hard CPU, memory
or device limits. Snap's reduced confinement does not provide AppArmor isolation.
Graphics and hardware access depend on the host and the integration. Use trusted
images and programs; consult the relevant [resource contracts](architecture.md#contracts)
before relying on a particular isolation or device feature.

## Build

Build hosts are Linux and Android/Termux; Windows users can use WSL2 with Linux
tools. A native runtime build targets ARM64.

Install a C compiler, CMake, Ninja, Git, Linux UAPI headers and DRM headers
(`linux-libc-dev` and `libdrm-dev` on Debian; `linux-headers` and `libdrm-dev`
on Alpine). DRM headers describe the wire ABI; the runtime does not link libdrm.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
cmake --install build --prefix "$HOME/.local" --component Shroot
```

Ensure `$HOME/.local/bin` is on `PATH`. Android cross builds use the NDK CMake
toolchain with `ANDROID_ABI=arm64-v8a` and `ANDROID_PLATFORM=android-34`.

For a local ARM64 Termux package, use a separate build directory:

```sh
cmake -S . -B build/termux -G Ninja -C packaging/termux.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/termux -j 4
cpack --config build/termux/CPackConfig.cmake -B build/packages
```

The package installs one `shroot` command and selects `$PREFIX/var/lib/shroot`
at build time. Cross-packagers supply the target `TERMUX_PREFIX` and Android
toolchain. The package does not contain or own any installed environments.

Dependencies are pinned and linked statically by default. SQLite can instead
come from the system or an embedding project's CMake target, subject to the
[provider requirements](embedding.md#sqlite-provider). The image worker uses
dynamic host libc for DNS. HTTP/TLS dependencies belong only to that worker,
not the supervisor or `libshroot`.

The [embedding guide](embedding.md) covers CMake options, installed bundles,
client-only builds and API ownership. The [fixture guide](tests/README.md)
covers component tests and real-application checks.

## Documentation

| Task | Guide |
| --- | --- |
| Install, run, back up and remove environments | [Environment libraries](library.md) |
| Embed the C management API | [libshroot](embedding.md) |
| Understand runtime ownership and execution | [Architecture](architecture.md) |
| Work with OCI images, layers and storage | [Images](images.md), [inode store](inode-store.md) |
| Configure networking | [Networking](networking.md) |
| Check host requirements and fallbacks | [Kernel compatibility](kernel-compatibility.md) |
| Run tests and compare application coverage | [Fixtures](tests/README.md), [distribution matrix](tests/validation-matrix.md) |

Shroot is licensed under [GNU GPLv3](LICENSE). Dependency licenses and source
provenance are described in [ORIGIN.md](ORIGIN.md).
