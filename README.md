# Shroot

**Run ARM64 Linux environments on Android and Linux, without root or a VM.**

Install a distribution from an OCI image or rootfs archive, then run its
unmodified binaries on the host kernel. On Android, Shroot runs under an app's
own UID (including Termux) or Android Shell; on ARM64 Linux, it runs as your
normal user. Both need a [Linux 5.15 or newer kernel](kernel-compatibility.md).
Workloads include systemd, sandboxed Chromium and k3s.

Shroot stands for *Supervisor-Hosted Root*. Here, *root* means the root of the
guest filesystem, not root privileges on the host.

Use the `shroot` CLI for your own environments or the [`libshroot` C API](embedding.md)
to add Linux to another application. Both manage the same stores; neither
requires Java or an Android service.

[Install in Termux](#install-in-termux) |
[Install on Linux](#install-on-arm64-linux) |
[Start a distribution](#get-started) |
[Build](#build) |
[Embed](embedding.md) |
[Architecture](architecture.md) |
[Host tests](tests/README.md#qualified-hosts) |
[Distribution matrix](tests/validation-matrix.md)

## Install In Termux

In **aarch64 Termux**, use the Termux `.deb` package from the
[latest GitHub release](https://github.com/mekhontsev/shroot/releases/latest),
not the generic Android `.tar.gz` archive. To install or upgrade:

```sh
url="https://github.com/mekhontsev/shroot/releases/latest/download"
pkg=shroot-termux-aarch64.deb
curl -fLO "$url/$pkg" && curl -fLO "$url/$pkg.sha256" &&
  sha256sum -c "$pkg.sha256" && PATH="$PREFIX/bin:$PATH" apt install "./$pkg"
```

No root, extra APK or APT repository is needed. Environments stay in
`$PREFIX/var/lib/shroot` across package upgrades. Continue with [Get Started](#get-started).

## Install On ARM64 Linux

Download the `linux-aarch64.tar.gz` bundle and its matching `.sha256` file
from the [latest release](https://github.com/mekhontsev/shroot/releases/latest).
From a directory containing only that release's pair, run:

```sh
sha256sum -c shroot-*-linux-aarch64.tar.gz.sha256 &&
  mkdir -p "$HOME/.local" &&
  tar -xzf shroot-*-linux-aarch64.tar.gz --strip-components=1 -C "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

## Get Started

Install Debian from Docker Hub and open a shell in it:

```sh
shroot install debian:stable --name debian
shroot login debian
```

Type `exit` to return to the host shell. To run a single command instead of
opening a login shell:

```sh
shroot exec debian -- cat /etc/os-release
```

With the environment stopped, back it up and restore it under a new name:

```sh
shroot backup debian debian.tar.zst
shroot restore debian.tar.zst --name restored
shroot list
```

`shroot backup` creates a compressed OCI image archive. Restore it in Shroot
or load the same file into Docker with `docker load -i debian.tar.zst`,
without conversion. See [images and storage](images.md#rootfs-archives-and-backup)
for details on guest metadata and ownership.

Already have an ARM64 rootfs tarball? Import it with
`shroot install alpine-rootfs.tar.gz --rootfs --name alpine`.
`shroot --print-library` shows where your environments live.
See the [library guide](library.md) for other image sources, storage locations and cleanup.

## How Shroot Compares To PRoot-Like Tools

Like [PRoot](https://github.com/termux/proot), Shroot runs Linux programs on
the host kernel without root privileges or a VM. Shroot implements a subset
of Linux kernel behavior in userspace. For example, when guest root calls
`chown`, the file's guest owner changes without changing its host owner.
Other guest processes see the change, permission checks use it, and it survives
a restart. Shroot also manages guest mounts, process IDs, cgroups and networking
so that systemd can run as PID 1 and k3s can run containers inside the guest.

PRoot-like tools can leave ordinary syscalls to the host kernel. For calls
that need interception, techniques include external tracing and rewriting
syscall instructions in the guest. Shroot's [Lazy SVC](#lazy-svc) can handle
a call in the guest thread or consult a separate supervisor for shared state.

For a debugger, what matters is which guest events it can observe, not how
the runtime intercepts a syscall. In Shroot, stock GDB can attach to a running
multithreaded program in the same launch, inspect its threads and detach.
See [guest debugging](debugging.md) for tested workflows and limits.

## What It Runs

- **Linux distributions and packages:** stock glibc and musl, package managers,
  compilers, static programs and Go binaries.
- **Init systems and services:** systemd, OpenRC and runit as guest PID 1.
- **Containers and Kubernetes:** Docker, Podman, runc, LXC, systemd-nspawn,
  BuildKit and k3s, including multi-node networking and persistent volumes.
- **Desktop applications:** X11/Wayland desktops, Chromium, Firefox, VS Code,
  selected Flatpak/Snap applications and FUSE document portals. For graphical
  applications in Termux, see [connecting to Termux:X11](library.md#use-termuxx11).
- **Development tools:** GDB, LLDB, gdbserver, strace and QEMU's software emulator.
- **Recursive execution:** [run Shroot inside Shroot](#recursive-execution) without
  a special nesting mode.

The [distribution matrix](tests/validation-matrix.md) shows which workloads
were tested on each distribution and where limitations remain.
[Host tests](tests/README.md#qualified-hosts) cover Android with 4 KiB pages
and a Raspberry Pi 5 with 16 KiB pages.

## Lazy SVC

On the first interception of an eligible AArch64 syscall instruction (`svc`),
Shroot rewrites it in process memory. Later calls from that site can check the
guest's seccomp policy and complete in the calling thread, or ask the supervisor
over shared memory, without a ptrace stop on every call. Ordinary native reads
and writes stay native. Nothing is patched on disk.

When a site cannot be rewritten, the guest policy is unavailable, or a debugger
owns execution, Shroot uses its Base seccomp/ptrace path. Both paths use the same
syscall implementations. To select Base explicitly for a launch, pass
`--env SHROOT_MACHINE_ENTRY=0` to `shroot exec`.
See [cooperative entry](cooperative-entry.md) for admission,
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

The host launches Shroot; Shroot's ELF loader loads guest programs from the
environment store. SQLite holds guest names, inode identities, permissions
and layer relationships; native files hold their data. Shared image
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
