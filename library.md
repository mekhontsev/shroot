# Environment Libraries

A library is a directory of named, independently writable
environments. The native image owner manages it; the CLI and `libshroot` use the
same implementation. Names are local to that library, not global distributions.

`shroot os-info /path/to/store` reads distribution presentation without
starting a guest. It returns JSON with `prettyName`, `versionId` and a
hex-encoded PNG (empty fields mean unavailable). The guest's
`/etc/os-release` takes precedence over `/usr/lib/os-release`. A named
logo is resolved in system icon directories, not on the host or the network.
These values are display hints, not a store identity or a software version
constraint.

Without options, the standalone CLI uses the absolute `$XDG_DATA_HOME/shroot`,
or `$HOME/.local/share/shroot` when XDG data home is unset, empty or relative.
The Termux package selects its target `$PREFIX/var/lib/shroot` at build time;
an inherited `PREFIX` does not redirect a Linux binary running inside a guest.
Packagers can set an absolute `SHROOT_DEFAULT_LIBRARY` at CMake configuration.
This is a CLI choice: callers of `libshroot` always supply their own path.

`shroot --print-library` prints the selected directory without opening or
creating it. `shroot --library DIR COMMAND` selects a different library for one
invocation. A bare `work` in `login`, `exec`, `run`, `backup`, `remove` or
`resolver` is always an environment name; `./work` and `/path/to/work`
refer to a store directly. Selection never depends on what exists in the current directory.

```sh
shroot install alpine-rootfs.tar.gz --rootfs --name alpine
shroot install debian:stable --name debian
shroot list
shroot login alpine
shroot exec alpine -- /bin/sh -c 'id; uname -a'
shroot backup alpine alpine.tar.zst
shroot restore alpine.tar.zst --name restored
shroot remove restored
shroot prune
```

`install LAYOUT --oci --name NAME` imports a local OCI layout, selecting Linux ARM64 and
preserving guest ownership. `install REFERENCE --name NAME` pulls a public OCI
image over HTTPS, including registries requiring anonymous Bearer authorization.
`--resolver CONTENTS` on installation seeds an absent or empty
resolver file; `resolver NAME CONTENTS --replace` explicitly replaces it while
the environment is idle. No host DNS choice or network privilege is implicit.

Initialization, installation and restore can create the library root and, for
the default location, its parents. An explicit directory's parent must exist.
An absent default library lists as `[]`; a missing explicitly selected library
or an incomplete catalog reports an error. Reads and removal never create libraries.
Names contain 1-64 ASCII letters, digits, `_`, `.` or `-`, starting
with a letter or digit. Arguments and paths are never interpreted as shell code.

## Use Termux:X11

A guest launched from Termux can use its existing Termux:X11 server. For
display `:1`, forward just the local X socket (both pathname and abstract
forms). In this example `$auth` is a private directory containing only the
server's `Xauthority` file, with a cookie valid for the guest's display name.
Start the server with that file (`termux-x11 :1 -nolisten tcp -auth "$auth/Xauthority"`).

```sh
socket="$TMPDIR/.X11-unix/X1"
shroot exec debian --env DISPLAY=:1 --env XAUTHORITY=/tmp/xauth/Xauthority \
  --bind-ro-create "$auth" /tmp/xauth \
  --socket-path /tmp/.X11-unix/X1 "$socket" \
  --socket-abstract /tmp/.X11-unix/X1 "$socket" -- /usr/bin/xev
```

The guest does not need the rest of Termux's temporary directory or disabled X
access control. To verify a running server, use
`python tests/test_termux_x11.py debian --display 1 --authority "$auth/Xauthority"`.
The test needs `xdpyinfo` and `xev` in the guest and `xdotool` in Termux. It
checks that the window maps and receives a mouse click and a keystroke.

## Identity And Storage

The library contains `names`, `instances`, `images`, `layers`, `cache` and `work`.
Each name record retains a stable environment UUID and a separate storage key.
Published name records use format 2; format 1 is also admitted without rewriting
installed identities or paths. These catalog formats are independent of inode
storage family 17, metadata revisions, the runtime version and image import
identity. Unknown catalog versions fail without mutation.

Records use relative resource keys. Native source references remain relative
where possible. `relocate-library OLD NEW` moves an idle library without copying
file bodies and coordinates with the same catalog lock. A library handle captures
its selected path; recreate handles after an explicitly coordinated move.

Rootfs input is copied once into a private anonymous snapshot before hashing and
import. Identical archives share a sealed base image but retain separate
environment IDs and writable stores. Local OCI layouts use shared verified
layers. The importer owns archive validation and metadata; the catalog never
extracts files itself or creates another filesystem implementation.

## Registry Downloads

References accept a registry/repository with a tag or `@sha256:...` digest.
Unqualified names use Docker Hub and an omitted tag means `latest`. Multi-platform
indexes select Linux ARM64/v8; ambiguous matches, unsupported media, incorrect
sizes and digests fail before name publication. Downloaded layouts use the same
native importer and shared layers as local layouts. Identical selected manifests
share a sealed base, not writable state or environment identity.

TLS verifies the certificate chain and hostname. Android uses its system CA
directory; ordinary Linux uses its host certificate bundle or directory.
`--ca-file FILE` and `--ca-directory DIRECTORY` explicitly select custom trust.
There is no insecure mode. Both initial URLs and redirects require HTTPS and
reject embedded credentials. Registry tokens are sent only to that registry's
origin, never to a different-port/host CDN or to the token endpoint. Private
registry login credentials are not yet supported.

The library's `cache` retains verified digest-addressed blobs. Each reuse checks
size and hash. Downloads publish by synced no-replace rename, without a second
copy of large layers or a host hardlink requirement. Cancellation preserves
completed blobs; the next pull recovers abandoned download files under the
catalog lock. `prune` can discard the download cache without affecting imported
stores. Corrupt completed cache entries fail explicitly; prune before retrying.

JSON responses are bounded to 8 MiB, index nesting to five documents, layers to
256 per image and aggregate compressed layer data to 64 GiB. Descriptor admission
also limits each blob to 8 GiB. Connect and stalled-transfer deadlines bound
network failure, not total installation time. Curl and Mbed TLS are linked
statically into the image worker only; no network library runs in a guest syscall
path or is loaded into the embedding application. The image worker uses the
host's dynamic libc so name resolution follows the host network, including
Android's system resolver; this does not change guest execution helpers.

## Lifetime And Recovery

Catalog mutations take a nonblocking POSIX lock, shared with library relocation.
Concurrent mutation reports busy. Listing and resolution can read committed
records during installation. Store use and removal retain the native lifetime
leases; a running environment prevents removal. Launch resolves a name to its
immutable storage key once. Runtime admission may fail if the selected store
becomes unavailable before its own lease is acquired; it never switches to a
replacement environment of the same name.

A new name is published only after its store and optional configuration are
ready, using a synced temporary file and no-replace rename. Failure to sync after
rename is an uncertain durable outcome: inspect the selected name before retrying.
Published data is not rolled back. Interrupted work remains unnamed and can be
collected by `prune`.

Removal rejects aliases and persistent dependents, then delegates to native
store removal. It does not need to read the selected store's SQLite metadata.
Unreadable metadata of another possible dependent remains an error, not evidence
that deletion is safe. Cleanup accepts only library-owned resources and never
follows a replacement symlink.

Pruning checks the complete dependency graph before deleting unreferenced
stores, removes dependents before their sources, and retains layers used by
surviving stores. Unknown stores and cycles fail explicitly. An indexed in-memory
graph avoids repeated whole-library scans for long source chains; it is not
another persistent database or work on the syscall path. Native leases still
arbitrate live use. Completed-removal journals and unpublished input files use
their existing recovery owners.

`list` emits a JSON array; `resolve NAME` emits one JSON object containing
`name`, `id`, `store`, `image` and `source`. Installation emits progress followed
by that record. Use a separate `resolve` for structured post-install inspection;
operation success and errors come from the job result, not progress text.

## Verification

`tests/test_library.py` runs against the actual native backend, without Java or
an Android application. It covers shared rootfs/OCI inputs, named execution and
cancellation, backup/restore, catalog locking, format admission, identity/store
separation, aliases, busy stores, corrupted metadata, relocation, recovery,
dependency cycles and long chains. It reuses the native client guest fixture.
Every run creates and removes its own temporary library.

`tests/test_registry.py` uses local HTTPS servers with explicit test trust and
the actual CLI, image worker and importer. It covers anonymous Bearer exchange,
multi-platform selection, cross-origin redirects, certificate verification,
corrupt input/cache, cancellation and retry, then executes the imported guest.
It requires Python and the OpenSSL command-line tool to generate ephemeral
certificates; no public network or preinstalled distribution is required.
