# Environment Libraries

A library is an explicitly selected directory of named, independently writable
environments. The native image owner manages it; the CLI and `libshroot` use the
same implementation. Names are local to that library, not global distributions.

```sh
shroot library "$HOME/linux" install rootfs alpine-rootfs.tar.gz alpine
shroot library "$HOME/linux" install registry docker.io/library/debian:stable debian
shroot library "$HOME/linux" list
shroot library "$HOME/linux" login alpine
shroot library "$HOME/linux" exec alpine -- /bin/sh -c 'id; uname -a'
shroot library "$HOME/linux" backup alpine alpine.tar.zst
shroot library "$HOME/linux" restore alpine.tar.zst restored
shroot library "$HOME/linux" remove restored
shroot library "$HOME/linux" prune
```

`install oci LAYOUT NAME` imports a local OCI layout, selecting Linux ARM64 and
preserving guest ownership. `install registry REFERENCE NAME` pulls a public OCI
image over HTTPS, including registries requiring anonymous Bearer authorization.
`--resolver CONTENTS` on installation seeds an absent or empty
resolver file; `resolver NAME CONTENTS --replace` explicitly replaces it while
the environment is idle. No host DNS choice or network privilege is implicit.

Initialization, installation and restore can create the selected library root;
its parent must exist. Read and removal operations do not create missing
libraries. Names contain 1-64 ASCII letters, digits, `_`, `.` or `-`, starting
with a letter or digit. Arguments and paths are never interpreted as shell code.

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
