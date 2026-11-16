# Environment Libraries

A library is an explicitly selected directory of named, independently writable
environments. The native image owner manages it; the CLI and `libshroot` use the
same implementation. Names are local to that library, not global distributions.

```sh
shroot library "$HOME/linux" install rootfs alpine-rootfs.tar.gz alpine
shroot library "$HOME/linux" list
shroot library "$HOME/linux" login alpine
shroot library "$HOME/linux" exec alpine -- /bin/sh -c 'id; uname -a'
shroot library "$HOME/linux" backup alpine alpine.tar.zst
shroot library "$HOME/linux" restore alpine.tar.zst restored
shroot library "$HOME/linux" remove restored
shroot library "$HOME/linux" prune
```

`install oci LAYOUT NAME` imports a local OCI layout, selecting Linux ARM64 and
preserving guest ownership. Registry acquisition is not yet provided by this
native catalog. `--resolver CONTENTS` on installation seeds an absent or empty
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
