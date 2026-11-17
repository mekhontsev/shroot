# Source Provenance

The initial history is extracted from
https://github.com/mekhontsev/magicdesk at
`e03e124f`, retaining author and commit history for the native runtime, its
fixtures and the optional native command-channel wire implementation.

`include/resource_protocol.h` is the versioned resource-attachment wire
declaration from https://github.com/mekhontsev/magicdesk-x11 at
`973d3c48c73aa4f55d1671f79ba1e651151d4b16`, path
`lorie/src/main/cpp/lorie/resource_protocol.h`. It describes an optional client
connection, not a build dependency on an X server or Android renderer.

The inherited GPL-3.0 license is in LICENSE. Pinned native dependencies retain
their individual license texts in the build's licenses directory and release
bundles. No licensing changes are implied by repository extraction.
