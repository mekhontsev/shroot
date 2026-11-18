# Source Provenance

| Component | Source |
| --- | --- |
| Native runtime, fixtures and optional command-channel wire implementation | [MagicDesk at `e03e124f`](https://github.com/mekhontsev/magicdesk/tree/e03e124f); the repository retains the original author and commit history. |
| [Resource-attachment wire declaration](include/resource_protocol.h) | [magicdesk-x11 header at `973d3c48`](https://github.com/mekhontsev/magicdesk-x11/blob/973d3c48c73aa4f55d1671f79ba1e651151d4b16/lorie/src/main/cpp/lorie/resource_protocol.h). This optional client protocol does not require an X server or Android renderer at build time. |

Shroot retains its [GPL-3.0 license](LICENSE). Pinned dependencies retain their
own license texts in the build's licenses directory and in release bundles.
