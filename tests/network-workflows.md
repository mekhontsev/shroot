# Network Fixtures

Run the smallest workload that exercises the required path: a launch profile, a container publication, or a complete booted cluster. [Fixture setup and executor selection](README.md#fixture-transports).

## Launch Profiles

`test_launch_network.py --store STORE --build BUILD` checks the common launch
network profile under UID 2000: run/exec/login/low-level entrypoints, offline
loopback, isolated DNS views, concurrent bridge TCP/UDP publications, outgoing
TCP/UDP, a real libc DNS query, conflicts, cancellation and abnormal exit.
The store needs Python 3 and an installed resolver; `--cli-only` needs only a
shell and cat (also tested on Alpine). `--native-tests` includes the resource,
mount and filesystem-worker suites, including partial port-reservation rollback.
Traffic assertions use local native peers, independently of internet stability.
`test_os_boot.py --network bridge --dns IP` applies the same profile to stock
init boot; its default remains routed. Reports identify the native binaries.

## K3s

`test_k3s.py [BUILD] ENVIRONMENT K3S_ARM64 --machine-entry` uses an installed
recipe environment with Python 3, util-linux and a verified upstream k3s binary.
The receipt records its SHA-256, version, runtime hashes and entry/kernel profile.
Container images are imported or pulled by stock containerd. Repeatable
`--images ARCHIVE.tar` supplies verified airgap or workload archives through
each node's normal image inbox; receipts record their hashes. Missing images
still require registry access. No distribution packages are built or installed
by the fixture.

K3s is in scope for every recipe OS. Use `--executor app|shell` to select the
host identity; omitted `BUILD` tests the installed APK. `--store PATH` selects
an already accessible store instead of resolving the recipe name. This also
supports the [borrowed-store handoff](host-execution.md#borrowing-an-installed-environment)
without a second rootfs. A result applies only to its recorded OS and executor.

The default profile uses stock VXLAN; `--backend host-gw` selects the alternative.
The node runs in a private `--network bridge` by default, so its low-numbered
ServiceLB ports do not require host bind privileges. `--network routed` also
tests automatic host publication and requires the corresponding native port
permissions. Both profiles retain the pod, Service, ingress and restart checks.
`test_k3s.py` always uses one selected distribution. For a mixed cluster run
`test_k3s_cluster.py [BUILD] SERVER_ENVIRONMENT AGENT_ENVIRONMENT K3S_ARM64`.
It additionally accepts `--agent-store PATH` for an explicit agent store.
Both entrypoints share `k3s_fixture.py` for workloads, lifecycle and cleanup.
The mixed fixture attaches the existing agent store read-only and gives it
private configuration and runtime mounts. It does not install packages or copy
the rootfs; receipts identify both distributions and the staged runtime.
Each node retains distribution inputs under `/var`, including certificate stores
referenced from `/etc`. Kubelet, CNI, Rancher and log data have separate empty
mounts. Missing mountpoints are prepared before read-only attachment and only
those empty directories are removed afterwards; installed data is retained.
Use `test_k3s.py --nodes 2` for two nodes within one distribution; the mixed
entrypoint always uses two nodes. Server and agent have independent network,
PID, mount, UTS and cgroup namespaces, connected by a veth underlay on the same device.
Both profiles retain stock Traefik, ServiceLB and NetworkPolicy.
The fixture checks Node Ready, CoreDNS, kubelet root filesystem capacity, cross-pod
DNS/ClusterIP HTTP, policy deny/allow/update/delete, Deployment scale/rolling
update, local-path PVC retention, and ingress through the Service and node address.
With two nodes, DNS and HTTP must cross nodes, and the agent restarts independently.
Server restart must retain pod UID and Service address; ordinary deletion uses
the default termination grace. After restart, the kubelet's own inventory must
reacquire the pods before executing inside them; retained API readiness alone
does not satisfy this check.
Private PID/mount namespaces retire remaining shims and runtime data; logs and
the structured result are downloaded before deleting the fixture directory.
Use `--base` for fallback entry or `--kernel-profile linux-5.15` for host-capability
fallbacks. Neither that profile nor this scenario certifies a physical 5.15 kernel
or networking between separate devices.

`test_k3s_boot.py BUILD ENVIRONMENT K3S_ARM64 INSTALL_SH --init systemd|openrc`
tests one installed recipe through the production `magicdesk-init` helper.
Each boot uses a private bridge, so distribution services can bind guest ports
such as the DNS stub's 53 without publishing privileged Android listeners.
Supply a verified binary and its unmodified upstream installation script; their
hashes are recorded. The installer runs inside the first boot and installs the
stock enabled service. API readiness and the init service's completed activation
are checked separately; observing an activating service never restarts it.
Repeatable `--images ARCHIVE.tar` supplies verified
upstream airgap bundles or workload OCI archives through k3s's normal agent
image directory. Images absent from those archives still require registry access.
Three complete Shroot launches cover initial boot,
orderly poweroff/restart, then exact-supervisor SIGKILL and recovery. Each boot
checks Node Ready, CoreDNS, pod DNS/Service IO and a synced local-path PVC write;
recovery also compares node, namespace, pod, volume, Service and credential
identity. Killing a supervisor is distinct from a k3s-only restart or power loss.
The fixture refuses an existing k3s installation and preserves pre-existing
kubelet/CNI state. Preparation and cleanup both run inside the production init
session, including the distribution's own mounts of `/etc` and `/var`. After
test launches stop, a cleanup boot retires the stock service and restores owned
files. Interrupted launches are stopped by their exact registry identity.
It accepts the same entry/kernel profiles, `--executor app|shell`, and `--store`
for an existing store accessible to that executor, including a borrowed store.
Native control fixtures use the executor's verified executable mapping; the
guest installation does not switch Android identity. Its phase logs and receipts
are separate from the broader multi-node workload checks above.

`test_network_vxlan.py BUILD ENVIRONMENT` checks the packet/control contract
independently of k3s and registry availability. It covers an independent wire
peer, shared UDP ports and VNI isolation, MTU and outer filtering, static IPv4/IPv6
neighbors/FDB, routed `onlink` traffic, TCP streams, UDP fragmentation and teardown.
It accepts the same entry and kernel-profile options.

`test_ipset.py BUILD ENVIRONMENT` separately exercises stock ipset and iptables-nft,
IPv4/IPv6 prefix membership, exclusions, referenced-set replacement, large
restore/dump, transactional rejection and metadata-only NFLOG delivery. It accepts
the same entry and kernel-profile options. `probe_nft_runtime.py` covers TCP
tracking deletion/expiry without transport loss and namespace-scoped timeout
controls. Neither test substitutes for the real k3s policy controller.

## Container Publication And IPv6

The Docker and Podman network probes allocate paired TCP/UDP ports through an
observer outside Shroot, then check publication, collision rejection, and port
release. They do not assume fixed test ports are unused. Docker diagnostic
profiles use a private empty daemon config so their explicit flags do not collide
with `/etc/docker/daemon.json` written by the installer. This does not validate
that system daemon's service-unit startup. Host-side observer ownership checks:
`python tests/test_network_observer.py`.
The Docker probe selects a Python image automatically for `--exercise-ports`;
an explicit `--image` must also provide Python for that scenario.
`--profile nftables --no-userland-proxy` requires Docker 29+ and checks the
same local matrix as `--profile routed`, which retains the older proxy profile.
Both engine probes keep internet checks opt-in (`--internet`); local TCP/UDP,
container-name DNS, conflicts and cleanup must pass independently. A token-scoped
HTTP endpoint on the native host interface also verifies outbound request and
response routing without a public server. This catches reverse-NAT/raw-chain
ordering failures independently of external connectivity. Podman's optional
`--host-limits` is diagnostic: normal acceptance uses the common logical
NOFILE/NPROC contract without explicit container limit overrides. The physical
Android limits still apply.

Both accept `--executor shell|app` through the shared fixture executor.
`--exercise-ports` also runs the same writable-layer checks in both containers:
rename, hardlink identity/link counts, open-after-unlink, a nested exec with an
inherited seccomp filter, 128 create/rename/remove cycles and 4096 open/read/close
operations. Temporary files are removed within each container. These are
correctness checks, not isolated filesystem benchmarks. A launcher-level lazy
completion count alone does not establish acceleration inside its containers.

`--exercise-ports --ipv6` selects a dual-stack container bridge and checks IPv6
TCP/UDP publication and named peers. `--ipv6-host ADDRESS` selects an address
assigned to both the outer Shroot namespace and Android for publication and
native observation; the default is `::1`. Podman's `--ipv6-publish-host ::`
separates a guest wildcard binding from the Android observer address, which
need not be assigned to a guest interface. Both choices are retained in the
receipt. Test a non-loopback address separately: Netavark's IPv6 localhost
forwarding is not equivalent to its ordinary host-address path. Its nft backend
does not provide IPv6 loopback SNAT; a loopback source cannot enter a non-loopback
IPv6 interface. Do not relax Shroot ingress checks to make that scenario pass.
The fixtures neither add Android addresses nor modify Android routing.

`--internet-ipv6` additionally requires UDP DNS, TCP DNS and certificate-verified
HTTPS from both containers to `2606:4700:4700::1111`. All sockets explicitly use
AF_INET6, without IPv4 fallback; the HTTPS response must identify an IPv6 source.
This opt-in public test needs a working Android IPv6 uplink, not just addresses
inside Shroot. A VPN can reject IPv6 even when cellular service provides it.
Any temporary host-routing exception belongs to an explicitly authorized lab
setup, scoped to the test destination/UID and removed after the run; it is not a
recipe prerequisite or a production VPN bypass.
`test_network_ipv6.py --build BUILD --name NAME --internet` uses the same public
assertions natively and in guest `routed`/`bridge` modes, in addition to its local
address/route, ICMPv6, dual-stack socket, nftables and port-publication checks.
Omit `--internet` for deterministic local coverage.

## Multicast, DHCP And NixOS Boot

`test_network_multicast.py BUILD STORE` checks IPv4/IPv6 membership, reuse,
namespace fanout, leave, loopback, hops, filtering and unicast responses with
both entry modes. `test_network_dhcp.py BUILD STORE [--ipv6]` runs packaged
dhcpcd against a fixture server in another guest namespace. It requires a lease,
renewal, DNS hook options, routes and bidirectional traffic using the leased
address. `--python PATH --path PATH` selects packaged tools in non-FHS guests
such as NixOS; it does not substitute the client or change Android networking.
`test_nixos_boot.py --build BUILD --store STORE --system CLOSURE --python PYTHON`
boots an idle, disposable NixOS store through its stock activation and
`/sbin/init`, using the common private init mounts. A private guest DHCP/DNS
peer supplies a lease to the unmodified dhcpcd unit. Checks cover its non-root
identity, capabilities, no-new-privileges and seccomp, address/default route,
stock resolvconf, real libc DNS lookup, UDP traffic, service restart and
shutdown. `--network preconfigured` instead boots a recipe generation with
its launch-owned uplink, retaining the common systemd service and shutdown
assertions without expecting a DHCP unit. `--entry base` repeats the boot without lazy entry. The fixture
server is not a production DHCP service or an Android uplink test; neither
Android addresses nor routes, DNS or privileged ports are changed.

## Routing, Firewall And Performance

`probe_podman_runtime.py BUILD STORE --rootless-user USER --exercise-ports
--internet` runs stock Podman as an existing disposable guest user with
subuid/subgid ranges and the distribution's UID-map/network helper packages.
Only private API mounts are prepared as guest root. Containers retain normal
seccomp and cgroup settings. Rootless checks retain the installed Podman's
default network; `--network` selects an explicit diagnostic alternative.
tests cover external TCP/UDP ports, outbound IO, conflicts and teardown.
Named-peer DNS checks apply to the separate bridge mode, not isolated rootless
networks. The fixture ends its Podman pause process with `podman system migrate`.

`probe_docker_runtime.py BUILD STORE --rootless-user USER --storage-driver overlay2
--cgroup v2 --exercise-ports --internet` starts the distribution's
`dockerd-rootless.sh` (or Alpine's `dockerd-rootless`) through stock RootlessKit, slirp4netns and UID-map helpers
as an ordinary guest user. It requires rootless and seccomp security options,
then checks two containers, published TCP/UDP, peer IP/name lookup, outbound IO,
port conflicts and teardown. The named diagnostic `rootless*` profiles without
`--rootless-user` only enter a guest user namespace; they do not substitute for
this ordinary-user integration test.

`test_booted_containers.py --session SESSION --engine podman|docker --rootless`
runs the same probes through an existing ordinary-user init-session controller.
It retains that user's identity and the booted system mounts; it neither starts
a rootful daemon nor prepares another sysfs/cgroup view. Without `--rootless`,
the driver tests the booted rootful service.

`test_lwip_context` checks namespace-local protocol state and memory limits;
the `test_task_resources` target includes `test_network_tun.c` for TUN/TAP ABI,
queue ownership, virtio-net layout/checksum/segmentation, ARP ioctls,
IPv4/IPv6 TCP/UDP, fragment reassembly and raw ICMP.

`probe_packet_runtime.py` exercises real packet applications in an installed
recipe environment (Debian by default), using the staged native build as shell
UID 2000. TUN uses unmodified ARM64 tun2socks and GOST executables; place them
in `ASSETS` as `tun2socks-linux-arm64` and `gost`. TAP requires the distribution's
`qemu-system-aarch64`, a trusted Alpine ARM64 kernel/initramfs pair with
virtio-net modules, and the static `packet_vm` test target:

```sh
python tests/probe_packet_runtime.py --kind tun --assets ASSETS
cmake --build build/shroot-image-tests --target packet_vm
python tests/probe_packet_runtime.py --kind tap \
  --kernel vmlinuz-virt --initramfs initramfs-virt
python tests/probe_packet_runtime.py --kind vpn --installed
python tests/probe_packet_runtime.py --kind wireguard
python tests/probe_packet_runtime.py --kind openconnect
python tests/probe_packet_runtime.py --kind ipsec --network bridge
python tests/probe_packet_runtime.py --kind tailscale --network bridge --assets ASSETS
```

Use `--build BUILD`, `--environment NAME` and `--base` as needed. `--installed`
uses the APK runtime; TAP still takes its test executable from `--build`. The report
records native and input hashes. No package is installed by the fixture, and
no host interface is configured. TUN separates the proxy and client namespaces,
tests IPv4/IPv6 TCP/UDP with payload verification and half-close, and rejects a
route bypass before/after tun2socks runs. TAP tests the same transports in both
directions against a real VM kernel, retaining QEMU's automatic TAP feature
negotiation. VPN requires packaged OpenVPN/OpenSSL/iproute2: an ephemeral TLS
peer tests both address families, DNS hooks, route isolation and restoration.
`--container-image IMAGE` runs the OpenVPN consumer in a pre-pulled Python
Podman image, using `--container-cache` and `--container-runroot` for its test
storage. Container seccomp remains enabled. WireGuard requires packaged
wireguard-go/wireguard-tools and covers encrypted bulk traffic, SIGKILL and restart.
OpenConnect requires openconnect/ocserv and OpenSSL: certificate-authenticated
DTLS, IPv4/IPv6, DNS and disconnect restoration. IPsec uses stock strongSwan's
kernel-libipsec/kernel-netlink/VICI plugins, not kernel XFRM. Its private bridge
permits IKE's guest ports 500/4500 without binding privileged Android ports.
Tailscale assets are stock ARM64 `tailscale`, `tailscaled` and `headscale` binaries.
Its private TLS control plane, embedded DERP and two ordinary TUN clients require
no account or changes to Android's network. These application fixtures require
actual payload exchange; daemon startup alone is not a pass.
`--load` adds four concurrent TCP streams per family, small-message latency,
16 MiB per direction, slow receivers, half-close and descriptor-release checks.
Receipts retain CPU frequencies and whole-launch wall/user/system time separately
from client-only CPU and exchange timings. It is a bounded workload, not an
Internet-throughput claim. The option applies to direct consumers; an OCI image
must explicitly retain `MD_PACKET_LOAD` to run it inside that container.
`test_booted_libvirt.py --session SESSION --kernel KERNEL --initrd INITRD
--network --network-forward nat` checks a managed bridge/TAP with DHCP/DNS,
bidirectional VM traffic and cleanup. Start its headless retained session with
`installed_desktop.py start --network-profile bridge`; routed wildcard DHCP
binds otherwise request privileged Android ports. For this packet scenario,
`INITRD` is the official gzip-compressed Alpine initramfs, from which the fixture
builds its private VM image, not the raw kernel-contract CPIO used by the direct
TCG test. Modular libvirt preparation starts both the QEMU and network services.
Without `--network`, omit `--initrd` to build the shared Landlock contract
image from `--build`; `--direct` runs that same image without Libvirt.
The echo peer lives beyond a routed veth
in a separate namespace and verifies the translated IPv4 source and port range.
`--network-forward open` checks the same topology without NAT; IPv6 uses routed
traffic. ICMP REJECT is not substituted with DROP.
All services, staged files and temporary initramfs trees are cleaned
up; receipts remain under `build/packet-apps`.

`test_network_ethernet.py BUILD STORE` checks packet/raw sockets and stock
`tc qdisc ... htb` plus `u32 ... action csum` in Base and lazy modes. It sends
bad-checksum IPv4/UDP packets, checks repaired bytes and nonmatching traffic,
then deletes the filter/qdisc and verifies unchanged delivery and link cleanup.
Unsupported bandwidth classes must fail, not silently omit shaping.
`test_network_tc.c` adds branch-local copies, fragmented/option-bearing packets,
namespace lifetime, lost ACKs and atomic rollback to the native resource suite.

`test_routed_network.py` adds libc interface lookup, IPv4 packet information
with absent/truncated receive buffers, a datagram queued before sender close,
and receiver-close/rebind without reusing stale reply mappings.
`probe_nft_runtime.py BUILD STORE --network bridge --machine-entry` (or `--base`)
checks stock nft/iptables catalogue operations, atomic rollback, verdict maps,
UDP DNAT and immediate IPv4/IPv6 TCP REJECT. It also checks NAT
state aliases, randomized masquerade rule admission, CTNETLINK inventory and UDP
mapping deletion/re-admission on the same socket. TCP tracking deletion and
expiry must leave the stream usable and admit a new record on subsequent IO.
Unsupported rate-dependent forwarding rules fail without committing their
table. The default `routed` mode also
publishes the fixture's port 53 on Android and can fail with EACCES under host
bind policy; use the explicit private bridge for guest-only coverage, not as a
substitute for external publication tests. The native network-launch fixture
separately requires new and established native TCP peers to receive reset.
`benchmark_network.py BUILD STORE --sysroot GLIBC_SYSROOT` compares one static
binary under shell/native, host, routed, filtered and NAT modes with rotated
rounds. It reports application CPU separately from whole-invocation CPU;
the latter includes startup, rule preparation and cleanup. Local DNAT uses the
OUTPUT hook. Reports retain CPU-frequency observations with each sample.
`--reference BASELINE` interleaves both runtime builds against the same guest
and native executable; pairs stay adjacent and alternate their order.
`--profile nat` selects a focused comparison; repeat the option for multiple
profiles. `--output DIRECTORY` separates comparison receipts.
`benchmark_readiness.py --build BUILD --reference BASELINE --store STORE`
interleaves filesystem/readiness workloads across both runtimes and Base/lazy
entry. Both benchmark runners select `--executor local|shell|app`; local
execution resolves host utilities from PATH, while Android adapters use the
selected device's tools. Readiness timing needs host `time`; explicit CPU
placement additionally needs `taskset`. The fixture needs a C compiler and Linux
headers inside its guest (Alpine: `build-base linux-headers`).
It does not pin CPUs by default. `--cpu-mask HEX` applies the same native
taskset mask to both runtime process trees for a controlled follow-up; reports
retain that mask and CPU-frequency observations. This changes neither governor
nor host frequency limits, and pinned results do not certify unpinned performance.
`--application-filter` measures the same workloads after guest seccomp admission.
The separate instrumented entry control uses the selected filter/PID-namespace
configuration and requires post-filter completions when a filter is requested.
Focused `--workload` selections include `identity` (four UID/GID reads), `uname`,
`ipc-nowait` (a SysV send/receive pair) and `socket-nowait` (a datagram pair).
`socket-rights` sends an eventfd through SCM_RIGHTS, receives it with
MSG_CMSG_CLOEXEC, checks the received flags and closes the copy on every iteration.
Unlike the ordinary datagram pair, this exercises descriptor custody and publication.
`fd-bytes` reads a regular file's current available bytes with `FIONREAD`;
`fd-ioctl` instead changes an eventfd's nonblocking mode with `FIONBIO`.
These retain their normal owners and guest filters; setup is outside the timed loop.
Use `--statistics` in a separate run to record syscall, checkpoint, ptrace and
supervisor CPU counters; instrumented timings are not a performance baseline.
`MD_PROGRESS` separates retained-actor work, task-owner progress, resident
entry and PID collection. These elapsed-time counters include descheduling;
`MD_RETAINED` counts group and fallback actor traversals to expose repeated tree
scans independently of CPU frequency.
`MD_WORKER_STARTUP` separates inode admission, runtime directories, attachments
and provider preparation. Store and mount counters include worker startup;
ordinary launches do not sample these clocks.

`test_os_boot.py --service-io avahi|cups|firewalld` supplements the stock boot
observer with protocol IO and three stop/start cycles. Avahi must answer mDNS
over both families; CUPS must answer an IPP request within the fixture's normal
readiness bound; firewalld must enforce a live rule. Unsupported service rules
remain a failure, not a reason to mask the service or enlarge its timeout.
