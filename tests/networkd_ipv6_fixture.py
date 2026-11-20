#!/usr/bin/env python3
"""Exercise the booted distribution's networkd with an actual virtual IPv6 router."""
import json
import os
from contextlib import contextmanager, ExitStack
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time


def run(*argv):
    try:
        return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=15)
    except subprocess.CalledProcessError as error:
        print(error.output, flush=True)
        raise


def enter_net(fd):
    if hasattr(os, 'setns'):
        os.setns(fd, 0)
    else:  # Distribution Python before 3.12.
        import ctypes
        if ctypes.CDLL(None, use_errno=True).setns(fd, 0) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


@contextmanager
def router_peer():
    # The router must not own a client address. A real reverse-path filter
    # can legitimately reject incoming traffic sourced from the host itself.
    namespace = 'md-ra-peer-' + str(os.getpid())
    with ExitStack() as stack:
        run('ip', 'netns', 'add', namespace)
        stack.callback(run, 'ip', 'netns', 'del', namespace)
        run('ip', 'link', 'add', 'mdra0', 'type', 'veth', 'peer', 'name', 'mdra1')
        stack.callback(run, 'ip', 'link', 'del', 'mdra0')
        run('ip', 'link', 'set', 'mdra1', 'netns', namespace)
        with open('/proc/self/ns/net', 'rb') as origin, open('/run/netns/' + namespace, 'rb') as peer:
            enter_net(peer.fileno())
            try:
                run('ip', 'link', 'set', 'lo', 'up')
                run('ip', 'link', 'set', 'mdra1', 'up')
                Path('/proc/sys/net/ipv6/conf/mdra1/forwarding').write_text('1')
                run('ip', '-6', 'address', 'add', 'fd92:10::1/64', 'dev', 'mdra1')
                link = json.loads(run('ip', '-j', '-6', 'address', 'show', 'dev', 'mdra1'))[0]
                stream = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6))
                servers = [stack.enter_context(socket.socket(socket.AF_INET6, kind))
                           for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)]
            finally:
                enter_net(origin.fileno())
        yield link, stream, servers


def main():
    started = str(int(time.time()))
    run('systemctl', 'start', 'systemd-networkd.service')
    pid = run('systemctl', 'show', '-p', 'MainPID', '--value', 'systemd-networkd').strip()
    assert pid.isdecimal() and int(pid) > 0, pid
    wait_online = Path('/proc', pid, 'exe').resolve(strict=True).with_name('systemd-networkd-wait-online')
    config = Path('/run/systemd/network/00-md-ipv6-ra.network')
    config.parent.mkdir(parents=True, exist_ok=True)
    assert not config.exists()
    config.write_text('''[Match]
Name=mdra0
[Network]
DHCP=no
LinkLocalAddressing=ipv6
IPv6AcceptRA=yes
KeepConfiguration=yes
[IPv6AcceptRA]
DHCPv6Client=no
UseDNS=no
''')
    tracer = None
    try:
        if os.environ.get('MD_NETWORKD_TRACE') == '1':
            tracer = subprocess.Popen(['strace', '-f', '-s', '2048', '-e', 'trace=sendmsg,recvmsg',
                                       '-o', '/run/md-networkd.trace', '-p', pid], stderr=subprocess.PIPE)
            # EVENT_WAIT: ptrace attach confirmation; expiry fails diagnostics.
            assert select.select([tracer.stderr], [], [], 10)[0]
            assert b'attached' in tracer.stderr.readline()
        run('networkctl', 'reload')
        with router_peer() as (router, stream, servers), \
                socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as changes:
            router_address = next(a['local'] for a in router['addr_info'] if a['scope'] == 'link')
            stream.settimeout(15)
            changes.settimeout(15)
            changes.bind((0, 0x100 | 0x400))  # RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE
            mask = [0xffffffff] * 8
            mask[133 // 32] &= ~(1 << (133 % 32))
            stream.setsockopt(socket.IPPROTO_ICMPV6, 1, struct.pack('=8I', *mask))
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'mdra1\0')
            stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                              socket.inet_pton(socket.AF_INET6, 'ff02::2') + struct.pack('=I', router['ifindex']))
            stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, router['ifindex'])
            stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            stream.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
            run('ip', 'link', 'set', 'mdra0', 'up')
            # EVENT_WAIT: networkd's actual router solicitation, never a settling delay.
            solicitation, source = stream.recvfrom(2048)
            assert solicitation[0] == 133 and len(solicitation) >= 8, solicitation
            prefix = socket.inet_pton(socket.AF_INET6, 'fd92:10::')
            advertisement = struct.pack('!BBHBBHII', 134, 0, 0, 64, 0, 300, 0, 0)
            advertisement += struct.pack('!BBBBIII16s', 3, 4, 64, 0xc0, 300, 120, 0, prefix)
            advertisement += struct.pack('!BBHI', 5, 1, 0, 1440)
            stream.sendto(advertisement, ('ff02::1', 0))
            deadline = time.monotonic() + 20
            while True:
                addresses = json.loads(run('ip', '-j', '-6', 'address', 'show', 'dev', 'mdra0'))
                routes = json.loads(run('ip', '-j', '-6', 'route', 'show', 'dev', 'mdra0'))
                address = next((a for link in addresses for a in link['addr_info']
                                if a['local'].startswith('fd92:10:') and 'dadfailed' not in a), None)
                nexthops = {n['id']: n for n in json.loads(run('ip', '-j', 'nexthop', 'show'))}
                route = next((r for r in routes if r.get('dst') == 'default'
                              and r.get('gateway', nexthops.get(r.get('nhid'), {}).get('gateway')) == router_address), None)
                if address and route:
                    assert address['valid_life_time'] <= 300 and address['preferred_life_time'] <= 120, address
                    break
                # EVENT_WAIT: address/route notifications after RA; timeout fails configuration.
                remaining = deadline - time.monotonic()
                assert remaining > 0 and select.select([changes], [], [], remaining)[0], (addresses, routes, nexthops)
                changes.recv(65536)
            run(str(wait_online), '--interface=mdra0:routable', '--ipv6', '--timeout=10')
            lookup = json.loads(run('ip', '-j', '-6', 'route', 'get', 'fd92:10::1234', 'oif', 'mdra0'))[0]
            metrics = lookup.get('metrics', {})
            if isinstance(metrics, list):
                metrics = {key: value for item in metrics for key, value in item.items()}
            # Older networkd publishes RA parameters as route metrics; newer
            # versions also update the per-interface defaults. Check the route
            # that applications actually use, not one version's storage choice.
            mtu = metrics.get('mtu', int(Path('/proc/sys/net/ipv6/conf/mdra0/mtu').read_text()))
            hops = metrics.get('hoplimit', int(Path('/proc/sys/net/ipv6/conf/mdra0/hop_limit').read_text()))
            assert mtu == 1440 and hops == 64, (lookup, mtu, hops)
            print('NETWORKD_EFFECTIVE_ROUTE', json.dumps(lookup), flush=True)
            for server in servers:
                kind = server.type
                with socket.socket(socket.AF_INET6, kind) as client:
                    server.settimeout(5)
                    client.settimeout(5)
                    server.bind(('fd92:10::1', 0))
                    client.bind((address['local'], 0))
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'mdra0\0')
                    if kind == socket.SOCK_STREAM:
                        server.listen()
                    client.connect(server.getsockname())
                    assert client.getsockopt(socket.IPPROTO_IPV6, getattr(socket, 'IPV6_MTU', 24)) == 1440
                    assert client.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS) == 64
                    client.sendall(b'ipv6')
                    if kind == socket.SOCK_STREAM:
                        accepted, peer = server.accept()
                        with accepted:
                            accepted.settimeout(5)
                            assert accepted.recv(4) == b'ipv6'
                            accepted.sendall(b'ok')
                    else:
                        data, peer = server.recvfrom(16)
                        assert data == b'ipv6'
                        server.sendto(b'ok', peer)
                    assert peer[0] == address['local'], peer
                    assert client.recv(2) == b'ok'
            stream.sendto(struct.pack('!BBHBBHII', 134, 0, 0, 64, 0, 0, 0, 0), ('ff02::1', 0))
            deadline = time.monotonic() + 10
            while True:
                routes = json.loads(run('ip', '-j', '-6', 'route', 'show', 'dev', 'mdra0'))
                if not any(r.get('dst') == 'default' for r in routes):
                    break
                remaining = deadline - time.monotonic()
                # EVENT_WAIT: route withdrawal notification; timeout is failure.
                assert remaining > 0 and select.select([changes], [], [], remaining)[0], routes
                changes.recv(65536)
            print('PASS stock networkd: RA, SLAAC lifetimes, gateway, wait-online, MTU, TCP/UDP and router withdrawal', flush=True)
    finally:
        if tracer:
            tracer.send_signal(signal.SIGINT)
            tracer.communicate(timeout=10)
            for line in Path('/run/md-networkd.trace').read_text().splitlines():
                if 'NLMSG_ERROR' in line and 'error=0' not in line:
                    print('NETWORKD_TRACE', line, flush=True)
        print(run('journalctl', '-b', '--since=@' + started, '-u', 'systemd-networkd', '-n', '160', '--no-pager'), flush=True)
        config.unlink()
        run('networkctl', 'reload')


if __name__ == '__main__':
    main()
