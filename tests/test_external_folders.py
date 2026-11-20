"""Exercise external FUSE through the public CLI and a real guest, without Android providers."""
import argparse
import errno
from pathlib import Path
import socketserver
import struct
import subprocess
import tempfile
import threading

from client_fixture import archive_fixture


class Peer(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            header = self.rfile.read(40)
            if not header:
                return
            length, op, unique, node = struct.unpack_from("<IIQQ", header)
            body = self.rfile.read(length - 40)
            data, err = b"", 0
            attr = struct.pack("<6Q10I", node, 9, 1, 0, 0, 0, 0, 0, 0,
                               0o40777 if node == 1 else 0o100666, 1, 0, 0, 0, 4096, 0)
            if op == 26:
                data = struct.pack("<6I", 7, 31, 0, 0, 0, 16384)
            elif op == 1 and body == b"token\0":
                attr = struct.pack("<Q", 2) + attr[8:60] + struct.pack("<I", 0o100666) + attr[64:]
                data = struct.pack("<4Q2I", 2, 1, 0, 0, 0, 0) + attr
            elif op == 3:
                data = bytes(16) + attr
            elif op in (14,27):
                data = struct.pack("<QII", node, 0, 0)
            elif op == 15:
                _, offset, size = struct.unpack_from("<QQI", body)
                data = bytes(self.server.contents[offset:offset+size])
            elif op == 16:
                _, offset, size = struct.unpack_from("<QQI", body)
                self.server.contents[offset:offset+size] = body[40:]
                data = struct.pack("<II", size, 0)
            elif op == 28:
                _,offset,_ = struct.unpack_from("<QQI",body)
                if offset == 0:
                    data = struct.pack("<QQII",2,1,5,8)+b"token"+bytes(3)
            elif op in (2,42):
                continue
            elif op == 1:
                err = -errno.ENOENT
            elif op not in (18,25,29,34):
                err = -errno.ENOSYS
            frame = struct.pack("<IiQ", 16+len(data), err, unique) + data
            try:
                self.wfile.write(frame[:5])
                self.wfile.write(frame[5:])
            except (BrokenPipeError, ConnectionResetError):
                return


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    build = parser.parse_args().build.resolve()
    with tempfile.TemporaryDirectory() as directory:
        tmp = Path(directory)
        def cli(*args):
            subprocess.run([build/"shroot", "--library",tmp/"library", *args], check=True, timeout=60)
        archive_fixture(build, tmp/"root.tar.gz")
        cli("install",tmp/"root.tar.gz","--rootfs","--name","folders")
        with Server(str(tmp/"rw"), Peer) as rw, Server(str(tmp/"ro"), Peer) as ro:
            for server in (rw,ro):
                server.contents = bytearray(b"read-only")
                threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                for _ in range(2):
                    cli("exec","folders","--bind-fuse",tmp/"rw","/mnt/android/Work",
                        "--bind-fuse-ro",tmp/"ro","/mnt/android/Read only","--","/bin/client-guest","external-folders")
                    assert rw.contents.startswith(b"updated") and ro.contents == b"read-only"
            finally:
                rw.shutdown()
                ro.shutdown()


if __name__ == "__main__":
    main()
