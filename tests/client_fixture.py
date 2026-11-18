"""Shared native client input, independent of Android and its transports."""
import io
from pathlib import Path
import subprocess
import tarfile

from bundle_layout import elf_details, elf_interpreter


def guest_libraries(binary):
    interpreter = elf_interpreter(elf_details(binary, 'readelf'))
    if not interpreter:
        return
    yield Path(interpreter)
    # These executables were built for the native runner. Its ELF loader
    # resolves the whole dependency tree, including the system SQLite provider.
    listing = subprocess.check_output([interpreter, '--list', str(binary.resolve())],
                                      env={'LC_ALL': 'C'}, text=True, timeout=30)
    for line in listing.splitlines():
        name, arrow, resolved = line.strip().partition(' => ')
        path = Path((resolved if arrow else name).rsplit(' (0x', 1)[0])
        if path.is_absolute():
            yield path
        elif arrow:
            raise ValueError(f'{binary}: unresolved dependency: {line.strip()}')


def archive_fixture(build, archive, *, binaries=()):
    def installed_file(entry):
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = ''
        entry.mode = 0o755 if entry.mode & 0o111 else 0o644
        return entry

    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for name in ("bin", "tmp", "etc"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            tar.addfile(entry)
        tar.add(build / "client-guest", arcname="bin/client-guest", filter=installed_file)
        libraries = set()
        for path, name in binaries:
            tar.add(path.resolve(strict=True), arcname=name, filter=installed_file)
            libraries.update(guest_libraries(path))
        for path in sorted(libraries):
            # Archive the bytes at the path used by the loader, not a host symlink.
            tar.add(path.resolve(strict=True), arcname=str(path.relative_to('/')), filter=installed_file)
        payload = b"libshroot payload"
        entry = tarfile.TarInfo("payload")
        entry.mode = 0o644
        entry.size = len(payload)
        tar.addfile(entry, io.BytesIO(payload))
        for name, content in (("etc/resolv.conf", b"nameserver 192.0.2.53\n"),
                              ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")):
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
        for name, kind in (("hardlink", tarfile.LNKTYPE), ("link", tarfile.SYMTYPE)):
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.linkname = "payload"
            tar.addfile(entry)
