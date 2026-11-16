"""Shared native client input, independent of Android and its transports."""
import io
import tarfile


def archive_fixture(build, archive):
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for name in ("bin", "tmp", "etc"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            tar.addfile(entry)
        tar.add(build / "client-guest", arcname="bin/client-guest")
        payload = b"libshroot payload"
        entry = tarfile.TarInfo("payload")
        entry.mode = 0o644
        entry.size = len(payload)
        tar.addfile(entry, io.BytesIO(payload))
        for name, kind in (("hardlink", tarfile.LNKTYPE), ("link", tarfile.SYMTYPE)):
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.linkname = "payload"
            tar.addfile(entry)
