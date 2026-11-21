"""Read distribution artwork through the guest VFS, without any executable in the image."""
import base64
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAIAAAB7QOjdAAAAD0lEQVR4nGP4z8DA8J8BAAf/Af8Bf4mnAAAAAElFTkSuQmCC")


def inspect(cli, files):
    with tempfile.TemporaryDirectory(prefix="shroot-logo-") as tmp:
        archive, store = Path(tmp) / "root.tar", Path(tmp) / "image"
        with tarfile.open(archive, "w") as tar:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                if isinstance(data, str):
                    entry.type, entry.linkname = tarfile.SYMTYPE, data
                    tar.addfile(entry)
                else:
                    entry.size = len(data)
                    tar.addfile(entry, io.BytesIO(data))
        subprocess.run([cli, "rootfs", archive, store], check=True, stdout=subprocess.DEVNULL)
        return json.loads(subprocess.check_output([cli, "os-info", store]))


if __name__ == "__main__":
    cli = Path(sys.argv[1]).resolve() / "shroot"
    vendor = b'PRETTY_NAME="Vendor OS"\nVERSION_ID=42\nLOGO=vendor-logo\n'
    assets = {"usr/lib/os-release": vendor, "usr/share/icons/hicolor/48x48/places/vendor-logo.png": PNG}
    expected = {"prettyName": "Vendor OS", "versionId": "42", "png": PNG.hex()}
    assert inspect(cli, assets) == expected
    assert inspect(cli, {"etc/os-release": vendor, "usr/share/icons/hicolor/index.theme":
                         b"[Icon Theme]\nScaledDirectories=custom@2/distributions\n",
                         "usr/local/share/icons/hicolor/custom@2/distributions/vendor-logo.png": PNG}) == expected
    assert inspect(cli, {**assets, "etc/os-release": "../usr/lib/os-release"}) == expected
    override = b'PRETTY_NAME="Work \\"OS\\""\nLOGO=/usr/share/icons/hicolor/48x48/places/vendor-logo.png\n'
    assert inspect(cli, {**assets, "etc/os-release": override}) == {"prettyName": 'Work "OS"', "versionId": "", "png": ""}
    assert inspect(cli, {"etc/os-release": b"PRETTY_NAME='$(not-executed)'\nLOGO=unknown\n"})["prettyName"] == "$(not-executed)"
    assert inspect(cli, {"etc/os-release": b"x"*17000, **assets}) == {"prettyName": "", "versionId": "", "png": ""}
    print("PASS offline OS presentation: precedence, symlink, quoting, logo, missing and oversized data")
