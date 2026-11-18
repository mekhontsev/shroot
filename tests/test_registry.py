#!/usr/bin/env python3
"""Production OCI client against authenticated local HTTPS registries and CDNs."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from client_fixture import archive_fixture
from rootfs_oci_fixture import write_layout

BUILD = None
MEDIA = "application/vnd.oci.image."


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ssl.SSLError):
            # Cancellation may close TLS without a close-notify exchange.
            self.close_connection = True

    def do_GET(self):
        fixture = self.server.fixture
        fixture.requests.append((self.server.role, self.path, self.headers.get("Authorization")))
        status, headers, data = fixture.reply(self.server.role, self.path, self.headers)
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.path.endswith(fixture.layer_digest) and fixture.pause_layer:
            fixture.layer_entered.set()
            fixture.layer_release.wait(15)
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class RegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trust = tempfile.TemporaryDirectory(prefix="shroot-registry-ca-")
        directory = Path(cls.trust.name)
        cls.cert, cls.key = directory / "ca.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-addext", "basicConstraints=critical,CA:TRUE"],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.trust.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shroot-registry-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "library"
        archive = self.root / "rootfs.tar.gz"
        archive_fixture(BUILD, archive)
        layout = self.root / "layout"
        self.identity = write_layout([archive], layout)
        self.blobs = {"sha256:" + file.name: file.read_bytes()
                      for file in (layout / "blobs/sha256").iterdir()}
        self.document = json.loads(self.blobs[self.identity["digest"]])
        self.layer_digest = self.document["layers"][0]["digest"]
        descriptor = dict(self.identity, platform={"os": "linux", "architecture": "arm64", "variant": "v8"})
        wrong_arch = dict(descriptor, platform={"os": "linux", "architecture": "amd64"})
        self.index = {"schemaVersion": 2, "mediaType": MEDIA + "index.v1+json",
                      "manifests": [wrong_arch, descriptor]}
        self.requests = []
        self.pause_layer = False
        self.layer_entered, self.layer_release = threading.Event(), threading.Event()
        self.addCleanup(self.layer_release.set)
        self.corrupt = None
        self.fail_layer = False
        self.redirect = True
        self.auth = True
        self.bad_token = False
        self.challenge = None
        self.downgrade = False
        self.redirect_loop = False
        self.foreign_auth = False
        self.registry = self.server("registry")
        self.cdn = self.server("cdn")
        self.ref = f"localhost:{self.registry.server_port}/project/test:latest"
        self.cli = [str(BUILD / "shroot"), "--runtime", str(BUILD), "library", str(self.library)]
        self.call("init")

    def server(self, role):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        server.fixture, server.role = self, role
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
        thread.start()

        def close():
            self.layer_release.set()
            server.shutdown()
            server.server_close()
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.addCleanup(close)
        return server

    def reply(self, role, path, headers):
        route = urlsplit(path)
        if role == "cdn":
            if self.foreign_auth:
                return 401, [("WWW-Authenticate", f'Bearer realm="https://localhost:{self.registry.server_port}/evil"')], b""
            digest = route.path.rsplit("/", 1)[-1]
            data = self.blobs[digest]
            return 200, [], b"x" + data[1:] if self.corrupt == digest else data
        if route.path == "/token":
            query = parse_qs(route.query)
            self.assertEqual(query["scope"], ["repository:project/test:pull"])
            self.assertEqual(query["service"], ["fixture"])
            return 200, [], encoded({"token": "bad\r\nInjected: value" if self.bad_token else "fixture-token"})
        if self.auth and headers.get("Authorization") != "Bearer fixture-token":
            challenge = self.challenge or (f'Bearer realm="https://localhost:{self.registry.server_port}/token", '
                                           'service="fixture", scope="ignored:untrusted:scope"')
            return 401, [("WWW-Authenticate", challenge)], b"authentication required"
        if "/manifests/" in route.path:
            selector = route.path.rsplit("/", 1)[-1]
            if selector == "latest":
                return 200, [], encoded(self.index)
            if selector in self.blobs:
                return 200, [], self.blobs[selector]
        if "/blobs/" in route.path:
            digest = route.path.rsplit("/", 1)[-1]
            if digest not in self.blobs:
                return 404, [], b""
            if digest == self.layer_digest and self.fail_layer:
                return 503, [], b"retry later"
            if self.redirect_loop:
                return 307, [("Location", path)], b""
            if self.redirect:
                scheme = "http" if self.downgrade else "https"
                return 307, [("Location", f"{scheme}://localhost:{self.cdn.server_port}/data/{digest}")], b""
            data = self.blobs[digest]
            return 200, [], b"x" + data[1:] if self.corrupt == digest else data
        return 404, [], b""

    def call(self, *args, code=0):
        result = subprocess.run(self.cli + list(map(str, args)), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr + repr(self.requests))
        return result.stdout

    def install(self, name="test", reference=None, code=0, trust=True):
        args = ["install", "registry", reference or self.ref, name]
        if trust:
            args += ["--ca-file", str(self.cert)]
        return self.call(*args, code=code)

    def test_authenticated_index_cdn_and_guest_execution(self):
        self.install()
        record = json.loads(self.call("resolve", "test"))
        self.assertEqual(record["image"], "import-v1-oci-" + self.identity["digest"][7:])
        self.call("exec", "test", "--", "/bin/client-guest", "exit42", code=42)
        self.assertTrue(any(role == "cdn" for role, _, _ in self.requests))
        self.assertTrue(all(auth is None for role, _, auth in self.requests if role == "cdn"))
        self.assertTrue(all(auth is None for _, path, auth in self.requests if path.startswith("/token")))
        self.requests.clear()
        self.install("second")
        self.assertFalse(any("/blobs/" in path or role == "cdn" for role, path, _ in self.requests))
        self.assertEqual(len(list((self.library / "images").iterdir())), 1)
        self.assertFalse(list((self.library / "work").iterdir()))

    def test_explicit_digest_and_directory_trust(self):
        reference = self.ref.rsplit(":", 1)[0] + "@" + self.identity["digest"]
        self.call("install", "registry", reference, "test", "--ca-directory", self.cert.parent)
        self.call("exec", "test", "--", "/bin/client-guest", "exit42", code=42)

    def test_certificate_verification_and_no_plaintext_redirect(self):
        self.install(code=1, trust=False)
        self.assertFalse(list((self.library / "names").iterdir()))
        self.requests.clear()
        self.downgrade = True
        self.install(code=1)
        self.assertFalse(any(role == "cdn" for role, _, _ in self.requests))

    def test_corrupt_download_and_completed_cache_reuse(self):
        self.corrupt = self.layer_digest
        self.install(code=1)
        self.assertFalse((self.library / "cache" / self.layer_digest[7:]).exists())
        config = self.document["config"]["digest"]
        self.assertTrue((self.library / "cache" / config[7:]).exists())
        self.requests.clear()
        self.corrupt = None
        self.install()
        self.assertFalse(any(config in path for _, path, _ in self.requests))

    def test_corrupt_existing_cache_is_not_trusted(self):
        self.install()
        cached = self.library / "cache" / self.layer_digest[7:]
        data = cached.read_bytes()
        cached.write_bytes(b"x" + data[1:])
        self.install("second", code=1)
        self.assertEqual(len(json.loads(self.call("list"))), 1)

    def test_invalid_auth_challenge_and_token(self):
        realm = f"https://localhost:{self.registry.server_port}/token"
        for value in [f'Bearer realm="{realm}", realm="{realm}"',
                      'Bearer realm="http://localhost/token"', 'Bearer realm="unterminated',
                      f'Bearer realm="{realm}",service="fixture",',
                      f'Bearer realm="https://user:pass@localhost:{self.registry.server_port}/token"']:
            with self.subTest(challenge=value):
                self.challenge = value
                self.install(code=1)
        self.assertFalse(any(path.startswith("/token") for _, path, _ in self.requests))
        self.challenge = None
        self.bad_token = True
        self.install(code=1)

    def test_foreign_auth_is_not_followed_and_redirects_are_bounded(self):
        self.foreign_auth = True
        self.install(code=1)
        self.assertFalse(any(path == "/evil" for _, path, _ in self.requests))
        self.foreign_auth = False
        self.redirect_loop = True
        self.requests.clear()
        self.install(code=1)
        self.assertLess(len(self.requests), 20)

    def test_platform_ambiguity_size_and_schema_rejected(self):
        valid = json.loads(json.dumps(self.index))
        for change in ("architecture", "duplicate", "size", "schema", "object"):
            self.index = json.loads(json.dumps(valid))
            if change == "architecture":
                self.index["manifests"][1]["platform"]["architecture"] = "amd64"
            elif change == "duplicate":
                self.index["manifests"].append(self.index["manifests"][1])
            elif change == "size":
                self.index["manifests"][1]["size"] += 1
            elif change == "schema":
                self.index["schemaVersion"] = 2 + (1 << 32)
            else:
                self.index["manifests"] = {"unexpected": self.index["manifests"][1]}
            with self.subTest(change=change):
                self.install(code=1)
        self.assertFalse(list((self.library / "names").iterdir()))

    def test_cancelled_download_has_no_named_partial_and_releases_lock(self):
        self.redirect = False
        self.pause_layer = True
        command = self.cli + ["install", "registry", self.ref, "test", "--ca-file", str(self.cert)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(self.layer_entered.wait(10), "download did not reach the layer")
            process.send_signal(signal.SIGTERM)
            output, error = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0, output + error)
        finally:
            self.layer_release.set()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.assertFalse((self.library / "cache" / self.layer_digest[7:]).exists())
        self.pause_layer = False
        self.install()
        self.assertFalse(list((self.library / "work").iterdir()))
        self.assertFalse(list((self.library / "cache").glob(".download-*")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args, rest = parser.parse_known_args()
    BUILD = args.build.resolve()
    unittest.main(argv=[__file__] + rest)
