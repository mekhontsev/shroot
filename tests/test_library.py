#!/usr/bin/env python3
"""Native named stores: durable identity, dependencies and process ownership."""
import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import tempfile
import unittest
import uuid

from client_fixture import archive_fixture
from rootfs_oci_fixture import write_layout

BUILD = None


class LibraryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shroot-library-", dir=BUILD)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "library"
        self.cli = [str(BUILD / "shroot"), "--runtime", str(BUILD)]
        self.archive = self.root / "rootfs.tar.gz"
        archive_fixture(BUILD, self.archive)
        self.call("init")

    def command(self, *args, code=0):
        result = subprocess.run(self.cli + [str(arg) for arg in args], text=True,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout

    def call(self, *args, code=0):
        return self.command("library", self.library, *args, code=code)

    def install(self, name):
        self.call("install", "rootfs", self.archive, name)
        return json.loads(self.call("resolve", name))

    def synthetic(self, name, sources=(), version=2):
        identity, key = str(uuid.uuid4()), str(uuid.uuid4())
        if version == 1:
            key = identity
        store = self.library / "instances" / key
        store.mkdir()
        with closing(sqlite3.connect(store / "namespace.db")) as db, db:
            db.execute("CREATE TABLE sources(path TEXT)")
            db.executemany("INSERT INTO sources VALUES(?)", [(str(source),) for source in sources])
        record = dict(format=version, name=name, id=identity, store=key, image="", source="fixture")
        if version == 1:
            del record["store"]
        path = self.library / "names" / (name + ".json")
        path.write_text(json.dumps(record))
        return store, path

    def test_install_shares_image_not_identity_and_retains_old_record(self):
        first, second = self.install("first"), self.install("second")
        self.assertEqual(first["image"], second["image"])
        self.assertNotEqual(first["store"], second["store"])
        self.assertNotEqual(first["id"], Path(first["store"]).name)
        self.assertEqual(len(list((self.library / "images").iterdir())), 1)
        saved = (self.library / "names/first.json").read_bytes()
        self.call("prune")
        self.assertEqual((self.library / "names/first.json").read_bytes(), saved)
        self.assertEqual([item["name"] for item in json.loads(self.call("list"))], ["first", "second"])
        self.call("remove", "first")
        replacement = self.install("first")
        self.assertNotEqual(first["id"], replacement["id"])
        self.assertEqual(second, json.loads(self.call("resolve", "second")))
        self.call("remove", "first")
        self.call("remove", "second")
        self.call("prune")
        self.assertFalse(list((self.library / "images").iterdir()))

    def test_guest_launch_backup_restore_and_resolver(self):
        first = self.install("first")
        self.call("exec", "first", "--env", "LIBSHROOT_TEST=retained ' value", "--",
                  "/bin/client-guest", "spaces ' ; $(false)")
        self.call("exec", "first", "--", "/bin/client-guest", "exit42", code=42)
        self.call("resolver", "first", "nameserver 192.0.2.1\n", "--replace")
        backup = self.root / "backup.tar.zst"
        self.call("backup", "first", backup)
        self.call("restore", backup, "restored")
        restored = json.loads(self.call("resolve", "restored"))
        self.assertEqual(restored["image"], "")
        self.assertNotEqual(first["id"], restored["id"])
        self.call("exec", "restored", "--", "/bin/client-guest", "exit42", code=42)

    def test_local_oci_reuses_shared_layers(self):
        layout = self.root / "layout"
        write_layout([self.archive], layout)
        self.call("install", "oci", layout, "a")
        self.call("install", "oci", layout, "b")
        self.assertEqual(len(list((self.library / "layers").iterdir())), 1)
        self.call("remove", "a")
        self.call("prune")
        self.call("exec", "b", "--", "/bin/client-guest", "exit42", code=42)
        self.call("remove", "b")
        self.call("prune")
        self.assertFalse(list((self.library / "layers").iterdir()))

    def test_catalog_lock_allows_readers_and_blocks_mutations(self):
        self.synthetic("a")
        with (self.library / "library.lock").open("r+") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.call("remove", "a", code=1)
            self.call("prune", code=1)
            self.assertEqual(len(json.loads(self.call("list"))), 1)
            self.call("resolve", "a")

    def test_local_oci_rejects_fifo_inputs_without_waiting(self):
        for name in ("index.json", "blob"):
            with self.subTest(input=name):
                layout = self.root / ("fifo-" + name)
                descriptor = write_layout([self.archive], layout)
                source = layout / "index.json" if name == "index.json" else layout / "blobs/sha256" / descriptor["digest"][7:]
                source.unlink()
                os.mkfifo(source)
                self.call("install", "oci", layout, "fifo", code=1)
        self.assertFalse(list((self.library / "names").iterdir()))

    def test_relocation_preserves_identity_and_relative_sources(self):
        before = self.install("a")
        destination = self.root / "moved"
        with (self.library / "library.lock").open("r+") as lock:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.command("relocate-library", self.library, destination, code=1)
        self.command("relocate-library", self.library, destination)
        self.assertFalse(self.library.exists())
        self.library = destination
        after = json.loads(self.call("resolve", "a"))
        self.assertEqual(after["id"], before["id"])
        self.assertEqual(Path(after["store"]).name, Path(before["store"]).name)
        self.call("exec", "a", "--", "/bin/client-guest", "exit42", code=42)
        self.call("prune")

    def test_independent_store_key_and_missing_store(self):
        original, record = self.synthetic("original")
        selected, other = self.synthetic("selected")
        data = json.loads(record.read_text())
        identity = data["id"]
        data["store"] = selected.name
        record.write_text(json.dumps(data))
        other.unlink()
        self.call("prune")
        self.assertFalse(original.exists())
        self.assertEqual(json.loads(self.call("resolve", "original"))["id"], identity)
        self.command("remove", selected)
        self.call("resolve", "original", code=1)
        self.assertEqual(len(json.loads(self.call("list"))), 1)
        self.call("remove", "original")
        self.assertEqual(json.loads(self.call("list")), [])

    def test_removal_and_input_journals_are_owned_and_recovered(self):
        store, record = self.synthetic("interrupted")
        tomb = store.with_name(".md-remove-" + store.name)
        store.rename(tomb)
        self.call("remove", "interrupted")
        self.assertFalse(record.exists() or tomb.exists())
        (self.library / "names/.publish-abandoned").write_text("unpublished")
        work = self.library / "work/install-abandoned"
        work.mkdir()
        (work / "input").write_bytes(b"input")
        cache = self.library / "cache" / ("a" * 64)
        cache.write_bytes(b"verified-on-demand")
        self.call("prune")
        self.assertFalse(work.exists() or cache.exists())
        self.assertFalse(list((self.library / "names").iterdir()))

    def test_long_chain_and_self_projection_dependencies(self):
        previous = None
        stores = []
        for index in range(200):
            store, record = self.synthetic("node" + str(index), [previous / "objects"] if previous else [])
            with closing(sqlite3.connect(store / "namespace.db")) as db, db:
                db.execute("INSERT INTO sources VALUES(?)", (str(store / "objects"),))
            stores.append(store)
            record.unlink()
            previous = store
        self.call("prune")
        self.assertFalse(any(store.exists() for store in stores))

    def test_old_metadata_is_read_without_schema_admission_or_rewrite(self):
        store, record = self.synthetic("old", version=1)
        original = record.read_bytes()
        (store / "namespace.db").write_bytes(b"unsupported database")
        result = json.loads(self.call("resolve", "old"))
        self.assertEqual(result["id"], store.name)
        self.assertEqual(record.read_bytes(), original)
        self.call("remove", "old")
        self.assertFalse(store.exists())

    def test_alias_and_dependent_protect_selected_store(self):
        base, base_record = self.synthetic("base")
        middle, middle_record = self.synthetic("middle", ["../" + base.name + "/objects"])
        work, work_record = self.synthetic("work", [middle / "objects"])
        self.call("remove", "base", code=1)
        self.call("remove", "middle", code=1)
        base_record.unlink()
        middle_record.unlink()
        self.call("prune")
        self.assertTrue(base.exists() and middle.exists())
        alias = self.library / "names/alias.json"
        data = json.loads(work_record.read_text())
        data["name"] = "alias"
        alias.write_text(json.dumps(data))
        self.call("remove", "work", code=1)
        alias.unlink()
        work_record.unlink()
        lock = os.open(work, os.O_RDONLY)
        try:
            fcntl.flock(lock, fcntl.LOCK_SH)
            self.call("prune", code=1)
            self.assertTrue(base.exists() and middle.exists() and work.exists())
        finally:
            os.close(lock)
        self.call("prune")
        self.assertFalse(base.exists() or middle.exists() or work.exists())

    def test_cycles_and_unknown_store_fail_before_removal(self):
        a, ar = self.synthetic("a")
        b, br = self.synthetic("b", [a / "objects"])
        ar.unlink()
        br.unlink()
        with closing(sqlite3.connect(a / "namespace.db")) as db, db:
            db.execute("INSERT INTO sources VALUES(?)", (str(b / "objects"),))
        self.call("prune", code=1)
        self.assertTrue(a.exists() and b.exists())
        (a / "namespace.db").write_bytes(b"not SQLite")
        self.call("prune", code=1)
        self.assertTrue(a.exists() and b.exists())

    def test_record_validation_never_selects_external_storage(self):
        store, record = self.synthetic("a")
        data = json.loads(record.read_text())
        for key, value in (("store", "../outside"), ("id", "1-1-1-1-1"), ("image", "a/b"),
                           ("name", "other"), ("format", 4294967298), ("format", 3)):
            record.write_text(json.dumps(dict(data, **{key: value})))
            self.call("resolve", "a", code=1)
            self.call("remove", "a", code=1)
        record.write_text(json.dumps(data)[:-1] + ',"name":"a"}')
        self.call("list", code=1)
        self.assertTrue(store.exists())
        record.unlink()
        record.symlink_to(self.archive)
        self.call("list", code=1)

    def test_live_guest_store_and_catalog_cancellation(self):
        self.install("held")
        command = self.cli + ["library", str(self.library), "exec", "held", "--", "/bin/client-guest", "hold"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "guest readiness")
                self.assertEqual(os.read(process.stdout.fileno(), 6), b"ready\n")
            self.call("remove", "held", code=1)
            process.terminate()
            output, error = process.communicate(timeout=10)
            self.assertIn(process.returncode, (143, 0), (output, error))
            self.call("remove", "held")
            self.call("prune")
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)

    def test_nonregular_input_and_interrupted_install_cleanup(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.call("install", "rootfs", fifo, "blocked", code=1)
        link = self.root / "link"
        link.symlink_to(self.archive)
        self.call("install", "rootfs", link, "blocked", code=1)
        self.call("install", "rootfs", self.archive, "blocked", "--resolver", "x" * 8193, code=1)
        self.assertEqual(json.loads(self.call("list")), [])
        self.call("prune")
        self.assertFalse(list((self.library / "instances").iterdir()))
        self.assertFalse(list((self.library / "images").iterdir()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    args, remaining = parser.parse_known_args()
    BUILD = args.build.resolve()
    unittest.main(argv=[__file__, *remaining])
