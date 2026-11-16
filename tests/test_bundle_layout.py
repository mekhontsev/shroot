#!/usr/bin/env python3
"""Artifact validation is shared by native execution and cross-built bundles."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from audit_bundle import audit_archive
from bundle_layout import HELPERS, audit_bundle, audit_elf


ELF = '''Class: ELF64
Data: 2's complement, little endian
Machine: AArch64
  LOAD 0x000000 0x000000 0x000000 0x010000 0x010000 R E 0x4000
'''
NEEDED = '  0x000001 (NEEDED) Shared library: [libc.so]\n'


class ElfLayout(unittest.TestCase):
    def audit(self, details, dynamic=False, system='Android'):
        with patch('bundle_layout.elf_details', return_value=details):
            return audit_elf(Path('fixture'), 'readelf', dynamic=dynamic, system=system)

    def test_static_and_dynamic(self):
        self.assertEqual(self.audit(ELF), [])
        self.assertEqual(self.audit(ELF + NEEDED, True), ['libc.so'])

    def test_gnu_and_llvm_load_alignment(self):
        self.audit(ELF.replace('0x4000', '0x10000'))
        with self.assertRaises(AssertionError):
            self.audit(ELF + '  LOAD 0x000000 0x000000 0x000000 0x100 0x100 RW 0x1000\n')

    def test_reject_foreign_abi_and_debug_sections(self):
        for details in (ELF.replace('ELF64', 'ELF32'), ELF.replace('AArch64', 'X86-64'),
                        ELF.replace('little endian', 'big endian'),
                        ELF + '.debug_info', ELF + '.zdebug_info'):
            with self.subTest(details=details), self.assertRaises(AssertionError):
                self.audit(details)

    def test_reject_unexpected_linkage(self):
        for details, dynamic in ((ELF + NEEDED, False), (ELF, True),
                                 (ELF + NEEDED.replace('libc.so', 'liblwip.so'), True),
                                 (ELF + NEEDED.replace('libc.so', 'libsqlite3.so'), True)):
            with self.subTest(details=details, dynamic=dynamic), self.assertRaises(AssertionError):
                self.audit(details, dynamic)

    def test_reject_build_machine_library_paths(self):
        for tag in ('RPATH', 'RUNPATH'):
            with self.subTest(tag=tag), self.assertRaises(AssertionError):
                self.audit(ELF + f'  ({tag}) Library path: [/build/lib]\n')

    def test_interpreter_matches_platform(self):
        for system, interpreter in (('Android', '/system/bin/linker64'),
                                    ('Linux', '/lib/ld-linux-aarch64.so.1'),
                                    ('Linux', '/lib/ld-musl-aarch64.so.1')):
            details = ELF + NEEDED + f'  [Requesting program interpreter: {interpreter}]\n'
            with self.subTest(system=system, interpreter=interpreter):
                self.audit(details, True, system)
                with self.assertRaises(AssertionError):
                    self.audit(details, False, system)
                with self.assertRaises(AssertionError):
                    self.audit(details, True, 'Linux' if system == 'Android' else 'Android')


class BundleLayout(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.prefix = Path(temporary.name) / 'bundle'
        self.runtime = self.prefix / 'libexec/shroot'
        self.runtime.mkdir(parents=True)
        self.metadata = dict(format=1, version='1.0.0-dev', minimumKernel='5.15', system='Android',
                             architecture='aarch64', testHooks=False,
                             helpers={role: f'libmagicdesk_guest_{role}.so' for role in HELPERS})
        paths = ['bin/shroot', 'lib/libshroot.so', 'include/shroot.h', 'lib/libshroot.a',
                 'lib/cmake/Shroot/ShrootConfig.cmake', 'share/doc/shroot/LICENSE']
        paths += [f'libexec/shroot/{name}' for name in self.metadata['helpers'].values()]
        paths += [f'share/doc/shroot/licenses/{name}.txt'
                  for name in ('sqlite', 'curl', 'mbedtls', 'lwip', 'zlib', 'zstd', 'libarchive')]
        for name in paths:
            path = self.prefix / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        elf = patch('bundle_layout.audit_elf', return_value=[])
        self.elf = elf.start()
        self.addCleanup(elf.stop)

    def audit(self, **options):
        (self.runtime / 'runtime.json').write_text(json.dumps(self.metadata))
        return audit_bundle(self.prefix, **options)

    def test_default_production_bundle(self):
        self.audit(production=True, system='Android', version='1.0.0-dev')
        self.assertEqual(len(self.elf.call_args_list), 7)
        dynamic = {call.args[0].name for call in self.elf.call_args_list if call.kwargs['dynamic']}
        self.assertEqual(dynamic, {'libshroot.so', 'libmagicdesk_guest_image.so'})

    def test_reject_mismatched_metadata(self):
        for key, value in (('testHooks', True), ('testHooks', 'false'), ('system', 'Windows'),
                           ('architecture', 'x86_64'), ('minimumKernel', '6.0'), ('format', 2)):
            original = self.metadata[key]
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.metadata[key] = value
                self.audit(production=True)
            self.metadata[key] = original
        for options in (dict(system='Linux'), dict(version='0.0.0')):
            with self.subTest(options=options), self.assertRaises(AssertionError):
                self.audit(**options)

    def test_reject_extra_runtime_and_missing_license(self):
        extra = self.runtime / 'test-helper'
        extra.touch()
        with self.assertRaises(AssertionError):
            self.audit()
        extra.unlink()
        for name in ('sqlite', 'curl', 'mbedtls', 'lwip', 'zlib', 'zstd', 'libarchive'):
            notice = self.prefix / f'share/doc/shroot/licenses/{name}.txt'
            notice.unlink()
            with self.subTest(notice=name), self.assertRaisesRegex(AssertionError,name):
                self.audit()
            notice.touch()

    def test_reject_duplicate_or_escaping_helpers(self):
        for name in (self.metadata['helpers']['run'], '../outside'):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.metadata['helpers']['image'] = name
                self.audit()

    def test_reject_symlinked_runtime(self):
        path = self.runtime / self.metadata['helpers']['image']
        path.unlink()
        path.symlink_to('../../bin/shroot')
        with self.assertRaises(AssertionError):
            self.audit()


class ArchiveLayout(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / 'runtime.tar.gz'

    def create(self, name='bundle/bin/shroot', mode=0o755, link=None):
        with tarfile.open(self.archive, 'w:gz') as stream:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if link:
                info.type, info.linkname = tarfile.SYMTYPE, link
            stream.addfile(info, io.BytesIO())
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(str(self.archive) + '.sha256').write_text(f'{self.digest}  {self.archive.name}\n')

    def test_valid_checksum_and_root(self):
        self.create()
        with patch('audit_bundle.audit_bundle', return_value={}) as audit:
            audit_archive(self.archive, 'selected-readelf', production=True)
        self.assertEqual(audit.call_args.args[0].name, 'bundle')
        self.assertEqual(audit.call_args.args[1], 'selected-readelf')
        self.assertEqual(audit.call_args.kwargs, dict(production=True))

    def test_checksum_mismatch(self):
        self.create()
        with self.archive.open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(AssertionError, 'checksum'):
            audit_archive(self.archive, 'readelf')

    def test_wrong_checksum_filename(self):
        self.create()
        Path(str(self.archive) + '.sha256').write_text(f'{self.digest}  other.tar.gz\n')
        with self.assertRaisesRegex(AssertionError, 'exactly this artifact'):
            audit_archive(self.archive, 'readelf')

    def test_reject_traversal(self):
        for name in ('../escape', '/absolute', 'bundle/../../escape', 'bundle\\..\\escape'):
            self.create(name)
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, 'Unsafe archive path'):
                audit_archive(self.archive, 'readelf')

    def test_reject_external_link(self):
        self.create('bundle/link', link='../../outside')
        with self.assertRaises(tarfile.FilterError):
            audit_archive(self.archive, 'readelf')

    def test_reject_lost_executable_permission(self):
        self.create(mode=0o644)
        with self.assertRaisesRegex(AssertionError, 'Non-executable'):
            audit_archive(self.archive, 'readelf')


if __name__ == '__main__':
    unittest.main()
