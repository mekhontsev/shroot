#!/usr/bin/env python3
"""A dependency reconfigure preserves outputs until its source or patch changes."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PATCH = '''diff --git a/src/value.c b/src/value.c
--- a/src/value.c
+++ b/src/value.c
@@ -1 +1 @@
-upstream
+patched
'''


class PatchedSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='shroot source ')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.upstream, self.output, self.patch = root / 'upstream', root / 'output', root / 'context.patch'
        (self.upstream / 'src').mkdir(parents=True)
        (self.upstream / 'src/value.c').write_text('upstream\n')
        self.patch.write_text(PATCH)

    def prepare(self, success=True):
        command = ['cmake', f'-Dupstream={self.upstream}', f'-Doutput={self.output}',
                   f'-Dpatch={self.patch}', f'-DGIT_EXECUTABLE={shutil.which("git")}',
                   '-P', str(Path(__file__).resolve().parents[1] / 'lwip/prepare.cmake')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)

    def test_unchanged_inputs_do_not_touch_generated_files(self):
        self.prepare()
        patched = self.output / 'src/value.c'
        self.assertEqual(patched.read_text(), 'patched\n')
        self.assertEqual((self.upstream / 'src/value.c').read_text(), 'upstream\n')
        os.utime(patched, ns=(1000000000, 1000000000))
        self.prepare()
        self.assertEqual(patched.stat().st_mtime_ns, 1000000000)

    def test_patch_and_upstream_content_invalidate_copy(self):
        self.prepare()
        self.patch.write_text(PATCH.replace('+patched', '+replacement'))
        self.prepare()
        self.assertEqual((self.output / 'src/value.c').read_text(), 'replacement\n')
        source = self.upstream / 'src/extra.c'
        source.write_text('new\n')
        self.prepare()
        self.assertEqual((self.output / 'src/extra.c').read_text(), 'new\n')
        source.unlink()
        self.prepare()
        self.assertFalse((self.output / 'src/extra.c').exists())

    def test_failure_never_publishes_successful_identity(self):
        self.prepare()
        self.patch.write_text('invalid patch\n')
        self.prepare(success=False)
        self.assertFalse((self.output / '.source-identity').exists())
        self.patch.write_text(PATCH)
        self.prepare()
        self.assertEqual((self.output / 'src/value.c').read_text(), 'patched\n')


if __name__ == '__main__':
    unittest.main()
