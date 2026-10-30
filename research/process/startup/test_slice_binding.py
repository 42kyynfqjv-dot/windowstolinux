"""Adversarial artifact binding through the real Linux slice harness.

Synthetic PE bytes specify offsets independently of the production mapper. These
are rejection tests, not Windows observations or translated program comparisons.
"""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


class SliceBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        # One independently laid-out file-backed section at RVA 0x1000.
        pe = bytearray(0x300)
        pe[:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 0x80)
        pe[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<H', pe, 0x86, 1)
        struct.pack_into('<H', pe, 0x94, 0xe0)
        struct.pack_into('<I', pe, 0xb4, 0x400000)
        struct.pack_into('<IIII', pe, 0x180, 0x100, 0x1000, 0x100, 0x200)
        self.handler = bytes(range(24))
        pe[0x200:0x218] = self.handler
        self.pe = bytes(pe)
        self.report = {
            'pe_sha256': hashlib.sha256(self.pe).hexdigest(),
            'handler_sha256': hashlib.sha256(self.handler).hexdigest(),
            'handler_rva': 0x1000,
            'fault_rva': 0x1080,
            'resume_rva': 0x1082,
        }
        (self.root / 'slice.exe').write_bytes(self.pe)
        (self.root / 'handler.bin').write_bytes(self.handler)

    def assert_rejected_before_compilation(self, message):
        (self.root / 'report.json').write_text(json.dumps(self.report))
        # Patching the real subprocess entry point makes this check portable and
        # proves failure happened in provenance checks, not because a fake compiler
        # could not run. No event bytes are needed before these rejection points.
        with patch.object(sys, 'argv', ['check_slice.py', str(self.root),
                                       str(self.root / 'never-run-compiler')]), \
                patch.object(sys, 'path', [str(HERE), *sys.path]), \
                patch('subprocess.run') as compiler:
            with self.assertRaisesRegex(ValueError, message):
                runpy.run_path(str(HERE / 'check_slice.py'), run_name='__main__')
            compiler.assert_not_called()
        self.assertFalse((self.root / 'handler.rs').exists())
        self.assertFalse((self.root / 'native').exists())

    def test_retained_pe_change_rejects(self):
        changed = bytearray(self.pe)
        changed[-1] ^= 1
        (self.root / 'slice.exe').write_bytes(changed)
        self.assert_rejected_before_compilation('PE changed')

    def test_changed_slice_cannot_be_authorized_by_its_own_hash(self):
        changed = b'\xff' + self.handler[1:]
        (self.root / 'handler.bin').write_bytes(changed)
        self.report['handler_sha256'] = hashlib.sha256(changed).hexdigest()
        self.assert_rejected_before_compilation('slice not from retained PE')

    def test_report_hash_must_match_retained_slice(self):
        self.report['handler_sha256'] = '0' * 64
        self.assert_rejected_before_compilation('slice changed')

    def test_wrong_rva_rejects_even_when_inside_section(self):
        self.report['handler_rva'] += 1
        self.assert_rejected_before_compilation('slice not from retained PE')

    def test_truncated_file_backing_rejects_after_valid_file_hash(self):
        truncated = self.pe[:0x210]
        (self.root / 'slice.exe').write_bytes(truncated)
        self.report['pe_sha256'] = hashlib.sha256(truncated).hexdigest()
        self.assert_rejected_before_compilation('truncated file-backed range')


if __name__ == '__main__':
    unittest.main()
