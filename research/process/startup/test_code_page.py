import hashlib
import json
from pathlib import Path
import struct
import tempfile
import sys
import unittest
from observe_code_page import HERE,validate,observe,validate_identity

class CodePageObservation(unittest.TestCase):
    def test_independent_protocol_and_no_default_acp_or_last_error_assumption(self):
        expected=json.loads((HERE/'code-page-expectations.json').read_text())
        for acp in (1252,65001):
            b=struct.pack('<9I',0x31504356,acp,2,65001,1,0x12345678,0xffffffff,0,87)
            result=validate(b,expected)
            self.assertEqual(result['observed_acp'],acp)
            self.assertEqual(result['cases'][1]['last_error'],87)
            for cut in range(len(b)):
                with self.assertRaises(ValueError):validate(b[:cut],expected)
            for word in (0,2,3,4,6,7):
                changed=bytearray(b);changed[word*4]^=1
                with self.assertRaises(ValueError):validate(changed,expected)
            with self.assertRaises(ValueError):validate(b+b'x',expected)
    def test_actual_image_identity_cannot_be_substituted_by_successful_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'launch').mkdir();data=b'owned authored fixture bytes';digest=hashlib.sha256(data).hexdigest()
            for mode in ('intact','changed-copy','changed-image','changed-launch'):
                (p/'code-page-probe.exe').write_bytes(data+(b'x' if mode=='changed-image' else b''))
                (p/'launch/program.bin').write_bytes(data+(b'x' if mode=='changed-copy' else b''))
                (p/'launch/launch.json').write_text(json.dumps(dict(executed_sha256='0'*64 if mode=='changed-launch' else digest)))
                if mode=='intact':validate_identity(p,digest)
                else:
                    with self.assertRaisesRegex(ValueError,'PE identity mismatch'):validate_identity(p,digest)
    def test_frozen_sources(self):
        frozen=json.loads((HERE/'code-page-frozen.json').read_text())
        for name,digest in frozen['sources'].items():self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
    def test_host_guard(self):
        if sys.platform=='win32':self.skipTest('non-Windows host guard')
        with self.assertRaisesRegex(RuntimeError,'requires Windows'):observe(Path('unused-code-page'))
