import struct
import unittest
from command_line_contract import HERE,vectors,rust_vectors,decode_probe,validate_probe

def packet(row,acp=65001,stable=3):
    word=lambda n:struct.pack('<I',n)
    blob=lambda b:word(len(b))+b
    return word(0x31444d43)+word(acp)+word(stable)+blob(bytes.fromhex(row['utf8_hex'])+b'\0')+blob(bytes.fromhex(row['utf16le_hex'])+b'\0\0')+word(len(row['argv']))+b''.join(blob(x.encode('utf-16le')+b'\0\0') for x in row['argv'])

class CommandLineContract(unittest.TestCase):
    def test_frozen_rust_vectors_match_independent_data(self):
        self.assertEqual((HERE/'command-line-vectors.rs').read_text(encoding='utf-8'),rust_vectors())
    def test_unicode_and_confusable_bytes_are_lossless(self):
        row=vectors()[5];data=validate_probe(packet(row),row)
        self.assertIn('Ā'.encode(),data['a']);self.assertIn('＂'.encode(),data['a']);self.assertIn('😀'.encode(),data['a'])
    def test_all_frozen_protocols_validate(self):
        for row in vectors():self.assertEqual(validate_probe(packet(row),row)['acp'],65001)
    def test_truncation_and_trailing_bytes_reject(self):
        b=packet(vectors()[0])
        for i in range(len(b)):
            with self.assertRaises(ValueError):decode_probe(b[:i])
        with self.assertRaises(ValueError):decode_probe(b+b'x')
    def test_unsupported_acp_and_unstable_pointer_reject(self):
        row=vectors()[0]
        for acp,stable in [(1252,3),(65001,0),(65001,1),(65001,2)]:
            with self.assertRaises(ValueError):validate_probe(packet(row,acp,stable),row)
    def test_mismatch_cannot_be_a_valid_observation(self):
        a,b=vectors()[:2]
        with self.assertRaises(ValueError):validate_probe(packet(a),b)
    def test_observation_refuses_non_windows_execution(self):
        import sys
        from pathlib import Path
        from observe_command_line import observe
        if sys.platform=='win32':self.skipTest('host guard applies to non-Windows only')
        with self.assertRaisesRegex(RuntimeError,'requires Windows'):observe(Path('unused-command-line-observation'))

    def test_failed_probe_cannot_increment_observation_count(self):
        from subprocess import CompletedProcess
        from observe_command_line import record_result
        row=vectors()[0]
        for result in [CompletedProcess([],1,packet(row),b''),CompletedProcess([],0,packet(row)[:-1],b''),CompletedProcess([],0,packet(vectors()[1]),b'')]:
            report={'observations':0};record={'status':'started'}
            with self.assertRaises(ValueError):record_result(report,record,result,row)
            self.assertEqual(report['observations'],0);self.assertEqual(record['status'],'mismatch')
        report={'observations':0};record={};record_result(report,record,CompletedProcess([],0,packet(row),b''),row)
        self.assertEqual(report['observations'],1);self.assertEqual(record['status'],'matched')
