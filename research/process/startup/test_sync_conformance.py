import copy,hashlib,json,unittest
from pathlib import Path
from sync_conformance import validate
class SyncConformance(unittest.TestCase):
    def setUp(self):
        self.here=Path(__file__).resolve().parent
        self.frozen=json.loads((self.here/'sync-frozen.json').read_text())
    def test_expected_sequence_and_unconstrained_success_error(self):
        row=copy.deepcopy(self.frozen['expected'])
        for error in (0,0x1234,8):
            row['success_last_error']=error;self.assertEqual(validate(row),self.frozen['expected'])
    def test_failure_order_missing_recursion_and_canary_mutations(self):
        for key,value in [('initialized',False),('reinitialized',False),('canaries',False),('initialized',1),('events',[1,2,3,4,5]),('events',[1,2,2,3,4,4,5,4,1,5])]:
            row=copy.deepcopy(self.frozen['expected']);row[key]=value
            with self.assertRaises(ValueError):validate(row)
    def test_frozen_source_and_mutation(self):
        source=(self.here/'sync_probe.c').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),self.frozen['source_sha256'])
        self.assertNotEqual(hashlib.sha256(source+b' ').hexdigest(),self.frozen['source_sha256'])
