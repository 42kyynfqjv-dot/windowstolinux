import hashlib,json,unittest
from pathlib import Path
from provider_failure import validate
class ProviderFailureTests(unittest.TestCase):
    def test_independent_expected_failure_and_release(self):
        row=dict(before_absent=True,first_error=1114,after_first_absent=True,second_error=1114,after_second_absent=True,value=7,held_after_one_release=True,absent_after_final_release=True)
        validate(row)
        for key in row:
            changed=dict(row);changed[key]=False if type(row[key]) is bool else 0
            with self.assertRaises(ValueError):validate(changed)
        for key in ('first_error','second_error','value'):
            changed=dict(row);changed[key]=True
            with self.assertRaises(ValueError):validate(changed)
    def test_source_and_configuration_freeze(self):
        here=Path(__file__).parent;f=json.loads((here/'provider-failure-frozen.json').read_text())
        for name,digest in f['sources'].items():self.assertEqual(hashlib.sha256((here/name).read_bytes()).hexdigest(),digest)
