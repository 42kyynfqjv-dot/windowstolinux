import copy, hashlib, json, unittest
from pathlib import Path
from api_set_namespace import CONTRACTS, SYMBOLS, validate, authorize_native

def fixture():
    module=dict(machine=0x14c,sha256='a'*64,path='explicit synthetic fixture')
    return dict(windows_version=[10,0,20348],machine=0x14c,rows=[
        dict(contract=c,symbol=SYMBOLS[i],flags=0x800,loaded=i<3,same_handle=True,
             export_survives_one_release=True,load_host=module.copy(),export_host=module.copy(),
             ntdll=module.copy(),error=126) for i,c in enumerate(CONTRACTS)])

class NamespaceEvidence(unittest.TestCase):
    def test_observation_is_never_initialization_authority(self):
        report=fixture();result=validate(report)
        self.assertFalse(result['native_admission']);self.assertEqual(result['initialization'],'unproved')
        for claimed in ('success','failed','unknown',True):
            with self.assertRaisesRegex(ValueError,'initialization/effect proof'):authorize_native(report,claimed)
    def test_missing_duplicate_and_wrong_contract(self):
        for mode in range(3):
            r=fixture()
            if mode==0:r['rows'].pop()
            elif mode==1:r['rows'][1]=copy.deepcopy(r['rows'][0])
            else:r['rows'][1]['contract']='api-other-l1-1-0'
            with self.assertRaisesRegex(ValueError,'missing/ambiguous'):validate(r)
    def test_stale_export_failed_load_and_unstable_handle(self):
        for field in ('loaded','same_handle','export_survives_one_release'):
            r=fixture();r['rows'][0][field]=False
            with self.assertRaisesRegex(ValueError,'observation failed'):validate(r)
    def test_version_architecture_flags_and_symbol(self):
        for mode in range(4):
            r=fixture()
            if mode==0:r['windows_version']=[10,0,19045]
            elif mode==1:r['machine']=0x8664
            elif mode==2:r['rows'][0]['flags']=8
            else:r['rows'][0]['symbol']='WrongExport'
            with self.assertRaises(ValueError):validate(r)
    def test_wrong_dll_architecture_and_mixed_runtime(self):
        r=fixture();r['rows'][0]['load_host']['machine']=0x8664
        with self.assertRaisesRegex(ValueError,'provenance'):validate(r)
        r=fixture();r['rows'][1]['ntdll']['sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'mixed runtime'):validate(r)
    def test_failure_row_must_really_fail(self):
        for error in (0, -1, True, 0x100000000):
            r=fixture();r['rows'][3]['error']=error
            with self.assertRaisesRegex(ValueError,'did not fail'):validate(r)
    def test_truthy_values_are_not_observations(self):
        for field in ('loaded','same_handle','export_survives_one_release'):
            r=fixture();r['rows'][0][field]='false'
            with self.assertRaisesRegex(ValueError,'observation failed'):validate(r)
        r=fixture();r['rows'][3]['loaded']=True
        with self.assertRaisesRegex(ValueError,'did not fail'):validate(r)
    def test_original_authored_source_is_frozen(self):
        here=Path(__file__).resolve().parent;expected=json.loads((here/'api-set-frozen.json').read_text())['source_sha256'];source=(here/'api_set_probe.c').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),expected)
        self.assertNotEqual(hashlib.sha256(source+b' ').hexdigest(),expected)
