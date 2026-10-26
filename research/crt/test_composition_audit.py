"""Independent literal artifact record; tests the proof boundary, not Windows effects."""
import struct,unittest
from composition_audit import audit,sha
class Audit(unittest.TestCase):
    def evidence(self):
        b=bytearray(0x2200);struct.pack_into('<I',b,60,0x80);struct.pack_into('<H',b,0x94,224);struct.pack_into('<H',b,0x86,1);struct.pack_into('<IIII',b,0x180,0x2000,0x1000,0x2000,0x200)
        # Independently written instruction layout and expected call imports.
        code=[0x56,0x6a,1,0xe8,0x68,0x0c,0,0,0xe8,0xa3,6,0,0,0x50,0xe8,0x93,0x0c,0,0,0xe8,0x78,6,0,0,0x8b,0xf0,0xe8,0xb7,0x0c,0,0,0x6a,1,0x89,0x30,0xe8,0x88,3,0,0,0x83,0xc4,12,0x5e,0x84,0xc0,0x74,0x78]
        b[0x230:0x230+len(code)]=bytes(code);b[0x8e0:0x8e6]=bytes([0xb8,0,0x40,0,0,0xc3]);b[0x8c0:0x8c3]=bytes([0x33,0xc0,0xc3])
        c=dict(pe_sha256=sha(b),complete_effect_proof=False,emission_allowed=False,direct_calls=[dict(site_rva=0x1033,imported='api-ms-win-crt-runtime-l1-1-0.dll!_set_app_type'),dict(site_rva=0x103e,imported='api-ms-win-crt-stdio-l1-1-0.dll!_set_fmode')])
        r=dict(binding=dict(pe_sha256=sha(b)),effect_proof=False,emission_allowed=False,normalized_match=True,machine=332,rva=0x879d0,relocation_sites=[0x879d1],base=0x70000000,disk_sha256='synthetic',leaf=dict(destination='EAX',length=6,value=0x70104768,object_rva=0x104768))
        return b,c,r
    def test_local_facts_leave_six_obligations(self):
        out=audit(*self.evidence());self.assertFalse(out['composition_authorized']);self.assertEqual(len(out['blockers']),6);self.assertEqual(out['conditional_local_trace']['cleanup_bytes'],12)
    def test_altered_prior_call_or_cleanup_rejects(self):
        for offset in [0x233,0x23e,0x25a]:
            b,c,r=self.evidence();b[offset]^=1;c['pe_sha256']=r['binding']['pe_sha256']=sha(b)
            with self.assertRaises(AssertionError):audit(b,c,r)
    def test_forged_permission_or_foreign_artifact_rejects(self):
        for key,value in [('effect_proof',True),('emission_allowed',True),('machine',34404)]:
            b,c,r=self.evidence();r[key]=value
            with self.assertRaises(AssertionError):audit(b,c,r)
        b,c,r=self.evidence();r['binding']['pe_sha256']='different'
        with self.assertRaises(AssertionError):audit(b,c,r)
    def test_changed_order_relocation_and_pointer_rejects(self):
        b,c,r=self.evidence();c['direct_calls'].reverse()
        with self.assertRaises(AssertionError):audit(b,c,r)
        for change in ['relocation','pointer']:
            b,c,r=self.evidence()
            if change=='relocation':r['relocation_sites']=[]
            else:r['leaf']['value']+=4
            with self.assertRaises(AssertionError):audit(b,c,r)
if __name__=='__main__':unittest.main()
