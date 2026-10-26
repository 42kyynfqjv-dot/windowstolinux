import unittest
from dataclasses import replace
from image_read_model import Image, Section, Relocation, Rejected

# Independently authored literal image slices; no production or fixture generator.
CODE = bytes.fromhex('8b0d04304000 a108304000 03c8 a100304000 03c1 c3')
DATA = bytes.fromhex('02000000 03000000 04000000')

def example(code=CODE, data=DATA, relocs=(0x1002, 0x1007, 0x100e), **kwargs):
    sections = kwargs.pop('sections', [Section(0x1000, len(code), 0x400, code, 'code'),
                                       Section(0x3000, len(data), 0x800, data, 'writable')])
    return Image(0x400000, 0x5000, 0x1000, sections,
                 [Relocation(x) for x in relocs], **kwargs)

class ImageReads(unittest.TestCase):
    def test_literal_array_trace_and_stable_snapshot(self):
        data = bytearray(DATA); m = example(data=data); data[0] = 99
        result = m.prove()
        self.assertEqual(result['model_exit'], 9)
        self.assertEqual(result['reads'], [(0x1002,0x3004,3),(0x1007,0x3008,4),(0x100e,0x3000,2)])
        unknown = (None,)*4; positive = (False,False,False,False)
        self.assertEqual(result['trace'], [(None,3,unknown),(4,3,unknown),(4,7,positive),
                                           (2,7,positive),(9,7,positive),(9,7,positive)])
        self.assertFalse(result['emission_allowed'])
        self.assertEqual(result, m.prove())
        self.assertNotEqual(m.identity, example(data=bytes([99])+DATA[1:]).identity)

    def test_boundary_flags_and_mov_preservation(self):
        # First ADD is ECX+EAX. Third read replaces EAX but must preserve flags.
        for data, expected, flags in [
            ('00000000 ffffffff 01000000',0,(True,True,False,False)),
            ('00000080 ffffff7f 01000000',0,(False,False,True,True)),
            ('00000000 00000080 00000080',0,(True,True,False,True)),
            ('00000000 ff000000 00000000',255,(False,False,False,False))]:
            r=example(data=bytes.fromhex(data)).prove()
            self.assertEqual(r['model_exit'], expected)
            self.assertEqual(r['trace'][2][2],flags)
            self.assertEqual(r['trace'][3][2],flags)
        with self.assertRaisesRegex(Rejected,'exit domain'):
            example(data=bytes.fromhex('00000000 00010000 00000000')).prove()

    def test_full_ranges_not_just_first_byte(self):
        for va in (0x3fffff,0x400000,0x401000,0x402fff,0x403009,0x40300b,0x40300c,0xffffffff):
            b=bytearray(CODE); b[2:6]=va.to_bytes(4,'little')
            with self.assertRaises(Rejected):example(code=b).prove()
        # Unaligned complete words are explicitly allowed in fault-free domain.
        b=bytearray(CODE); b[2:6]=bytes.fromhex('01304000'); b[14:18]=bytes.fromhex('08304000')
        r=example(code=b,data=bytes.fromhex('00010000 00000000 00000000')).prove()
        self.assertEqual(r['reads'][0],(0x1002,0x3001,1));self.assertEqual(r['model_exit'],1)

    def test_metadata_full_width_and_loader_modified_data(self):
        for metadata in (((0x3007,1),), ((0x1005,1),), ((0x3000,12),)):
            with self.assertRaisesRegex(Rejected,'metadata'):example(metadata=metadata).prove()
        for site in (0x3000,0x3009):
            with self.assertRaises(Rejected):example(relocs=(0x1002,0x1007,0x100e,site)).prove()
        m=example();m.relocations=(Relocation(0x1002,1),)
        with self.assertRaisesRegex(Rejected,'unsupported relocation'):m.prove()

    def test_operand_binding_duplicates_overlap_and_missing(self):
        for sites in [(0x1002,0x1007), (0x1002,0x1007,0x100e,0x1002),
                      (0x1002,0x1003,0x1007,0x100e), (0x1000,0x1007,0x100e),
                      (0x1002,0x1007,0x100d), (0x1002,0x1007,0x1012)]:
            with self.assertRaises(Rejected):example(relocs=sites).prove()
        # Address-shaped bytes are not authority without the exact relocation.
        with self.assertRaises(Rejected):example(relocs=()).prove()

    def test_entire_code_effects_no_sampling_or_escape(self):
        for suffix in ('a300304000','890d00304000','e800000000','ffd0','eb00','72fe',
                       'c7050030400007000000','cd80','ff25 00304000','8b00','b800304000'):
            code=CODE[:-1]+bytes.fromhex(suffix)+b'\xc3'
            with self.assertRaisesRegex(Rejected,'unsupported effect'):example(code=code).prove()
        with self.assertRaisesRegex(Rejected,'code after'):example(code=CODE+b'\xcc').prove()
        with self.assertRaisesRegex(Rejected,'unknown scalar'):
            example(code=b'\x03\xc1'+CODE,relocs=(0x1004,0x1009,0x1010)).prove()
        for prefix in ('66','67','f0','f2','f3','2e','36','3e','26','64','65'):
            with self.assertRaises(Rejected):example(code=bytes.fromhex(prefix)+CODE).prove()

    def test_mapping_aliases_tails_startup_and_context(self):
        template=example().sections
        changes=[replace(template[1],raw=0x401),replace(template[1],rva=0x1001),
                 replace(template[1],virtual=13),replace(template[1],role='writable-zero'),
                 replace(template[1],rva=0xfffffff8)]
        for changed in changes:
            with self.assertRaises(Rejected):example(sections=[template[0],changed]).prove()
        for directory in (0,1,2,4,9,10,12,13,14,15):
            with self.assertRaisesRegex(Rejected,'directory'):example(directories=(5,6,directory))
        # Same numeric RVAs in a different snapshot read only its own data.
        self.assertEqual(example(data=bytes.fromhex('01000000 02000000 03000000')).prove()['model_exit'],6)
        with self.assertRaises(Rejected):example(sections=[replace(template[0],rva=0x1001),template[1]])

    def test_rebase_arithmetic_literal_addresses(self):
        # Independent PE HIGHLOW calculation, not a claim of observed Windows bases.
        original=(0x403004,0x403008,0x403000)
        for actual, expected in [(0x400000,(0x403004,0x403008,0x403000)),
                                 (0x10000000,(0x10003004,0x10003008,0x10003000)),
                                 (0x10000,(0x13004,0x13008,0x13000))]:
            fixed=tuple((x+actual-0x400000)&0xffffffff for x in original)
            self.assertEqual(fixed,expected)
            self.assertEqual(tuple(x-actual for x in fixed),(0x3004,0x3008,0x3000))

    def test_truncation_instruction_cap_and_absent_return(self):
        for length in range(21):
            with self.assertRaises(Rejected):example(code=CODE[:length]).prove()
        with self.assertRaisesRegex(Rejected,'instruction cap'):
            code=CODE[:-1]+b'\x03\xc1'*1024+b'\xc3'
            example(sections=[Section(0x1000,len(code),0x400,code,'code'),
                              Section(0x3000,12,0x2000,DATA,'writable')]).prove()

if __name__=='__main__':unittest.main()
