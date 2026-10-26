import unittest
from finite_loop_model import prove,trace,eligible,compare,increment,add,branch,Rejected
from image_read_model import Image,Section,Relocation
CODE=bytes.fromhex('33c0 33c9 390500304000 760f 0f1f4000 03c1 41 3b0d00304000 72f5 c3')
def example(n=5,code=CODE,sites=(0x1006,0x1015),data=None,metadata=()):
    data=n.to_bytes(4,'little') if data is None else data
    return Image(0x400000,0x5000,0x1000,[Section(0x1000,len(code),0x400,code,'code'),Section(0x3000,len(data),0x800,data,'writable')],[Relocation(s) for s in sites],metadata)
class FiniteLoops(unittest.TestCase):
    def test_literal_five_iteration_trace(self):
        p=prove(example());r=eligible(p)
        self.assertEqual((p.bound,p.steps,p.result,p.target),(5,26,10,0x3000))
        self.assertEqual(r['headers'],[(0,0,5),(1,0,4),(2,1,3),(3,3,2),(4,6,1)])
        self.assertEqual((r['eax'],r['ecx'],r['flags']),(10,5,(False,True,False,False)))
        self.assertFalse(r['emission_allowed'])
    def test_zero_one_exit_and_resource_boundaries(self):
        for n,total,steps in [(0,0,5),(1,0,10),(2,1,14),(23,253,98),(24,276,102),(254,32131,1022)]:
            p=prove(example(n));r=trace(p)
            self.assertEqual((r['eax'],r['ecx'],r['steps']),(total,n,steps))
            if n<=23:self.assertEqual(eligible(p)['eax'],total)
            else:
                with self.assertRaisesRegex(Rejected,'exit domain'):eligible(p)
        for n in (255,256,0x7fffffff,0x80000000,0xffffffff):
            with self.assertRaisesRegex(Rejected,'budget'):prove(example(n))
    def test_unsigned_compare_truth_table(self):
        for a,b,f,jb,jbe in [(0,0,(False,True,False,False),False,True),(0,1,(True,False,True,False),True,True),(0xffffffff,1,(False,False,True,False),False,False),(0x80000000,0x7fffffff,(False,False,False,True),False,False),(0x7fffffff,0x80000000,(True,False,True,True),True,True)]:
            self.assertEqual(compare(a,b),f);self.assertEqual(branch('jb',f),jb);self.assertEqual(branch('jbe',f),jbe)
    def test_inc_carry_preservation_and_wrap(self):
        for old,new,z,s,o in [(0,1,False,False,False),(0x7fffffff,0x80000000,False,True,True),(0xffffffff,0,True,False,False)]:
            for cf in (None,False,True):self.assertEqual(increment(old,(cf,None,None,None)),(new,(cf,z,s,o)))
        self.assertEqual(add(0xffffffff,1),(0,(True,True,False,False)))
    def test_unknown_inputs_and_conditions(self):
        for x in (None,-1,2**32,'pointer'):
            with self.assertRaises(Rejected):compare(x,1)
        for kind,flags in [('jb',(None,False,False,False)),('jbe',(False,None,False,False)),('jl',(False,False,False,False))]:
            with self.assertRaises(Rejected):branch(kind,flags)
    def test_unproved_cycles_and_unknown_reset_graphs(self):
        # Backedge to self/operand/entry, inverted or signed tests, no increment,
        # changed reset and store effect all reject before concrete execution.
        for offset,value in [(26,254),(26,246),(26,229),(25,0x73),(25,0x7c),(18,0x49),(18,0x90),(1,0xc1),(10,0x77),(5,0x0d),(19,0x89)]:
            b=bytearray(CODE);b[offset]=value
            with self.assertRaisesRegex(Rejected,'graph'):prove(example(code=b))
        for size in range(1,28):
            with self.assertRaises(Rejected):prove(example(code=CODE[:size]))
        with self.assertRaises(Rejected):prove(example(code=CODE+b'\xc3'))
    def test_bound_provenance_aliases_and_loader_writes(self):
        b=bytearray(CODE);b[21:25]=(0x403004).to_bytes(4,'little')
        with self.assertRaisesRegex(Rejected,'same word'):prove(example(code=b,data=b'\x05\0\0\0'*2))
        for sites in [(0x1006,), (0x1006,0x1015,0x3000),(0x1006,0x1015,0x1006),(0x1007,0x1015)]:
            with self.assertRaisesRegex(Rejected,'accounting'):prove(example(sites=sites))
        for va in (0x3fffff,0x401000,0x403001,0x403004):
            b=bytearray(CODE)
            for at in (6,21):b[at:at+4]=va.to_bytes(4,'little')
            with self.assertRaises(Rejected):prove(example(code=b))
        with self.assertRaisesRegex(Rejected,'metadata'):prove(example(metadata=((0x3003,1),)))
    def test_snapshot_and_different_images(self):
        data=bytearray(b'\x05\0\0\0');im=example(data=data);data[0]=6
        self.assertEqual(eligible(prove(im))['eax'],10)
        self.assertEqual(eligible(prove(example(6)))['eax'],15)
        self.assertNotEqual(prove(im).image,prove(example(6)).image)
if __name__=='__main__':unittest.main()
