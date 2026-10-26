import copy
import unittest
from commode_model import State,Pointer,write_zero,foreign
class Contract(unittest.TestCase):
    def ptr(self):return Pointer(1,'app-ucrt',1,0x70001000)
    def test_literal_four_byte_zero(self):
        s=State(frame_proven=True);self.assertEqual(write_zero(s,self.ptr()),'stored');self.assertEqual(s.value.to_bytes(4,'little'),b'\0\0\0\0')
    def test_same_address_not_same_owner(self):
        for p in [Pointer(2,'app-ucrt',1,0x70001000),Pointer(1,'static-crt',1,0x70001000),Pointer(1,'app-ucrt',2,0x70001000),Pointer(1.0,'app-ucrt',1,0x70001000),Pointer(True,'app-ucrt',1,0x70001000)]:
            s=State(frame_proven=True);before=copy.deepcopy(s)
            with self.assertRaises(ValueError):write_zero(s,p)
            self.assertEqual(s,before)
    def test_numeric_pointer_never_authority(self):
        s=State(frame_proven=True)
        with self.assertRaises(ValueError):write_zero(s,0x70001000)
    def test_invalid_ranges(self):
        for a in [0,-1,0.5,0x70001001,0xffffffff,0x100000000]:
            with self.assertRaises(ValueError):write_zero(State(frame_proven=True),Pointer(1,'app-ucrt',1,a))
        for n in [0,3,5,4.0]:
            with self.assertRaises(ValueError):write_zero(State(frame_proven=True,size=n),self.ptr())
    def test_dead_generation(self):
        with self.assertRaises(ValueError):write_zero(State(frame_proven=True,live=False),self.ptr())
    def test_success_observation_not_frame(self):
        s=State();self.assertEqual(write_zero(s,self.ptr()),'blocked');self.assertIsNone(s.value)
    def test_unknown_prior_effect_sticky(self):
        s=State(frame_proven=True);foreign(s);s.frame_proven=True
        self.assertEqual(write_zero(s,self.ptr()),'blocked')
    def test_unknown_overwritten_value_and_external_mutation(self):
        s=State(frame_proven=True,value=None);self.assertEqual(write_zero(s,self.ptr()),'stored')
        s.exclusive=False;self.assertEqual(write_zero(s,self.ptr()),'blocked')
if __name__=='__main__':unittest.main()
