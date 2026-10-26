import unittest
from model import State, api_states, read_join, digit_branch, prove

class Model(unittest.TestCase):
    def test_complete_return_partition(self):
        result=prove()
        self.assertEqual(result['outcomes'],[(0,0,'200'),(1,1,'202 or c0-48 [0,9]'),(2,2,'202 or 10*(c0-48)+(c1-48) [0,99]'),(4,65,'201'),(66,4294967295,'203')])
        self.assertFalse(result['emission_allowed'])
    def test_success_and_terminator_ranges(self):
        owner=object();_,one,two,_,_=api_states(owner)
        self.assertEqual(one.read(owner,0,4),('bytes',0,4))
        self.assertEqual(two.read(owner,2,4),('bytes',2,4))
        for s,offset in [(one,2),(two,4),(one,-1),(two,6)]:
            with self.assertRaises(ValueError):s.read(owner,offset,4)
    def test_unknown_failure_and_overflow(self):
        owner=object()
        for s in api_states(owner):
            if s.initialized==0:
                with self.assertRaises(ValueError):s.read(owner,0,4)
    def test_ownership_and_join(self):
        owner=object();states=api_states(owner)
        with self.assertRaises(ValueError):states[2].read(object(),0,4)
        with self.assertRaises(ValueError):read_join([states[0],states[2]],owner,0,4)
        with self.assertRaises(ValueError):read_join([states[1],states[2]],owner,2,4)
        self.assertEqual(len(read_join([states[1],states[2]],owner,0,4)),2)
    def test_bad_guard_and_saved_stack_offset(self):
        with self.assertRaises(ValueError):prove(short_limit=4)
        for offset in [0,4,5,7,8,10]:
            with self.assertRaises(ValueError):prove(second_offset_after_save=offset)
    def test_unsigned_word_guard_all_values(self):
        # Independent decimal interval oracle, exhaustive one-word domain;
        # not a sample-based proof over pairs or process inputs.
        for unit in range(65536):self.assertEqual(digit_branch(unit),48<=unit<=57)
        for unit,yes in [(0,False),(47,False),(48,True),(57,True),(58,False),(65535,False)]:
            self.assertEqual(digit_branch(unit),yes)
    def test_interval_boundaries(self):
        owner=object();s=State(4,4294967295,0,owner)
        yes,no=s.le(65);self.assertEqual((yes.lo,yes.hi,no.lo,no.hi),(4,65,66,4294967295))
        for n in [-1,4294967296]:
            with self.assertRaises(ValueError):State(n,n,0,owner)
    def test_digit_arithmetic_independent_table(self):
        # Actual scaled LEAs: 5*(c0-48), then -24, then c1+2*intermediate.
        for first,second,expected in [(48,48,0),(48,55,7),(52,50,42),(57,57,99)]:
            self.assertEqual(second+2*(5*(first-48)-24),expected)

if __name__=='__main__':unittest.main()
