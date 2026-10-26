import unittest
from initializer_model import State,dispatch
class Contract(unittest.TestCase):
 def call(self,entries,effects,state=None,**kw):
  state=state or State();r=dispatch(entries,effects,state,start=0x2000,end=0x2000+4*len(entries),code={0x1000,0x1100},**kw);return r,state
 def test_order_null_and_success(self):
  r,s=self.call([0,0x1000,0x1100],{0x1000:(0,{}),0x1100:(0,{})});self.assertEqual((r,s.trace),(0,[0x1000,0x1100]))
 def test_error_short_circuit_preserves_prior_effect(self):
  s=State({'x':0},{'x'});r,s=self.call([0x1000,0x1100],{0x1000:(7,{'x':1}),0x1100:(0,{'x':2})},s);self.assertEqual((r,s.trace,s.values),(7,[0x1000],{'x':1}))
 def test_void_does_not_interpret_integer(self):
  r,s=self.call([0x1000,0x1100],{0x1000:(7,{}),0x1100:(9,{})},integer=False);self.assertIsNone(r);self.assertEqual(s.trace,[0x1000,0x1100])
 def test_unknown_external_havocs_known_zero(self):
  s=State({'tls':0},{'tls'});r,s=self.call([0x1000,0x1100],{},s);self.assertIsNone(s.values['tls']);self.assertTrue(s.blocked);self.assertEqual(s.trace,[0x1000])
  r,s=self.call([0x1100],{0x1100:(0,{'tls':0})},s)
  self.assertIsNone(r);self.assertIsNone(s.values['tls']);self.assertEqual(s.trace,[0x1000])
 def test_unknown_result_stops_later_callbacks(self):
  r,s=self.call([0x1000,0x1100],{0x1000:(None,{})});self.assertTrue(s.blocked);self.assertEqual(s.trace,[0x1000])
 def test_changed_target_and_alias_reject_before_effect(self):
  for entries,kw in [([0x1200],{}),([0x1000],{'protected':[(0x2000,0x2004)]})]:
   s=State()
   with self.assertRaises(ValueError):self.call(entries,{0x1000:(0,{})},s,**kw)
   self.assertEqual(s.trace,[])
 def test_unknown_write_rejects(self):
  with self.assertRaises(ValueError):self.call([0x1000],{0x1000:(0,{'return':1})})
 def test_incomplete_word_rejects(self):
  with self.assertRaises(ValueError):dispatch([0],{},State(),start=0x2001,end=0x2005,code=set())
if __name__=='__main__':unittest.main()
