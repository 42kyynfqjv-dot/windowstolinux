import copy
import unittest
from onexit_model import State, Foreign, initialize, register, conversion, consume_model_table

class Contract(unittest.TestCase):
    def test_literal_policy_one_sentinel_layout(self):
        s=State();s.tables[0].words=(None,None,None)
        r=initialize(s,1)
        self.assertEqual((r.kind,r.eax,r.known_mask),('returned',1,0xffffffff))
        self.assertEqual(s.flag,1)
        self.assertEqual([t.words for t in s.tables],[(4294967295,4294967295,4294967295)]*2)
        self.assertEqual(s.events,['six sentinel stores; flag=1'])

    def test_zero_mode_sentinel_and_policy_one_mode_boundary(self):
        for mode,policy in [(0,0),(0,1),(0xffffffff,1)]:
            s=State(mode=mode);self.assertEqual(initialize(s,policy).eax,1)
            self.assertEqual(s.tables[1].words,(0xffffffff,)*3)

    def test_al_only_repeated_initialization_ignores_invalid_policy(self):
        s=State(flag=9);before=copy.deepcopy(s)
        r=initialize(s,7);self.assertEqual((r.eax,r.known_mask),(1,255));self.assertEqual(s,before)
        r=initialize(s,7,incoming_eax=0xdeadbeef);self.assertEqual(r.eax,0xdeadbe01)

    def test_invalid_policy_does_not_return_or_write(self):
        s=State();r=initialize(s,2)
        self.assertEqual(r.kind,'fastfail-request');self.assertIsNone(r.eax)
        self.assertEqual(s.flag,0);self.assertEqual(s.tables[0].words,(0,0,0))
        self.assertEqual(initialize(s,1).kind,'nonreturn')
        self.assertEqual(register(s,0x4018d0,allowed_callbacks={0x4018d0}).kind,'nonreturn')

    def test_import_numeric_success_does_not_prove_no_mutation(self):
        s=State();r=initialize(s,0,effects=[Foreign(result=0)])
        self.assertEqual(r.kind,'blocked');self.assertIsNone(s.flag)
        self.assertTrue(all(t.words==(None,None,None) for t in s.tables))
        self.assertEqual(initialize(s,1).kind,'blocked')

    def test_explicit_first_failure_preserves_upper_eax_and_prior_writes(self):
        s=State();r=initialize(s,0,effects=[Foreign(0xfffffff9,True,(10,11,12))])
        self.assertEqual(r.eax,0xffffff00);self.assertEqual(s.flag,0)
        self.assertEqual(s.tables[0].words,(10,11,12));self.assertEqual(s.tables[1].words,(0,0,0))
        self.assertEqual(s.events,['initialize-table-0'])

    def test_explicit_second_failure_retains_first_table_state(self):
        s=State();r=initialize(s,0,effects=[Foreign(0,True,(1,2,3)),Foreign(0x123456ff,True,(4,5,6))])
        self.assertEqual(r.eax,0x12345600);self.assertEqual(s.flag,0)
        self.assertEqual([t.words for t in s.tables],[(1,2,3),(4,5,6)])
        self.assertEqual([t.life for t in s.tables],['opaque-ready','unknown'])

    def test_explicit_success_opaque_lifecycle_requires_reinitialization(self):
        s=State();self.assertEqual(initialize(s,0,effects=[Foreign(0,True,(1,2,3)),Foreign(0,True,(4,5,6))]).eax,1)
        self.assertEqual(register(s,0x4018d0,allowed_callbacks={0x4018d0},effect=Foreign(0,True,(7,8,9))).eax,0)
        self.assertEqual(consume_model_table(s,0),[0x4018d0])
        self.assertEqual(register(s,0x4018d0,allowed_callbacks={0x4018d0},effect=Foreign(0,True,(7,8,9))).kind,'blocked')

    def test_unknown_state_and_nonreturn_are_not_success(self):
        for s in [State(flag=None),State(mode=None),State(blocked=True)]:
            self.assertEqual(initialize(s,0).kind,'blocked')
        s=State();self.assertEqual(initialize(s,None).kind,'blocked')
        s=State();self.assertEqual(initialize(s,0,effects=[Foreign(0,True,(0,0,0),True)]).kind,'blocked')

    def test_owner_full_ranges_and_protected_alias_reject_before_effect(self):
        for member,value in [('owner',2),('start',0x30d0),('start',0x30b0),('size',11)]:
            s=State();setattr(s.tables[1],member,value);before=copy.deepcopy(s)
            with self.assertRaises(ValueError):initialize(s,1)
            self.assertEqual(s,before)

    def test_sentinel_registration_unknown_effect_and_callback_provenance(self):
        s=State();initialize(s,1)
        with self.assertRaises(ValueError):register(s,0,allowed_callbacks={0x4018d0})
        with self.assertRaises(ValueError):register(s,0x5018d0,allowed_callbacks={0x4018d0})
        self.assertEqual(register(s,0x4018d0,allowed_callbacks={0x4018d0}).kind,'blocked')
        self.assertIn('_crt_atexit',s.events)
        s=State();initialize(s,1)
        self.assertEqual(register(s,0x4018d0,allowed_callbacks={0x4018d0},effect=Foreign(0,True)).eax,0)
        self.assertEqual(s.process_callbacks,[0x4018d0]);self.assertEqual(s.tables[0].callbacks,[])
        self.assertEqual(s.tables[0].words,(0xffffffff,)*3)

    def test_registration_failure_no_rollback_and_scalar_conversion_boundaries(self):
        s=State();initialize(s,0,effects=[Foreign(0,True,(1,2,3)),Foreign(0,True,(4,5,6))])
        r=register(s,0x4018d0,allowed_callbacks={0x4018d0},effect=Foreign(0xffffffff,True,(7,8,9)))
        self.assertEqual(r.eax,0xffffffff);self.assertEqual(s.tables[0].words,(7,8,9));self.assertEqual(s.tables[0].life,'unknown')
        for p,r,expected in [(1,0,(0,1)),(0x80000000,0,(0,1)),(0xffffffff,0,(0,1)),(0,0,(0xffffffff,0x44)),(1,1,(0xffffffff,0x44)),(1,0xffffffff,(0xffffffff,0x44))]:
            self.assertEqual(conversion(p,r),expected)

if __name__=='__main__':unittest.main()
