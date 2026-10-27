import unittest
from observe_boundary import verify_callback


class CallbackEvidence(unittest.TestCase):
    def test_other_node_cannot_supply_callback_successor(self):
        call = '0047cfd0 Node { operation: Call(Reg), successors: [4706258] }'
        verify_callback(call)
        for bad in [call.replace('4706258', '4706259') + '\n' +
                    '0047cfd2 Node { successors: [4706258] }',
                    call.replace('Call(Reg)', 'Nop'), call + '\n' + call]:
            with self.assertRaises(ValueError):
                verify_callback(bad)
