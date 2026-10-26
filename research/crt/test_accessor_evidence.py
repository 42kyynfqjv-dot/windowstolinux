"""Independent literal records and negative composition checks; no effect proof."""
import unittest

from check_accessor import assess, parse
from commode_model import Pointer, State, foreign, write_zero


class Evidence(unittest.TestCase):
    def test_expected_samples_do_not_close_frame(self):
        rows = parse(b'0 1879052288 0 0 0 1879048192\n1 1879052288 33 87 536875572 1879048192\n')
        self.assertEqual(assess(rows), dict(error_hypotheses_match=[True, True],
            same_pointer=True, accessor_effects_closed=False, emission_allowed=False))

    def test_changed_errors_and_pointer_are_retained(self):
        rows = parse(b'0 1879052288 4 5 6 1879048192\n1 1879052292 7 8 9 1879048192\n')
        self.assertEqual(rows[1][2:5], [7, 8, 9])
        self.assertEqual(assess(rows)['error_hypotheses_match'], [False, False])
        self.assertFalse(assess(rows)['same_pointer'])
        self.assertFalse(assess(rows)['accessor_effects_closed'])

    def test_truncated_reordered_and_out_of_range_records(self):
        first = b'0 1879052288 0 0 0 1879048192\n'
        for last in [b'', first, b'1 3 0 0 0 1\n',
                     b'1 1879052288 2147483648 0 0 1879048192\n',
                     b'1 1879052288 0 -1 0 1879048192\n',
                     b'1 1879052288 0 0 4294967296 1879048192\n']:
            with self.subTest(last=last), self.assertRaises(ValueError):
                parse(first + last)

    def test_unresolved_failure_nonreturn_and_concurrency_stay_blocked(self):
        # Conservative composition rule for each unresolved event, not its implementation.
        for event in ['unknown-write', 'exception', 'failure', 'nonreturn', 'concurrent-mutation']:
            with self.subTest(event=event):
                s = State(frame_proven=True)
                foreign(s)
                s.frame_proven = True  # A later sampled return cannot repair prior effects.
                self.assertEqual(write_zero(s, Pointer(1, 'app-ucrt', 1, 0x70001000)), 'blocked')
                self.assertIsNone(s.value)

    def test_stale_runtime_then_sample_does_not_create_authority(self):
        s = State(generation=2)
        old = Pointer(1, 'app-ucrt', 1, 0x70001000)
        self.assertEqual(write_zero(s, old), 'blocked')
        s.frame_proven = True
        self.assertEqual(write_zero(s, Pointer(1, 'app-ucrt', 2, 0x70001000)), 'blocked')


if __name__ == '__main__':
    unittest.main()
