"""A new test must not break the oracle; missing execution must not pass it."""
import subprocess
import unittest
from check_normal_wrapper import require_test_completions


class Completions(unittest.TestCase):
    def test_added_cases_and_crlf_pass(self):
        for count in [11, 12, 14]:
            raw = b''.join(b'test case%d ... ok\r\n' % i for i in range(count))
            raw += b'test result: ok. %d passed; 0 failed; 0 ignored;\r\n' % count
            require_test_completions(subprocess.CompletedProcess([], 0, raw), [b'case0', b'case10'])

    def test_missing_ignored_failed_duplicate_or_inconsistent_cannot_pass(self):
        good = b'test needed ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        bad = [good.replace(b'needed', b'other'), good.replace(b'... ok', b'... ignored'),
               good.replace(b'1 passed', b'11 passed'), good + good,
               good.replace(b'0 failed', b'1 failed'), good.replace(b'0 ignored', b'1 ignored')]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                require_test_completions(subprocess.CompletedProcess([], 0, raw), [b'needed'])
        with self.assertRaises(ValueError):
            require_test_completions(subprocess.CompletedProcess([], 1, good), [b'needed'])
