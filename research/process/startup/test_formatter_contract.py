"""Independent frozen formatter expectations; no converter or PE execution.

The small oracle uses Python's unbounded integers and regex replacement, not
the production x86 decoder, formatter state machine or emitted Rust. Literal
expected strings remain in formatter-frozen.json for a future native harness.
Buffer rows are pending instruction-derived obligations, not executions.
"""
import json
from pathlib import Path
import re
import unittest


FROZEN_PATH = Path(__file__).with_name('formatter-frozen.json')
FROZEN = json.loads(FROZEN_PATH.read_text(encoding='utf-8'))


def reference_format(storage: bytes, arguments: list[int | None]) -> tuple[bytes, int]:
    """Evaluate only the explicitly frozen scalar grammar and initialized cut.

    None denotes an unavailable scalar word. It is valid in an unused trailing
    slot, never a way to invent zero for a consumed argument. This function
    grants no pointer, memory, locale, FILE, or original-code authority.
    """
    end = storage.find(b'\0')
    if end < 0 or end > 4096 or len(arguments) > 64:
        raise ValueError('format/argument resource or termination boundary')
    format_bytes = storage[:end]
    consumed = 0

    def conversion(match: re.Match[bytes]) -> bytes:
        nonlocal consumed
        token = match.group()
        if token == b'%%':
            return b'%'
        if re.fullmatch(rb'%l?[diu]', token) is None:
            raise ValueError('outside bounded format grammar')
        if consumed >= len(arguments):
            raise ValueError('missing consumed argument')
        word = arguments[consumed]
        if type(word) is not int or not 0 <= word <= 0xffffffff:
            raise ValueError('consumed argument is not initialized scalar32')
        consumed += 1
        if token[-1:] != b'u' and word >= 0x80000000:
            word -= 0x100000000
        return str(word).encode('ascii')

    # Include every percent occurrence: malformed tails and unsupported fields
    # cannot escape validation merely because the supported-token regex misses.
    output = re.sub(rb'%(?:l?[diu]|%|[^%]*?(?=%|$))', conversion, format_bytes)
    if len(output) > 16384:
        raise ValueError('logical output bound')
    return output, consumed


class FormatterContractTests(unittest.TestCase):
    def test_literal_expectations_are_independent_and_preserve_windows_widths(self):
        ids = set()
        for case in FROZEN['format_cases']:
            with self.subTest(case=case['id']):
                self.assertNotIn(case['id'], ids)
                ids.add(case['id'])
                actual, consumed = reference_format(
                    case['format_ascii'].encode('ascii'), case['arguments_u32'])
                self.assertEqual(actual, case['expected_ascii'].encode('ascii'))
                self.assertEqual(consumed, case['consumed_arguments'])
        self.assertEqual(FROZEN['evidence_counts'], {
            'fresh_windows_observations': 0,
            'actual_windows_elf_pairs': 0,
            'whole_pe_translations': 0,
        })

    def test_unknown_or_missing_consumed_values_and_unproved_grammar_reject(self):
        for case in FROZEN['domain_rejections']:
            with self.subTest(case=case['id']), self.assertRaises(ValueError):
                reference_format(case['format_ascii'].encode('ascii'), case['arguments_u32'])
        for word in [-1, 0x100000000, 1.5, True, None]:
            with self.subTest(word=word), self.assertRaises(ValueError):
                reference_format(b'%u\0', [word])
        # Availability of unused arguments is not promoted into initialization.
        self.assertEqual(reference_format(b'%u\0%n', [7, None]), (b'7', 1))
        self.assertEqual(reference_format(b'\0', [None] * 64), (b'', 0))

    def test_complete_nul_argument_and_reachable_output_boundaries(self):
        self.assertEqual(reference_format(b'A' * 4096 + b'\0', []), (b'A' * 4096, 0))
        for storage, arguments in [
            (b'A' * 4097 + b'\0', []),
            (b'A' * 4096, []),
            (b'\0', [None] * 65),
            (b'%d' * 65 + b'\0', [1] * 64),
        ]:
            with self.subTest(length=len(storage), arguments=len(arguments)), self.assertRaises(ValueError):
                reference_format(storage, arguments)
        # Sixty-four two-byte signed conversions each expand to eleven bytes.
        # No admitted conversion expands further; the remaining 3968 literals
        # give 4672 total. 16384 is a ceiling, not an achievable format case.
        expected = b'A' * 3968 + b'-2147483648' * 64
        self.assertEqual(len(expected), 4672)
        self.assertEqual(reference_format(b'A' * 3968 + b'%d' * 64 + b'\0',
                                          [0x80000000] * 64), (expected, 64))

    def test_original_buffer_effects_keep_failure_order_and_count_domains(self):
        rows = {row['id']: row for row in FROZEN['buffer_effect_cases']}
        ordinary = rows['ordinary_calloc_failure_is_unbuffered']['expected']
        temporary = rows['temporary_failure_still_buffers']['expected']
        self.assertEqual(ordinary['flags'], 0x402)
        self.assertEqual(ordinary['flags'] & 0xc0, 0)
        self.assertEqual(ordinary['count'], 0)
        self.assertEqual(temporary['flags'], 0x282)
        self.assertNotEqual(temporary['flags'] & 0xc0, 0)
        self.assertEqual(temporary['count'], 2)
        self.assertEqual(rows['ordinary_calloc_success']['allocation']['arguments'], [4096, 1])
        capacity = rows['capacity_short_retains_new_byte']
        self.assertLess(capacity['ordered_effects'].index('write old AB once'),
                        capacity['ordered_effects'].index('store incoming C at base'))
        self.assertEqual(capacity['expected']['buffer_after_hex'], '43')
        self.assertEqual(capacity['expected']['write_calls'], 1)
        deferred = rows['deferred_format_success_then_flush_failure']
        logical = b'a\r\nb\n0'
        self.assertEqual(len(logical), deferred['expected']['printf_before_flush'])
        self.assertEqual(logical.replace(b'\n', b'\r\n'),
                         bytes.fromhex(deferred['backend'][0]['request_hex']))
        self.assertEqual(len(logical), 6)
        self.assertEqual(len(bytes.fromhex(deferred['backend'][0]['request_hex'])), 8)
        self.assertTrue(deferred['expected']['no_retry'])
        finished = rows['temporary_completion_clears_fields_after_failed_flush']
        self.assertEqual((0x282 | 0x10) & 0xfffffd7f, finished['expected']['flags_after'])
        self.assertIsNone(finished['expected']['base'])
        self.assertIsNone(finished['expected']['pointer'])


if __name__ == '__main__':
    unittest.main()
