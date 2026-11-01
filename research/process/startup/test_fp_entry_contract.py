import unittest
from fp_entry_contract import validate_entry_fp


class EntryFP(unittest.TestCase):
    def row(self):
        return dict(fp_context_flags=0x1003f, fp_control=0x27f, fp_status=0,
                    fp_tag=0xffff, fp_mxcsr=0x1f80, fp_mxcsr_mask=0)

    def test_observation_does_not_replace_nondefault_or_pending_values(self):
        for cw, sw, mx in [(0x27f, 0, 0x1f80), (0x77e, 0x8081, 0x5f81)]:
            row = self.row()
            row.update(fp_control=cw, fp_status=sw, fp_mxcsr=mx)
            got = validate_entry_fp(row)
            self.assertEqual((got['fp_control'], got['fp_status'], got['fp_mxcsr']), (cw, sw, mx))

    def test_missing_categories_and_unknown_fields_reject(self):
        for key, value in [('fp_context_flags', 0x10007), ('fp_control', None),
                           ('fp_mxcsr', True), ('fp_status', 65536)]:
            row = self.row()
            row[key] = value
            with self.assertRaises(ValueError):
                validate_entry_fp(row)
