"""Protocol/adversarial checks; authored rows here are not Windows evidence."""
import json
import unittest
import observe_fp_control as probe


class Protocol(unittest.TestCase):
    def rows(self):
        rows = [dict(kind=probe.KIND, pointer_bytes=4, compiler=194435229)]
        for i, cw in enumerate([0x003f, 0x023f, 0x033f, 0x073f, 0x0b3f, 0x0f3f]):
            for j in range(2):
                mx = 0x1f80 | (0x603f if j else 0)
                rows.append(dict(case=2*i+j, input=cw, output=cw|0x40,
                                 status_defined=0, mxcsr_in=mx, mxcsr_out=mx))
        return rows

    def encode(self, rows):
        return ('\r\n'.join(json.dumps(r) for r in rows)+'\r\n').encode()

    def test_valid_protocol(self):
        self.assertEqual(len(probe.validate(self.encode(self.rows()))), 64)

    def test_failures_cannot_be_counted_as_observations(self):
        for field, value in [('case', 1), ('output', 0), ('status_defined', 1),
                             ('mxcsr_out', 0), ('input', True)]:
            with self.subTest(field=field):
                rows = self.rows()
                rows[1][field] = value
                with self.assertRaises(ValueError):
                    probe.validate(self.encode(rows))
        for rows in [self.rows()[:-1], self.rows()+[self.rows()[1]]]:
            with self.assertRaises(ValueError):
                probe.validate(self.encode(rows))
        rows = self.rows()
        rows[0]['pointer_bytes'] = 8
        with self.assertRaises(ValueError):
            probe.validate(self.encode(rows))


if __name__ == '__main__':
    unittest.main()
