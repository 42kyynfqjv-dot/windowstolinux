"""Independent arithmetic/flag oracles; no imports from converter or generators."""
import itertools
import unittest
from dataclasses import FrozenInstanceError, replace
from model import Capability, Expr, Path, Predicate, U32, disjunction


def evaluate(expression, inputs, width=32):
    return (expression.constant + sum(a * x for a, x in
            zip(expression.coefficients, inputs))) % (1 << width)


def cpu_condition(value, immediate, width, condition):
    # Concrete subtraction's carry/zero truth table, separate from interval proof.
    result = (value - immediate) % (1 << width)
    cf, zf = value < immediate, result == 0
    return {'ne': not zf, 'be': cf or zf, 'a': not cf and not zf}[condition]


class PredicateTests(unittest.TestCase):
    def test_constant_truth_tables_and_width(self):
        for width in (16, 32):
            mask = (1 << width) - 1
            values = (0, 1, 202, 0x7fff, 0x8000, 65535, 65536, 0x80000000, U32)
            for value, k, cond in itertools.product(values, (0, 1, 202, mask), ('ne', 'be', 'a')):
                s = Path().write('eax', Expr(value)).compare('eax', k, width)
                expected = cpu_condition(value & mask, k, width, cond)
                self.assertEqual(s.branch(cond), (s,) if expected else ())
                self.assertEqual(s.branch(cond, False), () if expected else (s,))

    def test_integer_enclosures_and_entailment_against_enumeration(self):
        # Small complete domains; signed representative, wrap and correlations vary.
        for width, constant, coefficients in itertools.product(
                (16, 32), (0, 202, 65534, U32 - 2),
                ((1, 1, 0), (10, 1, 0), (U32, 2, 0), (1, U32, 0), (0, 0, 0))):
            e = Expr(constant, coefficients)
            ranges = ((0, 3), (0, 3), (0, 0))
            values = [evaluate(e, (a, b, 0), width) for a, b in itertools.product(range(4), repeat=2)]
            lo, hi = e.bounds(ranges, width)
            self.assertTrue(all(lo <= value <= hi for value in values))
            for k, cond in itertools.product((0, 1, 202, (1 << width) - 1), ('ne', 'be', 'a')):
                fact = Predicate(e, width, k).entails(ranges, cond)
                if fact is not None:
                    self.assertTrue(all(cpu_condition(v, k, width, cond) == fact for v in values))

    def test_exact_fallback_modular_partition(self):
        for width, constant in itertools.product((16, 32), (0, U32, 65534)):
            s = Path(ranges=((0, 7), (0, 0), (0, 0))).write('eax', Expr(constant, (1, 0, 0)))
            for k, cond, taken in itertools.product((0, 2, (1 << width) - 1), ('ne', 'be', 'a'), (False, True)):
                children = s.compare('eax', k, width).branch(cond, taken)
                actual = {x for p in children for x in range(p.ranges[0][0], p.ranges[0][1] + 1)}
                expected = {x for x in range(8) if cpu_condition((x + constant) % (1 << width), k, width, cond) == taken}
                self.assertEqual(actual, expected)

    def test_wrap_and_correlation_unknowns_reject(self):
        for e, ranges, k in (
                (Expr(U32, (1, 1, 0)), ((0, 1), (0, 1), (0, 0)), 0),
                (Expr(0, (2, 0, 0)), ((0, 2), (0, 0), (0, 0)), 1),
                (Expr(0, (1, U32, 0)), ((0, 9), (0, 9), (0, 0)), 0)):
            # Second case cannot equal1 concretely: interval proof still rejects.
            with self.assertRaisesRegex(ValueError, 'not proved'):
                Path(ranges=ranges).write('eax', e).compare('eax', k).branch('ne')
        wide = Path(ranges=((0, 65536), (0, 0), (0, 0))).write('eax', Expr.symbol(0))
        with self.assertRaisesRegex(ValueError, 'truncated'):
            wide.compare('eax', 0, 16).branch('ne')
        # x-x normalized algebraically is zero; unrelated symbols must not correlate.
        self.assertEqual(Expr.symbol(0).scaled_add(Expr.symbol(0), U32), Expr())

    def test_snapshots_register_permutations_and_guard_order(self):
        for r, other in itertools.permutations(('eax', 'ecx', 'edx'), 2):
            s = Path().write(r, Expr.symbol(0)).compare(r, 9)
            overwritten = s.write(other, s.scalar(r)).write(r, Expr(202))
            children = overwritten.branch('be')
            self.assertEqual(len(children), 1)
            self.assertEqual(children[0].ranges[0], (0, 9))
            self.assertEqual(children[0].scalar(r), Expr(202))
        states = []
        for order in ((0, 1), (1, 0)):
            s = Path()
            for symbol in order:
                s = s.write('edx', Expr.symbol(symbol)).arithmetic('edx', (-48) & U32)
                (s,) = s.compare('edx', 9).branch('be')
            states.append(s.ranges)
        self.assertEqual(states[0], ((48, 57), (48, 57), (0, U32)))
        self.assertEqual(states[0], states[1])
        with self.assertRaises(FrozenInstanceError):
            s.scalar('edx').constant = 0

    def test_return_path_provenance_and_volatile_effects(self):
        paths = []
        for e, ranges in ((Expr(202), ((0, 65535), (0, 65535), (1, 2))),
                          (Expr((-528) & U32, (10, 1, 0)), ((48, 57), (48, 57), (2, 2)))):
            s = Path(ranges=ranges).write('eax', e).write('ecx', Expr(7)).compare('ecx', 7)
            s = s.returned()
            self.assertEqual(s.ranges, ranges)
            for r in ('ecx', 'edx'):
                with self.assertRaises(ValueError): s.scalar(r)
            with self.assertRaisesRegex(ValueError, 'unknown flags'): s.branch('ne')
            s = s.cleanup().compare('eax', 202)
            paths.append(s)
        error, success = disjunction(tuple(paths))
        self.assertEqual(error.branch('ne'), ())
        self.assertEqual(success.branch('ne'), (success,))
        with self.assertRaises(ValueError): Path().returned()

    def test_flag_preservation_reset_and_test(self):
        s = Path().write('eax', Expr(5)).compare('eax', 5)
        s = s.write('ecx', Expr(9)).lea('eax', None, 'ecx', 2, 6)
        self.assertEqual(s.scalar('eax'), Expr(24))
        self.assertEqual(s.branch('ne'), ())  # LEA/MOV did not replace predicate.
        for unknown in (s.arithmetic('eax', 1), s.cleanup(), s.returned()):
            with self.assertRaisesRegex(ValueError, 'unknown flags'): unknown.branch('ne')
        for value, nonzero in ((0, False), (1, True), (U32, True)):
            t = Path().write('eax', Expr(value)).test_self('eax')
            self.assertEqual(bool(t.branch('a')), nonzero)
            self.assertEqual(bool(t.branch('be')), not nonzero)
        with self.assertRaises(ValueError): s.branch('jl')

    def test_capability_read_before_overwrite_and_no_coercion(self):
        cap = Capability(object(), 1)
        s = Path(allocation=cap, initialized=6, borrowed=True).write('ecx', cap)
        s = s.read_word('eax', 'ecx', 0).read_word('edx', 'ecx', 2)
        self.assertEqual(s.scalar('eax'), Expr.symbol(0))
        self.assertEqual(s.scalar('edx'), Expr.symbol(1))
        s = s.lea('ecx', 'eax', 'eax', 4).lea('eax', 'edx', 'ecx', 2)
        self.assertEqual(s.scalar('eax'), Expr(0, (10, 1, 0)))
        with self.assertRaises(ValueError): s.read_word('eax', 'ecx', 0)
        for value in (cap, None):
            p = Path().write('eax', value)
            with self.assertRaises(ValueError): p.compare('eax', 202)
            with self.assertRaises(ValueError): p.lea('eax', None, 'eax', 2, 6)
        # Source=destination captures the capability before zero extension overwrites it.
        p = Path(allocation=cap, initialized=4, borrowed=True).write('edx', cap)
        self.assertEqual(p.read_word('edx', 'edx', 2).scalar('edx'), Expr.symbol(1))

    def test_ownership_initialization_joins_and_lifetime(self):
        cap = Capability(object(), 1)
        good = Path(allocation=cap, initialized=4, borrowed=True).write('ecx', cap)
        for bad in (replace(good, initialized=3), replace(good, live=False),
                    replace(good, borrowed=False), good.cleanup(locals=True),
                    good.write('ecx', Capability(cap.owner, 2)),
                    good.write('ecx', Capability(object(), 1))):
            with self.assertRaises(ValueError): bad.read_word('eax', 'ecx', 2)
        for offset in (-2, 1, 4, U32, True):
            with self.assertRaises(ValueError): good.read_word('eax', 'ecx', offset)
        joined = disjunction((good, replace(good, initialized=0)))
        self.assertEqual([p.initialized for p in joined], [4, 0])
        with self.assertRaises(ValueError): joined[1].read_word('eax', 'ecx', 0)
        self.assertEqual(good.cleanup().initialized, 4)

    def test_composed_all_domain_symbolic_trace(self):
        # Manual instruction-contract trace, NOT a PE interpreter or translation.
        returns = []
        cap = Capability(object(), 1)
        for length in (1, 2):
            s = Path(ranges=((0, 65535), (0, 0) if length == 1 else (0, 65535),
                             (length, length)), allocation=cap,
                     initialized=2 * (length + 1), borrowed=True).write('ecx', cap)
            s = s.read_word('eax', 'ecx', 0).arithmetic('eax', (-48) & U32).compare('eax', 9)
            returns.extend(p.write('eax', Expr(202)) for p in s.branch('a'))
            for p in s.branch('a', False):
                if length == 1:
                    returns.append(p)
                else:
                    p = p.read_word('edx', 'ecx', 2).arithmetic('edx', (-48) & U32).compare('edx', 9)
                    returns.extend(q.write('eax', Expr(202)) for q in p.branch('a'))
                    returns.extend(q.lea('ecx', 'eax', 'eax', 4).lea('eax', 'edx', 'ecx', 2)
                                   for q in p.branch('a', False))
        outputs = []
        for p in returns:
            p = p.returned().cleanup().compare('eax', 202)
            outputs.extend(p.branch('ne', False))
            outputs.extend(q.lea('eax', None, 'eax', 2, 6) for q in p.branch('ne'))
        self.assertEqual(len(outputs), 8)  # modular invalid-digit ranges split in two
        for p in outputs:
            lo, hi = p.scalar('eax').bounds(p.ranges)
            self.assertTrue(0 <= lo <= hi <= 255)
        # Literal C-level expectations, not generated from model transfer functions.
        for first, second, length, expected in ((48, 0, 1, 6), (55, 0, 1, 20),
                (52, 50, 2, 90), (48, 55, 2, 20), (57, 57, 2, 204),
                (97, 0, 1, 202), (48, 47, 2, 202), (0xffff, 0xffff, 2, 202)):
            inputs = (first, second, length)
            matching = [p for p in outputs if all(lo <= v <= hi for v, (lo, hi) in zip(inputs, p.ranges))]
            self.assertEqual(len(matching), 1)
            self.assertEqual(evaluate(matching[0].scalar('eax'), inputs), expected)

    def test_malformed_values_and_resource_boundaries(self):
        for value in (-1, U32 + 1, 1.5, True):
            with self.assertRaises(ValueError): Expr(value)
        with self.assertRaises(ValueError): Expr(0, [1, 0, 0])
        with self.assertRaises(ValueError): Path(ranges=((1, 0), (0, 0), (0, 0)))
        with self.assertRaises(ValueError): Path(registers=[None] * 3)
        for width in (8, 64):
            with self.assertRaises(ValueError): Predicate(Expr(), width, 0)
        with self.assertRaises(ValueError): Predicate(Expr(), 16, 65536)
        self.assertEqual(len(disjunction((Path(),) * 4096)), 4096)
        for paths in ((), (Path(),) * 4097):
            with self.assertRaises(ValueError): disjunction(paths)


if __name__ == '__main__':
    unittest.main()
