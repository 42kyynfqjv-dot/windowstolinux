"""SUB-561 independent test-only predicate model. No PE or emission authority.

The caller supplies a graph/stack/return-validated path. This module models its
scalar predicates and existing read-only borrow facts, not the call-stack proof.
"""
from dataclasses import dataclass, replace

U32 = (1 << 32) - 1
REGS = ('eax', 'ecx', 'edx')


def uint(value, maximum=U32):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('unsigned integer width')


def checked_ranges(ranges):
    if type(ranges) is not tuple or len(ranges) != 3:
        raise ValueError('immutable three-symbol ranges')
    for pair in ranges:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError('immutable range')
        lo, hi = pair
        uint(lo); uint(hi)
        if lo > hi:
            raise ValueError('empty range')


@dataclass(frozen=True)
class Expr:
    constant: int = 0
    coefficients: tuple = (0, 0, 0)

    def __post_init__(self):
        uint(self.constant)
        if type(self.coefficients) is not tuple or len(self.coefficients) != 3:
            raise ValueError('immutable affine expression')
        for coefficient in self.coefficients:
            uint(coefficient)

    @staticmethod
    def symbol(index):
        uint(index, 2)
        return Expr(0, tuple(int(i == index) for i in range(3)))

    def scaled_add(self, other, scale=1, displacement=0):
        if not isinstance(other, Expr):
            raise ValueError('scalar operands required')
        uint(scale); uint(displacement)
        return Expr((self.constant + other.constant * scale + displacement) & U32,
                    tuple((a + b * scale) & U32 for a, b in
                          zip(self.coefficients, other.coefficients)))

    def bounds(self, ranges, width=32):
        checked_ranges(ranges)
        if width not in (16, 32):
            raise ValueError('unsupported comparison width')
        # Integer enclosure of a congruent representative; NOT endpoint sampling.
        signed = lambda x: x if x < (1 << 31) else x - (1 << 32)
        lo = hi = signed(self.constant)
        for coefficient, (a, b) in zip(self.coefficients, ranges):
            k = signed(coefficient)
            lo += min(k * a, k * b)
            hi += max(k * a, k * b)
        modulus = 1 << width
        if lo // modulus != hi // modulus:
            return 0, modulus - 1
        return lo % modulus, hi % modulus


@dataclass(frozen=True)
class Capability:
    owner: object
    generation: int


@dataclass(frozen=True)
class Predicate:
    expression: Expr
    width: int
    immediate: int

    def __post_init__(self):
        if not isinstance(self.expression, Expr) or self.width not in (16, 32):
            raise ValueError('unknown/unsupported predicate')
        uint(self.immediate, (1 << self.width) - 1)

    def entails(self, ranges, condition):
        lo, hi = self.expression.bounds(ranges, self.width)
        k = self.immediate
        if condition == 'ne':
            return True if k < lo or k > hi else False if lo == hi == k else None
        if condition in ('be', 'a'):
            le = True if hi <= k else False if lo > k else None
            return le if condition == 'be' or le is None else not le
        raise ValueError('unsupported flag consumer')


@dataclass(frozen=True)
class Path:
    ranges: tuple = ((0, 65535), (0, 65535), (0, U32))
    registers: tuple = (None, None, None)
    predicate: object = None
    allocation: object = None
    initialized: int = 0
    live: bool = True
    borrowed: bool = False

    def __post_init__(self):
        checked_ranges(self.ranges)
        if type(self.registers) is not tuple or len(self.registers) != 3:
            raise ValueError('immutable register snapshots')
        uint(self.initialized, 8)

    def value(self, register):
        return self.registers[REGS.index(register)]

    def scalar(self, register):
        value = self.value(register)
        if not isinstance(value, Expr):
            raise ValueError('unknown, partial, nonlinear or pointer scalar')
        return value

    def write(self, register, value):
        if value is not None and not isinstance(value, (Expr, Capability)):
            raise ValueError('unsupported value')
        values = list(self.registers)
        values[REGS.index(register)] = value
        return replace(self, registers=tuple(values))

    def compare(self, register, immediate, width=32):
        return replace(self, predicate=Predicate(self.scalar(register), width, immediate))

    def test_self(self, register):
        # TEST r,r and CMP r,0 agree ONLY for this subset's CF/ZF consumers.
        return self.compare(register, 0)

    def lea(self, destination, base, index, scale, displacement=0):
        if scale not in (1, 2, 4, 8):
            raise ValueError('SIB scale')
        left = Expr() if base is None else self.scalar(base)
        right = self.scalar(index)  # capture before overwriting either operand
        return self.write(destination, left.scaled_add(right, scale, displacement))

    def arithmetic(self, register, displacement):
        return replace(self.write(register, self.scalar(register).scaled_add(
            Expr(), 0, displacement)), predicate=None)

    def read_word(self, destination, source, offset):
        cap = self.value(source)
        if (not isinstance(cap, Capability) or cap != self.allocation or
                not self.live or not self.borrowed or type(offset) is not int or
                offset not in (0, 2) or offset + 2 > self.initialized):
            raise ValueError('live borrowed complete initialized WORD required')
        return self.write(destination, Expr.symbol(offset // 2))

    def returned(self):
        # PRECONDITION: complete protected return/stack/ESI proof already passed.
        result = self.scalar('eax')
        return replace(self, registers=(result, None, None), predicate=None, borrowed=False)

    def cleanup(self, locals=False):
        # PRECONDITION: explicit argument/local tag proof already passed.
        return replace(self, predicate=None, live=self.live and not locals,
                       initialized=0 if locals else self.initialized)

    def branch(self, condition, taken=True):
        if not isinstance(self.predicate, Predicate) or type(taken) is not bool:
            raise ValueError('unknown flags')
        proven = self.predicate.entails(self.ranges, condition)
        if proven is not None:
            return (self,) if proven == taken else ()

        # Exact single-symbol preimage fallback; never invent multivariate facts.
        e, width, k = (self.predicate.expression, self.predicate.width,
                       self.predicate.immediate)
        m = 1 << width
        a = tuple(coefficient % m for coefficient in e.coefficients)
        if sum(coefficient != 0 for coefficient in a) != 1 or 1 not in a:
            raise ValueError('predicate not proved or invertible')
        index = a.index(1)
        if self.ranges[index][1] >= m:
            raise ValueError('truncated symbol not refinable')
        if condition == 'ne':
            desired = ((0, k - 1), (k + 1, m - 1)) if taken else ((k, k),)
        else:
            desired = ((0, k),) if (condition == 'be') == taken else ((k + 1, m - 1),)
        out = []
        for lo, hi in desired:
            if lo > hi:
                continue
            start, stop = (lo - e.constant) % m, (hi - e.constant) % m
            spans = ((start, stop),) if start <= stop else ((0, stop), (start, m - 1))
            for lo, hi in spans:
                lo, hi = max(lo, self.ranges[index][0]), min(hi, self.ranges[index][1])
                if lo <= hi:
                    ranges = list(self.ranges)
                    ranges[index] = (lo, hi)
                    out.append(replace(self, ranges=tuple(ranges)))
        return tuple(out)


def disjunction(paths):
    # No range hull, register replacement or initialized-byte union at a join.
    if type(paths) is not tuple or not paths or len(paths) > 4096:
        raise ValueError('path budget/empty join')
    if any(not isinstance(path, Path) for path in paths):
        raise ValueError('path required')
    return paths
