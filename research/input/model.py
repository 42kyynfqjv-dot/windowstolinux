"""Test-only interval/initialization proof for the frozen acyclic input program."""
from dataclasses import dataclass, replace
U32 = (1 << 32) - 1

@dataclass(frozen=True)
class State:
    lo: int
    hi: int
    initialized: int
    owner: object

    def __post_init__(self):
        if not (0 <= self.lo <= self.hi <= U32 and self.initialized in (0, 4, 6)):
            raise ValueError('invalid abstract state')

    def le(self, bound):
        yes = replace(self, hi=min(self.hi, bound)) if self.lo <= bound else None
        no = replace(self, lo=max(self.lo, bound + 1)) if self.hi > bound else None
        return yes, no

    def read(self, owner, offset, width):
        if owner is not self.owner or width != 4 or offset < 0 or offset + width > self.initialized:
            raise ValueError('unproved full owned read')
        # Returns a symbolic location, never a zero or a sampled character.
        return ('bytes', offset, width)


def api_states(owner):
    # Zero includes empty/missing/error, conservatively no readable bytes.
    # Success n=1/2 writes n+1 WCHARs. n=3 is impossible at capacity three.
    return (State(0, 0, 0, owner), State(1, 1, 4, owner),
            State(2, 2, 6, owner), State(4, 65, 0, owner), State(66, U32, 0, owner))


def read_join(states, owner, offset, width):
    if not states:
        raise ValueError('empty path')
    return tuple(s.read(owner, offset, width) for s in states)


def digit_branch(unit):
    if type(unit) is not int or not 0 <= unit <= 0xffff:
        raise ValueError('not a UTF16 unit')
    # LEA changes no flags; CMP AX,9 after low16 subtraction; JA = !CF && !ZF.
    ax = (unit - 48) & 0xffff
    cf, zf = ax < 9, ax == 9
    return not (not cf and not zf)


def prove(short_limit=2, second_offset_after_save=6):
    owner = object()
    outcomes = []
    for state in api_states(owner):
        zero, rest = state.le(0)  # TEST ECX,ECX / JNE, unsigned input domain
        if zero:
            outcomes.append((zero.lo, zero.hi, '200'))
        if rest is None:
            continue
        admitted, too_big = rest.le(65)
        if too_big:
            outcomes.append((too_big.lo, too_big.hi, '203'))
        if admitted is None:
            continue
        short, too_long = admitted.le(short_limit)
        if too_long:
            outcomes.append((too_long.lo, too_long.hi, '201'))
        if short is None:
            continue
        short.read(owner, 0, 4)
        # Character branches partition all low16 values into digit [48,57]
        # and its complement. Their invalid branch always exits202.
        if short.lo == short.hi == 1:
            outcomes.append((1, 1, '202 or c0-48 [0,9]'))
        elif short.lo == short.hi == 2:
            # PUSH ESI moves ESP down four bytes; [ESP+6] is local+2.
            short.read(owner, second_offset_after_save - 4, 4)
            if second_offset_after_save != 6:
                raise ValueError('wrong character location')
            outcomes.append((2, 2, '202 or 10*(c0-48)+(c1-48) [0,99]'))
        else:
            raise ValueError('unknown success length')
    # A model result is never production authority.
    return dict(outcomes=outcomes, emission_allowed=False)
