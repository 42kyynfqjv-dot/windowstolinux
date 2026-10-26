"""SUB-530 independent test-only scalar local frame model; no production imports.
Decoded actions only. Valid aligned stack/no-fault domain, no concrete ESP invented.
"""
from dataclasses import dataclass, replace


def need(ok, why):
    if not ok:
        raise ValueError(why)


def scalar(value):
    need(type(value) is int and 0 <= value <= 0xffffffff, 'scalar required')
    return value


@dataclass(frozen=True)
class Word:
    tag: str
    owner: int
    allocation: int = 0
    value: object = None


@dataclass(frozen=True)
class Frame:
    owner: int
    boundary: int
    esi: object
    target: int
    allocation: object = None


class Model:
    def __init__(self):
        self.words = [Word('entry', 0)]
        self.esi = ('unknown', 'entry-esi')
        self.eax = ('unknown', 'entry-eax')
        self.flags = None
        self.frames = [Frame(0, 0, self.esi, 0)]
        self.serial = self.steps = 0
        self.done = False

    @property
    def frame(self):
        return self.frames[-1]

    def tick(self):
        need(not self.done and self.steps < 1024, 'terminal/step limit')
        self.steps += 1

    def allocate8(self):
        f = self.frame
        need(f.allocation is None and len(self.words) == f.boundary+1, 'allocation shape')
        need(self.words[-1].tag in ('entry', 'return') and self.words[-1].owner == f.owner,
             'protected boundary')
        need(len(self.words)+2 <= 129, 'word limit')
        self.tick()
        self.serial += 1
        token = self.serial
        self.words.extend([Word('local', f.owner, token), Word('local', f.owner, token)])
        self.frames[-1] = replace(f, allocation=token)
        self.flags = None  # All tracked flags depend on unknown absolute ESP.

    def window(self):
        f = self.frame
        need(f.allocation is not None and len(self.words) == f.boundary+3, 'local frame shape')
        need(all(w.tag == 'local' and w.owner == f.owner and w.allocation == f.allocation
                 for w in self.words[-2:]), 'local ownership')
        return f

    def slot(self, offset):
        self.window()
        need(type(offset) is int and offset in (0, 4), 'aligned complete local word')
        return len(self.words)-1-offset//4

    def store(self, offset, value):
        at = self.slot(offset)
        scalar(value)
        self.tick()
        self.words[at] = replace(self.words[at], value=value)

    def load4(self):
        value = self.words[self.slot(4)].value
        scalar(value)  # None is uninitialized, never zero.
        self.tick()
        self.eax = value

    def add0(self):
        a, b = scalar(self.eax), scalar(self.words[self.slot(0)].value)
        self.tick()
        total = a+b
        result = total & 0xffffffff
        self.eax = result
        self.flags = (total > 0xffffffff, result == 0, bool(result & 0x80000000),
                      bool((~(a ^ b) & (a ^ result)) & 0x80000000))

    def cleanup8(self):
        f = self.window()
        self.tick()
        del self.words[-2:]
        self.frames[-1] = replace(f, allocation=None)
        self.flags = None

    def branch(self, flag):
        need(flag in (0, 1, 2, 3) and self.flags is not None, 'unknown flags')
        self.tick()
        return self.flags[flag]

    def call(self, target, continuation):
        need(len(self.frames)-1 < 32 and len(self.words) < 129, 'call/word limit')
        need(target not in [f.target for f in self.frames], 'recursive call')
        if self.frame.allocation is not None:
            self.window()
        else:
            need(len(self.words) == self.frame.boundary+1, 'call shape')
        self.tick()
        self.serial += 1
        owner = self.serial
        boundary = len(self.words)
        self.words.append(Word('return', owner, value=continuation))
        self.frames.append(Frame(owner, boundary, self.esi, target))

    def ret(self):
        f = self.frame
        need(f.allocation is None and len(self.words) == f.boundary+1, 'unbalanced return')
        need(self.esi == f.esi, 'callee-saved restoration')
        word = self.words[-1]
        need(word.owner == f.owner and word.tag == ('entry' if len(self.frames)==1 else 'return'),
             'protected return')
        value = scalar(self.eax)
        if len(self.frames) == 1:
            need(value <= 255, 'exit domain')
        self.tick()
        if len(self.frames) == 1:
            self.done = True
            return value
        self.words.pop()
        self.frames.pop()
        return word.value
