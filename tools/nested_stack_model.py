"""Independent SUB-525 test-only ownership model. No production code imported.
Inputs are assumed decoded/validated; this is not a PE loader or x86 emulator.
"""
from dataclasses import dataclass, replace


def need(ok, message):
    if not ok:
        raise ValueError(message)


@dataclass(frozen=True)
class Word:
    tag: str
    owner: int
    value: object


@dataclass(frozen=True)
class Frame:
    owner: int
    caller: int
    boundary: int
    continuation: int
    esi: object
    chain: tuple


def acyclic(edges):
    active, done = set(), set()
    def visit(node):
        need(node not in active, 'transfer cycle')
        if node in done:
            return
        active.add(node)
        for child in edges.get(node, ()):
            visit(child)
        active.remove(node)
        done.add(node)
    for node in edges:
        visit(node)


class Model:
    def __init__(self):
        self.words = [Word('entry', 0, None)]
        self.frames = []
        self.serial = self.steps = 0
        self.esi = object()
        self.flags = None

    @property
    def owner(self):
        return self.frames[-1].owner if self.frames else 0

    def tick(self):
        need(self.steps < 1024, 'step limit')
        self.steps += 1

    def push(self, value):
        need(len(self.words) < 129, 'word limit')
        self.tick()
        self.words.append(Word('data', self.owner, value))

    def call(self, target, continuation):
        need(len(self.frames) < 32 and len(self.words) < 129, 'call limit')
        need(all(target not in f.chain for f in self.frames), 'recursive call')
        self.tick()
        caller = self.owner
        self.serial += 1
        boundary = len(self.words)
        self.words.append(Word('return', self.serial, continuation))
        self.frames.append(Frame(self.serial, caller, boundary, continuation, self.esi, (target,)))

    def frame(self, balanced=False):
        need(bool(self.frames), 'entry frame')
        f = self.frames[-1]
        need(f.boundary < len(self.words) and self.words[f.boundary] == Word('return', f.owner, f.continuation), 'protected return')
        if balanced:
            need(len(self.words) == f.boundary + 1, 'unbalanced frame')
        return f

    def scalar_slot(self, at, f):
        need(at in (f.boundary-1, f.boundary-2) and at >= 0, 'argument range')
        w = self.words[at]
        need(w.tag == 'data' and w.owner == f.caller, 'argument owner')
        need(type(w.value) is int and 0 <= w.value <= 0xffffffff, 'scalar required')
        return w

    def copy8(self):
        f = self.frame()
        extra = len(self.words)-f.boundary-1
        need(extra in (0, 1), 'copy shape')
        need(all(w.tag == 'data' and w.owner == f.owner for w in self.words[f.boundary+1:]), 'local owner')
        # ESP refers to the current last element. Resolve BEFORE appending.
        value = self.scalar_slot(len(self.words)-3, f).value
        self.push(value)

    def cleanup2(self):
        need(len(self.words) >= 3 and all(w.tag == 'data' and w.owner == self.owner for w in self.words[-2:]), 'cleanup owner')
        self.tick()
        del self.words[-2:]
        self.flags = None

    def store(self, offset, value):
        need((offset, value) in ((8, 3), (4, 12)), 'store form')
        f = self.frame(True)
        at = len(self.words)-1-offset//4
        old = self.scalar_slot(at, f)
        # Grant this narrow borrowed-write authority only for a complete
        # two-scalar argument window, not one valid slot beside protected data.
        for argument in (f.boundary-1, f.boundary-2):
            self.scalar_slot(argument, f)
        self.tick()
        # Borrowed mutation: retain caller ownership; do not clone/steal the slot.
        self.words[at] = replace(old, value=value)

    def tail(self, target):
        f = self.frame(True)
        need(self.esi == f.esi, 'ESI restoration')
        for at in (f.boundary-1, f.boundary-2):
            self.scalar_slot(at, f)
        need(all(target not in x.chain for x in self.frames), 'tail cycle')
        self.tick()
        self.frames[-1] = replace(f, chain=f.chain+(target,))

    def ret(self):
        f = self.frame(True)
        need(self.esi == f.esi, 'ESI restoration')
        self.tick()
        self.words.pop()
        self.frames.pop()
        return f.continuation

    def je(self):
        need(type(self.flags) is bool, 'unknown ZF')
        self.tick()
        return self.flags
