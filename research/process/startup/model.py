"""Independent proof-state prototype. Not a Windows dispatcher or admission API."""
from dataclasses import dataclass


class Rejected(Exception):
    pass


def word(n):
    if type(n) is not int or not 0 <= n < 2**32:
        raise Rejected('uint32 required')
    return n


@dataclass(frozen=True)
class Pointer:
    process: object
    owner: object
    generation: int
    address: int


@dataclass(frozen=True)
class Encoded:
    pointer: Pointer
    cookie_version: int
    bits: int


class Records:
    def __init__(self):
        self.process = object()
        self.owners = {}
        self.cells = {}
        self.threads = {}
        self.cookie = None
        self.version = 0
        self.pending = set()

    def runnable(self):
        if self.pending:
            raise Rejected("unresolved process effects")

    def owner(self, base, size):
        self.runnable()
        word(base)
        if len(self.owners) >= 64:
            raise Rejected("owner budget")
        if type(size) is not int or size <= 0 or base+size > 2**32:
            raise Rejected('range')
        if any(base < b+n and b < base+size for b, n, _ in self.owners.values()):
            raise Rejected('overlap')
        key = object()
        self.owners[key] = (base, size, 1)
        return Pointer(self.process, key, 1, base)

    def check(self, p, size=4):
        self.runnable()
        if not isinstance(p, Pointer) or p.process is not self.process:
            raise Rejected('process identity')
        state = self.owners.get(p.owner)
        if state is None or state[2] != p.generation:
            raise Rejected('stale owner')
        base, length, _ = state
        if type(size) is not int or size <= 0 or not base <= p.address <= base+length-size:
            raise Rejected('complete range')

    def offset(self, p, n):
        if type(n) is not int:
            raise Rejected('offset')
        q = Pointer(p.process, p.owner, p.generation, word(p.address+n))
        self.check(q)
        return q

    def initialize_cookie(self, bits):
        word(bits)
        if any(chain for chain in self.threads.values()) or self.pending:
            raise Rejected('cookie change during protected frame')
        self.cookie = bits
        self.version += 1

    def encode(self, p):
        self.check(p)
        if self.cookie is None:
            raise Rejected('cookie uninitialized')
        return Encoded(p, self.version, p.address ^ self.cookie)

    def decode(self, e):
        if not isinstance(e, Encoded) or e.cookie_version != self.version or self.cookie is None:
            raise Rejected('encoding provenance')
        self.check(e.pointer)
        if e.bits ^ self.cookie != e.pointer.address:
            raise Rejected('encoding relation')
        return e.pointer

    def invalidate(self, at, size):
        self.check(at, size)
        # Any byte overwrite removes the complete typed-word fact, including an
        # overwrite with identical bytes. Numeric bytes alone cannot recreate it.
        for thread, chain in self.threads.items():
            if any(at.address < r.address+16 and r.address < at.address+size for r, _ in chain):
                self.pending.add(thread)
        for address in list(self.cells):
            if at.address < address+4 and address < at.address+size:
                del self.cells[address]

    def store(self, at, value):
        self.check(at)
        if isinstance(value, Pointer):
            self.check(value)
        elif isinstance(value, Encoded):
            self.decode(value)
        else:
            word(value)
        self.invalidate(at, 4)
        self.cells[at.address] = (at, value)

    def load(self, at):
        self.check(at)
        cell = self.cells.get(at.address)
        if cell is None or cell[0] != at:
            raise Rejected('uninitialized or invalidated field')
        value = cell[1]
        if isinstance(value, Pointer):
            self.check(value)
        if isinstance(value, Encoded):
            self.decode(value)
        return value

    def thread(self):
        self.runnable()
        if len(self.threads) >= 32:
            raise Rejected("thread budget")
        identity = object()
        # Empty means caller-established empty initial chain in this model only.
        self.threads[identity] = []
        return identity

    def register(self, thread, record, encoded_scope):
        if thread not in self.threads or thread in self.pending:
            raise Rejected('thread state')
        self.check(record, 16)
        self.decode(encoded_scope)
        if len(self.threads[thread]) >= 64:
            raise Rejected("registration budget")
        if any(any(record.address < p.address+16 and p.address < record.address+16 for p, _ in chain) for chain in self.threads.values()):
            raise Rejected('already registered')
        self.threads[thread].append((record, encoded_scope))

    def restore(self, thread, record):
        if thread in self.pending or thread not in self.threads:
            raise Rejected('unresolved exceptional effects')
        chain = self.threads[thread]
        if not chain or chain[-1][0] != record:
            raise Rejected('LIFO restoration')
        self.check(record, 16)
        self.decode(chain[-1][1])
        chain.pop()

    def external_unknown(self, thread):
        if thread not in self.threads:
            raise Rejected('thread identity')
        self.pending.update(self.threads)
        self.cookie = None
        self.version += 1
        self.cells.clear()

    def exception(self, thread, code):
        word(code)
        if thread not in self.threads:
            raise Rejected('thread identity')
        self.pending.add(thread)
        return ('dispatch-required', code)  # No guessed continuation/unwind.

    def retire(self, p):
        self.check(p)
        if any(any(r.owner is p.owner for r, _ in chain) for chain in self.threads.values()):
            raise Rejected('active registration lifetime')
        del self.owners[p.owner]
