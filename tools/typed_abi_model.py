"""SUB-517 test-only contract model; no PE decoder, converter or code emission.

Independently authored from PE/x86/MSVC contracts; MIT OR Apache-2.0.
Caller-supplied decoded fields are assumptions, not production provenance proof.
"""
from dataclasses import dataclass


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


@dataclass(frozen=True)
class Integer:
    value: int

    def __post_init__(self):
        require(0 <= self.value <= 0xffffffff, 'u32 scalar')


@dataclass(frozen=True)
class Unknown:
    # Identity, not a wildcard: two unknown origins cannot prove equal values.
    origin: object


@dataclass(frozen=True)
class Pointer:
    image: object
    rva: int


@dataclass(frozen=True)
class ImportSlot:
    image: object
    rva: int


@dataclass(frozen=True)
class Field:
    instruction: int
    length: int
    site: int
    form: str


class Image:
    def __init__(self, base=0x400000, data=b'Hello', start=0x2008, iat=0x2000):
        self.identity = object()
        self.base, self.data, self.start, self.iat = base, bytes(data), start, iat
        require(0 < base <= 0xffffffff and 0 <= start < 0xffffffff,
                'image address')
        require(base + start + len(data) <= 0xffffffff and base + iat + 4 <= 0xffffffff,
                'image overflow')
        require(iat + 4 <= start or start + len(data) <= iat, 'metadata overlap')
        self.issued = {}

    def bind(self, records, fields):
        """Exact join of annotated reachable fields to structurally valid HIGHLOWs.

        A future decoder must supply ALL reachable fields across both successors.
        This model cannot establish reachability or validate PE metadata itself.
        """
        require(len(records) == len(fields), 'relocation coverage')
        require(len({site for site, _ in records}) == len(records), 'duplicate record')
        mapping = dict(records)
        used, spans, result = set(), [], {}
        for f in fields:
            expected = {'push32': (5, 1), 'import-call': (6, 2)}.get(f.form)
            require(expected is not None and (f.length, f.site - f.instruction) == expected,
                    'exact operand field')
            require(0 <= f.instruction and f.instruction + f.length <= 0xffffffff,
                    'instruction bounds')
            span = (f.instruction, f.instruction + f.length)
            require(all(span[1] <= a or b <= span[0] for a, b in spans), 'instruction overlap')
            spans.append(span)
            require(f.site in mapping and f.site not in used, 'field/record mismatch')
            used.add(f.site)
            raw = mapping[f.site]
            require(self.base <= raw <= 0xffffffff, 'preferred VA')
            rva = raw - self.base
            if f.form == 'push32':
                require(self.start <= rva < self.start + len(self.data), 'immutable pointer')
                value = Pointer(self.identity, rva)
            else:
                require(rva == self.iat, 'exact import slot')
                value = ImportSlot(self.identity, rva)
            result[f.site] = value
        # Publish capabilities only after the complete join succeeds.
        self.issued.update((id(v), v) for v in result.values())
        return result

    def validate(self, value):
        require(isinstance(value, (Pointer, ImportSlot)) and value.image is self.identity
                and self.issued.get(id(value)) is value, 'unissued or foreign pointer')

    def buffer(self, value, count):
        self.validate(value)
        require(isinstance(value, Pointer) and isinstance(count, Integer), 'buffer types')
        n = count.value
        require(1 <= n <= 64 and self.start <= value.rva
                and value.rva + n <= self.start + len(self.data), 'complete buffer bounds')
        result = self.data[value.rva - self.start:value.rva - self.start + n]
        require(all(0x20 <= b <= 0x7e for b in result), 'permitted output bytes')
        return result


@dataclass(frozen=True)
class Word:
    kind: str
    owner: int
    value: object = None


@dataclass(frozen=True)
class Frame:
    owner: int
    incoming_esi: object
    continuation: object


class Machine:
    def __init__(self, image):
        self.image = image
        self.eax = Unknown(object())
        self.esi = Unknown(object())
        self.flags = None
        self.words = [Word('entry', 0)]
        self.frames = [Frame(0, self.esi, None)]
        self.serial = 0
        self.halted = False

    @property
    def owner(self):
        return self.frames[-1].owner

    def active(self):
        require(not self.halted, 'terminal state')

    def value(self, value):
        require(isinstance(value, (Integer, Unknown, Pointer)), 'data value type')
        if isinstance(value, Pointer):
            self.image.validate(value)

    def append(self, kind, value):
        self.active()
        require(len(self.words) < 129, '128-word resource limit')
        self.words.append(Word(kind, self.owner, value))

    def push(self, value):
        self.value(value)
        self.append('data', value)

    def save_esi(self):
        self.value(self.esi)
        self.append('saved-esi', self.esi)

    def restore_esi(self):
        self.active()
        top = self.words[-1]
        require(top.kind == 'saved-esi' and top.owner == self.owner, 'owned ESI save required')
        self.esi = top.value
        self.words.pop()

    def move_eax_to_esi(self):
        self.active()
        self.value(self.eax)
        self.esi = self.eax

    def call(self, continuation):
        self.active()
        self.value(self.esi)
        require(len(self.frames) <= 32, '32-call depth limit')
        require(len(self.words) < 129, '128-word resource limit')
        self.serial += 1
        self.words.append(Word('return', self.serial, continuation))
        self.frames.append(Frame(self.serial, self.esi, continuation))

    def argument(self, ordinal):
        self.active()
        require(ordinal in (1, 2) and len(self.frames) > 1, 'two-argument helper only')
        require(self.words[-1].kind == 'return' and self.words[-1].owner == self.owner,
                'argument access requires unmodified callee ESP')
        require(len(self.words) > ordinal, 'argument bounds')
        word = self.words[-1 - ordinal]
        require(word.kind == 'data' and word.owner == self.frames[-2].owner,
                'caller-owned argument required')
        return word.value

    def add_eax(self, value):
        self.active()
        require(isinstance(self.eax, Integer) and isinstance(value, Integer), 'scalar arithmetic only')
        self.eax = Integer((self.eax.value + value.value) & 0xffffffff)
        # Flags deliberately not modeled here. Production must compute all tracked flags.
        self.flags = None

    def cleanup_add(self, words):
        self.active()
        require(1 <= words <= 5 and len(self.words) > words, 'cleanup bound')
        require(all(w.kind == 'data' and w.owner == self.owner for w in self.words[-words:]),
                'cleanup cannot consume save/return/foreign words')
        del self.words[-words:]
        # ADD ESP computes flags from unknown absolute ESP, unlike LEA cleanup.
        self.flags = None

    def require_flags(self):
        self.active()
        require(self.flags is not None, 'unknown flags must be overwritten before branch')
        return self.flags

    def write(self, slot):
        self.active()
        self.image.validate(slot)
        require(isinstance(slot, ImportSlot) and slot.rva == self.image.iat, 'import call type')
        require(len(self.words) >= 4, 'three arguments required')
        args = self.words[-3:]
        require(all(w.kind == 'data' and w.owner == self.owner for w in args), 'owned output arguments')
        count, pointer, fd = [w.value for w in args]
        require(fd == Integer(1), 'stdout only')
        output = self.image.buffer(pointer, count)
        # Include the transient x86 CALL return word in resource accounting.
        require(len(self.words) < 129 and len(self.frames) <= 32, 'external call resource limit')
        self.eax = Integer(len(output))  # Successful regular-file write domain only.
        self.flags = None
        return output

    def ret(self):
        self.active()
        require(self.esi == self.frames[-1].incoming_esi, 'callee-saved ESI not restored')
        require(isinstance(self.eax, Integer), 'scalar return only')
        top = self.words[-1]
        if len(self.frames) == 1:
            require(len(self.words) == 1 and top.kind == 'entry', 'balanced entry return')
            require(self.eax.value <= 255, 'portable process exit range')
            self.halted = True
            return None
        require(top == Word('return', self.owner, self.frames[-1].continuation), 'protected return required')
        self.words.pop()
        self.frames.pop()
        return top.value

    def join_key(self):
        # Exact equality only. Incoming unknown identity and return continuation matter.
        return (self.image.identity, self.eax, self.esi, self.flags, tuple(self.words),
                tuple(self.frames), self.serial, self.halted)

    def join(self, other):
        require(self.join_key() == other.join_key(), 'unequal typed/context join')
        return self
