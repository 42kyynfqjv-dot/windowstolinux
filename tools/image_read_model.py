"""SUB-534 independent design experiment, not a PE parser or emission capability.

Inputs are section snapshots/metadata after checked PE intake. This model additionally
checks mapping aliases, binds every HIGHLOW field, and proves the entire code body
belongs to a deliberately call/branch/store-free language. No production imports.
"""
from dataclasses import dataclass
import hashlib

class Rejected(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Rejected(why)

def span(start, size):
    need(0 <= start < 2**32 and 0 < size and start + size < 2**32, 'range overflow/empty')
    return start, start + size

def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]

@dataclass(frozen=True)
class Section:
    rva: int
    virtual: int
    raw: int
    data: bytes
    role: str

@dataclass(frozen=True)
class Relocation:
    site: int
    kind: int = 3

class Image:
    def __init__(self, base, extent, entry, sections, relocations, metadata=(), directories=(5, 6)):
        self.sections = tuple(Section(s.rva, s.virtual, s.raw, bytes(s.data), s.role) for s in sections)
        self.relocations = tuple(relocations)
        self.metadata = tuple(span(a, n) for a, n in metadata)
        self.base, self.extent, self.entry = base, extent, entry
        need(base > 0 and base % 65536 == 0 and 0 < extent <= 1024*1024, 'base/image limit')
        span(base, extent)
        need(set(directories) <= {5, 6}, 'startup/external directory')
        need(1 <= len(self.sections) <= 8, 'section count')
        need(0 < len(self.relocations) <= 128, 'relocation count')
        virtual, raw = [], []
        for s in self.sections:
            need(s.role in ('code', 'immutable', 'writable', 'metadata'), 'section role/zero-fill')
            need(0 < s.virtual <= len(s.data), 'uninitialized virtual tail')
            v, f = span(s.rva, max(s.virtual, len(s.data))), span(s.raw, len(s.data))
            need(v[1] <= extent and s.rva >= 4096 and s.raw >= 512, 'section bounds')
            need(all(not overlaps(v, x) for x in virtual), 'virtual alias')
            need(all(not overlaps(f, x) for x in raw), 'file alias')
            virtual.append(v); raw.append(f)
        code = [s for s in self.sections if s.role == 'code']
        need(len(code) == 1 and entry == code[0].rva, 'single code/start entry')
        self.code = code[0]
        need(sum(s.role == 'writable' for s in self.sections) == 1, 'one initialized data section')
        for i, m in enumerate(self.metadata):
            self.locate(m[0], m[1]-m[0])
            need(all(not overlaps(m, n) for n in self.metadata[:i]), 'metadata alias')
        self.outside(self.code.rva, self.code.virtual)
        # Identity includes mappings as well as copied bytes, for audit only. Binding
        # never accepts a public digest or a candidate from a different Image.
        self.identity = hashlib.sha256(repr((base, extent, entry, self.sections,
                                             self.relocations, self.metadata)).encode()).hexdigest()

    def locate(self, rva, width):
        a, b = span(rva, width)
        matches = [s for s in self.sections if s.rva <= a and b <= s.rva + min(s.virtual, len(s.data))]
        need(len(matches) == 1, 'complete initialized range')
        s = matches[0]
        return s, s.data[a-s.rva:b-s.rva]

    def outside(self, rva, width):
        region = span(rva, width)
        need(all(not overlaps(region, m) for m in self.metadata), 'metadata overlap')

    def prove(self):
        """Returns model observations only. No executable eligibility token escapes."""
        sites = set()
        for r in self.relocations:
            need(r.kind == 3, 'unsupported relocation')
            s, _ = self.locate(r.site, 4)
            need(s.role == 'code', 'loader write outside code')
            self.outside(r.site, 4)
            need(all(not overlaps(span(r.site, 4), span(x, 4)) for x in sites), 'relocation alias')
            sites.add(r.site)
        code = self.code.data[:self.code.virtual]
        pc, used, reads, instructions = 0, set(), [], []
        while pc < len(code):
            need(len(instructions) < 1024, 'instruction cap')
            tail = code[pc:]
            if tail.startswith(b'\x8b\x0d') or tail.startswith(b'\xa1'):
                offset, reg = (2, 'ecx') if tail.startswith(b'\x8b\x0d') else (1, 'eax')
                length = offset + 4
                need(len(tail) >= length, 'truncated address')
                site = self.code.rva + pc + offset
                need(site in sites, 'missing exact HIGHLOW field')
                va = int.from_bytes(tail[offset:length], 'little')
                need(va >= self.base, 'VA below preferred base')
                target = va - self.base
                s, data = self.locate(target, 4)
                need(s.role == 'writable', 'read requires initialized data role')
                self.outside(target, 4)
                # No pointer tag: loaded data is scalar, and this language has no
                # operation that uses a register value as an address.
                value = int.from_bytes(data, 'little')
                instructions.append(('read', reg, value)); reads.append((site, target, value)); used.add(site)
            elif tail[:2] in (b'\x03\xc8', b'\x03\xc1'):
                length = 2
                instructions.append(('add', 'ecx' if tail[1] == 0xc8 else 'eax'))
            elif tail[0] == 0xc3:
                need(pc + 1 == len(code), 'code after terminal return')
                instructions.append(('ret',)); length = 1
            else:
                raise Rejected(f'unsupported effect/form at +{pc:#x}')
            pc += length
        need(instructions and instructions[-1] == ('ret',), 'missing terminal return')
        need(used == sites, 'unbound loader write')
        reg = {'eax': None, 'ecx': None}; flags = (None,)*4; trace = []
        for instruction in instructions:
            if instruction[0] == 'read':
                _, dest, value = instruction; reg[dest] = value
            elif instruction[0] == 'add':
                dest = instruction[1]; source = 'eax' if dest == 'ecx' else 'ecx'
                a, b = reg[dest], reg[source]
                need(a is not None and b is not None, 'unknown scalar')
                result = (a+b) & 0xffffffff
                flags = (a+b > 0xffffffff, result == 0, bool(result & 0x80000000),
                         bool((~(a ^ b) & (a ^ result)) & 0x80000000))
                reg[dest] = result
            else:
                need(reg['eax'] is not None and 0 <= reg['eax'] <= 255, 'exit domain')
            trace.append((reg['eax'], reg['ecx'], flags))
        return {'model_exit': reg['eax'], 'reads': reads, 'trace': trace,
                'emission_allowed': False, 'identity': self.identity}
