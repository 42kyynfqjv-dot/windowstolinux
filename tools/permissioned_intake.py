"""SUB-528 test-only range/permission model. Never emits or authorizes execution.

Independent Python specification experiment, not imported by the converter.
Primary format provenance and deliberately narrower policy: SUB528-PE32-DESIGN.md.
"""
from dataclasses import dataclass
import hashlib
import struct


class Rejected(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Rejected(reason)


def end32(start, size):
    need(0 <= start <= 0xffffffff and 0 < size <= 0xffffffff, 'range: empty/negative')
    need(start + size <= 0xffffffff, 'range: overflow')
    return start + size


def overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def rounded(n):
    return end32(n, 4095) & ~4095


@dataclass(frozen=True)
class Section:
    index: int
    rva: int
    virtual: int
    raw: int
    size: int
    role: str


class Image:
    def __init__(self, blob):
        self.blob = bytes(blob)  # Snapshot: later caller mutation cannot change provenance.
        self.identity = hashlib.sha256(self.blob).hexdigest()
        self.sections = []
        self.metadata = []
        self.pointers = []
        self.blockers = []
        self.metadata_closed = False
        self.envelope()
        self.directory_policy()

    def file(self, start, size):
        finish = end32(start, size)
        need(finish <= len(self.blob), 'range: truncated file')
        return self.blob[start:finish]

    def number(self, at, fmt='I'):
        return struct.unpack('<' + fmt, self.file(at, struct.calcsize('<' + fmt)))[0]

    def envelope(self):
        need(len(self.blob) <= 4 * 1024 * 1024, 'limit: file')
        need(self.file(0, 2) == b'MZ', 'header: DOS')
        pe = self.number(60)
        need(pe >= 64 and pe % 8 == 0, 'policy: PE offset')
        need(self.file(pe, 4) == b'PE\0\0', 'header: PE')
        self.file(pe, 24)
        need(self.number(pe + 4, 'H') == 0x14c, 'architecture: x86 PE32 required')
        count = self.number(pe + 6, 'H')
        need(1 <= count <= 8, 'limit: section count')
        need(self.number(pe + 12) == self.number(pe + 16) == 0, 'policy: COFF symbols')
        optional = self.number(pe + 20, 'H')
        self.coff = self.number(pe + 22, 'H')
        need(self.coff & 2 and not self.coff & ~0x30f, 'policy: COFF execution flags')
        o = pe + 24
        self.file(o, optional)
        need(optional >= 96, 'header: short optional header')
        need(self.number(o, 'H') == 0x10b, 'architecture: x86 PE32 required')
        directories = self.number(o + 92)
        need(directories <= 16 and 96 + 8 * directories <= optional, 'header: directory count')
        extra = optional - 96 - 8 * directories
        need(not extra or not any(self.file(o + 96 + 8 * directories, extra)), 'policy: optional extension')
        need(self.number(o + 32) == 4096 and self.number(o + 36) == 512, 'policy: alignment')
        need(self.number(o + 52) == self.number(o + 88) == 0, 'policy: loader fields')
        need(self.number(o + 68, 'H') == 3, 'policy: console subsystem')
        self.dll = self.number(o + 70, 'H')
        need(not self.dll & ~0x8540, 'policy: DLL flags')
        for at in (72, 80):
            need(0 < self.number(o + at + 4) <= self.number(o + at), 'policy: stack/heap')
        self.base = self.number(o + 28)
        self.extent = self.number(o + 56)
        headers = self.number(o + 60)
        need(self.base > 0 and self.base % 65536 == 0, 'policy: image base')
        need(0 < self.extent <= 1024 * 1024 and self.extent % 4096 == 0, 'limit: image')
        end32(self.base, self.extent)
        need(headers >= o + optional + count * 40 and headers % 512 == 0, 'header: extent')
        self.file(0, headers)
        raw_spans = [(0, headers)]
        next_rva = rounded(headers)
        # Roles describe permissions/content, never section names or ordinal positions.
        roles = {0x60000020: 'code', 0x40000040: 'immutable',
                 0xc0000040: 'writable', 0xc0000080: 'writable-zero',
                 0x42000040: 'discardable-metadata'}
        for i in range(count):
            at = o + optional + i * 40
            self.file(at, 40)
            virtual, rva, size, raw = (self.number(at + n) for n in (8, 12, 16, 20))
            flags = self.number(at + 36)
            need(flags in roles, 'policy: section permissions/content')
            role = roles[flags]
            need(not any(self.file(at + 24, 12)), 'policy: section COFF records')
            need(virtual > 0 and rva == next_rva, 'mapping: virtual extent/order')
            need(size % 512 == 0, 'mapping: raw alignment')
            if size:
                need(raw % 512 == 0, 'mapping: raw alignment')
                finish = end32(raw, size)
                self.file(raw, size)
                need(all(not overlap((raw, finish), span) for span in raw_spans), 'mapping: raw alias')
                raw_spans.append((raw, finish))
                need(role != 'writable-zero', 'policy: initialized BSS')
            else:
                need(raw == 0 and role == 'writable-zero', 'policy: empty raw section')
            need(virtual <= size or role.startswith('writable'), 'policy: nonwritable zero-fill')
            # Reserve raw padding as well as virtual data; neither padding is readable.
            next_rva = rounded(end32(rva, max(virtual, size)))
            need(next_rva <= self.extent, 'mapping: image bounds')
            self.sections.append(Section(i, rva, virtual, raw, size, role))
        need(next_rva == self.extent, 'mapping: image extent')
        self.raw_spans = raw_spans
        need(sum(s.role == 'code' for s in self.sections) == 1, 'policy: one code region')
        self.entry = self.number(o + 16)
        section, _ = self.locate(self.entry, 1)
        need(section.role == 'code', 'entry: executable file-backed byte required')
        self.dirs = {}
        for i in range(directories):
            address, length = self.number(o + 96 + i * 8), self.number(o + 100 + i * 8)
            if address == length == 0:
                continue
            need(address != 0 and length != 0, 'directory: incomplete pair')
            if i == 4:  # Security directory uses a FILE offset, never an RVA.
                finish = end32(address, length)
                self.file(address, length)
                need(address % 8 == 0 and all(not overlap((address, finish), x) for x in raw_spans),
                     'directory: certificate file alias/alignment')
            else:
                self.reserve(address, length, 'directory-' + str(i))
            self.dirs[i] = (address, length)
        need(not (self.coff & 1 and 5 in self.dirs), 'relocation: stripped contradiction')

    def locate(self, rva, size, backed=True):
        finish = end32(rva, size)
        matches = [s for s in self.sections if s.rva <= rva and
                   finish <= s.rva + (min(s.virtual, s.size) if backed else s.virtual)]
        need(len(matches) == 1, 'range: outside whole section')
        s = matches[0]
        return s, s.raw + rva - s.rva

    def reserve(self, rva, size, name):
        s, at = self.locate(rva, size)
        span = (rva, end32(rva, size))
        need(all(not overlap(span, (a, b)) for a, b, _ in self.metadata), 'metadata: alias')
        self.metadata.append((*span, name))
        return s, at

    def outside_metadata(self, rva, size):
        span = (rva, end32(rva, size))
        need(all(not overlap(span, (a, b)) for a, b, _ in self.metadata), 'metadata: program alias')

    def directory_policy(self):
        unsupported = sorted(set(self.dirs) - {1, 5, 6, 12})
        self.blockers.extend('unsupported-directory-' + str(i) for i in unsupported)
        if 1 in self.dirs or 12 in self.dirs:
            # No partial import parser: transitive descriptor/name/thunk metadata is unknown.
            self.blockers.append('import-closure-unvalidated')
        if 6 in self.dirs:
            rva, size = self.dirs[6]
            s, at = self.locate(rva, size)
            need(s.role == 'immutable' and size == 28 and rva % 4 == 0, 'debug: directory policy')
            need(self.number(at) == self.number(at + 8) == 0 and self.number(at + 12) == 13,
                 'debug: kind/version')
            length, address, raw = (self.number(at + n) for n in (16, 20, 24))
            need(0 < length <= 4096, 'debug: size')
            s, expected = self.reserve(address, length, 'debug-payload')
            need(s.role == 'immutable' and raw == expected, 'debug: RVA/file disagreement')
        # Cannot claim a complete metadata exclusion set with any unparsed directory.
        self.metadata_closed = not self.blockers
        if self.metadata_closed and 5 in self.dirs:
            self.relocations()
        if any(s.role.startswith('writable') for s in self.sections):
            self.blockers.append('writable-memory-unimplemented')
        if self.metadata_closed:
            self.blockers.append('instruction-ABI-and-provenance-proof-not-run')
        else:
            self.blockers.append('relocation-and-instruction-proof-not-run')

    def relocations(self):
        rva, size = self.dirs[5]
        section, at = self.locate(rva, size)
        need(section.role == 'discardable-metadata' and rva % 4 == 0 and size <= 4096,
             'relocation: directory policy')
        finish = at + size
        previous = -1
        sites = []
        while at < finish:
            need(finish - at >= 8, 'relocation: truncated block')
            page, length = self.number(at), self.number(at + 4)
            need(page % 4096 == 0 and previous < page < self.extent, 'relocation: page order')
            need(12 <= length <= finish - at and length % 4 == 0, 'relocation: block length')
            count, live = (length - 8) // 2, 0
            for i in range(count):
                word = self.number(at + 8 + 2 * i, 'H')
                if word >> 12 == 0:
                    need(word == 0 and i == count - 1, 'relocation: ABSOLUTE policy')
                    continue
                need(word >> 12 == 3, 'relocation: unsupported type')
                site = page + (word & 4095)
                section, raw = self.locate(site, 4)
                need(section.role == 'code', 'relocation: site must be code')
                self.outside_metadata(site, 4)
                span = (site, end32(site, 4))
                need(all(not overlap(span, x) for x in sites), 'relocation: overlapping sites')
                sites.append(span)
                need(len(sites) <= 128, 'limit: relocations')
                va = self.number(raw)
                need(va >= self.base, 'relocation: below preferred base')
                target = va - self.base
                dest, _ = self.locate(target, 1, backed=False)
                self.outside_metadata(target, 1)
                need(dest.role in ('immutable', 'writable', 'writable-zero'), 'relocation: destination role')
                # A candidate address is NOT a typed operand, nor proof of access width.
                self.pointers.append({'image': self.identity, 'site': site, 'rva': target,
                                      'role': dest.role, 'bound': False})
                live += 1
            need(live > 0, 'relocation: empty page')
            at += length
            previous = page

    def immutable(self, rva, size):
        need(self.metadata_closed, 'metadata: closure incomplete')
        s, at = self.locate(rva, size)
        need(s.role == 'immutable', 'permission: immutable required')
        self.outside_metadata(rva, size)
        return self.file(at, size)

    def report(self):
        return {'sha256': self.identity, 'stage': 'envelope-checked',
                'metadata_closed': self.metadata_closed, 'emission_allowed': False,
                'base_evidence': 'preferred-header-only', 'entry': self.entry,
                'sections': [vars(s) for s in self.sections], 'directories': sorted(self.dirs),
                'relocation_candidates': self.pointers, 'blockers': self.blockers}
