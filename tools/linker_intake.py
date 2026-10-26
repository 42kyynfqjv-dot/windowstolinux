"""SUB-515 test-only design model. Not imported by the converter; never emits code.

Independent implementation from the PE specification, MIT OR Apache-2.0.
Structural intake is NOT instruction acceptance or Windows loader emulation.
"""
from dataclasses import dataclass
import struct


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def end32(start, size):
    require(0 <= start <= 0xffffffff and 0 < size <= 0xffffffff,
            "empty or invalid range")
    end = start + size
    require(end <= 0xffffffff, "32-bit range overflow")
    return end


def overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


@dataclass(frozen=True)
class Section:
    rva: int
    virtual: int
    raw: int
    size: int
    flags: int


@dataclass(frozen=True)
class Pointer:
    # The image itself owns this value; never carry it to another image resolver.
    site: int
    rva: int


class Candidate:
    CODE = 0x60000020
    DATA = 0x40000040
    RELOC = 0x42000040

    def bytes_at(self, offset, size):
        end = end32(offset, size)
        require(end <= len(self.blob), "file bounds")
        return self.blob[offset:end]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.bytes_at(offset, struct.calcsize(fmt)))

    def location(self, rva, size, flags):
        end = end32(rva, size)
        matches = [s for s in self.sections if s.rva <= rva
                   and end <= s.rva + min(s.virtual, s.size) and s.flags == flags]
        require(len(matches) == 1, "whole range outside required file-backed section")
        s = matches[0]
        offset = s.raw + rva - s.rva
        self.bytes_at(offset, size)
        return offset

    def reserve(self, name, rva, size, flags=DATA):
        offset = self.location(rva, size, flags)
        span = (rva, end32(rva, size))
        require(all(not overlap(span, other) for _, other in self.reserved),
                "metadata alias")
        self.reserved.append((name, span))
        return offset

    def immutable(self, rva, size):
        offset = self.location(rva, size, self.DATA)
        span = (rva, end32(rva, size))
        require(all(not overlap(span, other) for _, other in self.reserved),
                "program read intersects metadata")
        return self.bytes_at(offset, size)

    def __init__(self, blob):
        self.blob = bytes(blob)
        self.reserved = []
        require(len(blob) <= 4 * 1024 * 1024, "file resource limit")
        require(self.bytes_at(0, 2) == b'MZ', "DOS signature")
        pe, = self.unpack('<I', 0x3c)
        require(pe >= 0x40 and pe % 8 == 0, "PE offset")
        require(self.bytes_at(pe, 4) == b'PE\0\0', "PE signature")
        machine, count, _, symbols, symbol_count, opt_size, coff = self.unpack('<HHIIIHH', pe + 4)
        require((machine, count, symbols, symbol_count, opt_size, coff)
                == (0x14c, 3, 0, 0, 0xe0, 0x102), "linker COFF profile")
        o = pe + 24
        self.bytes_at(o, opt_size)
        require(self.unpack('<H', o)[0] == 0x10b, "PE32 required")
        self.entry, = self.unpack('<I', o + 16)
        self.base, sa, fa = self.unpack('<III', o + 28)
        self.image_size, headers = self.unpack('<II', o + 56)
        require(self.base != 0 and self.base % 0x10000 == 0, "preferred base")
        require(self.image_size <= 1024 * 1024 and self.image_size % 0x1000 == 0,
                "image resource limit or alignment")
        end32(self.base, self.image_size)
        require((sa, fa) == (0x1000, 0x200), "alignment profile")
        require(self.unpack('<HH', o + 68) == (3, 0x8540), "subsystem/DLL characteristics")
        require(self.unpack('<I', o + 52)[0] == 0 and self.unpack('<I', o + 88)[0] == 0,
                "reserved loader fields")
        sr, sc, hr, hc = self.unpack('<IIII', o + 72)
        require(0 < sc <= sr and 0 < hc <= hr, "stack/heap settings")
        require(self.unpack('<I', o + 92)[0] == 16, "directory count")
        table = o + opt_size
        require(headers >= table + count * 40 and headers % fa == 0, "header extent")
        self.bytes_at(0, headers)
        self.sections = []
        previous_end = (headers + sa - 1) & -sa
        raw_spans = []
        for i in range(count):
            at = table + 40 * i
            vs, va, size, raw, reloc, lines, nr, nl, flags = self.unpack('<IIIIIIHHI', at + 8)
            require(flags in (self.CODE, self.DATA, self.RELOC), "section permissions")
            require(0 < vs <= size and size % fa == 0 and raw % fa == 0,
                    "section sizes/alignment")
            require(raw >= headers and va == previous_end, "section placement")
            require((reloc, lines, nr, nl) == (0, 0, 0, 0), "section COFF records")
            rend = end32(raw, size)
            vend = end32(va, max(vs, size))
            require(vend <= self.image_size, "image bounds")
            self.bytes_at(raw, size)
            require(all(not overlap((raw, rend), span) for span in raw_spans), "raw overlap")
            raw_spans.append((raw, rend))
            self.sections.append(Section(va, vs, raw, size, flags))
            previous_end = (end32(vend, sa - 1)) & -sa
        require(previous_end == self.image_size, "image extent")
        require(sorted(s.flags for s in self.sections) == sorted((self.CODE, self.DATA, self.RELOC)),
                "exact section roles")
        code = next(s for s in self.sections if s.flags == self.CODE)
        data = next(s for s in self.sections if s.flags == self.DATA)
        require(self.unpack('<III', o + 4) == (code.size, sum(s.size for s in self.sections if s != code), 0),
                "aggregate sizes")
        require(self.unpack('<II', o + 20) == (code.rva, data.rva), "base code/data")
        self.location(self.entry, 1, self.CODE)
        directories = [self.unpack('<II', o + 96 + i * 8) for i in range(16)]
        for i, pair in enumerate(directories):
            require(pair == (0, 0) if i not in (1, 5, 6, 12) else all(pair),
                    "directory allowlist/presence")
        self._imports(directories[1], directories[12])
        self._debug(directories[6])
        self._relocations(directories[5])

    def _imports(self, directory, iat_directory):
        rva, size = directory
        require(size == 40 and rva % 4 == 0, "one import descriptor and terminator")
        offset = self.reserve('import descriptors', rva, size)
        ilt, timestamp, forwarder, name, self.iat = self.unpack('<IIIII', offset)
        require((timestamp, forwarder) == (0, 0) and self.bytes_at(offset + 20, 20) == bytes(20),
                "binding/forwarder/terminator")
        require(iat_directory == (self.iat, 8) and ilt % 4 == self.iat % 4 == 0,
                "IAT directory/alignment")
        ip = self.reserve('IAT', self.iat, 8)
        lp = self.reserve('ILT', ilt, 8)
        thunk, terminator = self.unpack('<II', ip)
        require((thunk, terminator) == self.unpack('<II', lp) and terminator == 0,
                "thunk mismatch/terminator")
        require(thunk != 0 and thunk & 0x80000000 == 0 and thunk % 2 == 0, "named import required")
        np = self.reserve('hint/name', thunk, 9)
        require(self.bytes_at(np, 9) == b'\0\0_write\0', "exact hint/name")
        dp = self.reserve('DLL name', name, 11)
        require(self.bytes_at(dp, 11) == b'msvcrt.dll\0', "exact DLL name")

    def _debug(self, directory):
        rva, size = directory
        require(size == 28 and rva % 4 == 0, "one debug entry")
        offset = self.reserve('debug directory', rva, size)
        characteristics, _, major, minor, kind, length, address, pointer = self.unpack('<IIHHIIII', offset)
        require((characteristics, major, minor, kind) == (0, 0, 0, 13), "debug kind/version")
        require(0 < length <= 4096, "debug size")
        expected = self.reserve('opaque POGO debug payload', address, length)
        require(pointer == expected, "debug RVA/file disagreement")
        self.debug = dict(kind=kind, rva=address, size=length, file_offset=pointer)

    def _relocations(self, directory):
        rva, size = directory
        require(rva % 4 == 0 and 0 < size <= 4096, "relocation directory alignment/limit")
        offset = self.reserve('base relocations', rva, size, self.RELOC)
        end = offset + size
        cursor = offset
        prior_page = -1
        self.pointers = []
        spans = []
        self.blocks = []
        while cursor < end:
            require(cursor + 8 <= end, "truncated relocation block")
            page, length = self.unpack('<II', cursor)
            require(page % 0x1000 == 0 and prior_page < page < self.image_size,
                    "relocation page order/bounds")
            require(length >= 12 and length % 4 == 0 and cursor + length <= end,
                    "relocation block size")
            entries = self.unpack('<' + 'H' * ((length - 8) // 2), cursor + 8)
            live = 0
            for index, word in enumerate(entries):
                kind, delta = word >> 12, word & 0xfff
                if kind == 0:
                    require(word == 0 and index == len(entries) - 1, "canonical ABSOLUTE padding")
                    continue
                require(kind == 3, "unsupported relocation type")
                site = page + delta
                target = self.location(site, 4, self.CODE)
                span = (site, end32(site, 4))
                require(all(not overlap(span, previous) for previous in spans), "overlapping relocation targets")
                spans.append(span)
                value, = self.unpack('<I', target)
                require(value >= self.base, "relocated value below image base")
                dest = value - self.base
                if dest == self.iat:
                    self.location(dest, 4, self.DATA)
                else:
                    self.immutable(dest, 1)
                self.pointers.append(Pointer(site, dest))
                require(len(self.pointers) <= 128, "relocation count limit")
                live += 1
            require(live > 0, "empty relocation page")
            self.blocks.append(dict(page_rva=page, size=length, entries=list(entries)))
            cursor += length
            prior_page = page
        require(self.pointers, "missing HIGHLOW relocations")

    def bind(self, fields):
        """Model a FUTURE decoder-to-relocation join, not a decoder itself.

        fields: independently supplied (four-byte field RVA, role, access width).
        Real integration must obtain these from checked reachable instruction
        boundaries and enforce typed pointer uses, not from callers or guesses.
        """
        require(len(fields) == len(self.pointers), "relocation coverage")
        pointers = {p.site: p for p in self.pointers}
        used = set()
        result = []
        for site, role, width in fields:
            require(site in pointers and site not in used, "field/relocation mismatch")
            used.add(site)
            p = pointers[site]
            if role == 'import-call':
                require(p.rva == self.iat and width == 4, "import operand role")
            elif role == 'immutable-buffer':
                self.immutable(p.rva, width)
            else:
                raise Rejected("unsupported pointer use")
            result.append((role, p.rva, width))
        return result

    def rebase_words(self, actual_base):
        """Arithmetic model only: no file mutation, mapping or execution."""
        require(actual_base != 0 and actual_base % 0x10000 == 0, "actual base alignment")
        end32(actual_base, self.image_size)
        result = []
        for p in self.pointers:
            old = self.base + p.rva
            # PE HIGHLOW modular arithmetic, checked against a nonwrapping image pointer.
            relocated = (old + actual_base - self.base) & 0xffffffff
            require(relocated == actual_base + p.rva, "rebased pointer wraps")
            result.append((p.site, relocated))
        return result

    def report(self):
        return dict(status='structural candidate only; no instruction acceptance',
                    preferred_base=self.base, entry_rva=self.entry,
                    sections=[vars(s) for s in self.sections], debug=self.debug,
                    relocation_blocks=self.blocks, pointers=[vars(p) for p in self.pointers],
                    reserved=[(name, list(span)) for name, span in self.reserved],
                    arithmetic_rebase_samples={hex(b): self.rebase_words(b) for b in (0x10000, self.base, 0x10000000)})
