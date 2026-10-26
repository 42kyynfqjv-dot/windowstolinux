//! SUB-515 contract: structural candidate only. No conversion to the emitting Pe type.
use crate::{range, u16_at, u32_at};

const CODE: u32 = 0x6000_0020;
const DATA: u32 = 0x4000_0040;
const RELOC: u32 = 0x4200_0040;
fn need(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn end(start: u32, size: u32) -> Result<u32, String> {
    need(size != 0, "empty linker range")?;
    start
        .checked_add(size)
        .ok_or("linker range overflow".into())
}
fn rounded(value: u32) -> Result<u32, String> {
    Ok(value.checked_add(4095).ok_or("linker alignment overflow")? & !4095)
}
fn overlaps(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 < b.1 && b.0 < a.1
}
#[derive(Clone, Copy)]
struct Section {
    rva: u32,
    size: u32,
    raw: u32,
    virtual_size: u32,
    flags: u32,
}
/// All fields are private; no API exposes this as an emitter-authorized image.
pub(crate) struct Candidate<'a> {
    bytes: &'a [u8],
    base: u32,
    entry: u32,
    image_size: u32,
    sections: Vec<Section>,
    metadata: Vec<(u32, u32)>,
    iat: u32,
}
impl<'a> Candidate<'a> {
    fn location(&self, rva: u32, size: u32, flags: u32) -> Result<usize, String> {
        let finish = end(rva, size)?;
        let mut found = None;
        for s in &self.sections {
            if s.flags == flags && rva >= s.rva && finish <= end(s.rva, s.size.min(s.virtual_size))?
            {
                need(found.is_none(), "ambiguous linker mapping")?;
                let offset = s
                    .raw
                    .checked_add(rva - s.rva)
                    .ok_or("linker file overflow")? as usize;
                range(self.bytes, offset, size as usize)?;
                found = Some(offset);
            }
        }
        found.ok_or("whole range outside linker section".into())
    }
    fn reserve(&mut self, rva: u32, size: u32, flags: u32) -> Result<usize, String> {
        let offset = self.location(rva, size, flags)?;
        let span = (rva, end(rva, size)?);
        need(
            self.metadata.iter().all(|&x| !overlaps(x, span)),
            "linker metadata alias",
        )?;
        self.metadata.push(span);
        Ok(offset)
    }
    fn immutable(&self, rva: u32, size: u32) -> Result<(), String> {
        self.location(rva, size, DATA)?;
        let span = (rva, end(rva, size)?);
        need(
            self.metadata.iter().all(|&x| !overlaps(x, span)),
            "linker pointer into metadata",
        )
    }
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        need(bytes.len() <= 4 * 1024 * 1024, "linker file resource limit")?;
        need(range(bytes, 0, 2)? == b"MZ", "missing DOS signature")?;
        let pe = u32_at(bytes, 0x3c)? as usize;
        need(pe >= 64 && pe.is_multiple_of(8), "linker PE offset")?;
        need(range(bytes, pe, 4)? == b"PE\0\0", "missing PE signature")?;
        // The complete header must exist before any fixed-offset arithmetic.
        range(bytes, pe, 24 + 224 + 120)?;
        need(
            u16_at(bytes, pe + 4)? == 0x14c
                && u16_at(bytes, pe + 6)? == 3
                && u16_at(bytes, pe + 20)? == 224
                && u16_at(bytes, pe + 22)? == 0x102,
            "linker COFF profile",
        )?;
        need(
            u32_at(bytes, pe + 12)? == 0 && u32_at(bytes, pe + 16)? == 0,
            "linker COFF symbols",
        )?;
        let o = pe + 24;
        need(
            u16_at(bytes, o)? == 0x10b
                && u16_at(bytes, o + 68)? == 3
                && u16_at(bytes, o + 70)? == 0x8540,
            "linker optional profile",
        )?;
        need(
            u32_at(bytes, o + 32)? == 4096 && u32_at(bytes, o + 36)? == 512,
            "linker alignment profile",
        )?;
        need(
            u32_at(bytes, o + 52)? == 0
                && u32_at(bytes, o + 88)? == 0
                && u32_at(bytes, o + 92)? == 16,
            "linker loader fields",
        )?;
        for at in [72, 80] {
            let reserve = u32_at(bytes, o + at)?;
            let commit = u32_at(bytes, o + at + 4)?;
            need(
                commit > 0 && commit <= reserve,
                "linker stack/heap settings",
            )?;
        }
        let base = u32_at(bytes, o + 28)?;
        let image_size = u32_at(bytes, o + 56)?;
        let headers = u32_at(bytes, o + 60)?;
        need(
            base != 0 && base.is_multiple_of(65536),
            "linker preferred base",
        )?;
        need(
            image_size <= 1024 * 1024 && image_size.is_multiple_of(4096),
            "linker image limit",
        )?;
        end(base, image_size)?;
        need(
            headers as usize >= o + 224 + 120 && headers.is_multiple_of(512),
            "linker header extent",
        )?;
        range(bytes, 0, headers as usize)?;
        let mut image = Self {
            bytes,
            base,
            entry: u32_at(bytes, o + 16)?,
            image_size,
            sections: Vec::new(),
            metadata: Vec::new(),
            iat: 0,
        };
        let mut next = rounded(headers)?;
        let mut raw_spans = Vec::new();
        for i in 0..3 {
            let at = o + 224 + i * 40;
            let s = Section {
                virtual_size: u32_at(bytes, at + 8)?,
                rva: u32_at(bytes, at + 12)?,
                size: u32_at(bytes, at + 16)?,
                raw: u32_at(bytes, at + 20)?,
                flags: u32_at(bytes, at + 36)?,
            };
            need(
                matches!(s.flags, CODE | DATA | RELOC),
                "linker section permissions",
            )?;
            need(
                s.virtual_size > 0
                    && s.virtual_size <= s.size
                    && s.size.is_multiple_of(512)
                    && s.raw.is_multiple_of(512),
                "linker section sizes",
            )?;
            need(
                s.raw >= headers && s.rva == next,
                "linker section placement",
            )?;
            need(
                u32_at(bytes, at + 24)? == 0
                    && u32_at(bytes, at + 28)? == 0
                    && u32_at(bytes, at + 32)? == 0,
                "linker section COFF records",
            )?;
            let raw_end = end(s.raw, s.size)?;
            let virtual_end = end(s.rva, s.size)?;
            need(virtual_end <= image_size, "linker image bounds")?;
            range(bytes, s.raw as usize, s.size as usize)?;
            need(
                raw_spans.iter().all(|&x| !overlaps(x, (s.raw, raw_end))),
                "linker raw overlap",
            )?;
            raw_spans.push((s.raw, raw_end));
            next = rounded(virtual_end)?;
            image.sections.push(s);
        }
        need(next == image_size, "linker image extent")?;
        for role in [CODE, DATA, RELOC] {
            need(
                image.sections.iter().filter(|s| s.flags == role).count() == 1,
                "linker section roles",
            )?;
        }
        let code = image.sections.iter().find(|s| s.flags == CODE).unwrap();
        let data = image.sections.iter().find(|s| s.flags == DATA).unwrap();
        let initialized = image
            .sections
            .iter()
            .filter(|s| s.flags != CODE)
            .try_fold(0u32, |n, s| n.checked_add(s.size))
            .ok_or("linker aggregate overflow")?;
        need(
            u32_at(bytes, o + 4)? == code.size
                && u32_at(bytes, o + 8)? == initialized
                && u32_at(bytes, o + 12)? == 0
                && u32_at(bytes, o + 20)? == code.rva
                && u32_at(bytes, o + 24)? == data.rva,
            "linker aggregate fields",
        )?;
        image.location(image.entry, 1, CODE)?;
        let mut dirs = [(0, 0); 16];
        for (i, pair) in dirs.iter_mut().enumerate() {
            *pair = (
                u32_at(bytes, o + 96 + i * 8)?,
                u32_at(bytes, o + 100 + i * 8)?,
            );
            need(
                if matches!(i, 1 | 5 | 6 | 12) {
                    pair.0 != 0 && pair.1 != 0
                } else {
                    *pair == (0, 0)
                },
                "linker directory allowlist",
            )?;
        }
        image.imports(dirs[1], dirs[12])?;
        image.debug(dirs[6])?;
        image.relocations(dirs[5])?;
        Ok(image)
    }
    fn imports(&mut self, (rva, size): (u32, u32), iat_dir: (u32, u32)) -> Result<(), String> {
        need(
            size == 40 && rva.is_multiple_of(4),
            "linker import descriptor size",
        )?;
        let at = self.reserve(rva, size, DATA)?;
        let ilt = u32_at(self.bytes, at)?;
        let name = u32_at(self.bytes, at + 12)?;
        self.iat = u32_at(self.bytes, at + 16)?;
        need(
            u32_at(self.bytes, at + 4)? == 0
                && u32_at(self.bytes, at + 8)? == 0
                && range(self.bytes, at + 20, 20)? == [0; 20],
            "linker import binding/terminator",
        )?;
        need(
            iat_dir == (self.iat, 8) && ilt.is_multiple_of(4) && self.iat.is_multiple_of(4),
            "linker IAT extent/alignment",
        )?;
        let ip = self.reserve(self.iat, 8, DATA)?;
        let lp = self.reserve(ilt, 8, DATA)?;
        let thunk = u32_at(self.bytes, ip)?;
        need(
            range(self.bytes, ip, 8)? == range(self.bytes, lp, 8)?
                && u32_at(self.bytes, ip + 4)? == 0,
            "linker thunk mismatch",
        )?;
        need(
            thunk != 0 && thunk & 0x80000000 == 0 && thunk.is_multiple_of(2),
            "linker named import",
        )?;
        let np = self.reserve(thunk, 9, DATA)?;
        need(
            range(self.bytes, np, 9)? == b"\0\0_write\0",
            "linker hint/name",
        )?;
        let dp = self.reserve(name, 11, DATA)?;
        need(
            range(self.bytes, dp, 11)? == b"msvcrt.dll\0",
            "linker DLL name",
        )
    }
    fn debug(&mut self, (rva, size): (u32, u32)) -> Result<(), String> {
        need(size == 28 && rva.is_multiple_of(4), "linker debug extent")?;
        let at = self.reserve(rva, size, DATA)?;
        need(
            u32_at(self.bytes, at)? == 0
                && u32_at(self.bytes, at + 8)? == 0
                && u32_at(self.bytes, at + 12)? == 13,
            "linker debug kind/version",
        )?;
        let length = u32_at(self.bytes, at + 16)?;
        need(length > 0 && length <= 4096, "linker debug size")?;
        let address = u32_at(self.bytes, at + 20)?;
        let expected = self.reserve(address, length, DATA)?;
        need(
            u32_at(self.bytes, at + 24)? as usize == expected,
            "linker debug RVA/file disagreement",
        )
    }
    fn relocations(&mut self, (rva, size): (u32, u32)) -> Result<(), String> {
        need(
            rva.is_multiple_of(4) && size > 0 && size <= 4096,
            "linker relocation extent",
        )?;
        let mut at = self.reserve(rva, size, RELOC)?;
        let finish = at + size as usize;
        let mut previous = None;
        let mut sites = Vec::new();
        while at < finish {
            need(finish - at >= 8, "linker truncated relocation block")?;
            let page = u32_at(self.bytes, at)?;
            let length = u32_at(self.bytes, at + 4)? as usize;
            need(
                page.is_multiple_of(4096)
                    && page < self.image_size
                    && previous.is_none_or(|p| page > p),
                "linker relocation page order",
            )?;
            need(
                length >= 12 && length.is_multiple_of(4) && length <= finish - at,
                "linker relocation block size",
            )?;
            let count = (length - 8) / 2;
            let mut live = 0;
            for index in 0..count {
                let word = u16_at(self.bytes, at + 8 + index * 2)?;
                if word >> 12 == 0 {
                    need(word == 0 && index == count - 1, "linker ABSOLUTE padding")?;
                    continue;
                }
                need(word >> 12 == 3, "unsupported linker relocation type")?;
                let site = page
                    .checked_add(u32::from(word & 0xfff))
                    .ok_or("linker relocation RVA overflow")?;
                let offset = self.location(site, 4, CODE)?;
                let span = (site, end(site, 4)?);
                need(
                    sites.iter().all(|&x| !overlaps(x, span)),
                    "overlapping linker relocation targets",
                )?;
                sites.push(span);
                need(sites.len() <= 128, "linker relocation count limit")?;
                let dest = u32_at(self.bytes, offset)?
                    .checked_sub(self.base)
                    .ok_or("linker pointer below base")?;
                if dest == self.iat {
                    self.location(dest, 4, DATA)?;
                } else {
                    self.immutable(dest, 1)?;
                }
                live += 1;
            }
            need(live > 0, "linker empty relocation page")?;
            at += length;
            previous = Some(page);
        }
        need(!sites.is_empty(), "linker missing relocations")
    }
    pub(crate) fn reject_emission(&self) -> Result<String, String> {
        let offset = self.location(self.entry, 1, CODE)?;
        let section = self.sections.iter().find(|s| s.flags == CODE).unwrap();
        let size = section.virtual_size.min(section.size) - (self.entry - section.rva);
        let code = range(self.bytes, offset, size as usize)?;
        if let Err(error) = crate::control::decode_instruction(code, 0) {
            return Err(format!("linker intake validated; unsupported entry at RVA {:#x} (opcode {:#04x}): {error}; emission blocked",self.entry,code[0]));
        }
        Err("linker intake validated; emission blocked pending typed pointer provenance".into())
    }
}
