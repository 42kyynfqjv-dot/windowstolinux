//! Checked owned PE envelope: diagnostic reports and separate importless intake capability.
use crate::{range, u16_at, u32_at};
type Result<T> = std::result::Result<T, String>;
fn need(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn end(a: u32, n: u32) -> Result<u32> {
    need(n > 0, "range: empty")?;
    a.checked_add(n).ok_or("range: overflow".into())
}
fn round(a: u32) -> Result<u32> {
    Ok(end(a, 4095)? & !4095)
}
fn overlap(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 < b.1 && b.0 < a.1
}
#[derive(Clone, Copy, PartialEq)]
enum Role {
    Code,
    Immutable,
    Writable,
    Zero,
    Metadata,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Immutable => "immutable",
            Self::Writable => "writable",
            Self::Zero => "writable-zero",
            Self::Metadata => "discardable-metadata",
        }
    }
    fn writable(self) -> bool {
        matches!(self, Self::Writable | Self::Zero)
    }
}
struct Section {
    rva: u32,
    virtual_size: u32,
    raw: u32,
    size: u32,
    role: Role,
}
struct Pointer {
    site: u32,
    rva: u32,
    role: Role,
}
struct Envelope {
    bytes: Vec<u8>,
    base: u32,
    extent: u32,
    entry: u32,
    sections: Vec<Section>,
    metadata: Vec<(u32, u32)>,
    dirs: [Option<(u32, u32)>; 16],
    pointers: Vec<Pointer>,
    closed: bool,
    blockers: Vec<String>,
}
impl Envelope {
    fn number(&self, at: usize) -> Result<u32> {
        u32_at(&self.bytes, at)
    }
    fn locate(&self, rva: u32, n: u32, backed: bool) -> Result<(&Section, Option<usize>)> {
        let finish = end(rva, n)?;
        let s = self
            .sections
            .iter()
            .find(|s| {
                rva >= s.rva
                    && finish
                        <= s.rva
                            + if backed {
                                s.virtual_size.min(s.size)
                            } else {
                                s.virtual_size
                            }
            })
            .ok_or("range: outside whole section")?;
        let offset = if finish <= s.rva + s.virtual_size.min(s.size) {
            Some((s.raw + rva - s.rva) as usize)
        } else {
            None
        };
        Ok((s, offset))
    }
    fn file_location(&self, rva: u32, n: u32) -> Result<(Role, usize)> {
        let (s, at) = self.locate(rva, n, true)?;
        Ok((s.role, at.ok_or("range: no file backing")?))
    }
    fn reserve(&mut self, rva: u32, n: u32) -> Result<(Role, usize)> {
        let result = self.file_location(rva, n)?;
        let span = (rva, end(rva, n)?);
        need(
            self.metadata.iter().all(|&x| !overlap(x, span)),
            "metadata: alias",
        )?;
        self.metadata.push(span);
        Ok(result)
    }
    fn outside(&self, rva: u32, n: u32) -> Result<()> {
        let span = (rva, end(rva, n)?);
        need(
            self.metadata.iter().all(|&x| !overlap(x, span)),
            "metadata: program alias",
        )
    }
    fn parse(bytes: Vec<u8>) -> Result<Self> {
        need(bytes.len() <= 4 * 1024 * 1024, "limit: file")?;
        need(range(&bytes, 0, 2)? == b"MZ", "header: DOS")?;
        let pe = u32_at(&bytes, 60)? as usize;
        need(pe >= 64 && pe.is_multiple_of(8), "policy: PE offset")?;
        range(&bytes, pe, 24)?;
        need(range(&bytes, pe, 4)? == b"PE\0\0", "header: PE")?;
        need(
            u16_at(&bytes, pe + 4)? == 0x14c,
            "architecture: x86 PE32 required",
        )?;
        let count = u16_at(&bytes, pe + 6)? as usize;
        need((1..=8).contains(&count), "limit: section count")?;
        need(
            u32_at(&bytes, pe + 12)? == 0 && u32_at(&bytes, pe + 16)? == 0,
            "policy: COFF symbols",
        )?;
        let optional = u16_at(&bytes, pe + 20)? as usize;
        let coff = u16_at(&bytes, pe + 22)?;
        need(
            coff & 2 != 0 && coff & !0x30f == 0,
            "policy: COFF execution flags",
        )?;
        let o = pe + 24;
        range(&bytes, o, optional)?;
        need(optional >= 96, "header: short optional header")?;
        need(
            u16_at(&bytes, o)? == 0x10b,
            "architecture: x86 PE32 required",
        )?;
        let nd = u32_at(&bytes, o + 92)? as usize;
        need(
            nd <= 16 && 96 + 8 * nd <= optional,
            "header: directory count",
        )?;
        need(
            range(&bytes, o + 96 + 8 * nd, optional - 96 - 8 * nd)?
                .iter()
                .all(|&x| x == 0),
            "policy: optional extension",
        )?;
        need(
            u32_at(&bytes, o + 32)? == 4096 && u32_at(&bytes, o + 36)? == 512,
            "policy: alignment",
        )?;
        need(
            u32_at(&bytes, o + 52)? == 0 && u32_at(&bytes, o + 88)? == 0,
            "policy: loader fields",
        )?;
        need(u16_at(&bytes, o + 68)? == 3, "policy: console subsystem")?;
        need(u16_at(&bytes, o + 70)? & !0x8540 == 0, "policy: DLL flags")?;
        for at in [72, 80] {
            let reserve = u32_at(&bytes, o + at)?;
            let commit = u32_at(&bytes, o + at + 4)?;
            need(commit > 0 && commit <= reserve, "policy: stack/heap")?;
        }
        let base = u32_at(&bytes, o + 28)?;
        let extent = u32_at(&bytes, o + 56)?;
        let headers = u32_at(&bytes, o + 60)?;
        need(base > 0 && base.is_multiple_of(65536), "policy: image base")?;
        need(
            extent > 0 && extent <= 1024 * 1024 && extent.is_multiple_of(4096),
            "limit: image",
        )?;
        end(base, extent)?;
        need(
            headers as usize >= o + optional + count * 40 && headers.is_multiple_of(512),
            "header: extent",
        )?;
        range(&bytes, 0, headers as usize)?;
        let entry = u32_at(&bytes, o + 16)?;
        let mut image = Self {
            bytes,
            base,
            extent,
            entry,
            sections: vec![],
            metadata: vec![],
            dirs: [None; 16],
            pointers: vec![],
            closed: false,
            blockers: vec![],
        };
        let mut raw_spans = vec![(0, headers)];
        let mut next = round(headers)?;
        for i in 0..count {
            let at = o + optional + i * 40;
            range(&image.bytes, at, 40)?;
            let virtual_size = image.number(at + 8)?;
            let rva = image.number(at + 12)?;
            let size = image.number(at + 16)?;
            let raw = image.number(at + 20)?;
            let role = match image.number(at + 36)? {
                0x60000020 => Role::Code,
                0x40000040 => Role::Immutable,
                0xc0000040 => Role::Writable,
                0xc0000080 => Role::Zero,
                0x42000040 => Role::Metadata,
                _ => return Err("policy: section permissions/content".into()),
            };
            need(
                range(&image.bytes, at + 24, 12)?.iter().all(|&x| x == 0),
                "policy: section COFF records",
            )?;
            need(
                virtual_size > 0 && rva == next,
                "mapping: virtual extent/order",
            )?;
            need(size.is_multiple_of(512), "mapping: raw alignment")?;
            if size > 0 {
                need(raw.is_multiple_of(512), "mapping: raw alignment")?;
                let finish = end(raw, size)?;
                range(&image.bytes, raw as usize, size as usize)?;
                need(
                    raw_spans.iter().all(|&x| !overlap(x, (raw, finish))),
                    "mapping: raw alias",
                )?;
                raw_spans.push((raw, finish));
                need(role != Role::Zero, "policy: initialized BSS")?;
            } else {
                need(raw == 0 && role == Role::Zero, "policy: empty raw section")?;
            }
            need(
                virtual_size <= size || role.writable(),
                "policy: nonwritable zero-fill",
            )?;
            next = round(end(rva, virtual_size.max(size))?)?;
            need(next <= extent, "mapping: image bounds")?;
            image.sections.push(Section {
                rva,
                virtual_size,
                raw,
                size,
                role,
            });
        }
        need(next == extent, "mapping: image extent")?;
        need(
            image
                .sections
                .iter()
                .filter(|s| s.role == Role::Code)
                .count()
                == 1,
            "policy: one code region",
        )?;
        need(
            image.file_location(entry, 1)?.0 == Role::Code,
            "entry: executable file-backed byte required",
        )?;
        for i in 0..nd {
            let address = image.number(o + 96 + i * 8)?;
            let size = image.number(o + 100 + i * 8)?;
            if address == 0 && size == 0 {
                continue;
            }
            need(address != 0 && size != 0, "directory: incomplete pair")?;
            if i == 4 {
                let finish = end(address, size)?;
                range(&image.bytes, address as usize, size as usize)?;
                need(
                    address.is_multiple_of(8)
                        && raw_spans.iter().all(|&x| !overlap(x, (address, finish))),
                    "directory: certificate file alias/alignment",
                )?;
            } else {
                image.reserve(address, size)?;
            }
            image.dirs[i] = Some((address, size));
        }
        need(
            coff & 1 == 0 || image.dirs[5].is_none(),
            "relocation: stripped contradiction",
        )?;
        image.policy()?;
        Ok(image)
    }
    fn policy(&mut self) -> Result<()> {
        for i in 0..16 {
            if self.dirs[i].is_some() && !matches!(i, 1 | 5 | 6 | 12) {
                self.blockers.push(format!("unsupported-directory-{i}"));
            }
        }
        if self.dirs[1].is_some() || self.dirs[12].is_some() {
            self.blockers.push("import-closure-unvalidated".into());
        }
        if let Some((rva, size)) = self.dirs[6] {
            let (role, at) = self.file_location(rva, size)?;
            need(
                role == Role::Immutable && size == 28 && rva.is_multiple_of(4),
                "debug: directory policy",
            )?;
            need(
                self.number(at)? == 0 && self.number(at + 8)? == 0 && self.number(at + 12)? == 13,
                "debug: kind/version",
            )?;
            let length = self.number(at + 16)?;
            let address = self.number(at + 20)?;
            let raw = self.number(at + 24)?;
            need(length > 0 && length <= 4096, "debug: size")?;
            let (role, expected) = self.reserve(address, length)?;
            need(
                role == Role::Immutable && raw as usize == expected,
                "debug: RVA/file disagreement",
            )?;
        }
        self.closed = self.blockers.is_empty();
        if self.closed {
            if let Some(pair) = self.dirs[5] {
                self.relocations(pair)?;
            }
        }
        if self.sections.iter().any(|s| s.role.writable()) {
            self.blockers.push("writable-memory-unimplemented".into());
        }
        self.blockers.push(
            if self.closed {
                "instruction-ABI-and-provenance-proof-not-run"
            } else {
                "relocation-and-instruction-proof-not-run"
            }
            .into(),
        );
        Ok(())
    }
    fn relocations(&mut self, (rva, size): (u32, u32)) -> Result<()> {
        let (role, mut at) = self.file_location(rva, size)?;
        need(
            role == Role::Metadata && rva.is_multiple_of(4) && size <= 4096,
            "relocation: directory policy",
        )?;
        let finish = at + size as usize;
        let mut previous = None;
        let mut sites = vec![];
        while at < finish {
            need(finish - at >= 8, "relocation: truncated block")?;
            let page = self.number(at)?;
            let length = self.number(at + 4)? as usize;
            need(
                page.is_multiple_of(4096)
                    && page < self.extent
                    && previous.is_none_or(|p| page > p),
                "relocation: page order",
            )?;
            need(
                length >= 12 && length <= finish - at && length.is_multiple_of(4),
                "relocation: block length",
            )?;
            let count = (length - 8) / 2;
            let mut live = 0;
            for i in 0..count {
                let word = u16_at(&self.bytes, at + 8 + 2 * i)?;
                if word >> 12 == 0 {
                    need(word == 0 && i == count - 1, "relocation: ABSOLUTE policy")?;
                    continue;
                }
                need(word >> 12 == 3, "relocation: unsupported type")?;
                let site = page
                    .checked_add(u32::from(word & 4095))
                    .ok_or("relocation: overflow")?;
                let (role, raw) = self.file_location(site, 4)?;
                need(role == Role::Code, "relocation: site must be code")?;
                self.outside(site, 4)?;
                let span = (site, end(site, 4)?);
                need(
                    sites.iter().all(|&x| !overlap(x, span)),
                    "relocation: overlapping sites",
                )?;
                sites.push(span);
                need(sites.len() <= 128, "limit: relocations")?;
                let target = self
                    .number(raw)?
                    .checked_sub(self.base)
                    .ok_or("relocation: below preferred base")?;
                let (dest, _) = self.locate(target, 1, false)?;
                let role = dest.role;
                self.outside(target, 1)?;
                need(
                    matches!(role, Role::Immutable | Role::Writable | Role::Zero),
                    "relocation: destination role",
                )?;
                self.pointers.push(Pointer {
                    site,
                    rva: target,
                    role,
                });
                live += 1;
            }
            need(live > 0, "relocation: empty page")?;
            at += length;
            previous = Some(page);
        }
        Ok(())
    }
    fn report(&self) -> String {
        let sections=self.sections.iter().enumerate().map(|(i,s)|format!("{{\"index\":{i},\"rva\":{},\"virtual\":{},\"raw\":{},\"size\":{},\"role\":\"{}\"}}",s.rva,s.virtual_size,s.raw,s.size,s.role.name())).collect::<Vec<_>>().join(",");
        let dirs = self
            .dirs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.is_some())
            .map(|(i, _)| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let pointers = self
            .pointers
            .iter()
            .map(|p| {
                format!(
                    "{{\"site\":{},\"rva\":{},\"role\":\"{}\",\"bound\":false}}",
                    p.site,
                    p.rva,
                    p.role.name()
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        // Strings below are internal constants, never unescaped PE-controlled text.
        let blockers = self
            .blockers
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"stage\":\"envelope-checked\",\"metadata_closed\":{},\"emission_allowed\":false,\"base_evidence\":\"preferred-header-only\",\"entry\":{},\"sections\":[{sections}],\"directories\":[{dirs}],\"relocation_candidates\":[{pointers}],\"blockers\":[{blockers}]}}",self.closed,self.entry)
    }
}
/// Diagnostic entry point: report strings never confer execution authority.
pub(crate) fn inspect(bytes: Vec<u8>) -> Result<String> {
    Ok(Envelope::parse(bytes)?.report())
}
#[cfg(test)]
mod tests;

/// Capability created from owned PE bytes, never from the diagnostic report.
/// This proves intake only; linker graph/state proof must still precede emission.
pub(crate) struct Importless {
    image: Envelope,
}
impl Importless {
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self> {
        let image = Envelope::parse(bytes)?;
        need(
            image
                .sections
                .iter()
                .all(|s| matches!(s.role, Role::Code | Role::Immutable)),
            "importless: only code and immutable sections",
        )?;
        need(
            image
                .dirs
                .iter()
                .enumerate()
                .all(|(i, d)| i == 6 || d.is_none()),
            "importless: unsupported directory",
        )?;
        need(
            image.closed && image.pointers.is_empty(),
            "importless: metadata closure",
        )?;
        Ok(Self { image })
    }
    // The only program bytes exposed are validated file-backed executable bytes.
    // No absolute address, immutable-data read, IAT or relocation capability exists.
    pub(crate) fn code(&self) -> Result<(u32, u32, &[u8])> {
        let section = self
            .image
            .sections
            .iter()
            .find(|s| s.role == Role::Code)
            .ok_or("code region")?;
        let size = section.virtual_size.min(section.size);
        self.image.outside(section.rva, size)?;
        Ok((
            self.image.entry,
            section.rva,
            range(&self.image.bytes, section.raw as usize, size as usize)?,
        ))
    }
    pub(crate) fn translate(&self) -> Result<String> {
        crate::linker::translate_importless(self)
    }
}
