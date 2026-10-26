use crate::{range, u32_at, Pe, Section};
pub fn parse(bytes: &[u8], section: &Section, optional: usize, base: u32) -> Result<u32, String> {
    let mut spans = Vec::new();
    let mut take = |rva: u32, len: u32| -> Result<&[u8], String> {
        let delta = rva
            .checked_sub(section.virtual_address)
            .ok_or("import RVA")?;
        let end = delta.checked_add(len).ok_or("import overflow")?;
        if end > section.virtual_size || end > section.raw_size {
            return Err("import bounds".into());
        }
        if spans.iter().any(|&(a, b)| delta < b && a < end) {
            return Err("aliased imports".into());
        }
        spans.push((delta, end));
        range(
            bytes,
            section
                .raw_offset
                .checked_add(delta)
                .ok_or("import offset")? as usize,
            len as usize,
        )
    };
    if u32_at(bytes, optional + 108)? != 40 || u32_at(bytes, optional + 196)? != 8 {
        return Err("import directory sizes".into());
    }
    let d = take(u32_at(bytes, optional + 104)?, 40)?;
    if d[20..].iter().any(|&v| v != 0) || u32_at(d, 4)? != 0 || u32_at(d, 8)? != 0 {
        return Err("import descriptor".into());
    }
    let ilt = u32_at(d, 0)?;
    let iat = u32_at(d, 16)?;
    if ilt == 0
        || !ilt.is_multiple_of(4)
        || !iat.is_multiple_of(4)
        || iat != u32_at(bytes, optional + 192)?
    {
        return Err("import table alignment/directory".into());
    }
    let lookup = take(ilt, 8)?;
    let address = take(iat, 8)?;
    if lookup != address || u32_at(lookup, 4)? != 0 {
        return Err("import thunks".into());
    }
    let name = u32_at(lookup, 0)?;
    if name == 0 || name & 0x80000000 != 0 || !name.is_multiple_of(2) {
        return Err("ordinal/name import".into());
    }
    if take(u32_at(d, 12)?, 11)? != b"msvcrt.dll\0" || take(name, 9)? != b"\0\0_write\0" {
        return Err("import allowlist".into());
    }
    base.checked_add(iat)
        .ok_or_else(|| "IAT VA overflow".into())
}
impl Pe<'_> {
    pub(crate) fn output_bytes(&self, address: u32, count: u32) -> Result<Vec<u8>, String> {
        if !(1..=64).contains(&count) {
            return Err("output count".into());
        }
        address.checked_add(count - 1).ok_or("output VA overflow")?;
        let data = self.sections.get(1).ok_or("output data")?;
        let delta = address
            .checked_sub(self.image_base)
            .and_then(|v| v.checked_sub(data.virtual_address))
            .ok_or("output provenance")?;
        let end = delta.checked_add(count).ok_or("output range")?;
        if end > data.raw_size || end > data.virtual_size {
            return Err("output bounds".into());
        }
        let bytes = range(
            self.bytes,
            data.raw_offset
                .checked_add(delta)
                .ok_or("output file offset")? as usize,
            count as usize,
        )?;
        if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
            return Err("output byte domain".into());
        }
        Ok(bytes.to_vec())
    }
}
