use std::env;
mod control;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

#[derive(Debug)]
struct Pe<'a> {
    bytes: &'a [u8],
    entry_rva: u32,
    sections: Vec<Section>,
}

fn range(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], String> {
    let end = offset.checked_add(len).ok_or("offset overflow")?;
    bytes
        .get(offset..end)
        .ok_or_else(|| "truncated PE file".into())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2)?.try_into().unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?.try_into().unwrap(),
    ))
}

impl<'a> Pe<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if range(bytes, 0, 2)? != b"MZ" {
            return Err("missing DOS signature".into());
        }
        let pe_offset = u32_at(bytes, 0x3c)? as usize;
        if range(bytes, pe_offset, 4)? != b"PE\0\0" {
            return Err("missing PE signature".into());
        }
        let coff = pe_offset.checked_add(4).ok_or("offset overflow")?;
        if u16_at(bytes, coff)? != 0x14c {
            return Err("only x86 PE32 is supported".into());
        }
        let section_count = u16_at(bytes, coff + 2)? as usize;
        if section_count != 1 {
            return Err("only one-section PE32 images are supported".into());
        }
        if u16_at(bytes, coff + 18)? != 0x0102 {
            return Err("unsupported COFF characteristics".into());
        }
        if u32_at(bytes, coff + 8)? != 0 || u32_at(bytes, coff + 12)? != 0 {
            return Err("COFF symbols are unsupported".into());
        }
        let optional_size = u16_at(bytes, coff + 16)? as usize;
        let optional = coff.checked_add(20).ok_or("offset overflow")?;
        range(bytes, optional, optional_size)?;
        if optional_size != 0xe0 || u16_at(bytes, optional)? != 0x10b {
            return Err("only standard PE32 optional headers are supported".into());
        }
        if u32_at(bytes, optional + 92)? != 16 {
            return Err("unsupported PE data-directory count".into());
        }
        for index in 0..16 {
            let directory = optional + 96 + index * 8;
            if u32_at(bytes, directory)? != 0 || u32_at(bytes, directory + 4)? != 0 {
                return Err(format!("unsupported nonempty PE data directory {index}"));
            }
        }
        if u16_at(bytes, optional + 68)? != 3 || u16_at(bytes, optional + 70)? != 0 {
            return Err("only console images without DLL characteristics are supported".into());
        }
        let image_base = u32_at(bytes, optional + 28)?;
        let stack_reserve = u32_at(bytes, optional + 72)?;
        let stack_commit = u32_at(bytes, optional + 76)?;
        let heap_reserve = u32_at(bytes, optional + 80)?;
        let heap_commit = u32_at(bytes, optional + 84)?;
        if image_base == 0
            || !image_base.is_multiple_of(0x10000)
            || u32_at(bytes, optional + 52)? != 0
            || u32_at(bytes, optional + 88)? != 0
            || stack_commit == 0
            || stack_commit > stack_reserve
            || heap_commit == 0
            || heap_commit > heap_reserve
        {
            return Err("unsupported or invalid PE loader settings".into());
        }
        let section_alignment = u32_at(bytes, optional + 32)?;
        let file_alignment = u32_at(bytes, optional + 36)?;
        if section_alignment != 0x1000 || file_alignment != 0x200 {
            return Err("unsupported PE section or file alignment".into());
        }
        let entry_rva = u32_at(bytes, optional + 16)?;
        let image_size = u32_at(bytes, optional + 56)?;
        let headers_size = u32_at(bytes, optional + 60)?;
        image_base
            .checked_add(image_size)
            .ok_or("image address overflow")?;
        let section_table = optional
            .checked_add(optional_size)
            .ok_or("offset overflow")?;
        let section_table_end = section_table
            .checked_add(section_count * 40)
            .ok_or("offset overflow")?;
        if headers_size as usize > bytes.len()
            || (headers_size as usize) < section_table_end
            || !headers_size.is_multiple_of(file_alignment)
            || image_size == 0
            || !image_size.is_multiple_of(section_alignment)
        {
            return Err("invalid PE image or header bounds".into());
        }
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let at = section_table
                .checked_add(i.checked_mul(40).ok_or("offset overflow")?)
                .ok_or("offset overflow")?;
            range(bytes, at, 40)?;
            let section = Section {
                virtual_size: u32_at(bytes, at + 8)?,
                virtual_address: u32_at(bytes, at + 12)?,
                raw_size: u32_at(bytes, at + 16)?,
                raw_offset: u32_at(bytes, at + 20)?,
                characteristics: u32_at(bytes, at + 36)?,
            };
            let virtual_end = section
                .virtual_address
                .checked_add(section.virtual_size.max(section.raw_size))
                .ok_or("section RVA overflow")?;
            let raw_end = section
                .raw_offset
                .checked_add(section.raw_size)
                .ok_or("section file offset overflow")?;
            if section.virtual_size == 0
                || section.raw_size == 0
                || !section.virtual_address.is_multiple_of(section_alignment)
                || !section.raw_offset.is_multiple_of(file_alignment)
                || !section.raw_size.is_multiple_of(file_alignment)
                || section.raw_offset < headers_size
                || section.virtual_address < section_alignment
                || section.virtual_address < headers_size
                || virtual_end > image_size
                || raw_end as usize > bytes.len()
                || section.characteristics != 0x6000_0020
            {
                return Err("unsupported or invalid executable section".into());
            }
            range(
                bytes,
                section.raw_offset as usize,
                section.raw_size as usize,
            )?;
            sections.push(section);
        }
        Ok(Self {
            bytes,
            entry_rva,
            sections,
        })
    }

    fn entry_bytes(&self) -> Result<&'a [u8], String> {
        const EXECUTE: u32 = 0x2000_0000;
        for section in &self.sections {
            if section.characteristics & EXECUTE == 0 {
                continue;
            }
            let Some(delta) = self.entry_rva.checked_sub(section.virtual_address) else {
                continue;
            };
            if delta >= section.virtual_size || delta >= section.raw_size {
                continue;
            }
            let start = (section.raw_offset as usize)
                .checked_add(delta as usize)
                .ok_or("offset overflow")?;
            let available = (section.raw_size.min(section.virtual_size) - delta) as usize;
            return range(self.bytes, start, available);
        }
        Err("entry point is not in executable file-backed bytes".into())
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let input = args.next().ok_or("usage: w2l INPUT.exe OUTPUT.rs")?;
    let output = args.next().ok_or("usage: w2l INPUT.exe OUTPUT.rs")?;
    if args.next().is_some() {
        return Err("usage: w2l INPUT.exe OUTPUT.rs".into());
    }
    let bytes = fs::read(&input).map_err(|e| e.to_string())?;
    let pe = Pe::parse(&bytes)?;
    let source = control::translate(pe.entry_bytes()?)?;
    fs::write(Path::new(&output), source).map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("w2l: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0102u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xb4..0xb8].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xbc..0xc0].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0xdc..0xde].copy_from_slice(&3u16.to_le_bytes());
        bytes[0xe0..0xe4].copy_from_slice(&0x100000u32.to_le_bytes());
        bytes[0xe4..0xe8].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xe8..0xec].copy_from_slice(&0x100000u32.to_le_bytes());
        bytes[0xec..0xf0].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xf4..0xf8].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x178..0x17d].copy_from_slice(b".text");
        bytes[0x180..0x184].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x188..0x18c].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x18c..0x190].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x19c..0x1a0].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[0x200..0x200 + code.len()].copy_from_slice(code);
        bytes
    }

    #[test]
    fn parses_and_translates_supported_path() {
        let bytes = fixture(&[0xb8, 7, 0, 0, 0, 0x05, 5, 0, 0, 0, 0xc3]);
        let entry = Pe::parse(&bytes).unwrap().entry_bytes().unwrap();
        assert_eq!(control::exit_for_test(entry).unwrap(), 12);
        assert!(control::translate(entry)
            .unwrap()
            .contains("overflowing_add(5)"));
    }

    #[test]
    fn rejects_non_pe_and_unsupported_instruction() {
        assert!(Pe::parse(b"not a PE").is_err());
        let bytes = fixture(&[0xeb, 0xfe]);
        assert!(control::translate(Pe::parse(&bytes).unwrap().entry_bytes().unwrap()).is_err());
    }

    #[test]
    fn rejects_entry_outside_executable_raw_data() {
        let mut bytes = fixture(&[0xc3]);
        bytes[0xa8..0xac].copy_from_slice(&0x1200u32.to_le_bytes());
        assert!(Pe::parse(&bytes).unwrap().entry_bytes().is_err());
    }

    #[test]
    fn rejects_use_of_unknown_entry_eax() {
        assert!(control::translate(&[0x05, 1, 0, 0, 0, 0xc3]).is_err());
    }

    #[test]
    fn rejects_every_truncated_fixture_prefix() {
        let bytes = fixture(&[0xc3]);
        for len in 0..bytes.len() {
            assert!(Pe::parse(&bytes[..len]).is_err(), "accepted prefix {len}");
        }
    }

    #[test]
    fn rejects_every_nonempty_pe_directory() {
        for index in 0..16 {
            let mut bytes = fixture(&[0xb8, 0, 0, 0, 0, 0xc3]);
            let directory = 0xf8 + index * 8;
            bytes[directory..directory + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            let error = Pe::parse(&bytes).unwrap_err();
            assert!(error.contains(&format!("directory {index}")), "{error}");
        }
    }

    #[test]
    fn rejects_dll_multisection_and_ambiguous_bounds() {
        let base = fixture(&[0xb8, 0, 0, 0, 0, 0xc3]);

        let mut dll = base.clone();
        dll[0x96..0x98].copy_from_slice(&0x2102u16.to_le_bytes());
        assert!(Pe::parse(&dll).is_err());

        let mut multisection = base.clone();
        multisection[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        assert!(Pe::parse(&multisection).is_err());

        let mut invalid_image_base = base.clone();
        invalid_image_base[0xb4..0xb8].copy_from_slice(&0x400001u32.to_le_bytes());
        assert!(Pe::parse(&invalid_image_base).is_err());

        let mut image_address_overflow = base.clone();
        image_address_overflow[0xb4..0xb8].copy_from_slice(&0xffff_0000u32.to_le_bytes());
        image_address_overflow[0xd0..0xd4].copy_from_slice(&0x2_0000u32.to_le_bytes());
        assert!(Pe::parse(&image_address_overflow).is_err());

        let mut raw_overflow = base.clone();
        raw_overflow[0x18c..0x190].copy_from_slice(&0xffff_fe00u32.to_le_bytes());
        assert!(Pe::parse(&raw_overflow).is_err());

        let mut virtual_overflow = base.clone();
        virtual_overflow[0x184..0x188].copy_from_slice(&0xffff_f000u32.to_le_bytes());
        assert!(Pe::parse(&virtual_overflow).is_err());

        let mut virtual_padding = base;
        virtual_padding[0x180..0x184].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Pe::parse(&virtual_padding).unwrap().entry_bytes().unwrap(),
            &[0xb8]
        );
        assert!(
            control::translate(Pe::parse(&virtual_padding).unwrap().entry_bytes().unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_section_overlapping_virtual_headers() {
        let mut bytes = fixture(&[0x31, 0xc0, 0xc3]);
        bytes.resize(0x1400, 0);
        bytes[0xd4..0xd8].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[0x18c..0x190].copy_from_slice(&0x1200u32.to_le_bytes());
        assert!(Pe::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_raw_section_extent_beyond_image() {
        let mut bytes = fixture(&[0x31, 0xc0, 0xc3]);
        bytes.resize(0x1400, 0);
        bytes[0x188..0x18c].copy_from_slice(&0x1200u32.to_le_bytes());
        assert!(Pe::parse(&bytes).is_err());
    }

    #[test]
    fn entry_offset_maps_to_code_and_respects_virtual_end() {
        let mut bytes = fixture(&[0x90, 0x90, 0x31, 0xc0, 0xc3]);
        bytes[0xa8..0xac].copy_from_slice(&0x1002u32.to_le_bytes());
        let pe = Pe::parse(&bytes).unwrap();
        assert_eq!(
            control::exit_for_test(pe.entry_bytes().unwrap()).unwrap(),
            0
        );
        bytes[0xa8..0xac].copy_from_slice(&0x1100u32.to_le_bytes());
        assert!(Pe::parse(&bytes).unwrap().entry_bytes().is_err());
    }

    #[test]
    fn evaluates_wrapping_arithmetic_and_exit_range() {
        assert_eq!(
            control::exit_for_test(&[0xb8, 255, 255, 255, 255, 0x05, 3, 0, 0, 0, 0xc3]).unwrap(),
            2
        );
        assert_eq!(
            control::exit_for_test(&[0x31, 0xc0, 0x05, 9, 0, 0, 0, 0xc3]).unwrap(),
            9
        );
        assert_eq!(
            control::exit_for_test(&[0xb8, 255, 0, 0, 0, 0xc3]).unwrap(),
            255
        );
        assert!(control::translate(&[0xb8, 0, 1, 0, 0, 0xc3]).is_err());
        assert!(control::translate(&[0x05, 1, 0, 0, 0, 0xc3]).is_err());
    }
}
