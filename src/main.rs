use std::env;
use std::fmt::Write as _;
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
        if section_count == 0 || section_count > 96 {
            return Err("invalid section count".into());
        }
        let optional_size = u16_at(bytes, coff + 16)? as usize;
        let optional = coff.checked_add(20).ok_or("offset overflow")?;
        range(bytes, optional, optional_size)?;
        if optional_size < 96 || u16_at(bytes, optional)? != 0x10b {
            return Err("invalid PE32 optional header".into());
        }
        let entry_rva = u32_at(bytes, optional + 16)?;
        let section_table = optional
            .checked_add(optional_size)
            .ok_or("offset overflow")?;
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
            let available = (section.raw_size - delta) as usize;
            return range(self.bytes, start, available);
        }
        Err("entry point is not in executable file-backed bytes".into())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Op {
    MovEax(u32),
    AddEax(u32),
    XorEaxEax,
    Ret,
}

fn decode_straight_line(bytes: &[u8]) -> Result<Vec<Op>, String> {
    let mut ops = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() && ops.len() < 1024 {
        let opcode = bytes[at];
        let (op, size) = match opcode {
            0xb8 | 0x05 => {
                let immediate = u32_at(bytes, at + 1)?;
                (
                    if opcode == 0xb8 {
                        Op::MovEax(immediate)
                    } else {
                        Op::AddEax(immediate)
                    },
                    5,
                )
            }
            0x31 if bytes.get(at + 1) == Some(&0xc0) => (Op::XorEaxEax, 2),
            0xc3 => (Op::Ret, 1),
            _ => {
                return Err(format!(
                    "unsupported x86 instruction at entry offset {at}: 0x{opcode:02x}"
                ))
            }
        };
        at += size;
        let done = op == Op::Ret;
        ops.push(op);
        if done {
            if !matches!(ops.first(), Some(Op::MovEax(_) | Op::XorEaxEax)) {
                return Err("entry EAX is unknown before the first operation".into());
            }
            return Ok(ops);
        }
    }
    Err("entry path has no return within 1024 supported instructions".into())
}

fn generate_rust(ops: &[Op]) -> String {
    let mut out = String::from("// Experimental translation of one straight-line x86 entry path.\n// This is not a Windows application compatibility runtime.\nfn translated_entry() -> u32 {\n    let mut eax: u32;\n");
    for op in ops {
        match op {
            Op::MovEax(value) => writeln!(out, "    eax = 0x{value:08x};").unwrap(),
            Op::AddEax(value) => {
                writeln!(out, "    eax = eax.wrapping_add(0x{value:08x});").unwrap()
            }
            Op::XorEaxEax => writeln!(out, "    eax = 0;").unwrap(),
            Op::Ret => writeln!(out, "    return eax;").unwrap(),
        }
    }
    out.push_str("}\nfn main() { std::process::exit((translated_entry() & 0xff) as i32); }\n");
    out
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
    let ops = decode_straight_line(pe.entry_bytes()?)?;
    fs::write(Path::new(&output), generate_rust(&ops)).map_err(|e| e.to_string())
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
        bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
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
        let ops = decode_straight_line(entry).unwrap();
        assert_eq!(ops, vec![Op::MovEax(7), Op::AddEax(5), Op::Ret]);
        assert!(generate_rust(&ops).contains("eax.wrapping_add(0x00000005)"));
    }

    #[test]
    fn rejects_non_pe_and_unsupported_instruction() {
        assert!(Pe::parse(b"not a PE").is_err());
        let bytes = fixture(&[0xeb, 0xfe]);
        assert!(decode_straight_line(Pe::parse(&bytes).unwrap().entry_bytes().unwrap()).is_err());
    }

    #[test]
    fn rejects_entry_outside_executable_raw_data() {
        let mut bytes = fixture(&[0xc3]);
        bytes[0xa8..0xac].copy_from_slice(&0x1200u32.to_le_bytes());
        assert!(Pe::parse(&bytes).unwrap().entry_bytes().is_err());
    }

    #[test]
    fn rejects_use_of_unknown_entry_eax() {
        assert!(decode_straight_line(&[0x05, 1, 0, 0, 0, 0xc3]).is_err());
    }
}
