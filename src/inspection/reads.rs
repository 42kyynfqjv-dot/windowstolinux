//! Private complete-body initialized-data proof. Never constructed from inspection JSON.
use super::*;
use iced_x86::{Decoder, DecoderOptions};
include!("read_state.rs");
struct Proven(Vec<Op>);
impl Proven {
    fn emit(self) -> String {
        format!("// Native initialized-data program; SUB535 conditional domain applies.\n{}\nfn main() {{ use Op::*; let ops = {:?}; match execute(&ops) {{ Ok((v, _)) => std::process::exit(v as i32), Err(e) => {{ eprintln!(\"{{e}}\"); std::process::exit(125); }} }} }}\n", include_str!("read_state.rs"), self.0)
    }
}
pub(super) fn translate(image: Envelope) -> Result<String> {
    need(
        image.closed
            && image
                .dirs
                .iter()
                .enumerate()
                .all(|(i, d)| matches!(i, 5 | 6) || d.is_none()),
        "image reads: metadata closure",
    )?;
    need(
        image.dirs[5].is_some() && !image.pointers.is_empty(),
        "image reads: relocations required",
    )?;
    need(
        image
            .sections
            .iter()
            .filter(|s| s.role == Role::Writable)
            .count()
            == 1
            && image
                .sections
                .iter()
                .all(|s| s.role != Role::Zero && s.virtual_size <= s.size),
        "image reads: initialized sections required",
    )?;
    let code = image
        .sections
        .iter()
        .find(|s| s.role == Role::Code)
        .ok_or("image reads: code")?;
    need(
        image.entry == code.rva,
        "image reads: entry must start code",
    )?;
    image.outside(code.rva, code.virtual_size)?;
    let bytes = range(&image.bytes, code.raw as usize, code.virtual_size as usize)?;
    let mut pc = 0;
    let mut ops = vec![];
    let mut used = std::collections::BTreeSet::new();
    while pc < bytes.len() {
        need(ops.len() < 1024, "image reads: instruction cap")?;
        let tail = &bytes[pc..];
        let (op, length) = if tail.starts_with(&[0x8b, 0x0d]) || tail[0] == 0xa1 {
            let offset = if tail[0] == 0xa1 { 1 } else { 2 };
            let va = u32_at(tail, offset)?;
            let site = code
                .rva
                .checked_add((pc + offset) as u32)
                .ok_or("image reads: site overflow")?;
            let pointer = image
                .pointers
                .iter()
                .find(|p| p.site == site)
                .ok_or("image reads: missing exact HIGHLOW field")?;
            need(
                va.checked_sub(image.base) == Some(pointer.rva),
                "image reads: operand provenance",
            )?;
            let (role, raw) = image.file_location(pointer.rva, 4)?;
            need(
                role == Role::Writable,
                "image reads: initialized data target required",
            )?;
            image.outside(pointer.rva, 4)?;
            used.insert(site);
            let value = image.number(raw)?;
            (
                if offset == 1 {
                    Op::Eax(value)
                } else {
                    Op::Ecx(value)
                },
                offset + 4,
            )
        } else if tail.starts_with(&[0x03, 0xc8]) {
            (Op::AddEcx, 2)
        } else if tail.starts_with(&[0x03, 0xc1]) {
            (Op::AddEax, 2)
        } else if tail[0] == 0xc3 {
            need(pc + 1 == bytes.len(), "image reads: code after return")?;
            (Op::Ret, 1)
        } else {
            return Err(format!("image reads: unsupported effect at +{pc:#x}"));
        };
        let ins = Decoder::with_ip(
            32,
            tail,
            u64::from(code.rva) + pc as u64,
            DecoderOptions::NONE,
        )
        .decode();
        need(
            !ins.is_invalid() && ins.len() == length,
            "image reads: decoder disagreement",
        )?;
        ops.push(op);
        pc += length;
    }
    need(
        used.len() == image.pointers.len(),
        "image reads: unbound loader write",
    )?;
    execute(&ops)?;
    Ok(Proven(ops).emit())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_boundaries_and_read_flag_preservation() {
        for (a, b, cf, zf, sf, of) in [
            (u32::MAX, 1, true, true, false, false),
            (0x7fffffff, 1, false, false, true, true),
            (0x80000000, 0x80000000, true, true, false, true),
        ] {
            let (v, f) =
                execute(&[Op::Eax(a), Op::Ecx(b), Op::AddEcx, Op::Eax(9), Op::Ret]).unwrap();
            assert_eq!(v, 9);
            assert_eq!(
                f,
                Flags {
                    cf: Some(cf),
                    zf: Some(zf),
                    sf: Some(sf),
                    of: Some(of)
                }
            );
        }
        assert!(execute(&[Op::Eax(1), Op::AddEax, Op::Ret]).is_err());
        assert!(execute(&[Op::Eax(256), Op::Ret]).is_err());
        assert!(execute(&[Op::Eax(1)]).is_err());
        assert!(execute(&[Op::Eax(1), Op::Ret, Op::Ret]).is_err());
    }
}
