//! Research-only owned effect for one exact callback. No production imports this module.
use std::{collections::BTreeSet, env, fs};

type Result<T> = std::result::Result<T, &'static str>;
const CALLBACK: &[u8] = &[0xe8, 0x8b, 6, 0, 0, 0x33, 0xc0, 0xc3];
const HELPER: &[u8] = &[
    0xe8, 0xdb, 0xff, 0xff, 0xff, 0x8b, 0x48, 4, 0x83, 8, 0x24, 0x89, 0x48, 4, 0xe8, 0xdd, 0xff,
    0xff, 0xff, 0x8b, 0x48, 4, 0x83, 8, 2, 0x89, 0x48, 4, 0xc3,
];
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn bytes(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..p.checked_add(n).ok_or("offset overflow")?)
        .ok_or("truncated range")
}
fn u32_at(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(b, p, 4)?.try_into().unwrap()))
}
fn u16_at(b: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(b, p, 2)?.try_into().unwrap()))
}
fn overlap(a: u32, n: u32, b: u32, m: u32) -> bool {
    u64::from(a) < u64::from(b) + u64::from(m) && u64::from(b) < u64::from(a) + u64::from(n)
}
#[derive(Clone, Debug)]
struct Section {
    rva: u32,
    virtual_size: u32,
    raw: u32,
    size: u32,
    flags: u32,
}
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    file: Vec<u8>,
    known: Vec<bool>,
    // These are explicit research preconditions, not inferred from a successful baseline.
    blocked: bool,
    exclusive_no_fault_stack: bool,
}
impl Snapshot {
    fn new(file: Vec<u8>) -> Self {
        Self {
            known: vec![true; file.len()],
            file,
            blocked: false,
            exclusive_no_fault_stack: true,
        }
    }
}
struct Bound<'a> {
    snapshot: &'a Snapshot,
    regions: [usize; 2],
}
// A Bound cannot be used with a different snapshot: effect() accepts no state argument.
fn bind(snapshot: &Snapshot) -> Result<Bound<'_>> {
    require(!snapshot.blocked, "prior unknown effect")?;
    require(
        snapshot.exclusive_no_fault_stack,
        "missing ownership/stack precondition",
    )?;
    let b = &snapshot.file;
    require(
        b.len() <= 4 * 1024 * 1024 && snapshot.known.len() == b.len(),
        "snapshot size",
    )?;
    require(bytes(b, 0, 2)? == b"MZ", "DOS signature")?;
    let pe = u32_at(b, 60)? as usize;
    bytes(b, pe, 24 + 224)?;
    require(
        bytes(b, pe, 4)? == b"PE\0\0" && u16_at(b, pe + 4)? == 0x14c,
        "PE32 x86",
    )?;
    require(
        u16_at(b, pe + 20)? == 224 && u16_at(b, pe + 22)? == 0x102,
        "profile COFF",
    )?;
    let opt = pe + 24;
    require(
        u16_at(b, opt)? == 0x10b && u32_at(b, opt + 92)? == 16,
        "profile optional header",
    )?;
    let base = u32_at(b, opt + 28)?;
    require(
        base == 0x400000 && u32_at(b, opt + 56)? == 0x5000,
        "preferred image profile",
    )?;
    let headers = u32_at(b, opt + 60)?;
    require(headers == 0x400, "header profile")?;
    require(u16_at(b, pe + 6)? == 4, "section profile")?;
    let table = opt + 224;
    require(table + 160 <= headers as usize, "section table range")?;
    let mut sections: Vec<Section> = Vec::new();
    for i in 0..4 {
        let p = table + i * 40;
        let s = Section {
            rva: u32_at(b, p + 12)?,
            virtual_size: u32_at(b, p + 8)?,
            raw: u32_at(b, p + 20)?,
            size: u32_at(b, p + 16)?,
            flags: u32_at(b, p + 36)?,
        };
        let expected = [
            (0x1000, 0x60000020),
            (0x2000, 0x40000040),
            (0x3000, 0xc0000040),
            (0x4000, 0x42000040),
        ][i];
        require(
            (s.rva, s.flags) == expected && s.virtual_size > 0 && s.virtual_size <= 0x1000,
            "section permissions/profile",
        )?;
        require(
            s.raw >= headers && s.size > 0 && s.size <= 0x1000,
            "section backing",
        )?;
        bytes(b, s.raw as usize, s.size as usize)?;
        require(
            !sections.iter().any(|a| {
                overlap(a.rva, a.virtual_size, s.rva, s.virtual_size)
                    || overlap(a.raw, a.size, s.raw, s.size)
            }),
            "section alias",
        )?;
        sections.push(s);
    }
    let raw = |rva: u32, n: u32| -> Result<usize> {
        let end = rva.checked_add(n).ok_or("RVA overflow")?;
        let s = sections
            .iter()
            .find(|s| rva >= s.rva && end <= s.rva + s.virtual_size.min(s.size))
            .ok_or("unbacked range")?;
        Ok((s.raw + rva - s.rva) as usize)
    };
    let read = |rva: u32, n: u32| -> Result<&[u8]> {
        let p = raw(rva, n)?;
        require(
            snapshot.known[p..p + n as usize].iter().all(|x| *x),
            "uninitialized read",
        )?;
        bytes(b, p, n as usize)
    };
    // Exact owned regions exclude all other globals (cookie/onexit/TLS etc.).
    // No inference that arbitrary writable data is safe, nor that outside aliases are absent.
    for i in 0..16 {
        let rva = u32_at(b, opt + 96 + i * 8)?;
        let n = u32_at(b, opt + 100 + i * 8)?;
        require((rva == 0) == (n == 0), "partial directory")?;
        if n > 0 {
            require(i != 4, "certificate profile unsupported")?;
            raw(rva, n)?;
            require(!overlap(rva, n, 0x30d0, 16), "metadata alias")?;
        }
    }
    let reloc = u32_at(b, opt + 136)?;
    let len = u32_at(b, opt + 140)?;
    require(reloc == 0x4000 && len >= 8, "relocation directory")?;
    let records = read(reloc, len)?;
    let mut cursor = 0;
    let mut sites = BTreeSet::new();
    while cursor < records.len() {
        let page = u32_at(records, cursor)?;
        let n = u32_at(records, cursor + 4)? as usize;
        require(
            page % 4096 == 0 && n >= 8 && n.is_multiple_of(4),
            "relocation block",
        )?;
        let block = bytes(records, cursor, n)?;
        for p in (8..n).step_by(2) {
            let record = u16_at(block, p)?;
            if record >> 12 == 0 {
                continue;
            }
            require(record >> 12 == 3, "relocation type")?;
            let site = page
                .checked_add(u32::from(record & 4095))
                .ok_or("relocation overflow")?;
            raw(site, 4)?;
            require(
                !overlap(site, 4, 0x30d0, 16) && !overlap(site, 4, reloc, len),
                "relocation metadata/data alias",
            )?;
            require(
                !sites.iter().any(|x| overlap(*x, 4, site, 4)),
                "relocation duplicate/overlap",
            )?;
            sites.insert(site);
        }
        cursor += n;
    }
    // Reject any other relocation-backed pointer into the owned option words.
    // Unresolved non-relocated/external aliases remain an explicit isolation assumption.
    for site in &sites {
        let value = u32_at(b, raw(*site, 4)?)?;
        require(
            !(0x4030d0..0x4030e0).contains(&value) || [0x1751, 0x1761].contains(site),
            "foreign relocated alias",
        )?;
    }
    require(
        [0x20cc, 0x1751, 0x1761].iter().all(|s| sites.contains(s)),
        "missing HIGHLOW provenance",
    )?;
    for (start, n, allowed) in [
        (0x10e0, 8, None),
        (0x1770, 29, None),
        (0x1750, 6, Some(0x1751)),
        (0x1760, 6, Some(0x1761)),
        (0x20cc, 4, Some(0x20cc)),
    ] {
        require(
            !sites
                .iter()
                .any(|s| overlap(*s, 4, start, n) && Some(*s) != allowed),
            "unexpected code/table relocation",
        )?;
    }
    require(
        read(0x20cc, 4)? == (base + 0x10e0).to_le_bytes(),
        "callback target",
    )?;
    require(
        read(0x10e0, 8)? == CALLBACK && read(0x1770, 29)? == HELPER,
        "callback/helper forms",
    )?;
    let mut regions = [0; 2];
    for (i, (accessor, rva)) in [(0x1750, 0x30d0), (0x1760, 0x30d8)].into_iter().enumerate() {
        let code = read(accessor, 6)?;
        require(
            code[0] == 0xb8 && code[5] == 0xc3 && u32_at(code, 1)? == base + rva,
            "accessor/region ownership",
        )?;
        read(rva, 8)?;
        regions[i] = raw(rva, 8)?;
    }
    Ok(Bound { snapshot, regions })
}
#[derive(Debug, PartialEq)]
struct Effect {
    data: [u8; 16],
    ecx: u32,
    helper_flags: [Flags; 2],
}
#[derive(Debug, PartialEq)]
struct Flags {
    cf: bool,
    of: bool,
    zf: bool,
    sf: bool,
    pf: bool,
    af: Option<bool>,
}
impl Flags {
    // Defined arithmetic flags only; AF is deliberately excluded.
    fn defined_mask(&self) -> u32 {
        u32::from(self.cf)
            | (u32::from(self.pf) << 2)
            | (u32::from(self.zf) << 6)
            | (u32::from(self.sf) << 7)
            | (u32::from(self.of) << 11)
    }
}
fn logical_flags(value: u32) -> Flags {
    Flags {
        cf: false,
        of: false,
        zf: value == 0,
        sf: value >> 31 != 0,
        pf: (value as u8).count_ones().is_multiple_of(2),
        af: None,
    }
}
impl Bound<'_> {
    fn effect(&self) -> Effect {
        let mut data = [0; 16];
        for (i, p) in self.regions.iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&self.snapshot.file[*p..*p + 8]);
        }
        let mut lows = [0; 2];
        for (i, mask) in [0x24, 0x02].into_iter().enumerate() {
            let p = i * 8;
            lows[i] = u32_at(&data, p).unwrap() | mask;
            data[p..p + 4].copy_from_slice(&lows[i].to_le_bytes());
        }
        Effect {
            ecx: u32_at(&data, 12).unwrap(),
            data,
            helper_flags: lows.map(logical_flags),
        }
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    require(
        args.len() == 2 || args.len() == 4 && args[2] == "--vector",
        "usage: crt_option_state PE [--vector HEX16]",
    )?;
    let mut snapshot = Snapshot::new(fs::read(&args[1]).map_err(|_| "read snapshot")?);
    let original = bind(&snapshot)?;
    let regions = original.regions;
    let source = original.effect();
    if args.len() == 4 {
        let input = &args[3];
        require(input.len() == 32 && input.is_ascii(), "vector length")?;
        let values: Vec<_> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| "vector hex"))
            .collect::<Result<_>>()?;
        for (i, p) in regions.iter().enumerate() {
            snapshot.file[*p..*p + 8].copy_from_slice(&values[i * 8..i * 8 + 8]);
        }
    }
    let effect = bind(&snapshot)?.effect();
    let flags = logical_flags(0);
    println!("{{\"after\":\"{}\",\"eax\":0,\"ecx\":{},\"cf\":{},\"of\":{},\"zf\":{},\"sf\":{},\"pf\":{},\"af\":null,\"stack_delta_from_callback_entry\":4,\"peak_stack_bytes_below_entry\":8,\"preserved_registers\":[\"ebx\",\"edx\",\"esi\",\"edi\",\"ebp\"],\"helper_defined_flags\":[{},{}],\"exclusive_owned_no_fault_assumption\":true,\"source_after\":\"{}\",\"synthetic_vector\":{},\"emission_allowed\":false,\"complete_startup_proof\":false}}",
        hex(&effect.data),effect.ecx,flags.cf,flags.of,flags.zf,flags.sf,flags.pf,effect.helper_flags[0].defined_mask(),effect.helper_flags[1].defined_mask(),hex(&source.data),args.len()==4);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("option-state rejected: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(b: &mut [u8], p: usize, v: u32) {
        b[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fixture() -> Snapshot {
        // Independently authored minimal profile, not a runnable Windows fixture.
        let mut b = vec![0; 0x2400];
        b[..2].copy_from_slice(b"MZ");
        put(&mut b, 60, 0x80);
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x88].copy_from_slice(&[0x4c, 1, 4, 0]);
        b[0x94..0x98].copy_from_slice(&[0xe0, 0, 2, 1]);
        b[0x98..0x9a].copy_from_slice(&[0xb, 1]);
        for (p, v) in [
            (0xb4, 0x400000),
            (0xd0, 0x5000),
            (0xd4, 0x400),
            (0xf4, 16),
            (0x120, 0x4000),
            (0x124, 28),
        ] {
            put(&mut b, p, v);
        }
        for (i, (rva, pos, flags)) in [
            (0x1000, 0x400, 0x60000020),
            (0x2000, 0x1400, 0x40000040),
            (0x3000, 0x1c00, 0xc0000040),
            (0x4000, 0x2000, 0x42000040),
        ]
        .into_iter()
        .enumerate()
        {
            let p = 0x178 + i * 40;
            let n = if i == 0 {
                0x1000
            } else if i == 1 {
                0x800
            } else {
                0x400
            };
            for (off, v) in [(8, n), (12, rva), (16, n), (20, pos), (36, flags)] {
                put(&mut b, p + off, v);
            }
        }
        b[0x4e0..0x4e8].copy_from_slice(CALLBACK);
        b[0xb70..0xb8d].copy_from_slice(HELPER);
        for (p, v) in [(0xb50, 0x4030d0), (0xb60, 0x4030d8)] {
            b[p] = 0xb8;
            put(&mut b, p + 1, v);
            b[p + 5] = 0xc3;
        }
        put(&mut b, 0x14cc, 0x4010e0);
        put(&mut b, 0x2000, 0x1000);
        put(&mut b, 0x2004, 12);
        b[0x2008..0x200c].copy_from_slice(&[0x51, 0x37, 0x61, 0x37]);
        put(&mut b, 0x200c, 0x2000);
        put(&mut b, 0x2010, 16);
        b[0x2014..0x2016].copy_from_slice(&[0xcc, 0x30]);
        Snapshot::new(b)
    }
    fn rejects(s: Snapshot, reason: &str) {
        let before = s.clone();
        assert_eq!(bind(&s).err().unwrap(), reason);
        assert_eq!(s, before);
    }
    #[test]
    fn effects_and_full_write_footprint() {
        let mut s = fixture();
        s.file[0x1cd0..0x1ce0].copy_from_slice(&[
            0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x90,
        ]);
        let before = s.clone();
        let e = bind(&s).unwrap().effect();
        assert_eq!(hex(&e.data), "240000007856341202000000efcdab90");
        assert_eq!(e.ecx, 0x90abcdef);
        assert_eq!(s, before);
        assert_eq!(
            e.helper_flags[0],
            Flags {
                cf: false,
                of: false,
                zf: false,
                sf: false,
                pf: true,
                af: None
            }
        );
        assert_eq!(
            e.helper_flags[1],
            Flags {
                cf: false,
                of: false,
                zf: false,
                sf: false,
                pf: false,
                af: None
            }
        );
    }
    #[test]
    fn both_high_words_must_be_known() {
        for p in [0x1cdf, 0x1cd4] {
            let mut s = fixture();
            s.known[p] = false;
            rejects(s, "uninitialized read");
        }
    }
    #[test]
    fn reject_region_aliases_and_foreign_targets() {
        // Partial overlap, callback table, import metadata, neighboring protected state, another image VA.
        for address in [0x4030d7, 0x4020cc, 0x402000, 0x4030c8, 0x5030d8] {
            let mut s = fixture();
            put(&mut s.file, 0xb61, address);
            rejects(s, "accessor/region ownership");
        }
    }
    #[test]
    fn no_cross_snapshot_binding() {
        let a = fixture();
        let mut b = fixture();
        b.file[0x1cdc] = 0x5a;
        let bound_a = bind(&a).unwrap();
        let bound_b = bind(&b).unwrap();
        assert_eq!(bound_a.effect().ecx, 0);
        assert_eq!(bound_b.effect().ecx, 0x5a);
        // effect has no second image/state/region parameter. The borrow pins each input.
    }
    #[test]
    fn missing_or_overlapping_relocations() {
        let mut s = fixture();
        s.file[0x200a] = 0;
        s.file[0x200b] = 0;
        rejects(s, "missing HIGHLOW provenance");
        let mut s = fixture();
        s.file[0x200a] = 0x52;
        rejects(s, "relocation duplicate/overlap");
    }
    #[test]
    fn every_bound_instruction_byte_matters() {
        for (p, n) in [(0x4e0, 8), (0xb70, 29), (0xb50, 6), (0xb60, 6)] {
            for i in 0..n {
                let mut s = fixture();
                s.file[p + i] ^= 1;
                let before = s.clone();
                assert!(bind(&s).is_err());
                assert_eq!(s, before);
            }
        }
    }
    #[test]
    fn unknown_effect_and_stack_assumptions_block() {
        let mut s = fixture();
        s.blocked = true;
        rejects(s, "prior unknown effect");
        let mut s = fixture();
        s.exclusive_no_fault_stack = false;
        rejects(s, "missing ownership/stack precondition");
    }
    #[test]
    fn complete_region_bounds_and_permissions() {
        let mut s = fixture();
        put(&mut s.file, 0x178 + 2 * 40 + 8, 0xdf);
        rejects(s, "unbacked range");
        let mut s = fixture();
        put(&mut s.file, 0x178 + 2 * 40 + 36, 0xe0000040);
        rejects(s, "section permissions/profile");
        let mut s = fixture();
        put(&mut s.file, 0x178 + 2 * 40 + 20, 0x1400);
        rejects(s, "section alias");
    }
    #[test]
    fn metadata_and_relocation_cannot_alias_options() {
        let mut s = fixture();
        put(&mut s.file, 0xf8, 0x30d8);
        put(&mut s.file, 0xfc, 8);
        rejects(s, "metadata alias");
        let mut s = fixture();
        put(&mut s.file, 0x200c, 0x3000);
        s.file[0x2014..0x2016].copy_from_slice(&[0xd0, 0x30]);
        rejects(s, "relocation metadata/data alias");
    }
    #[test]
    fn foreign_relocated_alias_is_not_owner_authority() {
        let mut s = fixture();
        s.file[0x2016..0x2018].copy_from_slice(&[0xd0, 0x30]);
        put(&mut s.file, 0x14d0, 0x4030d8);
        rejects(s, "foreign relocated alias");
    }
    #[test]
    fn truncations_reject_without_panics() {
        let s = fixture();
        for n in 0..s.file.len() {
            let short = Snapshot::new(s.file[..n].to_vec());
            assert!(bind(&short).is_err());
        }
    }
}
