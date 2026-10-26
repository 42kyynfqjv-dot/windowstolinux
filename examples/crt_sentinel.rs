//! Research-only exact local effect. Never imported by the production converter.
use std::{collections::BTreeSet, env, fs};
type Result<T> = std::result::Result<T, &'static str>;
const HELPER: &[u8] = &[
    85, 139, 236, 128, 61, 169, 48, 64, 0, 0, 116, 4, 176, 1, 93, 195, 86, 139, 117, 8, 133, 246,
    116, 5, 131, 254, 1, 117, 124, 232, 94, 8, 0, 0, 133, 192, 116, 43, 133, 246, 117, 39, 104,
    172, 48, 64, 0, 232, 248, 8, 0, 0, 131, 196, 4, 133, 192, 117, 17, 104, 184, 48, 64, 0, 232,
    231, 8, 0, 0, 131, 196, 4, 133, 192, 116, 65, 50, 192, 94, 93, 195, 199, 5, 172, 48, 64, 0,
    255, 255, 255, 255, 199, 5, 176, 48, 64, 0, 255, 255, 255, 255, 199, 5, 180, 48, 64, 0, 255,
    255, 255, 255, 199, 5, 184, 48, 64, 0, 255, 255, 255, 255, 199, 5, 188, 48, 64, 0, 255, 255,
    255, 255, 199, 5, 192, 48, 64, 0, 255, 255, 255, 255, 198, 5, 169, 48, 64, 0, 1, 176, 1, 94,
    93, 195, 106, 5, 232, 64, 3, 0, 0, 204,
];
const WRAPPER: &[u8] = &[
    85, 139, 236, 131, 61, 172, 48, 64, 0, 255, 86, 139, 117, 8, 86, 117, 27, 232, 66, 7, 0, 0, 51,
    201, 131, 196, 4, 133, 192, 15, 68, 206, 247, 217, 94, 27, 201, 247, 217, 141, 65, 255, 93,
    195, 104, 172, 48, 64, 0, 232, 28, 7, 0, 0, 51, 201, 131, 196, 8, 133, 192, 15, 68, 206, 247,
    217, 94, 27, 201, 247, 217, 141, 65, 255, 93, 195,
];
const QUERY: &[u8] = &[51, 192, 57, 5, 152, 48, 64, 0, 15, 149, 192, 195];
const FASTFAIL: &[u8] = &[85, 139, 236, 139, 77, 8, 205, 41, 93, 195];
const REQUIRED: &[u32] = &[
    0x13e5, 0x140b, 0x141c, 0x1433, 0x143d, 0x1447, 0x1451, 0x145b, 0x1465, 0x146f, 0x15c5, 0x15ed,
    0x1c64, 0x20c8,
];
fn owned_overlap(r: u32, n: u32) -> bool {
    [(0x3098, 4), (0x30a9, 1), (0x30ac, 24)]
        .iter()
        .any(|(p, m)| overlap(r, n, *p, *m))
}
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
    flag: usize,
    mode: usize,
    tables: usize,
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
    require(
        snapshot
            .known
            .iter()
            .enumerate()
            .all(|(i, k)| *k || i >= 0x400),
        "unknown headers",
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
            require(
                ([1, 5, 6, 10, 12].contains(&i)) && !overlap(rva, n, 0x3000, 0x1000),
                "metadata alias",
            )?;
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
                !owned_overlap(site, 4) && !overlap(site, 4, reloc, len),
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
    // All non-data mapped bytes carry known snapshot provenance, including directories.
    // Only the six overwritten words may have unknown incoming contents.
    let flag = raw(0x30a9, 1)?;
    let mode = raw(0x3098, 4)?;
    let tables = raw(0x30ac, 24)?;
    require(
        snapshot
            .known
            .iter()
            .enumerate()
            .all(|(i, k)| *k || (tables..tables + 24).contains(&i)),
        "unknown snapshot state",
    )?;
    // Load config's declared extent may exceed the directory extent (this MSVC image does).
    let lc = u32_at(b, opt + 176)?;
    require(
        lc == 0x20f0 && u32_at(b, opt + 180)? == 64,
        "load config profile",
    )?;
    let config = read(lc, 192)?;
    require(
        u32_at(config, 0)? == 192
            && u32_at(config, 32)? == 0
            && u32_at(config, 56)? == 0
            && u32_at(config, 60)? == 0x403040,
        "protected load config pointers",
    )?;
    // Bind the observed load-config tail including SafeSEH/CFG metadata pointers.
    let mut tail = [0u8; 128];
    for (offset, value) in [
        (0, 0x402200u32),
        (4, 1),
        (8, 0x4020b0),
        (24, 0x100),
        (96, 0x402204),
        (120, 0x4020b4),
    ] {
        tail[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for site in [lc + 64, lc + 72, lc + 160, lc + 184] {
        require(sites.contains(&site), "load config provenance")?;
    }
    require(config[64..] == tail, "unsupported load config tail")?;
    require(sites.contains(&(lc + 60)), "cookie relocation")?;
    require(
        REQUIRED.iter().all(|s| sites.contains(s)),
        "missing HIGHLOW provenance",
    )?;
    for (rva, code) in [
        (0x13e0, HELPER),
        (0x15c0, WRAPPER),
        (0x1c60, QUERY),
        (0x17c0, FASTFAIL),
        (0x104f, &[0x6a, 1, 0x89, 0x30, 0xe8, 0x88, 3, 0, 0][..]),
    ] {
        require(
            read(rva, code.len() as u32)? == code,
            "exact helper/caller/query bytes",
        )?;
        require(
            !sites
                .iter()
                .any(|site| overlap(*site, 4, rva, code.len() as u32) && !REQUIRED.contains(site)),
            "unexpected code relocation",
        )?;
    }
    require(
        read(0x20c8, 4)? == 0x401030u32.to_le_bytes(),
        "callback target",
    )?;
    require(
        !sites
            .iter()
            .any(|s| overlap(*s, 4, 0x20c8, 4) && *s != 0x20c8),
        "callback relocation",
    )?;
    // Bind every admitted pointer into the regions, including wrapper operands whose
    // external effect remains blocked. Never infer absence of dynamic foreign aliases.
    for site in &sites {
        let value = u32_at(b, raw(*site, 4)?)?;
        if let Some(rva) = value.checked_sub(base) {
            require(
                !owned_overlap(rva, 1) || REQUIRED.contains(site),
                "foreign relocated alias",
            )?;
        }
    }
    Ok(Bound {
        snapshot,
        flag,
        mode,
        tables,
    })
}
#[derive(Clone, Copy, Debug, PartialEq)]
struct Bits {
    value: u32,
    known: u32,
}
impl Bits {
    fn new(value: u32, known: u32) -> Result<Self> {
        require(value & !known == 0, "noncanonical unknown bits")?;
        Ok(Self { value, known })
    }
}
#[derive(Debug, PartialEq)]
struct Flags {
    cf: bool,
    pf: bool,
    af: Option<bool>,
    zf: bool,
    sf: bool,
    of: bool,
}
impl Flags {
    fn mask(&self) -> u32 {
        u32::from(self.cf)
            | u32::from(self.pf) << 2
            | u32::from(self.zf) << 6
            | u32::from(self.sf) << 7
            | u32::from(self.of) << 11
    }
}
#[derive(Debug, PartialEq)]
struct Effect {
    eax: Bits,
    flags: Flags,
    writes: Vec<(u32, Vec<u8>)>,
    peak: u32,
}
impl Bound<'_> {
    // No substitute image, arbitrary address, writable memory or transferable owner token.
    fn effect(&self, policy: Option<u32>, incoming: Bits) -> Result<Effect> {
        let flag = self.snapshot.file[self.flag];
        if flag != 0 {
            // CMP byte,0; MOV AL,1: AF=0, CF=OF=0, sign is bit7 of the byte.
            return Ok(Effect {
                eax: Bits {
                    value: (incoming.value & 0xffffff00) | 1,
                    known: incoming.known | 255,
                },
                flags: Flags {
                    cf: false,
                    pf: flag.count_ones().is_multiple_of(2),
                    af: Some(false),
                    zf: false,
                    sf: flag & 128 != 0,
                    of: false,
                },
                writes: vec![],
                peak: 4,
            });
        }
        require(
            policy == Some(1),
            "only local policy 1; no imported/fastfail fallback",
        )?;
        let mode = u32_at(&self.snapshot.file, self.mode)?;
        // Query XOR/CMP/SETNE; TEST EAX; if nonzero TEST ESI (known policy1).
        // MOV stores, POPs and RET preserve these final arithmetic flags. AF undefined.
        let zero = mode == 0;
        let mut writes = Vec::new();
        for rva in (0x30ac..0x30c4).step_by(4) {
            writes.push((rva, vec![255; 4]));
        }
        writes.push((0x30a9, vec![1]));
        Ok(Effect {
            eax: Bits {
                value: 1,
                known: u32::MAX,
            },
            flags: Flags {
                cf: false,
                pf: zero,
                af: None,
                zf: zero,
                sf: false,
                of: false,
            },
            writes,
            peak: 12,
        })
    }
    fn table_hex(&self, e: &Effect) -> String {
        if !e.writes.is_empty() {
            return "ff".repeat(24);
        }
        (self.tables..self.tables + 24)
            .map(|i| {
                if self.snapshot.known[i] {
                    format!("{:02x}", self.snapshot.file[i])
                } else {
                    "??".into()
                }
            })
            .collect()
    }
}
fn integer(s: &str) -> Result<u32> {
    require(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "unsigned integer required",
    )?;
    s.parse().map_err(|_| "integer out of range")
}
fn parse_hex(s: &str) -> Result<Vec<u8>> {
    require(s.len() == 48 && s.is_ascii(), "24-byte vector required")?;
    (0..48)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "hex bytes required"))
        .collect()
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    require(
        args.len() == 2 || args.len() == 9 && args[2] == "--vector",
        "usage: crt_sentinel PE [--vector FLAG MODE POLICY EAX KNOWN_MASK HEX24]",
    )?;
    let mut snapshot = Snapshot::new(fs::read(&args[1]).map_err(|_| "read snapshot")?);
    let original = bind(&snapshot)?;
    let (flag, mode, tables) = (original.flag, original.mode, original.tables);
    let mut policy = Some(1);
    let mut incoming = Bits::new(0, 0)?;
    if args.len() == 9 {
        let value = integer(&args[3])?;
        snapshot.file[flag] = u8::try_from(value).map_err(|_| "flag width")?;
        snapshot.file[mode..mode + 4].copy_from_slice(&integer(&args[4])?.to_le_bytes());
        policy = if args[5] == "?" {
            None
        } else {
            Some(integer(&args[5])?)
        };
        incoming = Bits::new(integer(&args[6])?, integer(&args[7])?)?;
        snapshot.file[tables..tables + 24].copy_from_slice(&parse_hex(&args[8])?);
    }
    let bound = bind(&snapshot)?;
    let e = bound.effect(policy, incoming)?;
    let writes = e
        .writes
        .iter()
        .map(|(r, b)| {
            format!(
                "[{},\"{}\"]",
                r,
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    println!("{{\"tables_after\":\"{}\",\"flag_after\":{},\"eax\":{},\"eax_known\":{},\"defined_flags\":{},\"af\":{},\"writes\":[{}],\"peak_stack_bytes_below_entry\":{},\"stack_delta_from_helper_entry\":4,\"preserved_registers\":[\"ebx\",\"ecx\",\"edx\",\"esi\",\"edi\",\"ebp\"],\"synthetic_vector\":{},\"isolated_owned_no_fault_assumption\":true,\"prior_effects_closed\":false,\"complete_startup_proof\":false,\"emission_allowed\":false}}",bound.table_hex(&e),if e.writes.is_empty(){snapshot.file[flag]}else{1},e.eax.value,e.eax.known,e.flags.mask(),e.flags.af.map_or("null",|v|if v{"true"}else{"false"}),writes,e.peak,args.len()==9);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("sentinel rejected: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(b: &mut [u8], p: usize, v: u32) {
        b[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn pos(r: u32) -> usize {
        match r {
            0x1000..=0x1fff => (r - 0x1000 + 0x400) as usize,
            0x2000..=0x2fff => (r - 0x2000 + 0x1400) as usize,
            0x3000..=0x3fff => (r - 0x3000 + 0x2400) as usize,
            _ => (r - 0x4000 + 0x2800) as usize,
        }
    }
    fn fixture() -> Snapshot {
        // Authored structural PE profile, never a Windows executable. Code literals
        // construct the binding premise; expected effects below do not decode it.
        let mut b = vec![0; 0x2c00];
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
            (0x148, 0x20f0),
            (0x14c, 64),
        ] {
            put(&mut b, p, v);
        }
        for (i, (rva, n, flags)) in [
            (0x1000, 0x1000, 0x60000020),
            (0x2000, 0x1000, 0x40000040),
            (0x3000, 0x400, 0xc0000040),
            (0x4000, 0x400, 0x42000040),
        ]
        .into_iter()
        .enumerate()
        {
            for (off, v) in [
                (8, n),
                (12, rva),
                (16, n),
                (20, pos(rva) as u32),
                (36, flags),
            ] {
                put(&mut b, 0x178 + i * 40 + off, v);
            }
        }
        for (r, code) in [
            (0x13e0, HELPER),
            (0x15c0, WRAPPER),
            (0x1c60, QUERY),
            (0x17c0, FASTFAIL),
            (0x104f, &[0x6a, 1, 0x89, 0x30, 0xe8, 0x88, 3, 0, 0][..]),
        ] {
            let p = pos(r);
            b[p..p + code.len()].copy_from_slice(code);
        }
        put(&mut b, pos(0x20c8), 0x401030);
        for (off, v) in [
            (0, 192),
            (60, 0x403040),
            (64, 0x402200),
            (68, 1),
            (72, 0x4020b0),
            (88, 0x100),
            (160, 0x402204),
            (184, 0x4020b4),
        ] {
            put(&mut b, pos(0x20f0) + off, v);
        }
        let mut cursor = pos(0x4000);
        for page in [0x1000, 0x2000] {
            let sites: Vec<_> = REQUIRED
                .iter()
                .copied()
                .chain([0x212c, 0x2130, 0x2138, 0x2190, 0x21a8])
                .filter(|s| s & !4095 == page)
                .collect();
            let n = (8 + sites.len() * 2).next_multiple_of(4);
            put(&mut b, cursor, page);
            put(&mut b, cursor + 4, n as u32);
            for (i, s) in sites.iter().enumerate() {
                b[cursor + 8 + i * 2..cursor + 10 + i * 2]
                    .copy_from_slice(&(0x3000 | (*s as u16 & 4095)).to_le_bytes());
            }
            cursor += n;
        }
        put(&mut b, 0x124, (cursor - pos(0x4000)) as u32);
        Snapshot::new(b)
    }
    fn rejects(s: Snapshot) {
        let before = s.clone();
        assert!(bind(&s).is_err());
        assert_eq!(s, before);
    }
    #[test]
    fn literal_write_footprint_and_flags() {
        let mut s = fixture();
        s.file[pos(0x30ac)..pos(0x30c4)].fill(0x5a);
        s.known[pos(0x30ac)..pos(0x30c4)].fill(false);
        let before = s.clone();
        let e = bind(&s)
            .unwrap()
            .effect(Some(1), Bits::new(0, 0).unwrap())
            .unwrap();
        assert_eq!(
            e.writes,
            vec![
                (0x30ac, vec![255; 4]),
                (0x30b0, vec![255; 4]),
                (0x30b4, vec![255; 4]),
                (0x30b8, vec![255; 4]),
                (0x30bc, vec![255; 4]),
                (0x30c0, vec![255; 4]),
                (0x30a9, vec![1])
            ]
        );
        assert_eq!(
            (e.eax.value, e.eax.known, e.flags.mask(), e.flags.af, e.peak),
            (1, u32::MAX, 0x44, None, 12)
        );
        assert_eq!(s, before);
    }
    #[test]
    fn nonzero_mode_does_not_leak_query_flags() {
        for mode in [1, 0x80000000, u32::MAX] {
            let mut s = fixture();
            put(&mut s.file, pos(0x3098), mode);
            let e = bind(&s)
                .unwrap()
                .effect(Some(1), Bits::new(0xdeadbeef, u32::MAX).unwrap())
                .unwrap();
            assert_eq!((e.eax.value, e.flags.mask(), e.flags.af), (1, 0, None));
        }
    }
    #[test]
    fn early_return_all_byte_sign_parity_boundaries() {
        for (flag, mask) in [(1, 0), (2, 0), (3, 4), (127, 0), (128, 128), (255, 132)] {
            let mut s = fixture();
            s.file[pos(0x30a9)] = flag;
            let e = bind(&s)
                .unwrap()
                .effect(None, Bits::new(0xdeadbeef, u32::MAX).unwrap())
                .unwrap();
            assert_eq!(
                (e.eax.value, e.eax.known, e.flags.mask(), e.flags.af, e.peak),
                (0xdeadbe01, u32::MAX, mask, Some(false), 4)
            );
            assert!(e.writes.is_empty());
        }
    }
    #[test]
    fn unknown_eax_bits_preserved_and_unknown_table_not_read() {
        let mut s = fixture();
        s.file[pos(0x30a9)] = 1;
        s.known[pos(0x30ac)..pos(0x30c4)].fill(false);
        let b = bind(&s).unwrap();
        let e = b
            .effect(Some(99), Bits::new(0x80000000, 0x80000000).unwrap())
            .unwrap();
        assert_eq!((e.eax.value, e.eax.known), (0x80000001, 0x800000ff));
        assert_eq!(b.table_hex(&e), "??".repeat(24));
        assert!(e.writes.is_empty());
    }
    #[test]
    fn no_policy_fallback() {
        let s = fixture();
        let b = bind(&s).unwrap();
        for policy in [None, Some(0), Some(2), Some(u32::MAX)] {
            assert!(b.effect(policy, Bits::new(0, 0).unwrap()).is_err());
        }
    }
    #[test]
    fn integer_width_and_fractional_rejection() {
        for s in ["0.5", "1.0", "-1", "4294967296", "NaN", "+1", "1e0", ""] {
            assert!(integer(s).is_err());
        }
        assert_eq!(integer("4294967295"), Ok(u32::MAX));
        assert!(Bits::new(1, 0).is_err());
        for s in ["ff", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"] {
            assert!(parse_hex(s).is_err());
        }
    }
    #[test]
    fn unknown_inputs_and_prior_effects_block() {
        for r in [0x3098, 0x309b, 0x30a9, 0x13e0, 0x4000] {
            let mut s = fixture();
            s.known[pos(r)] = false;
            rejects(s);
        }
        let mut s = fixture();
        s.blocked = true;
        rejects(s);
        let mut s = fixture();
        s.exclusive_no_fault_stack = false;
        rejects(s);
    }
    #[test]
    fn binding_lifetime_cannot_substitute_an_image() {
        let a = fixture();
        let mut b = fixture();
        b.file[pos(0x30a9)] = 128;
        let ba = bind(&a).unwrap();
        let bb = bind(&b).unwrap();
        assert_eq!(
            ba.effect(Some(1), Bits::new(0, 0).unwrap())
                .unwrap()
                .writes
                .len(),
            7
        );
        assert_eq!(
            bb.effect(None, Bits::new(0, 0).unwrap())
                .unwrap()
                .writes
                .len(),
            0
        );
    }
    #[test]
    fn every_bound_byte_is_required() {
        for (r, n) in [
            (0x13e0, 161),
            (0x15c0, 76),
            (0x1c60, 12),
            (0x17c0, 10),
            (0x104f, 9),
            (0x20c8, 4),
        ] {
            for i in 0..n {
                let mut s = fixture();
                s.file[pos(r) + i] ^= 1;
                rejects(s);
            }
        }
    }
    #[test]
    fn complete_backing_permissions_and_aliases() {
        for (off, v) in [(8, 0xc3), (16, 0xc3), (36, 0xe0000040), (20, 0x1400)] {
            let mut s = fixture();
            put(&mut s.file, 0x178 + 80 + off, v);
            rejects(s);
        }
        let mut s = fixture();
        put(&mut s.file, 0xb4, 0x500000);
        rejects(s);
    }
    #[test]
    fn directories_and_cookie_cannot_alias_owned_state() {
        for dir in [0, 1, 4, 9, 10, 12] {
            let mut s = fixture();
            put(&mut s.file, 0xf8 + dir * 8, 0x30ac);
            put(&mut s.file, 0xfc + dir * 8, 12);
            rejects(s);
        }
        let mut s = fixture();
        put(&mut s.file, pos(0x212c), 0x4030ac);
        rejects(s);
    }
    #[test]
    fn missing_duplicate_or_foreign_relocations() {
        let s = fixture();
        for i in 0..REQUIRED.len() {
            let mut t = s.clone();
            let mut found = false;
            let mut c = pos(0x4000);
            while c < pos(0x4000) + u32_at(&t.file, 0x124).unwrap() as usize {
                let page = u32_at(&t.file, c).unwrap();
                let n = u32_at(&t.file, c + 4).unwrap() as usize;
                for p in (c + 8..c + n).step_by(2) {
                    if page + u32::from(u16_at(&t.file, p).unwrap() & 4095) == REQUIRED[i] {
                        t.file[p..p + 2].fill(0);
                        found = true;
                    }
                }
                c += n;
            }
            assert!(found);
            rejects(t);
        }
        let mut t = s.clone();
        t.file[pos(0x4000) + 10..pos(0x4000) + 12].copy_from_slice(&0x33e6u16.to_le_bytes());
        rejects(t);
        let mut t = s;
        put(&mut t.file, pos(0x21a8), 0x4030ac);
        rejects(t);
    }
    #[test]
    fn additional_pointer_and_bad_record_types_reject() {
        // The first page has a padding record. Turn it into a pointer outside
        // the bound bodies: this exercises alias rejection, not byte mismatch.
        let mut s = fixture();
        let n = u32_at(&s.file, pos(0x4000) + 4).unwrap() as usize;
        s.file[pos(0x4000) + n - 2..pos(0x4000) + n].copy_from_slice(&0x3d00u16.to_le_bytes());
        put(&mut s.file, pos(0x1d00), 0x4030b7);
        assert_eq!(bind(&s).err(), Some("foreign relocated alias"));
        for record in [0x13e5u16, 0x43e5, 0xa3e5] {
            let mut s = fixture();
            s.file[pos(0x4000) + 8..pos(0x4000) + 10].copy_from_slice(&record.to_le_bytes());
            rejects(s);
        }
        let mut s = fixture();
        put(&mut s.file, pos(0x4000) + 4, 7);
        rejects(s);
    }
    #[test]
    fn truncations_and_overflows_reject_without_panics() {
        let s = fixture();
        for n in 0..s.file.len() {
            assert!(bind(&Snapshot::new(s.file[..n].to_vec())).is_err());
        }
        for p in [60, 0x120, 0x124, 0x178 + 20] {
            let mut t = s.clone();
            put(&mut t.file, p, u32::MAX);
            rejects(t);
        }
    }
}

// Research-only binding reused by the external-cell example. No production caller.
#[allow(dead_code)]
pub(crate) fn validate_external_caller(file: &[u8]) -> Result<()> {
    let snapshot = Snapshot::new(file.to_vec());
    bind(&snapshot)?;
    let opt = u32_at(file, 60)? as usize + 24;
    let raw = |r: u32, n: u32| -> Result<usize> {
        let end = r.checked_add(n).ok_or("range overflow")?;
        for i in 0..4 {
            let p = opt + 224 + i * 40;
            let start = u32_at(file, p + 12)?;
            let size = u32_at(file, p + 8)?.min(u32_at(file, p + 16)?);
            if r >= start && end <= start + size {
                return Ok((u32_at(file, p + 20)? + r - start) as usize);
            }
        }
        Err("unbacked caller/import")
    };
    let read = |r, n| -> Result<&[u8]> { bytes(file, raw(r, n)?, n as usize) };
    require(
        read(0x1043, 19)?
            == [
                0xe8, 0x78, 6, 0, 0, 0x8b, 0xf0, 0xe8, 0xb7, 0x0c, 0, 0, 0x6a, 1, 0x89, 0x30, 0xe8,
                0x88, 3,
            ],
        "zero caller prefix",
    )?;
    require(
        read(0x1056, 2)? == [0, 0]
            && read(0x16c0, 3)? == [0x33, 0xc0, 0xc3]
            && read(0x1d06, 6)? == [0xff, 0x25, 0xa8, 0x20, 0x40, 0],
        "caller/helper/thunk",
    )?;
    let mut c = u32_at(file, opt + 136)?;
    let end = c + u32_at(file, opt + 140)?;
    let mut thunk = false;
    while c < end {
        let block = read(c, 8)?;
        let page = u32_at(block, 0)?;
        let n = u32_at(block, 4)?;
        for i in (8..n).step_by(2) {
            let v = u16_at(read(c + i, 2)?, 0)?;
            if v >> 12 != 3 {
                continue;
            }
            let site = page + u32::from(v & 4095);
            if site == 0x1d08 {
                thunk = true;
            }
            require(
                ![(0x1043, 21), (0x16c0, 3), (0x1d06, 6)]
                    .iter()
                    .any(|(p, n)| overlap(site, 4, *p, *n))
                    || site == 0x1d08,
                "caller relocation",
            )?;
        }
        c += n;
    }
    require(thunk, "thunk HIGHLOW")?;
    let string = |r: u32| -> Result<String> {
        let mut b = Vec::new();
        for i in 0..256 {
            let v = read(r.checked_add(i).ok_or("string overflow")?, 1)?[0];
            if v == 0 {
                return String::from_utf8(b).map_err(|_| "import UTF8");
            }
            b.push(v);
        }
        Err("import name cap")
    };
    let dir = u32_at(file, opt + 104)?;
    let len = u32_at(file, opt + 108)?;
    require((20..=640).contains(&len), "import directory cap")?;
    let mut found = false;
    let mut terminated = false;
    for j in 0..len / 20 {
        let d = read(dir + j * 20, 20)?;
        if d.iter().all(|b| *b == 0) {
            terminated = true;
            break;
        }
        let orig = u32_at(d, 0)?;
        let iat = u32_at(d, 16)?;
        let dll = string(u32_at(d, 12)?)?;
        let mut end = false;
        for i in 0..256u32 {
            let v = u32_at(
                read(orig.checked_add(i * 4).ok_or("thunk overflow")?, 4)?,
                0,
            )?;
            if v == 0 {
                end = true;
                break;
            }
            let slot = iat.checked_add(i * 4).ok_or("IAT overflow")?;
            require(v < 0x80000000, "ordinal import")?;
            if slot == 0x20a8 {
                require(
                    !found
                        && dll == "api-ms-win-crt-stdio-l1-1-0.dll"
                        && string(v.checked_add(2).ok_or("name overflow")?)? == "__p__commode",
                    "exact accessor import",
                )?;
                found = true;
            }
        }
        require(end, "unterminated thunk")?;
    }
    require(found && terminated, "accessor descriptor")
}
