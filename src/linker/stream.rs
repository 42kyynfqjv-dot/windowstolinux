//! Checked stream imports and whole-graph function-token propagation.
//! Binding is not an execution capability: cyclic frame/epoch proof is separate.
use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[path = "../stream/graph.rs"]
mod graph;
use graph::{Binary, Operand, Operation};
mod emit;
mod frame;
mod logic;
mod solver;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Function {
    Read,
    Write,
    LastError,
    StandardHandle,
}
impl Function {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Read => b"ReadFile\0",
            Self::Write => b"WriteFile\0",
            Self::LastError => b"GetLastError\0",
            Self::StandardHandle => b"GetStdHandle\0",
        }
    }
}
impl Candidate<'_> {
    pub(super) fn stream_imports(&mut self, ilt: u32, name: u32, count: u32) -> Result<(), String> {
        need((2..=4).contains(&count), "stream import count")?;
        need(
            ilt.is_multiple_of(4) && self.iat.is_multiple_of(4),
            "stream thunk alignment",
        )?;
        let size = (count + 1) * 4;
        let ip = self.reserve(self.iat, size, DATA)?;
        let lp = self.reserve(ilt, size, DATA)?;
        need(
            range(self.bytes, ip, size as usize)? == range(self.bytes, lp, size as usize)?
                && u32_at(self.bytes, ip + count as usize * 4)? == 0,
            "stream thunk mismatch/terminator",
        )?;
        let dll = b"KERNEL32.dll\0";
        let dp = self.reserve(name, dll.len() as u32, DATA)?;
        need(
            range(self.bytes, dp, dll.len())? == dll,
            "stream DLL identity",
        )?;
        let mut seen = BTreeSet::new();
        for slot in 0..count as usize {
            let thunk = u32_at(self.bytes, ip + slot * 4)?;
            need(
                thunk != 0 && thunk & 0x8000_0000 == 0 && thunk.is_multiple_of(2),
                "stream named import",
            )?;
            let mut found = None;
            for f in [
                Function::Read,
                Function::Write,
                Function::LastError,
                Function::StandardHandle,
            ] {
                if let Ok(at) = self.location(thunk, (2 + f.name().len()) as u32, DATA) {
                    if range(self.bytes, at + 2, f.name().len())? == f.name() {
                        found = Some(f);
                        break;
                    }
                }
            }
            let f = found.ok_or("stream unsupported imported name")?;
            need(seen.insert(f), "stream duplicate imported function")?;
            self.reserve(thunk, (2 + f.name().len()) as u32, DATA)?;
            self.functions.insert(self.iat + slot as u32 * 4, f);
        }
        self.api = Api::Stream;
        Ok(())
    }
}
#[derive(Debug)]
pub(super) struct Bound {
    pub(super) calls: BTreeMap<u32, Function>,
    graph: graph::Graph,
    loads: BTreeMap<u32, Function>,
}
fn merge(old: &mut [Option<Function>; 8], new: [Option<Function>; 8]) -> bool {
    let before = *old;
    for (a, b) in old.iter_mut().zip(new) {
        if *a != b {
            *a = None;
        }
    }
    before != *old
}
pub(super) fn bind(image: &Candidate<'_>) -> Result<Bound, String> {
    let section = image
        .sections
        .iter()
        .find(|s| s.flags == CODE)
        .ok_or("stream code section")?;
    let at = image.location(section.rva, section.virtual_size, CODE)?;
    let code = range(image.bytes, at, section.virtual_size as usize)?;
    let g = graph::decode(code, section.rva, image.entry)?;
    let mut loads = BTreeMap::new();
    let mut consumed = BTreeSet::new();
    for (&pc, node) in &g.nodes {
        let operands: Vec<&Operand> = match &node.operation {
            Operation::Binary(_, a, b) => vec![a, b],
            Operation::Call(a) | Operation::Push(a) => vec![a],
            _ => vec![],
        };
        for operand in operands {
            if let Operand::Memory(a, _) = operand {
                if a.base.is_none() && a.index.is_none() {
                    let dest = a
                        .displacement
                        .checked_sub(image.base)
                        .ok_or("stream absolute address below base")?;
                    let f = *image
                        .functions
                        .get(&dest)
                        .ok_or("stream absolute memory outside function IAT")?;
                    need(
                        matches!(
                            &node.operation,
                            Operation::Call(_)
                                | Operation::Binary(
                                    Binary::Move,
                                    Operand::Reg(graph::Reg { width: 32, .. }),
                                    Operand::Memory(_, 32)
                                )
                        ),
                        "stream IAT use outside function load/call",
                    )?;
                    let mut decoder = iced_x86::Decoder::with_ip(
                        32,
                        &code[(pc - section.rva) as usize..],
                        u64::from(pc),
                        iced_x86::DecoderOptions::NONE,
                    );
                    let instruction = decoder.decode();
                    let offsets = decoder.get_constant_offsets(&instruction);
                    need(
                        offsets.displacement_size() == 4,
                        "stream IAT displacement width",
                    )?;
                    let site = pc
                        .checked_add(offsets.displacement_offset() as u32)
                        .ok_or("stream relocation site overflow")?;
                    need(
                        image.pointers.get(&site) == Some(&dest),
                        "stream IAT relocation provenance",
                    )?;
                    need(consumed.insert(site), "stream reused relocation")?;
                    loads.insert(pc, f);
                }
            }
        }
    }
    need(
        consumed.len() == image.pointers.len(),
        "stream unbound relocation site",
    )?;
    // Must-analysis over a finite lattice. No arbitrary sampled iteration count:
    // each register can lose a known token only once at each existing node state.
    let mut states = BTreeMap::from([(g.entry, [None; 8])]);
    let mut queue = VecDeque::from([g.entry]);
    let mut visits = 0usize;
    while let Some(pc) = queue.pop_front() {
        visits += 1;
        need(visits <= 100_000, "stream function proof budget")?;
        let mut state = states[&pc];
        let node = &g.nodes[&pc];
        match &node.operation {
            Operation::Binary(op, Operand::Reg(dst), src) => {
                if !matches!(op, Binary::Compare | Binary::Test) {
                    state[dst.index as usize] = if *op == Binary::Move && dst.width == 32 {
                        match src {
                            Operand::Reg(r) if r.width == 32 => state[r.index as usize],
                            Operand::Memory(_, 32) => loads.get(&pc).copied(),
                            _ => None,
                        }
                    } else {
                        None
                    };
                }
            }
            Operation::ConditionalMove(_, dst, _)
            | Operation::ZeroExtend(dst, _)
            | Operation::Address(dst, _)
            | Operation::Increment(dst)
            | Operation::Decrement(dst)
            | Operation::Negate(dst)
            | Operation::Not(dst)
            | Operation::Set(_, dst)
            | Operation::Pop(dst) => state[dst.index as usize] = None,
            Operation::Leave => {
                state[4] = None;
                state[5] = None;
            }
            Operation::Call(_) => {
                state[0] = None;
                state[1] = None;
                state[2] = None;
            }
            _ => {}
        }
        for &next in &node.successors {
            if let Some(old) = states.get_mut(&next) {
                if merge(old, state) {
                    queue.push_back(next);
                }
            } else {
                states.insert(next, state);
                queue.push_back(next);
            }
        }
    }
    let mut calls = BTreeMap::new();
    for (&pc, node) in &g.nodes {
        if let Operation::Call(target) = &node.operation {
            let f = match target {
                Operand::Reg(r) => states[&pc][r.index as usize],
                Operand::Memory(_, 32) => loads.get(&pc).copied(),
                _ => None,
            }
            .ok_or("stream unresolved function token at call")?;
            calls.insert(pc, f);
        }
    }
    Ok(Bound {
        calls,
        graph: g,
        loads,
    })
}

pub(super) fn translate(bound: &Bound) -> Result<String, String> {
    let frames = frame::prove(bound)?;
    let logic = logic::encode(bound, &frames)?;
    if let Some(path) = std::env::var_os("W2L_STREAM_OBLIGATIONS") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(logic.text.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    solver::prove(&logic)?;
    Ok(emit::emit(bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn import_bytes(names: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        for (i, name) in names.iter().enumerate() {
            let at = 0xc0 + i * 32;
            bytes[at + 2..at + 2 + name.len()].copy_from_slice(name);
            let rva = (0x2000 + at as u32).to_le_bytes();
            bytes[i * 4..i * 4 + 4].copy_from_slice(&rva);
            bytes[0x20 + i * 4..0x24 + i * 4].copy_from_slice(&rva);
        }
        bytes[0x60..0x64].copy_from_slice(&0x2020u32.to_le_bytes());
        bytes[0x6c..0x70].copy_from_slice(&0x20a0u32.to_le_bytes());
        bytes[0x70..0x74].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0xa0..0xad].copy_from_slice(b"KERNEL32.dll\0");
        bytes
    }
    fn import_table(bytes: &[u8], iat: (u32, u32)) -> Result<Candidate<'_>, String> {
        let mut image = Candidate {
            bytes,
            base: 0x400000,
            entry: 0x1000,
            image_size: 0x3000,
            sections: vec![Section {
                rva: 0x2000,
                raw: 0,
                size: bytes.len() as u32,
                virtual_size: bytes.len() as u32,
                flags: DATA,
            }],
            metadata: vec![],
            iat: 0,
            api: Api::Write,
            functions: BTreeMap::new(),
            pointers: BTreeMap::new(),
        };
        image.imports((0x2060, 40), iat)?;
        Ok(image)
    }
    #[test]
    fn bounded_existing_import_subsets_and_order_are_semantic() {
        let names: [(&[u8], Function); 4] = [
            (b"WriteFile\0", Function::Write),
            (b"GetStdHandle\0", Function::StandardHandle),
            (b"ReadFile\0", Function::Read),
            (b"GetLastError\0", Function::LastError),
        ];
        for bits in 0u32..16 {
            if bits.count_ones() < 2 {
                continue;
            }
            let selected: Vec<_> = names
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .map(|(_, x)| *x)
                .collect();
            for reverse in [false, true] {
                let mut order = selected.clone();
                if reverse {
                    order.reverse();
                }
                let bytes = import_bytes(&order.iter().map(|x| x.0).collect::<Vec<_>>());
                let image = import_table(&bytes, (0x2000, (order.len() as u32 + 1) * 4)).unwrap();
                assert!(image.api == Api::Stream);
                assert_eq!(
                    image.functions,
                    order
                        .iter()
                        .enumerate()
                        .map(|(i, x)| (0x2000 + i as u32 * 4, x.1))
                        .collect()
                );
            }
        }
    }
    #[test]
    fn import_subsets_reject_aliases_early_nulls_extent_and_unknown_names() {
        let names: [&[u8]; 3] = [b"ReadFile\0", b"WriteFile\0", b"GetStdHandle\0"];
        let original = import_bytes(&names);
        for size in [0, 4, 8, 12, 17, 20, 24] {
            assert!(import_table(&original, (0x2000, size)).is_err(), "{size}");
        }
        assert!(import_table(&original, (0x2004, 16)).is_err());
        for (offset, value) in [
            (0, 0u32),
            (0x20, 0),
            (12, 1),
            (0x2c, 1),
            (0, 0x80000001),
            (0x60, 0x2000),
            (0x6c, 0x2000),
            (0, 0x23fe),
            (0, 0x20c1),
        ] {
            let mut bad = original.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                import_table(&bad, (0x2000, 16)).is_err(),
                "{offset:x}/{value:x}"
            );
        }
        for names in [
            [
                &b"ReadFile\0"[..],
                &b"ReadFile\0"[..],
                &b"GetStdHandle\0"[..],
            ],
            [
                &b"ReadFileX\0"[..],
                &b"WriteFile\0"[..],
                &b"GetStdHandle\0"[..],
            ],
        ] {
            assert!(import_table(&import_bytes(&names), (0x2000, 16)).is_err());
        }
    }
    fn proof(code: &[u8], sites: &[(u32, u32)]) -> Result<Bound, String> {
        let image = Candidate {
            bytes: code,
            base: 0x400000,
            entry: 0x1000,
            image_size: 0x3000,
            sections: vec![Section {
                rva: 0x1000,
                size: code.len() as u32,
                virtual_size: code.len() as u32,
                raw: 0,
                flags: CODE,
            }],
            metadata: vec![],
            iat: 0x2000,
            api: Api::Stream,
            functions: BTreeMap::from([(0x2000, Function::Read), (0x2004, Function::Write)]),
            pointers: sites.iter().copied().collect(),
        };
        bind(&image)
    }
    #[test]
    fn nonvolatile_tokens_survive_calls_volatile_tokens_do_not() {
        let p = proof(
            &[0x8b, 0x1d, 0, 0x20, 0x40, 0, 0xff, 0xd3, 0xff, 0xd3, 0xc3],
            &[(0x1002, 0x2000)],
        )
        .unwrap();
        assert_eq!(
            p.calls,
            BTreeMap::from([(0x1006, Function::Read), (0x1008, Function::Read)])
        );
        assert!(proof(
            &[0xa1, 0, 0x20, 0x40, 0, 0xff, 0xd0, 0xff, 0xd0, 0xc3],
            &[(0x1001, 0x2000)]
        )
        .unwrap_err()
        .contains("unresolved"));
    }
    #[test]
    fn branch_join_cannot_choose_a_function_from_only_one_path() {
        let code = [
            0x8b, 0x1d, 0, 0x20, 0x40, 0, 0x85, 0xc0, 0x74, 6, 0x8b, 0x1d, 4, 0x20, 0x40, 0, 0xff,
            0xd3, 0xc3,
        ];
        assert!(proof(&code, &[(0x1002, 0x2000), (0x100c, 0x2004)])
            .unwrap_err()
            .contains("unresolved"));
        let mut same = code;
        same[12] = 0;
        assert_eq!(
            proof(&same, &[(0x1002, 0x2000), (0x100c, 0x2000)])
                .unwrap()
                .calls[&0x1010],
            Function::Read
        );
    }
    #[test]
    fn missing_extra_wrong_relocations_and_iat_writes_reject() {
        let code = [0xff, 0x15, 0, 0x20, 0x40, 0, 0xc3];
        for sites in [
            vec![],
            vec![(0x1002, 0x2004)],
            vec![(0x1002, 0x2000), (0x1000, 0x2000)],
        ] {
            assert!(proof(&code, &sites).is_err());
        }
        assert!(proof(&[0x89, 0x1d, 0, 0x20, 0x40, 0, 0xc3], &[(0x1002, 0x2000)]).is_err());
    }
    #[test]
    fn cyclic_join_converges_and_drops_conflicting_tokens() {
        // ebx=Read; call ebx; test eax,eax; jne call; ret
        let code = [
            0x8b, 0x1d, 0, 0x20, 0x40, 0, 0xff, 0xd3, 0x85, 0xc0, 0x75, 0xfa, 0xc3,
        ];
        assert_eq!(
            proof(&code, &[(0x1002, 0x2000)]).unwrap().calls[&0x1006],
            Function::Read
        );
    }
}
