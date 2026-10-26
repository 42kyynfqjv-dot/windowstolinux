use super::*;
use crate::control::flags::Flags;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
include!("state.rs");
impl Candidate<'_> {
    pub(crate) fn translate(&self) -> Result<String, String> {
        self.translate_checked()
            .map_err(|e| format!("linker intake validated; emission blocked: {e}"))
    }
    fn translate_checked(&self) -> Result<String, String> {
        let mut graph = BTreeMap::new();
        let mut pending = vec![self.entry];
        let mut occupied = BTreeSet::new();
        let mut bound = BTreeSet::new();
        while let Some(pc) = pending.pop() {
            if graph.contains_key(&pc) {
                continue;
            }
            need(graph.len() < 1024, "decoded instruction limit")?;
            let at = self.location(pc, 1, CODE)?;
            let section = self.sections.iter().find(|s| s.flags == CODE).unwrap();
            let available = (section.virtual_size.min(section.size) - (pc - section.rva)) as usize;
            let b = range(self.bytes, at, available)?;
            let byte = |n: usize| {
                b.get(n)
                    .copied()
                    .ok_or_else(|| "truncated instruction".to_string())
            };
            let imm = |n: usize| u32_at(b, n);
            let (size, op) = match b[0] {
                0x56 => (1, Op::Save),
                0x5e => (1, Op::Restore),
                0xc3 => (1, Op::Ret),
                0xb8 => (5, Op::Mov(imm(1)?)),
                0x6a => (2, Op::Push(byte(1)? as i8 as i32 as u32)),
                0x68 => {
                    let site = pc + 1;
                    let v = imm(1)?;
                    let op = if let Some(&rva) = self.pointers.get(&site) {
                        need(rva != self.iat, "import slot as data")?;
                        bound.insert(site);
                        Op::Pointer(rva)
                    } else {
                        Op::Push(v)
                    };
                    (5, op)
                }
                0xff if b.get(..4) == Some(&[0xff, 0x74, 0x24, 8]) => (4, Op::CopyArgument),
                0xc7 if b.get(..8) == Some(&[0xc7, 0x44, 0x24, 8, 3, 0, 0, 0]) => {
                    (8, Op::StoreSecond)
                }
                0xc7 if b.get(..3) == Some(&[0xc7, 0x04, 0x24]) => (7, Op::StoreLocalZero(imm(3)?)),
                0xc7 if b.get(..4) == Some(&[0xc7, 0x44, 0x24, 4]) => (8, Op::StoreFour(imm(4)?)),
                0xff if byte(1)? == 0x15 => {
                    let site = pc + 2;
                    imm(2)?;
                    need(
                        self.pointers.get(&site) == Some(&self.iat),
                        "missing import relocation",
                    )?;
                    bound.insert(site);
                    (6, Op::Write)
                }
                0xba if b.get(..5) == Some(&[0xba, 1, 0, 0, 0]) => (5, Op::EdxOne),
                0x8b if b.get(..4) == Some(&[0x8b, 0x44, 0x24, 8]) => (4, Op::ScalarArgumentTwo),
                0x8b if b.get(..4) == Some(&[0x8b, 0x4c, 0x24, 4]) => (4, Op::EcxArgumentOne),
                0x3b if byte(1)? == 0xc8 => (2, Op::CompareEcxEax),
                0x0f if b.get(..3) == Some(&[0x0f, 0x4d, 0xc2]) => (3, Op::SelectGe),
                0x03 if b.get(..3) == Some(&[0x03, 0x04, 0x24]) => (3, Op::AddLocalZero),
                0x03 if byte(1)? == 0xc1 => (2, Op::AddEcx),
                0x8b if byte(1)? == 0xf0 => (2, Op::MoveEsi),
                0x8b if b.get(..4) == Some(&[0x8b, 0x44, 0x24, 4]) => (4, Op::Argument),
                0x03 if b.get(..4) == Some(&[0x03, 0x44, 0x24, 8]) => (4, Op::AddArgument),
                0x03 if b.get(..4) == Some(&[0x03, 0x44, 0x24, 12]) => (4, Op::AddThirdArgument),
                0x33 if byte(1)? == 0xc0 => (2, Op::Xor),
                0x83 => match byte(1)? {
                    0xec if byte(2)? == 8 => (3, Op::AllocateLocal),
                    0xc4 if byte(2)? == 8 => (3, Op::CleanupTwo),
                    0xc4 if byte(2)? == 20 => (3, Op::Cleanup),
                    0xc4 if byte(2)? == 24 => (3, Op::CleanupSix),
                    0xf8 => (3, Op::CompareEax(byte(2)? as i8 as i32 as u32)),
                    0xfe => (3, Op::CompareEsi(byte(2)? as i8 as i32 as u32)),
                    _ => return Err("unsupported 83 form".into()),
                },
                0xe8 | 0xe9 => {
                    let target = i64::from(pc) + 5 + i64::from(imm(1)? as i32);
                    need(
                        target >= 0 && target <= i64::from(u32::MAX),
                        "direct transfer target",
                    )?;
                    (
                        5,
                        if b[0] == 0xe8 {
                            Op::Call(target as u32)
                        } else {
                            Op::Tail(target as u32)
                        },
                    )
                }
                0x74 | 0x75 => {
                    let target = i64::from(pc) + 2 + i64::from(byte(1)? as i8);
                    need(
                        target >= i64::from(pc) + 2 && target <= i64::from(u32::MAX),
                        "forward branch target",
                    )?;
                    (
                        2,
                        if b[0] == 0x74 {
                            Op::Equal(target as u32)
                        } else {
                            Op::Branch(target as u32)
                        },
                    )
                }
                _ => return Err(format!("unsupported instruction at RVA {pc:#x}")),
            };
            self.location(pc, size, CODE)?;
            let decoded =
                iced_x86::Decoder::with_ip(32, b, u64::from(pc), iced_x86::DecoderOptions::NONE)
                    .decode();
            need(
                !decoded.is_invalid() && decoded.len() == size as usize,
                "decoder form/length",
            )?;
            for addr in pc..pc + size {
                need(occupied.insert(addr), "overlapping instructions")?
            }
            let next = pc + size;
            match op {
                Op::Ret => {}
                Op::Tail(t) => pending.push(t),
                Op::Call(t) | Op::Branch(t) | Op::Equal(t) => {
                    pending.push(t);
                    pending.push(next)
                }
                _ => pending.push(next),
            }
            graph.insert(pc, (op, next));
        }
        need(
            bound == self.pointers.keys().copied().collect(),
            "relocation operand bijection",
        )?;
        validate_routines(self.entry, &graph)?;
        let mut buffers = BTreeMap::new();
        let mut states = vec![State::new(self.entry)];
        let mut explored = 0;
        while let Some(mut state) = states.pop() {
            loop {
                explored += 1;
                need(explored <= 4096, "all-path state limit")?;
                let &(op, next) = graph.get(&state.pc).ok_or("missing decoded continuation")?;
                let alternate = state.step(op, next, &mut |rva, count| {
                    need((1..=64).contains(&count), "output count")?;
                    self.immutable(rva, count)?;
                    let at = self.location(rva, count, DATA)?;
                    let bytes = range(self.bytes, at, count as usize)?;
                    need(
                        bytes.iter().all(|b| (0x20..=0x7e).contains(b)),
                        "output bytes",
                    )?;
                    buffers.insert((rva, count), bytes.to_vec());
                    Ok(count)
                })?;
                if let Some(pc) = alternate {
                    let mut other = state.clone();
                    other.pc = pc;
                    states.push(other)
                }
                if state.done {
                    break;
                }
            }
        }
        Ok(ProvenProgram {
            entry: self.entry,
            graph,
            buffers,
        }
        .emit())
    }
}
// Constructed only after every reachable path passes the graph and ABI proof above.
struct ProvenProgram {
    entry: u32,
    graph: BTreeMap<u32, (Op, u32)>,
    buffers: BTreeMap<(u32, u32), Vec<u8>>,
}
impl ProvenProgram {
    fn emit(self) -> String {
        let mut source=String::from("// Validated static MSVC subset; no PE decoding at runtime.\n#[allow(dead_code)] mod abi {\n");
        source.push_str(
            &include_str!("../control/flags.rs")
                .lines()
                .filter(|l| !l.starts_with("//!"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        source.push_str(include_str!("state.rs"));
        source.push_str(
            include_str!("../control/output_runtime.rs")
                .split("#[cfg(test)]")
                .next()
                .unwrap(),
        );
        if self.buffers.is_empty() {
            source.push_str("pub fn run() { let mut output=|_:u32,_:u32|->Result<u32,String>{Err(\"unvalidated output\".into())};\n");
        } else {
            source.push_str("pub fn run() { let mut output=|rva:u32,n:u32|->Result<u32,String>{ let bytes:&[u8]=match (rva,n) {\n");
            for ((rva, n), bytes) in self.buffers {
                writeln!(source, "({rva},{n})=>&{bytes:?},").unwrap();
            }
            source.push_str(
                "_=>return Err(\"unvalidated output\".into())};Ok(native_output(bytes))};\n",
            );
        }
        writeln!(
            source,
            "let mut state=State::new({}); while !state.done {{ let (op,next)=match state.pc {{",
            self.entry
        )
        .unwrap();
        for (pc, (op, next)) in self.graph {
            writeln!(source, "{pc}=>(Op::{op:?},{next}),").unwrap();
        }
        source.push_str("_=>panic!(\"validated PC\")};state.step(op,next,&mut output).expect(\"validated transition\");} std::process::exit(state.eax.integer().unwrap() as i32);}}\nfn main(){abi::run()}\n");
        source
    }
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// All local edges increase PC; transfers form a separate acyclic routine graph.
fn validate_routines(entry: u32, graph: &BTreeMap<u32, (Op, u32)>) -> Result<(), String> {
    let mut roots = BTreeSet::from([entry]);
    for (op, _) in graph.values() {
        if let Op::Call(t) | Op::Tail(t) = op {
            roots.insert(*t);
        }
    }
    let mut owners = BTreeMap::new();
    let mut edges: BTreeMap<u32, BTreeSet<u32>> =
        roots.iter().map(|r| (*r, BTreeSet::new())).collect();
    for &root in &roots {
        let mut pending = vec![root];
        while let Some(pc) = pending.pop() {
            if let Some(old) = owners.get(&pc) {
                need(*old == root, "ambiguous routine region")?;
                continue;
            }
            need(
                pc == root || !roots.contains(&pc),
                "cross-routine local edge",
            )?;
            owners.insert(pc, root);
            let &(op, next) = graph.get(&pc).ok_or("routine target boundary")?;
            match op {
                Op::Ret => {}
                Op::Tail(t) => {
                    edges.get_mut(&root).unwrap().insert(t);
                }
                Op::Call(t) => {
                    edges.get_mut(&root).unwrap().insert(t);
                    pending.push(next);
                }
                Op::Branch(t) | Op::Equal(t) => {
                    need(t >= next && next > pc, "local cycle")?;
                    pending.extend([t, next]);
                }
                _ => {
                    need(next > pc, "local cycle")?;
                    pending.push(next);
                }
            }
        }
    }
    need(owners.len() == graph.len(), "unowned code")?;
    // Repeatedly remove leaves: bounded by the 1024 decoded-instruction cap.
    while !edges.is_empty() {
        let leaves: BTreeSet<u32> = edges
            .iter()
            .filter(|(_, v)| v.is_empty())
            .map(|(k, _)| *k)
            .collect();
        need(!leaves.is_empty(), "routine transfer cycle")?;
        edges.retain(|k, _| !leaves.contains(k));
        for targets in edges.values_mut() {
            targets.retain(|t| !leaves.contains(t));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod local_tests;
