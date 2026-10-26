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
                0x8b if byte(1)? == 0xf0 => (2, Op::MoveEsi),
                0x8b if b.get(..4) == Some(&[0x8b, 0x44, 0x24, 4]) => (4, Op::Argument),
                0x03 if b.get(..4) == Some(&[0x03, 0x44, 0x24, 8]) => (4, Op::AddArgument),
                0x33 if byte(1)? == 0xc0 => (2, Op::Xor),
                0x83 => match byte(1)? {
                    0xc4 if byte(2)? == 20 => (3, Op::Cleanup),
                    0xf8 => (3, Op::CompareEax(byte(2)? as i8 as i32 as u32)),
                    0xfe => (3, Op::CompareEsi(byte(2)? as i8 as i32 as u32)),
                    _ => return Err("unsupported 83 form".into()),
                },
                0xe8 => {
                    let target = i64::from(pc) + 5 + i64::from(imm(1)? as i32);
                    need(
                        target > i64::from(pc) && target <= i64::from(u32::MAX),
                        "forward call target",
                    )?;
                    (5, Op::Call(target as u32))
                }
                0x75 => {
                    let target = i64::from(pc) + 2 + i64::from(byte(1)? as i8);
                    need(
                        target >= i64::from(pc) + 2 && target <= i64::from(u32::MAX),
                        "forward branch target",
                    )?;
                    (2, Op::Branch(target as u32))
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
                Op::Call(t) | Op::Branch(t) => {
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
        source.push_str("pub fn run() { let mut output=|rva:u32,n:u32|->Result<u32,String>{ let bytes:&[u8]=match (rva,n) {\n");
        for ((rva, n), bytes) in buffers {
            writeln!(source, "({rva},{n})=>&{bytes:?},").unwrap();
        }
        source
            .push_str("_=>return Err(\"unvalidated output\".into())};Ok(native_output(bytes))};\n");
        writeln!(
            source,
            "let mut state=State::new({}); while !state.done {{ let (op,next)=match state.pc {{",
            self.entry
        )
        .unwrap();
        for (pc, (op, next)) in graph {
            writeln!(source, "{pc}=>(Op::{op:?},{next}),").unwrap();
        }
        source.push_str("_=>panic!(\"validated PC\")};state.step(op,next,&mut output).expect(\"validated transition\");} std::process::exit(state.eax.integer().unwrap() as i32);}}\nfn main(){abi::run()}\n");
        Ok(source)
    }
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
