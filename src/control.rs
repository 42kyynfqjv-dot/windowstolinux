//! Bounded, statically decoded forward control flow. No bytecode interpreter is emitted.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

const LIMIT: usize = 1024;
#[derive(Debug, Clone, Copy)]
enum Op {
    Mov(u32),
    Add(u32),
    Xor,
    Ret,
    Branch {
        flag: usize,
        when: bool,
        target: usize,
    },
}
#[derive(Debug)]
struct Instruction {
    op: Op,
    next: usize,
}
type Program = BTreeMap<usize, Instruction>;

fn decode(bytes: &[u8]) -> Result<Program, String> {
    let mut pending = BTreeSet::from([0]);
    let mut program = Program::new();
    let mut occupied = BTreeSet::new();
    while let Some(at) = pending.pop_first() {
        if program.contains_key(&at) {
            continue;
        }
        if program.len() == LIMIT {
            return Err("decoded instruction limit exceeded".into());
        }
        let opcode = *bytes
            .get(at)
            .ok_or("control flow leaves executable bytes")?;
        let (op, size) = match opcode {
            0xb8 | 0x05 => {
                let imm = super::u32_at(bytes, at + 1)?;
                (
                    if opcode == 0xb8 {
                        Op::Mov(imm)
                    } else {
                        Op::Add(imm)
                    },
                    5,
                )
            }
            0x31 if bytes.get(at + 1) == Some(&0xc0) => (Op::Xor, 2),
            0xc3 => (Op::Ret, 1),
            0x72..=0x75 => {
                let displacement = *bytes.get(at + 1).ok_or("truncated branch")? as i8;
                if displacement < 0 {
                    return Err("backward branches are unsupported".into());
                }
                let target = at
                    .checked_add(2 + displacement as usize)
                    .ok_or("branch overflow")?;
                (
                    Op::Branch {
                        flag: usize::from(opcode >= 0x74),
                        when: opcode % 2 == 0,
                        target,
                    },
                    2,
                )
            }
            _ => {
                return Err(format!(
                    "unsupported opcode {opcode:02x} at entry offset {at}"
                ))
            }
        };
        let next = at.checked_add(size).ok_or("instruction offset overflow")?;
        for byte in at..next {
            if !occupied.insert(byte) {
                return Err("overlapping instruction boundaries".into());
            }
        }
        if !matches!(op, Op::Ret) {
            pending.insert(next);
        }
        if let Op::Branch { target, .. } = op {
            pending.insert(target);
        }
        program.insert(at, Instruction { op, next });
    }
    Ok(program)
}

fn add_flags(a: u32, b: u32) -> (u32, [bool; 2]) {
    let (value, carry) = a.overflowing_add(b);
    (value, [carry, value == 0])
}

fn validate(program: &Program) -> Result<u8, String> {
    let mut eax = None;
    let mut flags = None;
    let mut pc = 0;
    for _ in 0..LIMIT {
        let instruction = program.get(&pc).ok_or("missing instruction")?;
        pc = instruction.next;
        match instruction.op {
            Op::Mov(value) => eax = Some(value),
            Op::Add(value) => {
                let (result, updated) = add_flags(eax.ok_or("unknown entry EAX")?, value);
                eax = Some(result);
                flags = Some(updated);
            }
            Op::Xor => {
                eax = Some(0);
                flags = Some([false, true]);
            }
            Op::Branch { flag, when, target } => {
                let known: [bool; 2] = flags.ok_or("branch reads unknown entry flags")?;
                if known[flag] == when {
                    pc = target;
                }
            }
            Op::Ret => {
                return u8::try_from(eax.ok_or("unknown return EAX")?)
                    .map_err(|_| "Windows exit status exceeds Linux's 8-bit exit range".into())
            }
        }
    }
    Err("execution instruction limit exceeded".into())
}

pub fn translate(bytes: &[u8]) -> Result<String, String> {
    let program = decode(bytes)?;
    validate(&program)?;
    // Each match arm is a statically decoded instruction, with fixed successors.
    // The entry state is only read after validation proves it initialized on this
    // deterministic path. Options preserve the check in the generated program.
    let mut out = String::from("// Statically decoded x86; bounded forward control flow.\nuse std::convert::TryFrom;\n#[allow(unused_assignments, unused_mut, unused_variables)]\nfn main() {\nlet mut eax: Option<u32> = None;\nlet mut flags: Option<[bool; 2]> = None;\nlet mut pc: usize = 0;\nfor _ in 0..1024 {\nmatch pc {\n");
    for (at, instruction) in &program {
        writeln!(out, "{at} => {{").unwrap();
        match instruction.op {
            Op::Mov(value) => writeln!(out, "eax = Some({value});").unwrap(),
            Op::Add(value) => writeln!(out, "let (value, carry) = eax.unwrap().overflowing_add({value}); eax = Some(value); flags = Some([carry, value == 0]);").unwrap(),
            Op::Xor => writeln!(out, "eax = Some(0); flags = Some([false, true]);").unwrap(),
            Op::Ret => writeln!(out, "std::process::exit(u8::try_from(eax.unwrap()).unwrap() as i32);").unwrap(),
            Op::Branch { flag, when, target } => writeln!(out, "if flags.unwrap()[{flag}] == {when} {{ pc = {target}; }} else {{ pc = {}; }}", instruction.next).unwrap(),
        }
        if !matches!(instruction.op, Op::Ret | Op::Branch { .. }) {
            writeln!(out, "pc = {};", instruction.next).unwrap();
        }
        out.push_str("}\n");
    }
    out.push_str(
        "_ => unreachable!(),\n}\n}\npanic!(\"validated instruction limit exceeded\");\n}\n",
    );
    Ok(out)
}

#[cfg(test)]
pub(super) fn exit_for_test(bytes: &[u8]) -> Result<u8, String> {
    validate(&decode(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn carry_and_zero_truth_table() {
        for (a, b, value, carry, zero) in [
            (0, 0, 0, false, true),
            (u32::MAX, 1, 0, true, true),
            (u32::MAX, 2, 1, true, false),
            (0x7fffffff, 1, 0x80000000, false, false),
        ] {
            assert_eq!(add_flags(a, b), (value, [carry, zero]));
        }
    }
    #[test]
    fn rejects_unknown_flags_backward_and_overlapping_code() {
        assert!(translate(&[0xb8, 0, 0, 0, 0, 0x74, 0, 0xc3]).is_err());
        assert!(translate(&[0x31, 0xc0, 0x74, 0xfe, 0xc3]).is_err());
        assert!(translate(&[0x31, 0xc0, 0x74, 1, 0xb8, 0, 0, 0, 0, 0xc3]).is_err());
        assert!(translate(&[0x31, 0xc0, 0x74, 127, 0xc3]).is_err());
    }
    #[test]
    fn mov_preserves_flags_and_both_successors_are_decoded() {
        let bytes = [
            0x31, 0xc0, 0xb8, 7, 0, 0, 0, 0x74, 6, 0xb8, 8, 0, 0, 0, 0xc3, 0xb8, 9, 0, 0, 0, 0xc3,
        ];
        assert_eq!(validate(&decode(&bytes).unwrap()).unwrap(), 9);
        let mut bad = bytes;
        bad[9] = 0x90;
        assert!(translate(&bad).is_err());
    }
    #[test]
    fn instruction_limit_and_exit_domain() {
        let mut code = [0x31, 0xc0].repeat(LIMIT);
        code.push(0xc3);
        assert!(translate(&code).is_err());
        assert!(translate(&[0xb8, 0, 1, 0, 0, 0xc3]).is_err());
        assert!(translate(&[0xc3]).is_err());
    }
}
