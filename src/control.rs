//! Bounded, statically decoded forward control flow. No bytecode interpreter is emitted.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

#[path = "control/flags.rs"]
pub(crate) mod flags;
use flags::Flags;
#[path = "control/stack.rs"]
pub(super) mod stack;
use stack::{Return, Stack};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Condition {
    Carry,
    Zero,
    SignedLess,
}
impl Condition {
    fn test(self, flags: Flags) -> bool {
        match self {
            Self::Carry => flags.carry,
            Self::Zero => flags.zero,
            Self::SignedLess => flags.sign != flags.overflow,
        }
    }
    fn rust(self) -> &'static str {
        match self {
            Self::Carry => "flags.unwrap().carry",
            Self::Zero => "flags.unwrap().zero",
            Self::SignedLess => "(flags.unwrap().sign != flags.unwrap().overflow)",
        }
    }
}
#[path = "control/output.rs"]
pub(super) mod output;
const LIMIT: usize = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Mov(u32),
    Import(u32),
    Output(u32),
    LoadAbsolute(u32),
    Add(u32),
    Compare(u32),
    PushData(u32),
    LoadArgument,
    DropData,
    Call {
        target: usize,
    },
    Xor,
    Ret,
    Branch {
        condition: Condition,
        when: bool,
        target: usize,
    },
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Instruction {
    pub(super) op: Op,
    pub(super) next: usize,
}
pub(super) type Program = BTreeMap<usize, Instruction>;

pub(super) fn decode(bytes: &[u8]) -> Result<Program, String> {
    decode_with(bytes, decode_instruction)
}

#[path = "control/decoder.rs"]
mod decoder;

pub(super) fn decode_instruction(bytes: &[u8], at: usize) -> Result<Instruction, String> {
    decoder::decode_instruction(bytes, at)
        .map_err(|error| format!("decode at entry offset {at}: {error}"))
}

// Frozen handwritten subset decoder: regression oracle only, never a fallback.
#[cfg(test)]
#[allow(dead_code)]
pub(super) fn oracle_instruction(bytes: &[u8], at: usize) -> Result<Instruction, String> {
    let opcode = *bytes
        .get(at)
        .ok_or("control flow leaves executable bytes")?;
    let (op, size) = match opcode {
        0xb8 | 0x05 | 0x3d => {
            let imm = super::u32_at(bytes, at + 1)?;
            (
                if opcode == 0xb8 {
                    Op::Mov(imm)
                } else if opcode == 0x05 {
                    Op::Add(imm)
                } else {
                    Op::Compare(imm)
                },
                5,
            )
        }
        0xa1 => (Op::LoadAbsolute(super::u32_at(bytes, at + 1)?), 5),
        0x68 => (Op::PushData(super::u32_at(bytes, at + 1)?), 5),
        0x8b if bytes.get(at..at + 4) == Some(&[0x8b, 0x44, 0x24, 4]) => (Op::LoadArgument, 4),
        0x8d if bytes.get(at..at + 4) == Some(&[0x8d, 0x64, 0x24, 4]) => (Op::DropData, 4),
        0xe8 => {
            let displacement = super::u32_at(bytes, at + 1)? as i32;
            if displacement < 0 {
                return Err("backward calls are unsupported".into());
            }
            let target = at
                .checked_add(5)
                .and_then(|end| end.checked_add(displacement as usize))
                .ok_or("call overflow")?;
            (Op::Call { target }, 5)
        }
        0x31 if bytes.get(at + 1) == Some(&0xc0) => (Op::Xor, 2),
        0xc3 => (Op::Ret, 1),
        0x72..=0x75 | 0x7c..=0x7d => {
            let displacement = *bytes.get(at + 1).ok_or("truncated branch")? as i8;
            if displacement < 0 {
                return Err("backward branches are unsupported".into());
            }
            let target = at
                .checked_add(2 + displacement as usize)
                .ok_or("branch overflow")?;
            (
                Op::Branch {
                    condition: match opcode {
                        0x72 | 0x73 => Condition::Carry,
                        0x74 | 0x75 => Condition::Zero,
                        _ => Condition::SignedLess,
                    },
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
    Ok(Instruction { op, next })
}

pub(super) fn decode_with(
    bytes: &[u8],
    decode_one: impl Fn(&[u8], usize) -> Result<Instruction, String>,
) -> Result<Program, String> {
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
        let Instruction { op, next } = decode_one(bytes, at)?;
        for byte in at..next {
            if !occupied.insert(byte) {
                return Err("overlapping instruction boundaries".into());
            }
        }
        if !matches!(op, Op::Ret) {
            pending.insert(next);
        }
        if let Op::Branch { target, .. } | Op::Call { target } = op {
            pending.insert(target);
        }
        program.insert(at, Instruction { op, next });
    }
    // Every non-return edge is forward. Compute maximum extra nesting on all paths.
    let mut depths: BTreeMap<usize, usize> = BTreeMap::new();
    for (&at, ins) in program.iter().rev() {
        let depth = match ins.op {
            Op::Ret => 0,
            Op::Call { target } => depths[&ins.next].max(1 + depths[&target]),
            Op::Branch { target, .. } => depths[&ins.next].max(depths[&target]),
            _ => depths[&ins.next],
        };
        if depth > 32 {
            return Err("call nesting limit exceeded".into());
        }
        depths.insert(at, depth);
    }
    Ok(program)
}

fn validate(program: &Program) -> Result<u8, String> {
    let mut eax = None;
    let mut flags = None;
    let mut pc = 0;
    let mut stack = Stack::new();
    for _ in 0..LIMIT {
        let instruction = program.get(&pc).ok_or("missing instruction")?;
        pc = instruction.next;
        match instruction.op {
            Op::Import(_) => return Err("import context required".into()),
            Op::Output(count) => {
                let args = stack.output_arguments(instruction.next)?;
                if args[0] != count {
                    return Err("output count mismatch".into());
                }
                eax = Some(count);
                flags = None;
            }
            Op::LoadAbsolute(_) => return Err("immutable image context required".into()),
            Op::Mov(value) => eax = Some(value),
            Op::PushData(value) => stack.push(value)?,
            Op::LoadArgument => eax = Some(stack.argument()?),
            Op::DropData => stack.cleanup()?,
            Op::Add(value) => {
                let (result, updated) = Flags::add(eax.ok_or("unknown entry EAX")?, value);
                eax = Some(result);
                flags = Some(updated);
            }
            Op::Compare(value) => {
                flags = Some(Flags::compare(eax.ok_or("unknown entry EAX")?, value));
            }
            Op::Xor => {
                eax = Some(0);
                flags = Some(Flags::xor_self());
            }
            Op::Branch {
                condition,
                when,
                target,
            } => {
                let known = flags.ok_or("branch reads unknown entry flags")?;
                if condition.test(known) == when {
                    pc = target;
                }
            }
            Op::Call { target } => {
                stack.call(instruction.next)?;
                pc = target;
            }
            Op::Ret => match stack.ret(eax)? {
                Return::Resume(next) => pc = next,
                Return::Exit(value) => return Ok(value),
            },
        }
    }
    Err("execution instruction limit exceeded".into())
}

#[allow(dead_code)] // Byte-only translation intentionally rejects image reads.
pub fn translate(bytes: &[u8]) -> Result<String, String> {
    emit(&decode(bytes)?)
}

pub(super) fn translate_with_reads(
    bytes: &[u8],
    mut read: impl FnMut(u32) -> Result<u32, String>,
) -> Result<String, String> {
    let mut program = decode(bytes)?;
    // Resolve every decoded path before validation, including untaken branches.
    // This lowering is valid only for the caller's validated immutable image.
    for instruction in program.values_mut() {
        if let Op::LoadAbsolute(address) = instruction.op {
            instruction.op = Op::Mov(read(address)?);
        }
    }
    emit(&program)
}

pub(super) fn emit(program: &Program) -> Result<String, String> {
    emit_outputs(program, &BTreeMap::new())
}
fn emit_outputs(program: &Program, payloads: &BTreeMap<usize, Vec<u8>>) -> Result<String, String> {
    for (at, ins) in program {
        if matches!(ins.op, Op::Import(_))
            || (matches!(ins.op, Op::Output(_)) && !payloads.contains_key(at))
        {
            return Err("import context required".into());
        }
    }
    if program
        .values()
        .any(|ins| matches!(ins.op, Op::LoadAbsolute(_)))
    {
        return Err("immutable image context required".into());
    }
    validate(program)?;
    // Each match arm is a statically decoded instruction, with fixed successors.
    // The entry state is only read after validation proves it initialized on this
    // deterministic path. Options preserve the check in the generated program.
    let mut out = String::from("#[allow(dead_code)]\nmod arithmetic {\n");
    out.push_str(include_str!("control/flags.rs").trim_start_matches(
        "//! Independently implemented 32-bit arithmetic contracts; see SUB502-CONTRACT.md.\n",
    ));
    out.push_str("\n}\nuse arithmetic::Flags;\n#[allow(dead_code)]\nmod stack {\n");
    out.push_str(
        include_str!("control/stack.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap(),
    );
    out.push_str("\n}\nuse stack::{Stack, Return};\n");
    if !payloads.is_empty() {
        out.push_str(
            include_str!("control/output_runtime.rs")
                .split("\n#[cfg(test)]")
                .next()
                .unwrap(),
        );
    }
    out.push_str("// Statically decoded x86; bounded forward control flow.\n#[allow(unused_assignments, unused_mut, unused_variables)]\nfn main() {\nlet mut eax: Option<u32> = None;\nlet mut flags: Option<Flags> = None;\nlet mut pc: usize = 0;\nlet mut stack = Stack::new();\nfor _ in 0..1024 {\nmatch pc {\n");
    for (at, instruction) in program {
        writeln!(out, "{at} => {{").unwrap();
        match instruction.op {
            Op::Import(_) => unreachable!(),
            Op::Output(count) => writeln!(out, "stack.output_arguments({}).unwrap(); eax = Some(native_output(&{:?})); flags = None; assert_eq!(eax, Some({count}));", instruction.next, payloads[at]).unwrap(),
            Op::LoadAbsolute(_) => unreachable!("unresolved image read rejected above"),
            Op::Mov(value) => writeln!(out, "eax = Some({value});").unwrap(),
            Op::PushData(value) => writeln!(out, "stack.push({value}).unwrap();").unwrap(),
            Op::LoadArgument => writeln!(out, "eax = Some(stack.argument().unwrap());").unwrap(),
            Op::DropData => writeln!(out, "stack.cleanup().unwrap();").unwrap(),
            Op::Add(value) => writeln!(out, "let (value, updated) = Flags::add(eax.unwrap(), {value}); eax = Some(value); flags = Some(updated);").unwrap(),
            Op::Compare(value) => writeln!(out, "flags = Some(Flags::compare(eax.unwrap(), {value}));").unwrap(),
            Op::Xor => writeln!(out, "eax = Some(0); flags = Some(Flags::xor_self());").unwrap(),
            Op::Call { target } => writeln!(out, "stack.call({}).unwrap(); pc = {target};", instruction.next).unwrap(),
            Op::Ret => writeln!(out, "match stack.ret(eax).unwrap() {{ Return::Resume(next) => pc = next, Return::Exit(value) => std::process::exit(i32::from(value)), }}").unwrap(),
            Op::Branch { condition, when, target } => writeln!(out, "if {} == {when} {{ pc = {target}; }} else {{ pc = {}; }}", condition.rust(), instruction.next).unwrap(),
        }
        if !matches!(
            instruction.op,
            Op::Ret | Op::Branch { .. } | Op::Call { .. }
        ) {
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
#[allow(dead_code)]
pub(super) type DecodeRecord = (usize, usize, String, Option<u32>, Option<usize>);
#[cfg(test)]
#[allow(dead_code)]
pub(super) fn records_for_comparison(bytes: &[u8]) -> Result<Vec<DecodeRecord>, String> {
    Ok(decode(bytes)?
        .iter()
        .map(|(&at, ins)| {
            let (name, immediate, target) = match ins.op {
                Op::Import(v) | Op::Output(v) => ("output", Some(v), None),
                Op::Mov(v) => ("mov", Some(v), None),
                Op::LoadAbsolute(v) => ("load_absolute", Some(v), None),
                Op::PushData(v) => ("push", Some(v), None),
                Op::LoadArgument => ("load_argument", None, None),
                Op::DropData => ("drop_data", None, None),
                Op::Add(v) => ("add", Some(v), None),
                Op::Compare(v) => ("cmp", Some(v), None),
                Op::Xor => ("xor", None, None),
                Op::Ret => ("ret", None, None),
                Op::Call { target } => ("call", None, Some(target)),
                Op::Branch {
                    condition,
                    when,
                    target,
                } => (
                    match (condition, when) {
                        (Condition::Carry, true) => "jb",
                        (Condition::Carry, false) => "jae",
                        (Condition::Zero, true) => "je",
                        (Condition::Zero, false) => "jne",
                        (Condition::SignedLess, true) => "jl",
                        (Condition::SignedLess, false) => "jge",
                    },
                    None,
                    Some(target),
                ),
            };
            (at, ins.next - at, name.to_string(), immediate, target)
        })
        .collect())
}

#[cfg(test)]
pub(super) fn exit_for_test(bytes: &[u8]) -> Result<u8, String> {
    validate(&decode(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calls_return_to_each_continuation_and_preserve_state() {
        // Two different return sites share one callee; independent expected result 8.
        let bytes = [
            0xb8, 1, 0, 0, 0, 0xe8, 11, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0x05, 3, 0, 0, 0, 0xc3, 0x05, 2,
            0, 0, 0, 0xc3,
        ];
        assert_eq!(exit_for_test(&bytes).unwrap(), 8);
        // Shared callee chooses distinct RET sites using each invocation's EAX.
        assert_eq!(
            exit_for_test(&[
                0xb8, 0, 0, 0, 0, 0xe8, 17, 0, 0, 0, 0x05, 0, 0, 0, 0, 0xe8, 7, 0, 0, 0, 0x05, 3,
                0, 0, 0, 0xc3, 0x90, 0x3d, 0, 0, 0, 0, 0x74, 6, 0xb8, 2, 0, 0, 0, 0xc3, 0xb8, 1, 0,
                0, 0, 0xc3
            ])
            .unwrap(),
            5
        );
        // CALL/RET cannot make unknown flags known.
        assert!(
            translate(&[0xe8, 8, 0, 0, 0, 0xb8, 0, 0, 0, 0, 0x74, 0, 0xc3, 0xc3])
                .unwrap_err()
                .contains("unknown entry flags")
        );
        // Internal return with unknown EAX is legal if caller initializes it.
        assert_eq!(
            exit_for_test(&[0xe8, 6, 0, 0, 0, 0xb8, 42, 0, 0, 0, 0xc3, 0xc3]).unwrap(),
            42
        );
        assert!(translate(&[0xe8, 1, 0, 0, 0, 0xc3, 0xc3]).is_err());
    }

    #[test]
    fn calls_reject_invalid_forms_targets_and_continuations() {
        for bytes in [
            &[0xe8, 0, 0, 0][..],
            &[0xe8, 255, 255, 255, 255, 0xc3],
            &[0xe8, 255, 255, 255, 127, 0xc3],
            &[0xe8, 0, 0, 0, 0],
            &[0xe8, 1, 0, 0, 0, 0xb8, 0, 0, 0, 0, 0xc3],
            &[0xe8, 1, 0, 0, 0, 0x90, 0xc3],
            &[0x66, 0xe8, 0, 0],
            &[0xff, 0xd0],
            &[0x9a, 0, 0, 0, 0, 0, 0],
            &[0xc2, 0, 0],
            &[0x50],
            &[0x58],
            &[0x8b, 0x04, 0x24],
        ] {
            assert!(translate(bytes).is_err(), "{bytes:02x?}");
        }
    }

    #[test]
    fn call_depth_and_dynamic_execution_limits() {
        for depth in [32, 33] {
            let mut code = vec![0x31, 0xc0];
            for _ in 0..depth {
                code.extend([0xe8, 1, 0, 0, 0, 0xc3]);
            }
            code.push(0xc3);
            assert_eq!(translate(&code).is_ok(), depth == 32);
        }
        // Actual zero-flag path exits immediately, but an untaken call path
        // would nest33 calls. All-path policy must reject it before execution.
        let mut untaken = vec![0x31, 0xc0, 0x74, 6, 0xe8, 2, 0, 0, 0, 0xc3, 0xc3];
        for _ in 0..32 {
            untaken.extend([0xe8, 1, 0, 0, 0, 0xc3]);
        }
        untaken.push(0xc3);
        assert!(translate(&untaken)
            .unwrap_err()
            .contains("call nesting limit"));
        // Shared callee is executed twice: 1 MOV +2 CALL +2 RET +caller RET
        // plus 2*n XORs. n509 ->1024 operations, n510 ->1026 (decode <1024).
        for n in [509, 510] {
            let mut code = vec![0xb8, 0, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0xe8, 1, 0, 0, 0, 0xc3];
            code.extend([0x31, 0xc0].repeat(n));
            code.push(0xc3);
            assert_eq!(translate(&code).is_ok(), n == 509);
            if n == 509 {
                // One extra MOV in caller makes exactly1025 dynamic operations.
                let mut extra = vec![0xb8, 0, 0, 0, 0];
                extra.extend(code);
                assert!(translate(&extra)
                    .unwrap_err()
                    .contains("execution instruction limit"));
            }
        }
    }

    #[test]
    fn production_decode_errors_report_offset_and_reason() {
        for (bytes, reason) in [
            (
                vec![0x31, 0xc0, 0x66, 0xc3],
                "encoding outside exact subset",
            ),
            (
                vec![0x31, 0xc0, 0xb8, 1],
                "invalid or truncated instruction",
            ),
            (vec![0x31, 0xc0, 0x74, 0xfe], "backward branches"),
        ] {
            let error = translate(&bytes).unwrap_err();
            assert!(error.contains("entry offset 2"), "{error}");
            assert!(error.contains(reason), "{error}");
        }
    }

    #[test]
    fn arithmetic_flags_match_wide_integer_oracle() {
        let values = [
            0u32,
            1,
            2,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            0xffff_ffff,
        ];
        for a in values {
            for b in values {
                let signed_a = i64::from(a as i32);
                let signed_b = i64::from(b as i32);
                let (sum, add) = Flags::add(a, b);
                let wide_sum = u64::from(a) + u64::from(b);
                let signed_sum = signed_a + signed_b;
                assert_eq!(sum, wide_sum as u32);
                assert_eq!(
                    add,
                    Flags {
                        carry: wide_sum > u64::from(u32::MAX),
                        zero: sum == 0,
                        sign: (sum as i32) < 0,
                        overflow: signed_sum < i64::from(i32::MIN)
                            || signed_sum > i64::from(i32::MAX)
                    }
                );
                let difference = signed_a - signed_b;
                let result = difference as i32;
                let cmp = Flags::compare(a, b);
                assert_eq!(
                    cmp,
                    Flags {
                        carry: i64::from(a) - i64::from(b) < 0,
                        zero: a == b,
                        sign: result < 0,
                        overflow: difference < i64::from(i32::MIN)
                            || difference > i64::from(i32::MAX)
                    }
                );
                assert_eq!(Condition::SignedLess.test(cmp), signed_a < signed_b);
            }
        }
        assert_eq!(
            Flags::xor_self(),
            Flags {
                carry: false,
                zero: true,
                sign: false,
                overflow: false
            }
        );
    }

    #[test]
    fn compare_preserves_eax_and_mov_preserves_signed_flags() {
        assert_eq!(
            exit_for_test(&[0xb8, 42, 0, 0, 0, 0x3d, 100, 0, 0, 0, 0xc3]).unwrap(),
            42
        );
        let bytes = [
            0xb8, 0, 0, 0, 128, 0x3d, 255, 255, 255, 127, 0xb8, 7, 0, 0, 0, 0x7c, 6, 0xb8, 11, 0,
            0, 0, 0xc3, 0xb8, 22, 0, 0, 0, 0xc3,
        ];
        assert_eq!(exit_for_test(&bytes).unwrap(), 22);
    }

    #[test]
    fn rejects_unsupported_comparison_forms_and_unknown_state() {
        for bytes in [
            &[0x3d, 1, 0, 0, 0, 0xc3][..],
            &[0xb8, 1, 0, 0, 0, 0x7c, 0, 0xc3][..],
            &[0x3d, 1, 2, 3][..],
            &[0x31, 0xc0, 0x7d, 0xfe, 0xc3][..],
            &[0x31, 0xc0, 0x7e, 0, 0xc3][..],
            &[0x66, 0x3d, 0, 0, 0xc3][..],
            &[0x0f, 0x8c, 0, 0, 0, 0][..],
        ] {
            assert!(translate(bytes).is_err());
        }
    }

    #[test]
    fn signed_join_recomputes_flags_from_path_state() {
        for (a, b, expected) in [
            (0x8000_0000u32, 0x7fff_ffffu32, 22),
            (0x7fff_ffff, 0x8000_0000, 11),
        ] {
            let mut code = vec![0xb8];
            code.extend(a.to_le_bytes());
            code.push(0x3d);
            code.extend(b.to_le_bytes());
            code.extend([
                0x7c, 5, 0xb8, 11, 0, 0, 0, 0x3d, 0, 0, 0, 0, 0x7c, 6, 0xb8, 11, 0, 0, 0, 0xc3,
                0xb8, 22, 0, 0, 0, 0xc3,
            ]);
            assert_eq!(exit_for_test(&code).unwrap(), expected);
        }
    }

    #[test]
    fn signed_targets_must_be_instruction_boundaries() {
        assert!(translate(&[0x31, 0xc0, 0x7d, 1, 0x3d, 0, 0, 0, 0, 0xc3]).is_err());
        assert!(translate(&[0x31, 0xc0, 0x7c, 127, 0xc3]).is_err());
    }

    #[test]
    fn carry_and_zero_truth_table() {
        for (a, b, value, carry, zero) in [
            (0, 0, 0, false, true),
            (u32::MAX, 1, 0, true, true),
            (u32::MAX, 2, 1, true, false),
            (0x7fffffff, 1, 0x80000000, false, false),
        ] {
            let (result, flags) = Flags::add(a, b);
            assert_eq!((result, flags.carry, flags.zero), (value, carry, zero));
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
    fn joins_and_zero_displacement_preserve_path_state() {
        assert_eq!(
            exit_for_test(&[0x31, 0xc0, 0x74, 5, 0xb8, 11, 0, 0, 0, 0x05, 1, 0, 0, 0, 0xc3])
                .unwrap(),
            1
        );
        assert_eq!(
            exit_for_test(&[
                0xb8, 1, 0, 0, 0, 0x05, 0, 0, 0, 0, 0x74, 5, 0xb8, 11, 0, 0, 0, 0x05, 1, 0, 0, 0,
                0xc3
            ])
            .unwrap(),
            12
        );
        assert_eq!(
            exit_for_test(&[0x31, 0xc0, 0x74, 0, 0x05, 3, 0, 0, 0, 0xc3]).unwrap(),
            3
        );
    }

    #[test]
    fn instruction_limit_accepts_exact_boundary() {
        let mut code = [0x31, 0xc0].repeat(LIMIT - 1);
        code.push(0xc3);
        assert_eq!(exit_for_test(&code).unwrap(), 0);
        code.splice(0..0, [0x31, 0xc0]);
        assert!(translate(&code).is_err());
    }

    #[test]
    fn rejects_truncated_immediates_and_conditions_outside_subset() {
        for code in [
            &[0xb8, 1, 2, 3][..],
            &[0x05, 1, 2, 3][..],
            &[0x74][..],
            &[0x31, 0xc0, 0x70, 0, 0xc3][..],
        ] {
            assert!(translate(code).is_err());
        }
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

#[cfg(test)]
#[path = "control/stack_program_tests.rs"]
mod stack_program_tests;

#[cfg(test)]
#[allow(dead_code)]
#[path = "control/output_runtime.rs"]
mod output_runtime_tests;
