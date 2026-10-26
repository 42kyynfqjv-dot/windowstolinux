use super::*;
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
pub(crate) fn translate(
    bytes: &[u8],
    iat: u32,
    mut read: impl FnMut(u32) -> Result<u32, String>,
    mut buffer: impl FnMut(u32, u32) -> Result<Vec<u8>, String>,
) -> Result<String, String> {
    let mut program = decode_with(bytes, |bytes, at| {
        if bytes.get(at) != Some(&0xff) {
            return decode_instruction(bytes, at);
        }
        let tail = &bytes[at..];
        let ins = Decoder::new(32, tail, DecoderOptions::NONE).decode();
        if tail.get(..2) != Some(&[0xff, 0x15])
            || ins.code() != Code::Call_rm32
            || ins.len() != 6
            || ins.op0_kind() != OpKind::Memory
            || ins.memory_base() != Register::None
            || ins.memory_index() != Register::None
            || ins.memory_displ_size() != 4
            || ins.memory_segment() != Register::DS
            || ins.memory_displacement64() != u64::from(iat)
        {
            return Err("unsupported imported call".into());
        }
        Ok(Instruction {
            op: Op::Import(iat),
            next: at + 6,
        })
    })?;
    if program
        .values()
        .filter(|i| matches!(i.op, Op::Import(_)))
        .count()
        != 1
    {
        return Err("exactly one imported call site required".into());
    }
    for ins in program.values_mut() {
        if let Op::LoadAbsolute(a) = ins.op {
            ins.op = Op::Mov(read(a)?);
        }
    }
    let mut pending = vec![(0, None, None, Stack::new(), false, 0)];
    let mut payloads = BTreeMap::new();
    let mut budget = 0;
    while let Some((mut pc, mut eax, mut flags, mut stack, mut used, mut steps)) = pending.pop() {
        loop {
            budget += 1;
            steps += 1;
            if steps > LIMIT || budget > 16384 {
                return Err("output analysis resource limit".into());
            }
            let at = pc;
            let ins = program.get(&at).ok_or("output missing instruction")?;
            pc = ins.next;
            match ins.op {
                Op::Mov(v) => eax = Some(v),
                Op::PushData(v) => stack.push(v)?,
                Op::LoadArgument => eax = Some(stack.argument()?),
                Op::DropData => stack.cleanup()?,
                Op::Add(v) => {
                    let (r, f) = Flags::add(eax.ok_or("unknown EAX")?, v);
                    eax = Some(r);
                    flags = Some(f);
                }
                Op::Compare(v) => flags = Some(Flags::compare(eax.ok_or("unknown EAX")?, v)),
                Op::Xor => {
                    eax = Some(0);
                    flags = Some(Flags::xor_self());
                }
                Op::Import(_) => {
                    if used {
                        return Err("repeated imported call".into());
                    }
                    used = true;
                    let [count, address, _] = stack.output_arguments(ins.next)?;
                    let value = buffer(address, count)?;
                    if let Some(old) = payloads.insert(at, value.clone()) {
                        if old != value {
                            return Err("context-dependent output payload".into());
                        }
                    }
                    eax = Some(count);
                    flags = None;
                }
                Op::Branch { target, .. } => {
                    flags.ok_or("unknown output-path flags")?;
                    if target != pc {
                        pending.push((target, eax, flags, stack.clone(), used, steps));
                    }
                }
                Op::Call { target } => {
                    stack.call(ins.next)?;
                    pc = target;
                }
                Op::Ret => match stack.ret(eax)? {
                    Return::Resume(next) => pc = next,
                    Return::Exit(_) => break,
                },
                _ => return Err("unresolved output instruction".into()),
            }
        }
    }
    for (at, payload) in &payloads {
        program.get_mut(at).unwrap().op = Op::Output(payload.len() as u32);
    }
    emit_outputs(&program, &payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code() -> Vec<u8> {
        let mut b = vec![
            0x68, 5, 0, 0, 0, 0x68, 0, 0x20, 0x40, 0, 0x68, 1, 0, 0, 0, 0xff, 0x15, 0x50, 0x30,
            0x40, 0,
        ];
        b.extend([0x8d, 0x64, 0x24, 4].repeat(3));
        b.extend([0xb8, 0, 0, 0, 0, 0xc3]);
        b
    }
    fn check(b: &[u8]) -> Result<String, String> {
        translate(
            b,
            0x403050,
            |_| Err("no read".into()),
            |a, n| {
                if a == 0x402000 && n == 5 {
                    Ok(b"Hello".to_vec())
                } else {
                    Err("bad buffer".into())
                }
            },
        )
    }
    #[test]
    fn imported_context_repetition_flags_and_encodings() {
        let base = code();
        assert!(check(&base).unwrap().contains("native_output"));
        let mut repeat = vec![0xe8, 11, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0xb8, 0, 0, 0, 0, 0xc3];
        repeat.extend(&base);
        assert!(check(&repeat).unwrap_err().contains("repeated"));
        for prefix in [0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x3e, 0x64, 0x65] {
            let mut b = base.clone();
            b.insert(15, prefix);
            assert!(check(&b).is_err());
        }
        for modrm in 0..=255u8 {
            if modrm != 0x15 {
                let mut b = base.clone();
                b[16] = modrm;
                assert!(check(&b).is_err());
            }
        }
        let mut b = base.clone();
        b.splice(33..38, [0x74, 0, 0xb8, 0, 0, 0, 0]);
        assert!(check(&b).is_err());
    }
    #[test]
    fn imported_stack_transient_limits_and_protected_words() {
        for count in [125, 126] {
            let mut s = Stack::new();
            for _ in 0..count {
                s.push(5).unwrap();
            }
            s.push(0x402000).unwrap();
            s.push(1).unwrap();
            assert_eq!(s.output_arguments(1).is_ok(), count == 125);
        }
        let mut s = Stack::new();
        s.push(5).unwrap();
        s.push(0x402000).unwrap();
        s.call(0).unwrap();
        s.push(1).unwrap();
        assert!(s.output_arguments(1).is_err());
        let mut s = Stack::new();
        for _ in 0..32 {
            s.call(0).unwrap();
        }
        s.push(5).unwrap();
        s.push(0x402000).unwrap();
        s.push(1).unwrap();
        assert!(s.output_arguments(1).is_err());
    }
}
