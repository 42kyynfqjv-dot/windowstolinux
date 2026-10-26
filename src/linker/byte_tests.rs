use super::*;
fn step(s: &mut State, op: Op) {
    s.step(op, s.pc + 1, &mut |_, _| panic!("output")).unwrap();
}
fn reject(s: &mut State, op: Op) {
    let before = s.clone();
    assert!(s.step(op, s.pc + 1, &mut |_, _| panic!("output")).is_err());
    assert_eq!(*s, before);
}
#[test]
fn partial_byte_inc_flags_and_full_consumers() {
    for (old, new, z, n, o) in [
        (0, 1, false, false, false),
        (127, 128, false, true, true),
        (128, 129, false, true, false),
        (255, 0, true, false, false),
    ] {
        for carry in [None, Some(false), Some(true)] {
            let mut s = State::new(0);
            s.eax = Value::Partial([Some(old), None, Some(0xab), None]);
            s.flags.carry = carry;
            step(&mut s, Op::IncAl);
            assert_eq!(s.eax, Value::Partial([Some(new), None, Some(0xab), None]));
            assert_eq!(
                s.flags,
                Knowledge {
                    carry,
                    zero: Some(z),
                    sign: Some(n),
                    overflow: Some(o)
                }
            );
            for op in [Op::AddEcx, Op::CompareEax(0), Op::MoveEsi, Op::Ret] {
                reject(&mut s, op);
            }
            step(&mut s, Op::PushEcx);
            step(&mut s, Op::StoreAl);
            step(&mut s, Op::LoadByteEax(1));
            assert_eq!(s.eax, Value::Integer(u32::from(new)));
        }
    }
    for value in [
        Value::Pointer(0x2000),
        Value::Unknown(0),
        Value::Partial([None, Some(1), Some(2), Some(3)]),
    ] {
        let mut s = State::new(0);
        s.eax = value;
        reject(&mut s, Op::IncAl);
    }
    let mut s = State::new(0);
    s.eax = Value::Integer(0x123456ff);
    step(&mut s, Op::IncAl);
    assert_eq!(s.eax, Value::Integer(0x12345600));
    // CMOV reads only SF/OF; JZ only ZF. Unknown required flags reject.
    s.eax = Value::Integer(127);
    s.edx = Value::Integer(9);
    step(&mut s, Op::IncAl);
    step(&mut s, Op::SelectGe);
    assert_eq!(s.eax, Value::Integer(9));
    s.flags.sign = None;
    reject(&mut s, Op::SelectGe);
    s.flags.zero = None;
    reject(&mut s, Op::Equal(99));
}
#[test]
fn byte_pop_repush_literal_trace_and_nested_context() {
    let mut s = State::new(0);
    step(&mut s, Op::PushEcx);
    step(&mut s, Op::StoreByte(0, 65));
    step(&mut s, Op::StoreByte(1, 66));
    step(&mut s, Op::LoadByteEax(1));
    step(&mut s, Op::IncAl);
    step(&mut s, Op::StoreAl);
    let caller = s.words.clone();
    for _ in 0..2 {
        step(&mut s, Op::Call(100));
        reject(&mut s, Op::LoadByteEax(0));
        step(&mut s, Op::PushEcx);
        reject(&mut s, Op::LoadByteEax(1));
        step(&mut s, Op::StoreByte(1, 7));
        step(&mut s, Op::LoadByteEax(1));
        step(&mut s, Op::PopEcx);
        step(&mut s, Op::Ret);
        assert_eq!(s.words, caller);
        s.ecx = Value::Unknown(2);
    }
    step(&mut s, Op::LoadByteEcx);
    step(&mut s, Op::LoadByteEax(0));
    step(&mut s, Op::AddEcx);
    let flags = s.flags;
    step(&mut s, Op::PopEcx);
    assert_eq!(s.ecx, Value::Partial([Some(65), Some(67), None, None]));
    step(&mut s, Op::PushEcx);
    assert_eq!(s.byte_window().unwrap(), [Some(65), Some(67), None, None]);
    step(&mut s, Op::PopEcx);
    assert_eq!(s.flags, flags);
    step(&mut s, Op::Ret);
    assert_eq!(s.eax, Value::Integer(132));
}
#[test]
fn byte_atomic_owner_alias_cleanup_and_unknown_failures() {
    for bad in [
        Word::Entry,
        Word::Return(0, 9),
        Word::Saved(0, Value::Unknown(1)),
        Word::Data(0, Value::Integer(1)),
        Word::Local(0, 1, Some(1)),
        Word::Bytes(99, 1, [Some(1); 4]),
        Word::Bytes(0, 99, [Some(1); 4]),
    ] {
        let mut s = State::new(0);
        step(&mut s, Op::PushEcx);
        s.words[1] = bad;
        for op in [
            Op::StoreByte(0, 7),
            Op::LoadByteEax(0),
            Op::PopEcx,
            Op::Call(10),
            Op::CleanupTwo,
        ] {
            reject(&mut s, op);
        }
    }
    let mut s = State::new(0);
    step(&mut s, Op::PushEcx);
    for op in [
        Op::LoadByteEax(0),
        Op::StoreAl,
        Op::PushEcx,
        Op::AllocateLocal,
        Op::StoreFour(12),
        Op::Argument,
        Op::CleanupTwo,
        Op::Cleanup,
        Op::CleanupSix,
        Op::Save,
        Op::Push(1),
        Op::Tail(10),
        Op::Ret,
        Op::StoreByte(2, 0),
        Op::LoadByteEax(2),
    ] {
        reject(&mut s, op);
    }
    let mut other = s.clone();
    step(&mut s, Op::StoreByte(1, 7));
    step(&mut s, Op::LoadByteEax(1));
    reject(&mut other, Op::LoadByteEax(1));
    s.steps = 1024;
    reject(&mut s, Op::PopEcx);
    let mut s = State::new(0);
    step(&mut s, Op::AllocateLocal);
    reject(&mut s, Op::PopEcx);
    reject(&mut s, Op::StoreByte(0, 1));
    let mut s = State::new(0);
    s.ecx = Value::Pointer(0x2000);
    reject(&mut s, Op::PushEcx);
}
