use super::*;
fn tick(s: &mut State, op: Op) {
    s.step(op, s.pc + 1, &mut |_, _| panic!("output")).unwrap();
}
fn reject(s: &mut State, op: Op) {
    let before = s.clone();
    assert!(s.step(op, s.pc + 1, &mut |_, _| panic!("output")).is_err());
    assert_eq!(*s, before, "rejected transition mutated state");
}
fn allocated() -> State {
    let mut s = State::new(0);
    tick(&mut s, Op::AllocateLocal);
    s
}
#[test]
fn local_literal_layout_initialization_flags_and_scalars() {
    let mut s = allocated();
    assert_eq!(
        s.words,
        [
            Word::Entry,
            Word::Local(0, 1, None),
            Word::Local(0, 1, None)
        ]
    );
    reject(&mut s, Op::Argument);
    tick(&mut s, Op::StoreLocalZero(7));
    reject(&mut s, Op::Argument);
    tick(&mut s, Op::StoreFour(5));
    assert_eq!(
        s.words,
        [
            Word::Entry,
            Word::Local(0, 1, Some(5)),
            Word::Local(0, 1, Some(7))
        ]
    );
    tick(&mut s, Op::Argument);
    tick(&mut s, Op::AddLocalZero);
    assert_eq!(s.eax, Value::Integer(12));
    tick(&mut s, Op::CleanupTwo);
    assert_eq!(s.flags, None);
    reject(&mut s, Op::Equal(99));
    tick(&mut s, Op::Ret);
    assert!(s.done);
    assert_eq!(s.steps, 7);
    reject(&mut s, Op::AllocateLocal);
    for (a, b, result, c, z, n, o) in [
        (0xffffffff, 1, 0, true, true, false, false),
        (0x7fffffff, 1, 0x80000000, false, false, true, true),
        (0x80000000, 0xffffffff, 0x7fffffff, true, false, false, true),
        (0x80000000, 0x80000000, 0, true, true, false, true),
        (0, 0xffffffff, 0xffffffff, false, false, true, false),
    ] {
        let mut s = allocated();
        tick(&mut s, Op::StoreLocalZero(b));
        tick(&mut s, Op::StoreFour(a));
        tick(&mut s, Op::Argument);
        tick(&mut s, Op::AddLocalZero);
        let expected = Some(Flags {
            carry: c,
            zero: z,
            sign: n,
            overflow: o,
        });
        assert_eq!(s.eax, Value::Integer(result));
        assert_eq!(s.flags, expected);
        tick(&mut s, Op::StoreFour(0x402000));
        tick(&mut s, Op::Argument);
        assert_eq!(s.eax, Value::Integer(0x402000));
        assert_eq!(s.flags, expected);
        for value in [Value::Pointer(0x2000), Value::Unknown(10)] {
            s.eax = value;
            reject(&mut s, Op::AddLocalZero);
        }
    }
}
#[test]
fn local_complete_window_atomic_ownership_and_no_cleanup_fallback() {
    for replacement in [
        Word::Entry,
        Word::Return(0, 99),
        Word::Saved(0, Value::Integer(1)),
        Word::Data(0, Value::Integer(1)),
        Word::Local(99, 1, Some(1)),
        Word::Local(0, 99, Some(1)),
    ] {
        for index in [1, 2] {
            let mut s = allocated();
            s.words[index] = replacement.clone();
            for op in [
                Op::StoreLocalZero(7),
                Op::StoreFour(5),
                Op::Argument,
                Op::AddLocalZero,
                Op::CleanupTwo,
                Op::Call(20),
            ] {
                reject(&mut s, op);
            }
        }
    }
    let mut s = allocated();
    s.words[0] = Word::Return(0, 7);
    reject(&mut s, Op::StoreFour(7));
    reject(&mut s, Op::CleanupTwo);
    let mut s = allocated();
    s.words[1] = Word::Data(0, Value::Integer(1));
    s.words[2] = Word::Data(0, Value::Integer(2));
    reject(&mut s, Op::CleanupTwo); // both Data still cannot trigger fallback
    s.frames[0].allocation = None;
    tick(&mut s, Op::CleanupTwo); // explicit Data mode
    let mut s = allocated();
    s.frames[0].allocation = None;
    reject(&mut s, Op::CleanupTwo); // untracked Local
    for values in [
        [Value::Integer(1), Value::Integer(2)],
        [Value::Pointer(0x2000), Value::Unknown(3)],
    ] {
        let mut s = State::new(0);
        s.words.extend(values.map(|v| Word::Data(0, v)));
        tick(&mut s, Op::CleanupTwo);
        assert_eq!(s.words, [Word::Entry]);
    }
}
#[test]
fn local_live_frame_exclusions_fresh_allocations_and_calls() {
    let mut s = allocated();
    for op in [
        Op::AllocateLocal,
        Op::Push(1),
        Op::Pointer(0x2000),
        Op::Save,
        Op::Restore,
        Op::CopyArgument,
        Op::StoreSecond,
        Op::Tail(10),
        Op::Write,
        Op::Cleanup,
        Op::CleanupSix,
        Op::Ret,
    ] {
        reject(&mut s, op);
    }
    tick(&mut s, Op::StoreLocalZero(7));
    tick(&mut s, Op::StoreFour(5));
    let caller = s.words.clone();
    for _ in 0..2 {
        tick(&mut s, Op::Call(20));
        reject(&mut s, Op::Argument);
        tick(&mut s, Op::AllocateLocal);
        reject(&mut s, Op::Argument);
        tick(&mut s, Op::StoreFour(1));
        tick(&mut s, Op::Argument);
        tick(&mut s, Op::CleanupTwo);
        tick(&mut s, Op::Ret);
        assert_eq!(s.words, caller);
    }
    tick(&mut s, Op::Argument);
    tick(&mut s, Op::AddLocalZero);
    assert_eq!(s.eax, Value::Integer(12));
    tick(&mut s, Op::CleanupTwo);
    tick(&mut s, Op::AllocateLocal);
    reject(&mut s, Op::Argument);
    tick(&mut s, Op::CleanupTwo);
    tick(&mut s, Op::Push(1));
    reject(&mut s, Op::AllocateLocal);
    let mut s = State::new(0);
    tick(&mut s, Op::Save);
    reject(&mut s, Op::AllocateLocal);
}
#[test]
fn local_path_initialization_limits_and_return_obligations() {
    let s = allocated();
    let mut a = s.clone();
    let mut b = s;
    tick(&mut a, Op::StoreFour(7));
    tick(&mut a, Op::Argument);
    reject(&mut b, Op::Argument);
    let mut s = allocated();
    s.steps = 1024;
    reject(&mut s, Op::StoreFour(7));
    let mut s = State::new(0);
    // Place each new Return above three valid caller Data words: boundary127.
    for _ in 0..31 {
        for _ in 0..3 {
            tick(&mut s, Op::Push(0));
        }
        tick(&mut s, Op::Call(100));
    }
    for _ in 0..2 {
        tick(&mut s, Op::Push(0));
    }
    tick(&mut s, Op::Call(100));
    assert_eq!(s.words.len(), 128);
    reject(&mut s, Op::AllocateLocal);
    reject(&mut s, Op::Call(100));
    let mut s = allocated();
    tick(&mut s, Op::Mov(256));
    tick(&mut s, Op::CleanupTwo);
    reject(&mut s, Op::Ret);
    let mut s = allocated();
    tick(&mut s, Op::Mov(7));
    tick(&mut s, Op::MoveEsi);
    tick(&mut s, Op::CleanupTwo);
    reject(&mut s, Op::Ret);
}
