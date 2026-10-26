use super::*;
fn no_output(_: u32, _: u32) -> Result<u32, String> {
    panic!("unexpected output")
}
#[test]
fn ownership_types_and_unknown_state() {
    let mut s = State::new(0);
    s.step(Op::Call(20), 5, &mut no_output).unwrap();
    s.step(Op::Mov(99), 21, &mut no_output).unwrap();
    s.step(Op::MoveEsi, 23, &mut no_output).unwrap();
    assert!(s
        .step(Op::Ret, 24, &mut no_output)
        .unwrap_err()
        .contains("ESI"));
    assert_eq!(s.frames.len(), 2);
    let mut s = State::new(0);
    s.step(Op::Save, 1, &mut no_output).unwrap();
    s.step(Op::Push(7), 3, &mut no_output).unwrap();
    s.step(Op::Call(20), 8, &mut no_output).unwrap();
    assert_eq!(s.argument(1).unwrap(), Value::Integer(7));
    assert!(s.argument(2).is_err());
    assert!(s.step(Op::Restore, 21, &mut no_output).is_err());
    let mut s = State::new(0);
    s.step(Op::Pointer(0x2060), 5, &mut no_output).unwrap();
    s.step(Op::Call(20), 10, &mut no_output).unwrap();
    s.step(Op::Argument, 24, &mut no_output).unwrap();
    assert!(s.step(Op::CompareEax(0), 27, &mut no_output).is_err());
    assert!(s.step(Op::Ret, 28, &mut no_output).is_err());
    let mut s = State::new(0);
    assert!(s.step(Op::Branch(10), 2, &mut no_output).is_err());
    for _ in 0..5 {
        s.step(Op::Push(1), 1, &mut no_output).unwrap();
    }
    s.flags = Some(Flags::xor_self());
    s.step(Op::Cleanup, 2, &mut no_output).unwrap();
    assert!(s.flags.is_none());
}
#[test]
fn nested_saves_and_typed_returns() {
    let mut s = State::new(0);
    let original = s.esi;
    s.step(Op::Save, 1, &mut no_output).unwrap();
    s.step(Op::Mov(5), 6, &mut no_output).unwrap();
    s.step(Op::MoveEsi, 8, &mut no_output).unwrap();
    for target in [20, 40] {
        s.step(Op::Call(target), 10, &mut no_output).unwrap();
        s.step(Op::Save, target + 1, &mut no_output).unwrap();
        s.step(Op::Mov(12), target + 6, &mut no_output).unwrap();
        s.step(Op::MoveEsi, target + 8, &mut no_output).unwrap();
        s.step(Op::Restore, target + 9, &mut no_output).unwrap();
        s.step(Op::Ret, target + 10, &mut no_output).unwrap();
        assert_eq!(s.pc, 10);
        assert_eq!(s.esi, Value::Integer(5));
    }
    s.step(Op::Restore, 11, &mut no_output).unwrap();
    assert_eq!(s.esi, original);
    s.step(Op::Ret, 12, &mut no_output).unwrap();
    assert!(s.done);
}

#[test]
fn third_argument_arithmetic_boundaries() {
    // Literal expectations, independent of Flags::add/compare and decoder output.
    for (a, b, value, carry, zero, sign, overflow) in [
        (7, 3, 10, false, false, false, false),
        (0xffff_ffff, 1, 0, true, true, false, false),
        (0x7fff_ffff, 1, 0x8000_0000, false, false, true, true),
        (0x8000_0000, 0x8000_0000, 0, true, true, false, true),
        (
            0x8000_0000,
            0xffff_ffff,
            0x7fff_ffff,
            true,
            false,
            false,
            true,
        ),
        (0, 0xffff_ffff, 0xffff_ffff, false, false, true, false),
    ] {
        let mut s = State::new(0);
        for n in [b, 42, a] {
            s.step(Op::Push(n), 0, &mut no_output).unwrap();
        }
        s.step(Op::Call(20), 5, &mut no_output).unwrap();
        s.step(Op::Argument, 24, &mut no_output).unwrap();
        let words = s.words.clone();
        s.step(Op::AddThirdArgument, 28, &mut no_output).unwrap();
        assert_eq!(s.eax, Value::Integer(value));
        assert_eq!(
            s.flags,
            Some(Flags {
                carry,
                zero,
                sign,
                overflow
            })
        );
        assert_eq!(s.words, words);
    }
}

#[test]
fn third_argument_complete_word_and_ownership() {
    for word in [
        Word::Entry,
        Word::Saved(0, Value::Integer(3)),
        Word::Return(0, 9),
        Word::Data(99, Value::Integer(3)),
        Word::Data(0, Value::Pointer(0x2060)),
        Word::Data(0, Value::Unknown(9)),
    ] {
        let mut s = State::new(0);
        s.words.push(word);
        for n in [5, 7] {
            s.step(Op::Push(n), 0, &mut no_output).unwrap();
        }
        s.step(Op::Call(20), 5, &mut no_output).unwrap();
        s.step(Op::Argument, 24, &mut no_output).unwrap();
        let words = s.words.clone();
        assert!(s.step(Op::AddThirdArgument, 28, &mut no_output).is_err());
        assert_eq!(s.words, words);
        assert_eq!(s.eax, Value::Integer(7));
    }
    // Insufficient words and a displaced Return cannot expose a partial argument.
    let mut s = State::new(0);
    s.step(Op::Call(20), 5, &mut no_output).unwrap();
    s.eax = Value::Integer(7);
    assert!(s.step(Op::AddThirdArgument, 24, &mut no_output).is_err());
    for n in [3, 5, 7] {
        s.step(Op::Push(n), 0, &mut no_output).unwrap();
    }
    assert!(s.step(Op::AddThirdArgument, 28, &mut no_output).is_err());
    for eax in [Value::Pointer(0x2060), Value::Unknown(0)] {
        let mut s = State::new(0);
        for n in [3, 5, 7] {
            s.step(Op::Push(n), 0, &mut no_output).unwrap();
        }
        s.step(Op::Call(20), 5, &mut no_output).unwrap();
        s.eax = eax;
        assert!(s.step(Op::AddThirdArgument, 24, &mut no_output).is_err());
        assert_eq!(s.eax, eax);
    }
}

#[test]
fn cleanup_six_atomic_ownership_and_unknown_flags() {
    for protected in [
        Word::Entry,
        Word::Saved(0, Value::Unknown(1)),
        Word::Return(0, 9),
        Word::Data(99, Value::Integer(0)),
    ] {
        for position in 0..6 {
            let mut s = State::new(0);
            s.words
                .extend((0..6).map(|_| Word::Data(0, Value::Integer(0))));
            s.words[position + 1] = protected.clone();
            let before = s.words.clone();
            assert!(s.step(Op::CleanupSix, 3, &mut no_output).is_err());
            assert_eq!(s.words, before);
        }
    }
    let mut s = State::new(0);
    assert!(s.step(Op::CleanupSix, 3, &mut no_output).is_err());
    for _ in 0..6 {
        s.step(Op::Push(1), 0, &mut no_output).unwrap();
    }
    s.step(Op::Xor, 2, &mut no_output).unwrap();
    s.step(Op::CleanupSix, 5, &mut no_output).unwrap();
    assert_eq!(s.words, [Word::Entry]);
    s.step(Op::Mov(0), 10, &mut no_output).unwrap();
    assert!(s
        .step(Op::Branch(20), 12, &mut no_output)
        .unwrap_err()
        .contains("unknown branch flags"));
    s.step(Op::CompareEax(0), 15, &mut no_output).unwrap();
    assert_eq!(
        s.step(Op::Branch(20), 17, &mut no_output).unwrap(),
        Some(20)
    );
    s.step(Op::Ret, 18, &mut no_output).unwrap();
    assert!(s.done);
    let mut s = State::new(0);
    for _ in 0..7 {
        s.step(Op::Push(1), 0, &mut no_output).unwrap();
    }
    s.step(Op::CleanupSix, 3, &mut no_output).unwrap();
    s.step(Op::Mov(0), 8, &mut no_output).unwrap();
    assert!(s.step(Op::Ret, 9, &mut no_output).is_err());
}

#[test]
fn nested_shared_third_argument_contexts() {
    let mut s = State::new(0);
    s.step(Op::Call(20), 5, &mut no_output).unwrap();
    // Same inner target and different caller-owned values in a truly nested call.
    for (a, b, c, expected) in [(7, 5, 3, 15), (1, 2, 3, 6)] {
        for n in [0, 0, 0, c, b, a] {
            s.step(Op::Push(n), 20, &mut no_output).unwrap();
        }
        s.step(Op::Call(100), 40, &mut no_output).unwrap();
        assert_eq!(s.frames.len(), 3);
        for op in [Op::Argument, Op::AddArgument, Op::AddThirdArgument] {
            s.step(op, 100, &mut no_output).unwrap();
        }
        assert_eq!(s.eax, Value::Integer(expected));
        s.step(Op::Ret, 113, &mut no_output).unwrap();
        assert_eq!(s.pc, 40);
        s.step(Op::CleanupSix, 43, &mut no_output).unwrap();
    }
    s.step(Op::Ret, 44, &mut no_output).unwrap();
    assert_eq!(s.pc, 5);
    s.step(Op::Ret, 6, &mut no_output).unwrap();
    assert!(s.done);
}

#[test]
fn new_forms_preserve_resource_limits() {
    let mut s = State::new(0);
    for _ in 0..128 {
        s.step(Op::Push(0), 0, &mut no_output).unwrap();
    }
    assert!(s.step(Op::Push(0), 0, &mut no_output).is_err());
    assert!(s.step(Op::Call(20), 5, &mut no_output).is_err());
    s.step(Op::CleanupSix, 3, &mut no_output).unwrap();
    assert_eq!(s.words.len(), 123);
    s.step(Op::Call(20), 5, &mut no_output).unwrap();
    s.step(Op::Mov(0), 25, &mut no_output).unwrap();
    s.step(Op::AddThirdArgument, 29, &mut no_output).unwrap();
    let mut s = State::new(0);
    for _ in 0..32 {
        s.step(Op::Call(20), 5, &mut no_output).unwrap();
    }
    assert!(s.step(Op::Call(20), 5, &mut no_output).is_err());
    let mut s = State::new(0);
    for _ in 0..6 {
        s.step(Op::Push(0), 0, &mut no_output).unwrap();
    }
    for _ in 6..1024 {
        s.step(Op::Mov(0), 0, &mut no_output).unwrap();
    }
    let before = s.words.clone();
    assert!(s.step(Op::CleanupSix, 3, &mut no_output).is_err());
    assert_eq!(s.words, before);
}
