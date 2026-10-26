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

#[test]
fn two_word_cleanup_ownership_flags_and_balance() {
    for protected in [
        Word::Entry,
        Word::Saved(0, Value::Unknown(1)),
        Word::Return(0, 9),
        Word::Data(99, Value::Integer(0)),
    ] {
        for position in 0..2 {
            let mut s = State::new(0);
            s.words.extend([
                Word::Data(0, Value::Integer(1)),
                Word::Data(0, Value::Integer(2)),
            ]);
            s.words[position + 1] = protected.clone();
            let before = s.words.clone();
            assert!(s.step(Op::CleanupTwo, 3, &mut no_output).is_err());
            assert_eq!(s.words, before);
        }
    }
    let mut s = State::new(0);
    assert!(s.step(Op::CleanupTwo, 3, &mut no_output).is_err());
    s.step(Op::Save, 1, &mut no_output).unwrap();
    let saved = s.words.clone();
    s.step(Op::Push(7), 3, &mut no_output).unwrap();
    s.step(Op::Pointer(0x2060), 8, &mut no_output).unwrap();
    s.step(Op::Xor, 10, &mut no_output).unwrap();
    s.step(Op::CleanupTwo, 13, &mut no_output).unwrap();
    assert_eq!(s.words, saved);
    assert!(s.flags.is_none());
    s.step(Op::Mov(0), 18, &mut no_output).unwrap();
    assert!(s.step(Op::Branch(30), 20, &mut no_output).is_err());
    s.step(Op::CompareEax(0), 23, &mut no_output).unwrap();
    assert_eq!(
        s.step(Op::Branch(30), 25, &mut no_output).unwrap(),
        Some(30)
    );
    s.step(Op::Restore, 26, &mut no_output).unwrap();
    s.step(Op::Ret, 27, &mut no_output).unwrap();
    assert!(s.done);
    let mut s = State::new(0);
    for _ in 0..3 {
        s.step(Op::Push(0), 0, &mut no_output).unwrap();
    }
    s.step(Op::CleanupTwo, 3, &mut no_output).unwrap();
    s.step(Op::Mov(0), 8, &mut no_output).unwrap();
    assert!(s.step(Op::Ret, 9, &mut no_output).is_err());
}

#[test]
fn conditional_scalar_literal_boundaries() {
    // CF/ZF/SF/OF and GE are literal expectations, not Flags helper results.
    for (a, b, carry, zero, sign, overflow, ge) in [
        (7, 5, false, false, false, false, true),
        (3, 4, true, false, true, false, false),
        (0, 0, false, true, false, false, true),
        (0x8000_0000, 0x7fff_ffff, false, false, false, true, false),
        (0x7fff_ffff, 0x8000_0000, true, false, true, true, true),
        (0xffff_ffff, 0, false, false, true, false, false),
        (0, 0xffff_ffff, true, false, false, false, true),
    ] {
        let mut s = State::new(0);
        s.ecx = Value::Integer(a);
        s.eax = Value::Integer(b);
        s.step(Op::EdxOne, 5, &mut no_output).unwrap();
        s.step(Op::CompareEcxEax, 7, &mut no_output).unwrap();
        let flags = Some(Flags {
            carry,
            zero,
            sign,
            overflow,
        });
        assert_eq!(s.flags, flags);
        assert_eq!(
            (s.ecx, s.eax, s.edx),
            (Value::Integer(a), Value::Integer(b), Value::Integer(1))
        );
        s.step(Op::SelectGe, 10, &mut no_output).unwrap();
        assert_eq!(s.eax, Value::Integer(if ge { 1 } else { b }));
        assert_eq!(s.flags, flags);
    }
    for (a, b, value, carry, zero, sign, overflow) in [
        (0xffff_ffff, 1, 0, true, true, false, false),
        (0x7fff_ffff, 1, 0x8000_0000, false, false, true, true),
        (0x8000_0000, 0x8000_0000, 0, true, true, false, true),
    ] {
        let mut s = State::new(0);
        s.eax = Value::Integer(a);
        s.ecx = Value::Integer(b);
        s.step(Op::AddEcx, 2, &mut no_output).unwrap();
        assert_eq!(s.eax, Value::Integer(value));
        assert_eq!(s.ecx, Value::Integer(b));
        assert_eq!(
            s.flags,
            Some(Flags {
                carry,
                zero,
                sign,
                overflow
            })
        );
    }
}

#[test]
fn conditional_invalid_scalars_and_unknown_flags() {
    for op in [Op::CompareEcxEax, Op::AddEcx, Op::SelectGe] {
        for bad in [Value::Pointer(0x2060), Value::Unknown(20)] {
            for operand in 0..2 {
                for flags in [Some(Flags::compare(0, 1)), Some(Flags::compare(1, 0))] {
                    let mut s = State::new(0);
                    s.eax = Value::Integer(5);
                    s.ecx = Value::Integer(3);
                    s.edx = Value::Integer(1);
                    s.flags = flags;
                    if operand == 0 {
                        s.eax = bad
                    } else if matches!(op, Op::SelectGe) {
                        s.edx = bad
                    } else {
                        s.ecx = bad
                    }
                    let before = (s.eax, s.ecx, s.edx, s.flags, s.words.clone());
                    assert!(s.step(op, 3, &mut no_output).is_err());
                    assert_eq!((s.eax, s.ecx, s.edx, s.flags, s.words), before);
                }
            }
        }
    }
    let mut s = State::new(0);
    s.eax = Value::Integer(0);
    s.step(Op::EdxOne, 5, &mut no_output).unwrap();
    assert!(s
        .step(Op::SelectGe, 8, &mut no_output)
        .unwrap_err()
        .contains("unknown conditional flags"));
    s.steps = 1024;
    assert!(s
        .step(Op::EdxOne, 13, &mut no_output)
        .unwrap_err()
        .contains("instruction limit"));
}

#[test]
fn scalar_argument_ownership_and_mov_flags() {
    for (op, index) in [(Op::ScalarArgumentTwo, 2), (Op::EcxArgumentOne, 1)] {
        for bad in [
            Word::Entry,
            Word::Return(0, 9),
            Word::Saved(0, Value::Integer(7)),
            Word::Data(99, Value::Integer(7)),
            Word::Data(0, Value::Pointer(0x2060)),
            Word::Data(0, Value::Unknown(12)),
        ] {
            let mut s = State::new(0);
            s.words.extend([
                Word::Data(0, Value::Integer(5)),
                Word::Data(0, Value::Integer(7)),
            ]);
            s.words[3 - index] = bad;
            s.step(Op::Call(20), 5, &mut no_output).unwrap();
            let before = (s.eax, s.ecx, s.words.clone());
            assert!(s.step(op, 24, &mut no_output).is_err());
            assert_eq!((s.eax, s.ecx, s.words), before);
        }
        let mut s = State::new(0);
        s.step(Op::Call(20), 5, &mut no_output).unwrap();
        assert!(s.step(op, 24, &mut no_output).is_err());
    }
    for flags in [None, Some(Flags::compare(0x8000_0000, 1))] {
        let mut s = State::new(0);
        s.flags = flags;
        for op in [
            Op::Push(5),
            Op::Push(7),
            Op::Call(20),
            Op::ScalarArgumentTwo,
            Op::EcxArgumentOne,
            Op::EdxOne,
        ] {
            s.step(op, 5, &mut no_output).unwrap();
            assert_eq!(s.flags, flags);
        }
        assert_eq!(
            (s.eax, s.ecx, s.edx),
            (Value::Integer(5), Value::Integer(7), Value::Integer(1))
        );
        s.step(Op::Push(0), 5, &mut no_output).unwrap();
        assert!(s.step(Op::EcxArgumentOne, 9, &mut no_output).is_err());
    }
}

#[test]
fn volatile_register_call_effects_and_fresh_external_origins() {
    let mut preserved = State::new(0);
    preserved.ecx = Value::Integer(7);
    preserved.edx = Value::Integer(1);
    preserved.flags = Some(Flags::compare(3, 4));
    let before = (preserved.ecx, preserved.edx, preserved.flags);
    for op in [Op::Call(20), Op::Mov(8), Op::Ret] {
        preserved.step(op, 5, &mut no_output).unwrap();
        assert_eq!((preserved.ecx, preserved.edx, preserved.flags), before);
    }
    let mut s = State::new(0);
    assert_ne!(s.ecx, s.edx);
    assert_ne!(s.ecx, s.eax);
    assert_ne!(s.edx, s.esi);
    for op in [
        Op::Push(5),
        Op::Push(7),
        Op::Call(20),
        Op::EcxArgumentOne,
        Op::EdxOne,
        Op::Mov(8),
        Op::Ret,
    ] {
        s.step(op, 5, &mut no_output).unwrap();
    }
    assert_eq!(
        (s.eax, s.ecx, s.edx),
        (Value::Integer(8), Value::Integer(7), Value::Integer(1))
    );
    let mut other = s.clone();
    other.ecx = Value::Integer(3);
    assert_eq!(s.ecx, Value::Integer(7));
    s.step(Op::CleanupTwo, 8, &mut no_output).unwrap();
    assert!(s.step(Op::SelectGe, 11, &mut no_output).is_err());
    for op in [Op::Push(5), Op::Pointer(0x2060), Op::Push(1)] {
        s.step(op, 12, &mut no_output).unwrap();
    }
    let words = s.words.clone();
    let esi = s.esi;
    let mut origins = vec![
        Value::Unknown(0),
        Value::Unknown(1),
        Value::Unknown(2),
        Value::Unknown(3),
    ];
    for _ in 0..3 {
        s.step(Op::Write, 18, &mut |rva, n| {
            assert_eq!((rva, n), (0x2060, 5));
            Ok(5)
        })
        .unwrap();
        assert_eq!(s.eax, Value::Integer(5));
        assert_eq!(s.esi, esi);
        assert_eq!(s.words, words);
        assert!(s.flags.is_none());
        for value in [s.ecx, s.edx] {
            assert!(matches!(value, Value::Unknown(_)));
            assert!(!origins.contains(&value));
            origins.push(value);
        }
        let clone = s.clone();
        assert_eq!((clone.ecx, clone.edx), (s.ecx, s.edx));
        assert!(s.step(Op::AddEcx, 20, &mut no_output).is_err());
        s.step(Op::CompareEax(5), 23, &mut no_output).unwrap();
        assert!(s.step(Op::SelectGe, 26, &mut no_output).is_err());
    }
}

#[test]
fn nested_copy_store_tail_context_and_atomic_rejection() {
    let mut s = State::new(0);
    for op in [
        Op::Push(5),
        Op::Push(7),
        Op::Call(0x1050),
        Op::CopyArgument,
        Op::CopyArgument,
    ] {
        s.step(op, 0x101b, &mut no_output).unwrap();
    }
    assert_eq!(
        s.words,
        vec![
            Word::Entry,
            Word::Data(0, Value::Integer(5)),
            Word::Data(0, Value::Integer(7)),
            Word::Return(1, 0x101b),
            Word::Data(1, Value::Integer(5)),
            Word::Data(1, Value::Integer(7))
        ]
    );
    s.step(Op::Call(0x1040), 0x105d, &mut no_output).unwrap();
    for op in [
        Op::Argument,
        Op::AddArgument,
        Op::Ret,
        Op::CleanupTwo,
        Op::CompareEax(12),
    ] {
        s.step(op, 0, &mut no_output).unwrap();
    }
    assert_eq!(s.pc, 0);
    assert_eq!(s.eax, Value::Integer(12));
    s.step(Op::StoreSecond, 0, &mut no_output).unwrap();
    s.step(Op::StoreFirst, 0, &mut no_output).unwrap();
    let before = s.words.clone();
    let flags = s.flags;
    s.step(Op::Tail(0x1040), 0x1080, &mut no_output).unwrap();
    assert_eq!(s.words, before);
    assert_eq!(s.flags, flags);
    assert_eq!(s.frames.len(), 2);
    for op in [Op::Argument, Op::AddArgument, Op::Ret] {
        s.step(op, 0, &mut no_output).unwrap();
    }
    assert_eq!(s.pc, 0x101b);
    assert_eq!(s.eax, Value::Integer(15));
    for position in [1, 2] {
        for bad in [
            Word::Entry,
            Word::Saved(0, Value::Integer(5)),
            Word::Return(0, 9),
            Word::Data(99, Value::Integer(5)),
            Word::Data(0, Value::Pointer(0x2008)),
            Word::Data(0, Value::Unknown(8)),
        ] {
            let mut copy = State::new(0);
            for op in [Op::Push(5), Op::Push(7), Op::Call(20)] {
                copy.step(op, 5, &mut no_output).unwrap();
            }
            if position == 2 {
                copy.step(Op::CopyArgument, 9, &mut no_output).unwrap();
            }
            copy.words[position] = bad.clone();
            let before = copy.words.clone();
            assert!(copy.step(Op::CopyArgument, 13, &mut no_output).is_err());
            assert_eq!(copy.words, before);
            for op in [Op::StoreFirst, Op::StoreSecond, Op::Tail(0x1040)] {
                let mut t = State::new(0);
                for op in [Op::Push(5), Op::Push(7), Op::Call(20)] {
                    t.step(op, 5, &mut no_output).unwrap();
                }
                t.words[position] = bad.clone();
                let before = t.words.clone();
                assert!(t.step(op, 0, &mut no_output).is_err());
                assert_eq!(t.words, before);
            }
        }
    }
}

#[test]
fn routine_graph_rejects_cycles_and_ambiguous_regions() {
    let good = BTreeMap::from([
        (0, (Op::Call(20), 5)),
        (5, (Op::Ret, 6)),
        (10, (Op::Mov(0), 15)),
        (15, (Op::Ret, 16)),
        (20, (Op::Tail(10), 25)),
    ]);
    validate_routines(0, &good).unwrap();
    let mut bad = good.clone();
    bad.insert(10, (Op::Call(20), 15));
    assert!(validate_routines(0, &bad).unwrap_err().contains("cycle"));
    let mut bad = good.clone();
    bad.insert(20, (Op::Tail(20), 25));
    bad.remove(&10);
    bad.remove(&15);
    assert!(validate_routines(0, &bad).unwrap_err().contains("cycle"));
    let mut bad = good.clone();
    bad.insert(0, (Op::Call(5), 5));
    assert!(validate_routines(0, &bad).is_err());
    let mut bad = good;
    bad.insert(20, (Op::Equal(15), 25));
    bad.insert(25, (Op::Ret, 26));
    bad.insert(0, (Op::Call(10), 5));
    assert!(validate_routines(0, &bad).is_err());
}
