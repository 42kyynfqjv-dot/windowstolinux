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
