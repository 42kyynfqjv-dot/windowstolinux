use super::*;
const LOAD: [u8; 4] = [0x8b, 0x44, 0x24, 4];
const DROP: [u8; 4] = [0x8d, 0x64, 0x24, 4];
fn push(value: u32) -> Vec<u8> {
    let mut v = vec![0x68];
    v.extend(value.to_le_bytes());
    v
}
fn helper(argument: u32, body: &[u8]) -> Vec<u8> {
    let mut v = push(argument);
    v.extend([0xe8, 5, 0, 0, 0]);
    v.extend(DROP);
    v.push(0xc3);
    v.extend(body);
    v
}

#[test]
fn exact_stack_ir_and_encoding_policy() {
    for (bytes, op) in [
        (push(0x12345678), Op::PushData(0x12345678)),
        (LOAD.to_vec(), Op::LoadArgument),
        (DROP.to_vec(), Op::DropData),
    ] {
        for at in [0, 17] {
            let mut code = vec![0x90; at];
            code.extend(&bytes);
            let expected = Instruction {
                op,
                next: at + bytes.len(),
            };
            assert_eq!(decode_instruction(&code, at).unwrap(), expected);
            assert_eq!(oracle_instruction(&code, at).unwrap(), expected);
        }
        for end in 0..bytes.len() {
            assert!(decode_instruction(&bytes[..end], 0).is_err());
        }
        for prefix in [
            0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67,
        ] {
            let mut code = vec![prefix];
            code.extend(&bytes);
            assert!(decode_instruction(&code, 0).is_err());
        }
    }
    // Exhaust every ModRM/SIB/displacement variation around both exact forms.
    for form in [LOAD, DROP] {
        for offset in 1..4 {
            for byte in 0..=255 {
                let mut changed = form;
                changed[offset] = byte;
                assert_eq!(decode_instruction(&changed, 0).is_ok(), changed == form);
            }
        }
    }
    for bad in [
        &[0x6a, 7][..],
        &[0x50],
        &[0x58],
        &[0x83, 0xc4, 4],
        &[0x81, 0xc4, 4, 0, 0, 0],
        &[0x89, 0x44, 0x24, 4],
        &[0x8b, 0x84, 0x24, 4, 0, 0, 0],
        &[0x8d, 0xa4, 0x24, 4, 0, 0, 0],
    ] {
        assert!(decode_instruction(bad, 0).is_err());
    }
}

#[test]
fn parameterized_arithmetic_shared_nested_and_joins() {
    let body = [0x8b, 0x44, 0x24, 4, 0x05, 5, 0, 0, 0, 0xc3];
    // Literal wrapping arithmetic expectations, independent of Flags::add.
    for (arg, expected) in [(7, 12), (9, 14), (11, 16), (u32::MAX, 4), (250, 255)] {
        assert_eq!(exit_for_test(&helper(arg, &body)).unwrap(), expected);
    }
    assert!(translate(&helper(251, &body))
        .unwrap_err()
        .contains("exit status"));
    // Shared helper reads the new caller-owned word on each invocation.
    let mut shared = push(7);
    shared.extend([0xe8, 19, 0, 0, 0]);
    shared.extend(DROP);
    shared.extend(push(9));
    shared.extend([0xe8, 5, 0, 0, 0]);
    shared.extend(DROP);
    shared.push(0xc3);
    shared.extend(body);
    assert_eq!(exit_for_test(&shared).unwrap(), 14);
    // Nested call cleans its own argument before reloading the outer caller word.
    let mut outer = push(11);
    outer.extend([0xe8, 14, 0, 0, 0]);
    outer.extend(DROP);
    outer.extend(body);
    outer.extend(body);
    assert_eq!(exit_for_test(&helper(7, &outer)).unwrap(), 12);
    // The branch join is reached with a balanced stack along either path.
    let mut joined = LOAD.to_vec();
    joined.extend([0x3d, 7, 0, 0, 0, 0x74, 9]);
    joined.extend(push(99));
    joined.extend(DROP);
    joined.extend(body);
    for (arg, expected) in [(7, 12), (9, 14)] {
        assert_eq!(exit_for_test(&helper(arg, &joined)).unwrap(), expected);
    }
    // Same join, but one branch leaves local data: reject the executed bad path.
    let mut bad_join = LOAD.to_vec();
    bad_join.extend([0x3d, 7, 0, 0, 0, 0x74, 5]);
    bad_join.extend(push(99));
    bad_join.extend(body);
    assert_eq!(exit_for_test(&helper(7, &bad_join)).unwrap(), 12);
    assert!(translate(&helper(9, &bad_join))
        .unwrap_err()
        .contains("argument"));
}

#[test]
fn stack_state_rejections_and_unknown_flags() {
    for body in [LOAD.to_vec(), DROP.to_vec(), push(7)] {
        let mut code = body;
        code.push(0xc3);
        assert!(translate(&code).is_err());
    }
    // No argument, or another return word below the current return.
    assert!(
        translate(&[0xe8, 1, 0, 0, 0, 0xc3, 0x8b, 0x44, 0x24, 4, 0xc3])
            .unwrap_err()
            .contains("argument")
    );
    let mut nested = vec![0xe8, 1, 0, 0, 0, 0xc3, 0xe8, 1, 0, 0, 0, 0xc3];
    nested.extend(LOAD);
    nested.push(0xc3);
    assert!(translate(&nested).unwrap_err().contains("argument"));
    for body in [
        [DROP.as_slice(), &[0xc3]].concat(), // Cannot discard return/caller data.
        [push(8).as_slice(), &[0xc3]].concat(), // Unbalanced local data.
        [push(8).as_slice(), &LOAD, &[0xc3]].concat(), // Load displaced by local data.
    ] {
        assert!(translate(&helper(7, &body)).is_err());
    }
    let mut doubled = push(7);
    doubled.extend(DROP);
    doubled.extend(DROP);
    doubled.extend([0xb8, 0, 0, 0, 0, 0xc3]);
    assert!(translate(&doubled).unwrap_err().contains("cleanup"));
    let mut stale = push(7);
    stale.extend(DROP);
    stale.extend([0xe8, 1, 0, 0, 0, 0xc3]);
    stale.extend(LOAD);
    stale.push(0xc3);
    assert!(translate(&stale).unwrap_err().contains("argument"));
    let mut unknown = push(7);
    unknown.extend([0xe8, 7, 0, 0, 0]);
    unknown.extend(DROP);
    unknown.extend([0x74, 0, 0xc3]);
    unknown.extend(LOAD);
    unknown.push(0xc3);
    assert!(translate(&unknown)
        .unwrap_err()
        .contains("unknown entry flags"));
    // Known flags pass through PUSH/CALL/LOAD/RET/LEA; LOAD does not set ZF.
    for (prefix, opcode, expected) in [
        (vec![0x31, 0xc0], 0x74, 22),
        (vec![0xb8, 255, 255, 255, 255, 0x05, 1, 0, 0, 0], 0x72, 22),
        (vec![0xb8, 255, 255, 255, 127, 0x05, 1, 0, 0, 0], 0x7c, 11),
        (vec![0xb8, 0, 0, 0, 128, 0x05, 255, 255, 255, 255], 0x7c, 22),
    ] {
        let mut code = prefix;
        code.extend(push(7));
        code.extend([0xe8, 18, 0, 0, 0]);
        code.extend(DROP);
        code.extend([opcode, 6, 0xb8, 11, 0, 0, 0, 0xc3, 0xb8, 22, 0, 0, 0, 0xc3]);
        code.extend(LOAD);
        code.push(0xc3);
        assert_eq!(exit_for_test(&code).unwrap(), expected);
    }
}

#[test]
fn stack_capacity_and_instruction_limits_in_production_paths() {
    for count in [127, 128, 129] {
        let mut code = push(1).repeat(count);
        code.extend(DROP.repeat(count));
        code.extend([0xb8, 0, 0, 0, 0, 0xc3]);
        assert_eq!(translate(&code).is_ok(), count <= 128);
        // CALL adds one more word while caller data remains live.
        let mut call = push(1).repeat(count);
        call.push(0xe8);
        call.extend(((count * 4 + 6) as u32).to_le_bytes());
        call.extend(DROP.repeat(count));
        call.extend([0xb8, 0, 0, 0, 0, 0xc3, 0xc3]);
        assert_eq!(translate(&call).is_ok(), count <= 127);
    }
    // Shared helper keeps decode size below1024; exact executed1024/1025 boundary.
    for extra in [0, 1] {
        let mut code = vec![0x31, 0xc0];
        if extra == 1 {
            code.extend([0xb8, 0, 0, 0, 0]);
        }
        code.extend([0xe8, 6, 0, 0, 0, 0xe8, 1, 0, 0, 0, 0xc3]);
        for _ in 0..254 {
            code.extend(push(1));
            code.extend(DROP);
        }
        code.extend([0x31, 0xc0, 0xc3]);
        assert_eq!(translate(&code).is_ok(), extra == 0);
    }
    // A branch target inside a PUSH immediate is still rejected.
    assert!(translate(&[0x31, 0xc0, 0x74, 1, 0x68, 0xc3, 0, 0, 0, 0xc3])
        .unwrap_err()
        .contains("overlapping"));
}
