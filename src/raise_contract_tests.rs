//! Independent original-call and containment regressions. These are compiler
//! contract tests, not Windows delivery or whole-PE execution evidence.
use super::{
    frame_proof::{self, GuestRegister, ProvenFrame},
    raise_call::{self, ArgumentRole},
    selection,
};
use std::collections::{BTreeMap, BTreeSet};

const ENTRY: u32 = 0x12000;
const COOKIE: u32 = 0x38000;
const TABLE: u32 = 0x39000;
const HANDLER: u32 = 0x25000;
const IAT: u32 = 0x3a000;

// Independently assembled conventional EH4 frame. No source fixture generator,
// production decoder, expected register getter or observed result builds bytes.
fn frame_bytes(arguments: &[u32], before_arguments: &[u8]) -> Vec<u8> {
    let mut code = vec![0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68];
    code.extend(TABLE.to_le_bytes());
    code.push(0x68);
    code.extend(HANDLER.to_le_bytes());
    code.extend([
        0x64, 0xa1, 0, 0, 0, 0, 0x50, 0x83, 0xec, 32, 0x53, 0x56, 0x57, 0xa1,
    ]);
    code.extend(COOKIE.to_le_bytes());
    code.extend([
        0x31, 0x45, 0xf8, 0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0, 0xc7, 0x45,
        0xfc, 0, 0, 0, 0,
    ]);
    code.extend(before_arguments);
    for word in arguments.iter().rev() {
        code.push(0x68);
        code.extend(word.to_le_bytes());
    }
    code
}

fn frame(code: &[u8]) -> ProvenFrame {
    frame_proof::prove_frame(
        code,
        ENTRY,
        COOKIE,
        &BTreeSet::from([TABLE]),
        &BTreeSet::from([HANDLER]),
    )
    .unwrap()
}

fn call(iat: u32) -> Vec<u8> {
    let mut code = vec![0xff, 0x15];
    code.extend(iat.to_le_bytes());
    code
}

#[test]
fn original_argument_cells_and_stack_are_distinct_from_captured_context() {
    for event in [0, 1, 0x8000_0000, 0xe042_4242, 0xefff_ffff] {
        let bytes = frame_bytes(&[event, 0, 0, 0], &[]);
        let frame = frame(&bytes);
        let proof = raise_call::prove_call(&frame, &call(IAT), frame.end(), IAT, event).unwrap();
        assert_eq!(proof.call_pc(), ENTRY + bytes.len() as u32);
        assert_eq!(proof.next_pc(), ENTRY + bytes.len() as u32 + 6);
        assert_eq!(proof.iat(), IAT);
        assert_eq!(proof.event_code(), event);
        assert_eq!(proof.caller_sp_offset(), -84);
        assert_eq!(proof.callee_sp_offset(), -88);
        assert_eq!(proof.normal_return_sp_offset(), -68);
        assert_eq!(proof.temporary_bytes(), 4);
        assert_eq!(proof.call_stack_extent(), 88);
        assert_eq!(
            proof
                .arguments()
                .map(|cell| (cell.role, cell.offset, cell.value)),
            [
                (ArgumentRole::ExceptionCode, -84, event),
                (ArgumentRole::ExceptionFlags, -80, 0),
                (ArgumentRole::ArgumentCount, -76, 0),
                (ArgumentRole::NullArgumentArray, -72, 0),
            ]
        );
        assert_eq!(
            proof.registers(),
            &[
                GuestRegister::StackOffset(-20),
                GuestRegister::EntryRegister(1),
                GuestRegister::EntryRegister(2),
                GuestRegister::EntryRegister(3),
                GuestRegister::StackOffset(-84),
                GuestRegister::StackOffset(-4),
                GuestRegister::EntryRegister(6),
                GuestRegister::EntryRegister(7),
            ]
        );
        assert!(proof.registers().iter().all(|r| r.known_bits() == (0, 0)));
        assert_eq!(proof.known_register_bits(), &[(0, 0); 8]);
        // The last original arithmetic was cookie XOR EBP. Only CF/OF are
        // established here; even those facts are guest call-site flags.
        assert_eq!(proof.known_flags(), (0x801, 0));
    }
}

#[test]
fn scalar_snapshots_do_not_zero_unknown_registers_or_alias_later_writes() {
    // MOV ECX,deadbeef; MOV EDX,ECX; MOV ECX,7. EDX keeps the copied value.
    let setup = [0xb9, 0xef, 0xbe, 0xad, 0xde, 0x8b, 0xd1, 0xb9, 7, 0, 0, 0];
    let frame = frame(&frame_bytes(&[1, 0, 0, 0], &setup));
    let proof = raise_call::prove_call(&frame, &call(IAT), frame.end(), IAT, 1).unwrap();
    assert_eq!(proof.registers()[1], GuestRegister::Scalar(7));
    assert_eq!(proof.registers()[2], GuestRegister::Scalar(0xdead_beef));
    assert_eq!(proof.registers()[2].known_bits(), (u32::MAX, 0xdead_beef));
    assert_eq!(proof.registers()[3], GuestRegister::EntryRegister(3));
    assert_eq!(proof.registers()[3].known_bits(), (0, 0));
    assert_eq!(
        proof.known_register_bits(),
        &[
            (0, 0),
            (u32::MAX, 7),
            (u32::MAX, 0xdead_beef),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
            (0, 0),
        ]
    );
    assert_eq!(proof.known_flags(), (0x801, 0));
}

#[test]
fn unsupported_raise_arguments_and_wrong_original_call_cannot_issue_event() {
    for arguments in [
        vec![],
        vec![1, 0, 0],
        vec![1, 0, 0, 0, 0],
        vec![2, 0, 0, 0],
        vec![1, 1, 0, 0],
        vec![1, 2, 0, 0],
        vec![1, 0, 1, 0],
        vec![1, 0, 16, 0x3b000],
        vec![1, 0, 0, 0x3b000],
        vec![0, 0, 0, 1],
    ] {
        let frame = frame(&frame_bytes(&arguments, &[]));
        assert!(raise_call::prove_call(&frame, &call(IAT), frame.end(), IAT, 1).is_err());
    }
    for event in [0x1000_0000, 0x9000_0000, 0xf042_4242, u32::MAX] {
        let frame = frame(&frame_bytes(&[event, 0, 0, 0], &[]));
        assert!(raise_call::prove_call(&frame, &call(IAT), frame.end(), IAT, event).is_err());
    }
    let frame = frame(&frame_bytes(&[1, 0, 0, 0], &[]));
    let bytes = call(IAT);
    for end in 0..bytes.len() {
        assert!(raise_call::prove_call(&frame, &bytes[..end], frame.end(), IAT, 1).is_err());
    }
    for prefix in [
        0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3,
    ] {
        let mut prefixed = vec![prefix];
        prefixed.extend(&bytes);
        assert!(raise_call::prove_call(&frame, &prefixed, frame.end(), IAT, 1).is_err());
    }
    let mut tail = bytes.clone();
    tail.push(0x90);
    let mut jump = bytes.clone();
    jump[1] = 0x25;
    for bad in [
        tail,
        jump,
        vec![0xff, 0xd0, 0x90, 0x90, 0x90, 0x90],
        call(IAT + 4),
    ] {
        assert!(raise_call::prove_call(&frame, &bad, frame.end(), IAT, 1).is_err());
    }
    for origin in [0, frame.end() - 1, frame.end() + 1] {
        assert!(raise_call::prove_call(&frame, &bytes, origin, IAT, 1).is_err());
    }
    for iat in [0, IAT + 1, u32::MAX - 3, frame.end() & !3] {
        assert!(raise_call::prove_call(&frame, &call(iat), frame.end(), iat, 1).is_err());
    }
}

#[test]
fn original_filter_outcomes_reject_escape_and_unknown_context_reads_before_emission() {
    let mut bytes = Vec::new();
    for value in [
        (-2i32) as u32,
        0,
        (-64i32) as u32,
        0,
        (-2i32) as u32,
        0x5000,
        0x6000,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    let table = selection::parse_eh4(&bytes, &BTreeSet::from([0x5000, 0x6000])).unwrap();
    let layout = selection::FilterLayout {
        start: -64,
        end: 0,
        exception_pointers_offset: -20,
        writable_words: vec![],
    };
    // Original pointer walk returns ExceptionCode as a signed filter result.
    let return_code = [0x8b, 0x45, 0xec, 0x8b, 0, 0x8b, 0, 0xc3];
    let original = BTreeMap::from([(
        0x5000,
        selection::OriginalFilter {
            origin: 0x5000,
            bytes: &return_code,
        },
    )]);
    let frames = [selection::FrameSelection {
        table: &table,
        try_level: 0,
        layout: &layout,
    }];
    let accepted = selection::select_frames(&frames, &original, 1).unwrap();
    assert_eq!(accepted.selected_frame(), 0);
    assert_eq!(accepted.target(), 0x6000);
    let zero = selection::select_frames(&frames, &original, 0)
        .err()
        .unwrap();
    assert!(zero.contains("borrowed root"));
    let negative = selection::select_frames(&frames, &original, 0x8000_0000)
        .err()
        .unwrap();
    assert!(negative.contains("ContinueExecution"));
    for bytes in [
        &[0xc3][..],                   // Unknown initial EAX cannot become a result.
        &[0x0f, 0x94, 0xc0, 0xc3][..], // Unknown flags/upper EAX.
        &[0x8b, 0x45, 0xec, 0x8b, 0x40, 4, 0x8b, 0, 0xc3][..], // CONTEXT is not ExceptionRecord.
        &[0x8b, 0x45, 0xec, 0x8b, 0, 0x8b, 0x40, 12, 0xc3][..], // ExceptionAddress is not known Code.
    ] {
        assert!(selection::prove_filter(bytes, 0x5000, &layout, 1).is_err());
    }
}
