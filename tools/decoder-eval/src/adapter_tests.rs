use crate::{adapter, control};

fn parity(bytes: &[u8]) -> bool {
    let original = control::decode_with(bytes, control::oracle_instruction);
    let trial = control::decode(bytes);
    match (original, trial) {
        (Ok(original), Ok(trial)) => {
            assert_eq!(trial, original, "IR differs for {bytes:02x?}");
            let source = control::emit(&original);
            assert_eq!(control::emit(&trial), source);
            let repeated = control::decode_with(bytes, adapter::decode_instruction).unwrap();
            assert_eq!(repeated, trial);
            assert_eq!(control::emit(&repeated), source); // Fresh decode and emission.
            source.is_ok()
        }
        (Err(_), Err(_)) => false, // Diagnostics may differ; rejection must not.
        (original, trial) => panic!("acceptance mismatch {bytes:02x?}: {original:?} vs {trial:?}"),
    }
}

#[test]
fn corpus_ir_source_and_single_byte_mutations_match() {
    let corpus =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("cases.tsv"))
            .expect("run scripts/export_decoder_cases.py first");
    let mut cases = 0;
    let mut mutations = 0;
    for line in corpus.lines() {
        let (_, hex) = line.split_once('\t').unwrap();
        let mut bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert!(parity(&bytes));
        // Every proper truncation, including empty, is compared. Some prefixes
        // ending in RET remain valid: never assume every truncation must fail.
        for end in 0..bytes.len() {
            parity(&bytes[..end]);
        }
        for at in 0..bytes.len() {
            let saved = bytes[at];
            for value in 0..=255 {
                bytes[at] = value;
                parity(&bytes);
                mutations += 1;
            }
            bytes[at] = saved;
        }
        cases += 1;
    }
    println!(
        "adapter: {cases} corpus IR/source matches, {mutations} single-byte mutation comparisons"
    );
}

#[test]
fn all_first_two_bytes_have_instruction_acceptance_and_ir_parity() {
    // Complete two-byte grid + enough remaining bytes for 15-byte x86 decoding.
    // Nonzero offsets exercise IP-relative target recovery.
    for at in [0, 17] {
        let mut bytes = vec![0; at + 15];
        for first in 0..=255 {
            for second in 0..=255 {
                bytes[at] = first;
                bytes[at + 1] = second;
                match (
                    control::oracle_instruction(&bytes, at),
                    adapter::decode_instruction(&bytes, at),
                ) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b),
                    (Err(_), Err(_)) => (),
                    (a, b) => panic!("{first:02x} {second:02x} at {at}: {a:?} vs {b:?}"),
                }
            }
        }
    }
    println!("adapter: 131072 instruction comparisons across two entry offsets");
}

#[test]
fn independently_specified_policy_rejections_and_boundaries() {
    // Literal expected IR is independent of the handwritten decoder oracle.
    use control::{Condition, Instruction, Op};
    for (code, expected) in [
        (vec![0xb8, 0x78, 0x56, 0x34, 0x12], Op::Mov(0x12345678)),
        (vec![0x05, 255, 255, 255, 255], Op::Add(u32::MAX)),
        (vec![0x3d, 0, 0, 0, 128], Op::Compare(0x80000000)),
        (vec![0x31, 0xc0], Op::Xor),
        (vec![0xc3], Op::Ret),
    ] {
        let mut bytes = vec![0x90; 17];
        bytes.extend(&code);
        assert_eq!(
            adapter::decode_instruction(&bytes, 17).unwrap(),
            Instruction {
                op: expected,
                next: 17 + code.len()
            }
        );
    }
    for (opcode, condition, when) in [
        (0x72, Condition::Carry, true),
        (0x73, Condition::Carry, false),
        (0x74, Condition::Zero, true),
        (0x75, Condition::Zero, false),
        (0x7c, Condition::SignedLess, true),
        (0x7d, Condition::SignedLess, false),
    ] {
        let mut bytes = vec![0x90; 17];
        bytes.extend([opcode, 127]);
        assert_eq!(
            adapter::decode_instruction(&bytes, 17).unwrap(),
            Instruction {
                op: Op::Branch {
                    condition,
                    when,
                    target: 146
                },
                next: 19
            }
        );
    }
    let mut call = vec![0x90; 17];
    call.extend([0xe8, 0x7f, 0, 0, 0]);
    assert_eq!(
        adapter::decode_instruction(&call, 17).unwrap(),
        Instruction {
            op: Op::Call { target: 149 },
            next: 22
        }
    );
    let forms: &[&[u8]] = &[
        &[0xb8, 0, 0, 0, 0],
        &[0x05, 0, 0, 0, 0],
        &[0x3d, 0, 0, 0, 0],
        &[0x31, 0xc0],
        &[0xc3],
        &[0xe8, 0, 0, 0, 0],
        &[0x72, 0],
        &[0x73, 0],
        &[0x74, 0],
        &[0x75, 0],
        &[0x7c, 0],
        &[0x7d, 0],
    ];
    for form in forms {
        assert!(adapter::decode_instruction(form, 0).is_ok());
        for end in 0..form.len() {
            assert!(adapter::decode_instruction(&form[..end], 0).is_err());
        }
        // All legacy prefix bytes, including ignored segment and REP prefixes.
        for prefix in [
            0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67,
        ] {
            let prefixed: Vec<_> = [prefix].iter().chain(form.iter()).copied().collect();
            assert!(adapter::decode_instruction(&prefixed, 0).is_err());
            assert!(!parity(&prefixed));
        }
    }
    for code in [
        &[0xb9, 0, 0, 0, 0][..],   // Other destination register.
        &[0x81, 0xc0, 0, 0, 0, 0], // Equivalent ADD EAX alternate encoding.
        &[0x33, 0xc0],             // Equivalent XOR EAX alternate encoding.
        &[0x31, 0x00],             // Memory operand.
        &[0xc2, 0, 0],             // RET with stack adjustment.
        &[0x0f, 0x84, 0, 0, 0, 0], // Near branch.
        &[0x74, 0xff],
        &[0x7c, 0x80], // Negative rel8.
        &[0x7e, 0],    // Other condition.
    ] {
        assert!(adapter::decode_instruction(code, 0).is_err());
        assert!(!parity(code));
    }
    for code in [
        &[0x31, 0xc0, 0x74, 1, 0xb8, 0, 0, 0, 0, 0xc3][..], // Target inside immediate.
        &[0x31, 0xc0, 0x74, 127, 0xc3],                     // Target out of executable bytes.
        &[0x31, 0xc0, 0x74, 1, 0x90, 0xc3],                 // Unsupported untaken path.
        &[0xb8, 0, 0, 0, 0, 0x74, 0, 0xc3],                 // Unknown flags.
        &[0x05, 0, 0, 0, 0, 0xc3],                          // Unknown EAX.
        &[0xb8, 0, 1, 0, 0, 0xc3],                          // Exit 256.
    ] {
        assert!(!parity(code));
    }
    assert!(parity(&[0x31, 0xc0, 0x74, 0, 0xc3]));
    // Displacement 127 is allowed when both paths end on instruction boundaries.
    let mut longest = vec![0x31, 0xc0, 0x74, 127, 0xc3];
    longest.resize(131, 0x90); // Unreachable bytes are intentionally not decoded.
    longest.push(0xc3);
    assert!(parity(&longest));
    let mut limit = [0x31, 0xc0].repeat(1023);
    limit.push(0xc3);
    assert!(parity(&limit));
    limit.splice(0..0, [0x31, 0xc0]);
    assert!(!parity(&limit));
}
