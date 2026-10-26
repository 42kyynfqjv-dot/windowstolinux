#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../src/control.rs"]
mod control;
#[cfg(test)]
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.checked_add(4).ok_or("overflow")?)
        .ok_or("truncated")?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}
#[cfg(test)]
mod evaluation {
    use super::control;
    use iced_x86::{Decoder, DecoderOptions, Register};
    use yaxpeax_arch::LengthedInstruction;
    use yaxpeax_x86::protected_mode::{InstDecoder, Operand, RegSpec};
    #[test]
    fn compare_current_corpus_metadata() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("cases.tsv");
        let corpus =
            std::fs::read_to_string(path).expect("run scripts/export_decoder_cases.py first");
        let mut cases = 0;
        let mut instructions = 0;
        for line in corpus.lines() {
            let (name, hex) = line.split_once('\t').unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let records = control::records_for_comparison(&bytes).unwrap();
            for (at, len, op, imm, target) in records {
                let i =
                    Decoder::with_ip(32, &bytes[at..], at as u64, DecoderOptions::NONE).decode();
                let y = InstDecoder::default().decode_slice(&bytes[at..]).unwrap();
                assert!(!i.is_invalid(), "{name}:{at}");
                assert_eq!(i.len(), len, "{name}:{at}");
                assert_eq!(y.len().to_const() as usize, len, "{name}:{at}");
                assert_eq!(
                    format!("{:?}", i.mnemonic()).to_lowercase(),
                    op,
                    "{name}:{at}"
                );
                let y_name = format!("{:?}", y.opcode()).to_lowercase();
                let y_name = match y_name.as_str() {
                    "jnb" => "jae",
                    "jz" => "je",
                    "jnz" => "jne",
                    "return" => "ret",
                    other => other,
                };
                assert_eq!(y_name, op, "{name}:{at}");
                if let Some(value) = imm {
                    assert_eq!(i.op0_register(), Register::EAX);
                    assert_eq!(i.immediate32(), value);
                    assert_eq!(
                        y.operand(0),
                        Operand::Register {
                            reg: RegSpec::eax()
                        }
                    );
                    assert_eq!(y.operand(1), Operand::ImmediateI32 { imm: value as i32 });
                }
                if op == "xor" {
                    assert_eq!(
                        (i.op0_register(), i.op1_register()),
                        (Register::EAX, Register::EAX)
                    );
                    assert_eq!(
                        y.operand(0),
                        Operand::Register {
                            reg: RegSpec::eax()
                        }
                    );
                    assert_eq!(y.operand(1), y.operand(0));
                }
                if let Some(destination) = target {
                    assert_eq!(i.near_branch32() as usize, destination);
                    let displacement = match y.operand(0) {
                        Operand::ImmediateI8 { imm } => i64::from(imm),
                        Operand::ImmediateI32 { imm } if op == "call" => i64::from(imm),
                        _ => panic!("branch/call operand"),
                    };
                    assert_eq!(at as i64 + len as i64 + displacement, destination as i64);
                }
                // Repeat from the same bytes/IP to detect stateful output.
                assert_eq!(i, Decoder::with_ip(32, &bytes[at..], at as u64, 0).decode());
                assert_eq!(
                    y,
                    InstDecoder::default().decode_slice(&bytes[at..]).unwrap()
                );
                instructions += 1;
            }
            cases += 1;
        }
        println!(
            "{cases} authored cases, {instructions} decoded records, zero metadata mismatches"
        );
    }
    #[test]
    fn truncated_encodings_fail_in_both_candidates() {
        for bytes in [
            &[][..],
            &[0x0f],
            &[0xb8, 1, 2, 3],
            &[0x05, 1, 2, 3],
            &[0x3d, 1, 2, 3],
            &[0x74],
            &[0x66],
        ] {
            assert!(Decoder::new(32, bytes, 0).decode().is_invalid());
            assert!(InstDecoder::default().decode_slice(bytes).is_err());
            assert!(control::records_for_comparison(bytes).is_err());
        }
    }
    #[test]
    fn decoder_validity_does_not_authorize_execution() {
        for bytes in [&[0x90][..], &[0x66, 0xb8, 1, 0], &[0xeb, 0xfe], &[0x7e, 0]] {
            assert!(!Decoder::new(32, bytes, 0).decode().is_invalid());
            assert!(InstDecoder::default().decode_slice(bytes).is_ok());
            assert!(control::records_for_comparison(bytes).is_err());
        }
    }
}

#[cfg(test)]
use control as adapter;
#[cfg(test)]
mod adapter_tests;
