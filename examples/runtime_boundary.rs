//! Research boundary inventory; never an effect-proof issuer.
use iced_x86::{Code, Decoder, DecoderOptions, OpKind};
use std::{env, fs};
fn inventory(bytes: &[u8], ip: u32) -> Vec<String> {
    let mut result = Vec::new();
    let mut decoder = Decoder::with_ip(32, bytes, u64::from(ip), DecoderOptions::NONE);
    for _ in 0..256 {
        if !decoder.can_decode() {
            result.push("blocked:window-end".into());
            return result;
        }
        let i = decoder.decode();
        let at = i.ip32();
        let mut line = format!("{at}: {:?} length={}", i.code(), i.len());
        if i.op_count() > 0 && i.op0_kind() == OpKind::NearBranch32 {
            line.push_str(&format!(" target={}", i.near_branch32()));
        }
        result.push(line);
        match i.code() {
            Code::Mov_r32_imm32 | Code::Mov_r32_rm32
                if i.op_count() == 2
                    && (i.op1_kind() == OpKind::Register
                        || i.op1_kind() == OpKind::Immediate32) => {}
            Code::Retnd => {
                result.push("boundary:return;effect-proof=false".into());
                return result;
            }
            _ => {
                result.push(format!(
                    "blocked:unresolved-effect-at={at};memory-base={:?};segment={:?}",
                    i.memory_base(),
                    i.segment_prefix()
                ));
                return result;
            }
        }
    }
    result.push("blocked:instruction-cap".into());
    result
}
fn main() {
    let a: Vec<_> = env::args().collect();
    let b = fs::read(&a[1]).unwrap();
    assert!(!b.is_empty() && b.len() <= 4096);
    for line in inventory(&b, a[2].parse().unwrap()) {
        println!("{line}");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_leaf() {
        assert_eq!(
            inventory(&[0xb8, 42, 0, 0, 0, 0xc3], 4096),
            [
                "4096: Mov_r32_imm32 length=5",
                "4101: Retnd length=1",
                "boundary:return;effect-proof=false"
            ]
        );
    }
    #[test]
    fn call_stops_before_unproved_continuation() {
        let r = inventory(&[0xe8, 5, 0, 0, 0, 0xc3], 4096);
        assert!(r[0].contains("target=4106"));
        assert_eq!(r.len(), 2);
        assert!(r[1].starts_with("blocked:"));
    }
    #[test]
    fn memory_tls_branch_invalid_stop() {
        for b in [
            &[0x64, 0xa1, 0x18, 0, 0, 0][..],
            &[0x89, 0x01],
            &[0x74, 0],
            &[0xeb, 0xfe],
            &[0xb8],
        ] {
            let r = inventory(b, 4096);
            assert_eq!(r.len(), 2);
            assert!(r[1].starts_with("blocked:"));
        }
    }
    #[test]
    fn bounded_window() {
        assert_eq!(inventory(&[], 0), ["blocked:window-end"]);
        let b = [0xb8, 0, 0, 0, 0].repeat(257);
        assert_eq!(inventory(&b, 0).last().unwrap(), "blocked:instruction-cap");
    }
}
