//! Test-only bounded normal-flow exploration. Never an execution capability.
use iced_x86::{Decoder, DecoderOptions, OpKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
};
fn u(b: &[u8], a: usize) -> u32 {
    u32::from_le_bytes(b[a..a + 4].try_into().unwrap())
}
fn h(b: &[u8], a: usize) -> usize {
    u16::from_le_bytes(b[a..a + 2].try_into().unwrap()) as usize
}
fn main() {
    let b = fs::read(env::args().nth(1).unwrap()).unwrap();
    assert!(b.len() < 4 * 1024 * 1024);
    let p = u(&b, 60) as usize;
    let o = p + 24;
    assert_eq!(h(&b, o), 0x10b);
    let base = u(&b, o + 28);
    let entry = u(&b, o + 16);
    let table = o + h(&b, p + 20);
    let sections: Vec<_> = (0..h(&b, p + 6))
        .map(|i| {
            let a = table + i * 40;
            (
                u(&b, a + 12),
                u(&b, a + 8).min(u(&b, a + 16)),
                u(&b, a + 20),
                u(&b, a + 36),
            )
        })
        .collect();
    let mut pending = vec![entry];
    let mut seen = BTreeSet::new();
    let mut occupied = BTreeMap::new();
    let mut gaps = BTreeSet::new();
    let mut indirect = BTreeSet::new();
    while let Some(at) = pending.pop() {
        if seen.contains(&at) {
            continue;
        }
        assert!(seen.len() < 10000);
        seen.insert(at);
        let candidates: Vec<_> = sections
            .iter()
            .filter(|(v, n, _, f)| *f & 0x20000000 != 0 && at >= *v && at - *v < *n)
            .collect();
        if candidates.len() != 1 {
            gaps.insert(at);
            continue;
        }
        let (v, n, raw, _) = *candidates[0];
        let pos = (raw + at - v) as usize;
        let end = (raw + n) as usize;
        assert!(end <= b.len());
        let ins = Decoder::with_ip(
            32,
            &b[pos..end],
            u64::from(base) + u64::from(at),
            DecoderOptions::NONE,
        )
        .decode();
        if ins.is_invalid() {
            gaps.insert(at);
            continue;
        }
        for j in 0..ins.len() {
            if let Some(old) = occupied.insert(at + j as u32, at) {
                assert_eq!(old, at, "overlapping instruction targets")
            }
        }
        let name = format!("{:?}", ins.mnemonic());
        let next = at + ins.len() as u32;
        if name == "Ret" || name == "Retf" {
            continue;
        }
        if name == "Int" || name == "Int3" || name == "Ud2" {
            gaps.insert(at);
            continue;
        }
        if name == "Call" || name.starts_with('J') || name.starts_with("Loop") {
            if ins.op0_kind() == OpKind::NearBranch32 {
                pending.push(ins.near_branch32().checked_sub(base).unwrap());
            } else {
                indirect.insert(at);
            }
            if name != "Jmp" {
                pending.push(next)
            }
        } else {
            pending.push(next)
        }
    }
    println!("{{\"entry_rva\":{entry},\"normal_flow_nodes\":{},\"indirect_sites\":{:?},\"unresolved_or_trap_sites\":{:?},\"complete_effect_proof\":false,\"emission_allowed\":false}}",seen.len(),indirect.into_iter().collect::<Vec<_>>(),gaps.into_iter().collect::<Vec<_>>());
}
