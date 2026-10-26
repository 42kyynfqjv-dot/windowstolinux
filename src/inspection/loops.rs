//! Exact graph plus structural rank proof; no sampled termination or fallback.
use super::*;
use iced_x86::{Decoder, DecoderOptions};
#[cfg(test)]
mod state {
    include!("loop_state.rs");
    #[test]
    fn independent_scalar_and_loop_boundaries() {
        for (n, result, steps) in [(0, 0, 5), (1, 0, 10), (5, 10, 26), (23, 253, 98)] {
            let (v, count, f) = run_bound(n, steps, result).unwrap();
            assert_eq!((v, count), (result, steps));
            assert_eq!(
                f,
                LoopFlags {
                    cf: false,
                    zf: true,
                    sf: false,
                    of: false
                }
            );
        }
        for (a, b, cf, zf, sf, of) in [
            (0, 1, true, false, true, false),
            (0x80000000, 0x7fffffff, false, false, false, true),
            (0x7fffffff, 0x80000000, true, false, true, true),
        ] {
            assert_eq!(cmp32(a, b), LoopFlags { cf, zf, sf, of });
        }
        for cf in [false, true] {
            assert_eq!(
                inc32(u32::MAX, cf),
                (
                    0,
                    LoopFlags {
                        cf,
                        zf: true,
                        sf: false,
                        of: false
                    }
                )
            );
            assert_eq!(
                inc32(0x7fffffff, cf),
                (
                    0x80000000,
                    LoopFlags {
                        cf,
                        zf: false,
                        sf: true,
                        of: true
                    }
                )
            );
        }
        assert_eq!(
            add32(u32::MAX, 1),
            (
                0,
                LoopFlags {
                    cf: true,
                    zf: true,
                    sf: false,
                    of: false
                }
            )
        );
        assert!(run_bound(255, 1026, 32385).is_err());
        assert!(run_bound(5, 25, 10).is_err());
        assert!(run_bound(5, 26, 11).is_err());
    }
}
struct ProvenLoop {
    _image: Envelope,
    bound: u32,
    steps: u32,
    result: u32,
}
impl ProvenLoop {
    fn emit(self) -> String {
        format!("// Native recognized finite loop; SUB537 conditional domain.\n{}\nfn main() {{ match run_bound({}, {}, {}) {{ Ok((v,_,_)) => std::process::exit(v as i32), Err(e) => {{ eprintln!(\"{{e}}\"); std::process::exit(125); }} }} }}\n",include_str!("loop_state.rs"),self.bound,self.steps,self.result)
    }
}
fn budget(n: u32) -> Result<(u32, u32)> {
    // Induction requires the exact graph checked below: i=0, one increment,
    // same stable bound and unsigned backedge. N-i decreases without u32 wrap.
    need(n <= 254, "loop: static iteration budget")?;
    let steps = if n == 0 { 5 } else { 6 + 4 * n };
    need(steps <= 1024, "loop: static step budget")?;
    let result = if n == 0 { 0 } else { n * (n - 1) / 2 };
    need(result <= 255, "loop: portable exit domain")?;
    Ok((steps, result))
}
pub(super) fn translate(image: Envelope) -> Result<String> {
    need(
        image.closed
            && image
                .dirs
                .iter()
                .enumerate()
                .all(|(i, d)| matches!(i, 5 | 6) || d.is_none()),
        "loop: metadata closure",
    )?;
    need(
        image.dirs[5].is_some() && image.pointers.len() == 2,
        "loop: exact relocation accounting",
    )?;
    need(
        image
            .sections
            .iter()
            .filter(|s| s.role == Role::Writable)
            .count()
            == 1
            && image
                .sections
                .iter()
                .all(|s| s.role != Role::Zero && s.virtual_size <= s.size),
        "loop: initialized sections",
    )?;
    let code = image
        .sections
        .iter()
        .find(|s| s.role == Role::Code)
        .ok_or("loop: code")?;
    need(
        image.entry == code.rva && code.virtual_size == 28,
        "loop: complete graph extent/entry",
    )?;
    image.outside(code.rva, 28)?;
    let bytes = range(&image.bytes, code.raw as usize, 28)?;
    let mut stencil = bytes.to_vec();
    stencil[6..10].fill(0);
    stencil[21..25].fill(0);
    need(
        stencil
            == [
                0x33, 0xc0, 0x33, 0xc9, 0x39, 0x05, 0, 0, 0, 0, 0x76, 0x0f, 0x0f, 0x1f, 0x40, 0,
                0x03, 0xc1, 0x41, 0x3b, 0x0d, 0, 0, 0, 0, 0x72, 0xf5, 0xc3,
            ],
        "loop: unproved graph/effect",
    )?;
    for (at, len) in [
        (0, 2),
        (2, 2),
        (4, 6),
        (10, 2),
        (12, 4),
        (16, 2),
        (18, 1),
        (19, 6),
        (25, 2),
        (27, 1),
    ] {
        let ins = Decoder::with_ip(
            32,
            &bytes[at..],
            u64::from(code.rva) + at as u64,
            DecoderOptions::NONE,
        )
        .decode();
        need(
            !ins.is_invalid() && ins.len() == len,
            "loop: decoder boundary",
        )?;
        if matches!(at, 10 | 25) {
            need(
                ins.near_branch_target() == u64::from(code.rva) + if at == 10 { 27 } else { 16 },
                "loop: edge target",
            )?;
        }
    }
    let mut target = None;
    let mut bound = 0;
    for at in [6, 21] {
        let site = code
            .rva
            .checked_add(at as u32)
            .ok_or("loop: site overflow")?;
        let p = image
            .pointers
            .iter()
            .find(|p| p.site == site)
            .ok_or("loop: missing exact HIGHLOW")?;
        need(
            u32_at(bytes, at)?.checked_sub(image.base) == Some(p.rva),
            "loop: address provenance",
        )?;
        image.outside(site, 4)?;
        image.outside(p.rva, 4)?;
        let (role, raw) = image.file_location(p.rva, 4)?;
        need(role == Role::Writable, "loop: initialized scalar target")?;
        need(
            target.is_none_or(|old| old == p.rva),
            "loop: invariant bound must be same word",
        )?;
        target = Some(p.rva);
        bound = image.number(raw)?;
    }
    let (steps, result) = budget(bound)?;
    Ok(ProvenLoop {
        _image: image,
        bound,
        steps,
        result,
    }
    .emit())
}
#[cfg(test)]
#[test]
fn static_budget_is_distinct_from_exit_domain() {
    assert_eq!(budget(0).unwrap(), (5, 0));
    assert_eq!(budget(23).unwrap(), (98, 253));
    for n in [24, 254] {
        assert!(budget(n).unwrap_err().contains("exit domain"));
    }
    for n in [255, 0x80000000, u32::MAX] {
        assert!(budget(n).unwrap_err().contains("iteration budget"));
    }
}
