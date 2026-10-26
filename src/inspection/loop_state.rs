// Checked scalar operations shared with emitted native structured loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoopFlags {
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
}
fn cmp32(a: u32, b: u32) -> LoopFlags {
    let v = a.wrapping_sub(b);
    LoopFlags {
        cf: a < b,
        zf: v == 0,
        sf: v & 0x80000000 != 0,
        of: (a ^ b) & (a ^ v) & 0x80000000 != 0,
    }
}
fn add32(a: u32, b: u32) -> (u32, LoopFlags) {
    let (v, cf) = a.overflowing_add(b);
    (
        v,
        LoopFlags {
            cf,
            zf: v == 0,
            sf: v & 0x80000000 != 0,
            of: (!(a ^ b) & (a ^ v)) & 0x80000000 != 0,
        },
    )
}
fn inc32(i: u32, cf: bool) -> (u32, LoopFlags) {
    let v = i.wrapping_add(1);
    (
        v,
        LoopFlags {
            cf,
            zf: v == 0,
            sf: v & 0x80000000 != 0,
            of: i == 0x7fffffff,
        },
    )
}
fn run_bound(
    n: u32,
    expected_steps: u32,
    expected_result: u32,
) -> std::result::Result<(u32, u32, LoopFlags), String> {
    if n > 254 {
        return Err("loop: runtime bound invariant".into());
    }
    // XOR EAX,EAX; XOR ECX,ECX. CMP then defines the flags consumed by JBE.
    let (mut eax, mut ecx) = (0, 0);
    let mut steps = 4;
    let mut flags = cmp32(n, eax);
    if !(flags.cf || flags.zf) {
        steps += 1; // exact NOP: no memory access
        loop {
            if steps + 4 >= 1024 || ecx >= n {
                return Err("loop: runtime rank/budget invariant".into());
            }
            let old_rank = n - ecx;
            let (sum, add_flags) = add32(eax, ecx);
            eax = sum;
            let (next, _inc_flags) = inc32(ecx, add_flags.cf);
            ecx = next;
            if n - ecx >= old_rank {
                return Err("loop: runtime progress invariant".into());
            }
            flags = cmp32(ecx, n);
            steps += 4;
            if !flags.cf {
                break;
            }
        }
    }
    steps += 1; // RET
    if steps != expected_steps || eax != expected_result || eax > 255 {
        return Err("loop: runtime exit invariant".into());
    }
    Ok((eax, steps, flags))
}
