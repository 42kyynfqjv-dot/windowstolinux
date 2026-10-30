//! Original compiler-helper certificates, separate from symbol binding.
//! The probe domain is an owned, committed fault-free stack, not stack growth.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

fn decode(code: &[u8], origin: u32) -> Result<Vec<Instruction>, String> {
    if origin == 0
        || code.is_empty()
        || code.len() > 256
        || origin.checked_add(code.len() as u32).is_none()
    {
        return Err("CRT helper extent".into());
    }
    let mut d = Decoder::with_ip(32, code, origin as u64, DecoderOptions::NONE);
    let mut result = Vec::new();
    while d.can_decode() {
        let i = d.decode();
        if i.is_invalid()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || result.len() >= 32
        {
            return Err("CRT helper instruction policy".into());
        }
        result.push(i);
    }
    Ok(result)
}
fn reg(i: &Instruction, n: u32, r: Register) -> bool {
    i.op_kind(n) == OpKind::Register && i.op_register(n) == r
}
fn mem(i: &Instruction, n: u32, base: Register, offset: u32) -> bool {
    i.op_kind(n) == OpKind::Memory
        && i.memory_base() == base
        && i.memory_index() == Register::None
        && i.memory_displacement32() == offset
        && (i.mnemonic() == Mnemonic::Lea || i.memory_size() == iced_x86::MemorySize::UInt32)
}
fn rr(i: &Instruction, op: Mnemonic, a: Register, b: Register) -> bool {
    i.mnemonic() == op && i.op_count() == 2 && reg(i, 0, a) && reg(i, 1, b)
}
fn ri(i: &Instruction, op: Mnemonic, r: Register) -> Option<u32> {
    (i.mnemonic() == op
        && i.op_count() == 2
        && reg(i, 0, r)
        && matches!(i.op1_kind(), OpKind::Immediate32 | OpKind::Immediate8to32))
    .then(|| i.immediate(1) as u32)
}
fn one(i: &Instruction, op: Mnemonic, r: Register) -> bool {
    i.mnemonic() == op && i.op_count() == 1 && reg(i, 0, r)
}
fn branch(i: &Instruction, op: Mnemonic, target: u32) -> bool {
    i.mnemonic() == op && i.op0_kind() == OpKind::NearBranch32 && i.near_branch32() == target
}
#[derive(Debug)]
pub(crate) struct StackProbeProof {
    origin: u32,
    page: u32,
}
impl StackProbeProof {
    pub fn target(&self) -> u32 {
        self.origin
    }
    pub fn page_bytes(&self) -> u32 {
        self.page
    }
    /// Include the original CALL's transient return and ECX slots. The probe
    /// TEST values are dead, but each touched page must be mapped/readable.
    /// EAX becomes a return word and stays opaque until an original overwrite.
    pub fn call_source(&self, continuation: u32) -> String {
        format!(
            r#"
let allocation=CrtCpu::number(cpu.r[0])?;
if allocation==0||allocation>65536||allocation%4!=0{{return Err("CRT probe allocation domain");}}
let before=CrtCpu::pointer(cpu.r[4])?;
if before.kind!=CrtRegionKind::Stack{{return Err("CRT probe stack owner");}}
let call_word=rt.offset(before,-4)?;let saved_word=rt.offset(before,-8)?;
let moved_return=rt.offset(call_word,-i64::from(allocation))?;
rt.valid(moved_return,allocation.checked_add(4).ok_or("CRT probe extent overflow")?)?;
let return_token=CrtValue::ProtectedReturn({continuation}u64);
let old_ecx=cpu.r[1];
let mut page=saved_word.address()&!({page}u32-1);
while moved_return.address()<page{{page=page.checked_sub({page}).ok_or("CRT stack probe underflow")?;
let probe=rt.offset(before,i64::from(page)-i64::from(before.address()))?;rt.valid(probe,4)?;}}
if rt.overlapping_tags(moved_return.address(),allocation+4).iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_))){{return Err("CRT probe crosses live protected slot");}}
rt.store(call_word,32,return_token)?;rt.store(saved_word,32,old_ecx)?;
// Storage canonically masks unknown scalar bits. Consume the exact stored
// snapshot while restoring the original register knowledge and opaque identity.
let saved_ecx=rt.load(saved_word,32)?;
rt.consume_stack(saved_word,saved_ecx)?;rt.consume_stack(call_word,return_token)?;
rt.store(moved_return,32,return_token)?;rt.consume_stack(moved_return,return_token)?;
cpu.r[4]=CrtValue::Pointer(rt.offset(moved_return,4)?);cpu.r[1]=old_ecx;
cpu.r[0]=CrtValue::Scalar{{bits:0,known:0}};cpu.flags=CrtFlags::unknown();
"#,
            page = self.page
        )
    }
}
pub(crate) fn prove_stack_probe(code: &[u8], origin: u32) -> Result<StackProbeProof, String> {
    use Mnemonic::*;
    use Register::*;
    let i = decode(code, origin)?;
    if i.len() != 19 {
        return Err("CRT stack probe complete body".into());
    }
    let page = ri(&i[16], Sub, EAX).ok_or("CRT probe page decrement")?;
    if page != 4096
        || ri(&i[7], And, EAX) != Some(!(page - 1))
        || !one(&i[0], Push, ECX)
        || !(i[1].mnemonic() == Lea && reg(&i[1], 0, ECX) && mem(&i[1], 1, ESP, 4))
        || !rr(&i[2], Sub, ECX, EAX)
        || !rr(&i[3], Sbb, EAX, EAX)
        || !one(&i[4], Not, EAX)
        || !rr(&i[5], And, ECX, EAX)
        || !rr(&i[6], Mov, EAX, ESP)
        || !rr(&i[8], Cmp, ECX, EAX)
        || !branch(&i[9], Jb, i[16].ip32())
        || !rr(&i[10], Mov, EAX, ECX)
        || !one(&i[11], Pop, ECX)
        || !(rr(&i[12], Xchg, EAX, ESP) || rr(&i[12], Xchg, ESP, EAX))
        || !(i[13].mnemonic() == Mov && reg(&i[13], 0, EAX) && mem(&i[13], 1, EAX, 0))
        || !(i[14].mnemonic() == Mov && mem(&i[14], 0, ESP, 0) && reg(&i[14], 1, EAX))
        || i[15].code() != Code::Retnd
        || !(i[17].mnemonic() == Test && mem(&i[17], 0, EAX, 0) && reg(&i[17], 1, EAX))
        || !branch(&i[18], Jmp, i[8].ip32())
    {
        return Err("CRT stack probe instruction/effect protocol".into());
    }
    Ok(StackProbeProof { origin, page })
}

#[derive(Debug)]
pub(crate) struct SecurityProof {
    origin: u32,
    cookie: u32,
    failure: u32,
}
impl SecurityProof {
    pub fn target(&self) -> u32 {
        self.origin
    }
    pub fn cookie(&self) -> u32 {
        self.cookie
    }
    pub fn failure_target(&self) -> u32 {
        self.failure
    }
    /// Valid guard equality must already be established by the caller's
    /// ownership proof. A mismatch cannot be lowered to a successful RET.
    pub fn call_source(&self, continuation: u32) -> String {
        format!(
            r#"
let cookie=rt.resolve_absolute({},CrtRegionKind::Module)?;
let expected=rt.load(cookie,32)?.known_scalar()?;
let actual=CrtCpu::number(cpu.r[1])?;
if actual!=expected{{return Err("CRT unproved guard-failure path");}}
let call_word=rt.offset(CrtCpu::pointer(cpu.r[4])?,-4)?;
let token=CrtValue::ProtectedReturn({continuation}u64);rt.store(call_word,32,token)?;
cpu.binary(rt,7,CrtValue::scalar(actual),CrtValue::scalar(expected),32)?;
rt.consume_stack(call_word,token)?;
"#,
            self.cookie
        )
    }
}
pub(crate) fn prove_security(code: &[u8], origin: u32) -> Result<SecurityProof, String> {
    use Mnemonic::*;
    use Register::*;
    let i = decode(code, origin)?;
    if i.len() != 4
        || !(i[0].mnemonic() == Cmp
            && reg(&i[0], 0, ECX)
            && mem(&i[0], 1, None, i[0].memory_displacement32()))
        || !branch(&i[1], Jne, i[3].ip32())
        || i[2].code() != Code::Retnd
        || i[3].mnemonic() != Jmp
        || i[3].op0_kind() != OpKind::NearBranch32
        || i[0].memory_displacement32() % 4 != 0
        || (origin..origin + code.len() as u32).contains(&i[3].near_branch32())
    {
        return Err("CRT security helper compare/RET/failure protocol".into());
    }
    Ok(SecurityProof {
        origin,
        cookie: i[0].memory_displacement32(),
        failure: i[3].near_branch32(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn probe() -> Vec<u8> {
        vec![
            0x51, 0x8d, 0x4c, 0x24, 4, 0x2b, 0xc8, 0x1b, 0xc0, 0xf7, 0xd0, 0x23, 0xc8, 0x8b, 0xc4,
            0x25, 0, 0xf0, 0xff, 0xff, 0x3b, 0xc8, 0x72, 0x0a, 0x8b, 0xc1, 0x59, 0x94, 0x8b, 0,
            0x89, 4, 0x24, 0xc3, 0x2d, 0, 0x10, 0, 0, 0x85, 0, 0xeb, 0xe9,
        ]
    }
    #[test]
    fn complete_probe_relations_and_mutations() {
        let p = probe();
        let a = prove_stack_probe(&p, 0x1000).unwrap();
        assert_eq!(a.page_bytes(), 4096);
        assert!(prove_stack_probe(&p, 0xfffffff0).is_err());
        for (at, b) in [
            (4, 8),
            (6, 0xc1),
            (17, 0xe0),
            (23, 9),
            (26, 0x58),
            (37, 1),
            (40, 1),
            (42, 0xe8),
        ] {
            let mut bad = p.clone();
            bad[at] = b;
            assert!(prove_stack_probe(&bad, 0x1000).is_err(), "mutation {at}");
        }
        for size in 0..p.len() {
            assert!(prove_stack_probe(&p[..size], 0x1000).is_err());
        }
    }
    #[test]
    fn guard_binding_preserves_external_failure_edge() {
        let raw = [
            0x3b, 0x0d, 0, 0x20, 0, 0, 0x75, 1, 0xc3, 0xe9, 0x72, 0, 0, 0,
        ];
        let p = prove_security(&raw, 0x1000).unwrap();
        assert_eq!(p.cookie(), 0x2000);
        assert_eq!(p.failure_target(), 0x1080);
        let mut bad = raw;
        bad[7] = 0;
        assert!(prove_security(&bad, 0x1000).is_err());
        bad = raw;
        bad[1] = 0x15;
        assert!(prove_security(&bad, 0x1000).is_err());
    }
}
