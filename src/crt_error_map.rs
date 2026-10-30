//! Instruction-derived, bounded CRT error mapping and owned context writes.
//! The table and all range/result constants come from the supplied image.
//! No Windows error-number switch, runtime lookup service or application
//! identity is used. The three complete decoded helpers must establish the
//! searched-table algorithm, unsigned fallback arithmetic and cdecl ownership.
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub va: u32,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Arg {
    Reg(Register),
    Imm(u32),
    Memory(Register, Register, u32, u32, u32),
    Target(u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Effect(Mnemonic, Vec<Arg>);

#[derive(Clone, Debug)]
pub(crate) struct ErrorMapProof {
    rows: Vec<(u32, u32)>,
    direct_low: u32,
    direct_high: u32,
    direct_row: usize,
    search_high: u32,
    first_bias: u32,
    first_width: u32,
    first_result: u32,
    second_bias: u32,
    second_width_mask: u32,
    final_add: u32,
    pub mapper: u32,
    pub updater: u32,
}

fn reg(r: Register) -> Arg {
    Arg::Reg(r)
}
fn imm(n: u32) -> Arg {
    Arg::Imm(n)
}
fn mem(base: Register, displacement: i32) -> Arg {
    Arg::Memory(base, Register::None, 1, displacement as u32, 32)
}
fn indexed(base: Register, index: Register, scale: u32, displacement: u32) -> Arg {
    Arg::Memory(base, index, scale, displacement, 32)
}
fn byte(base: Register, displacement: u32) -> Arg {
    Arg::Memory(base, Register::None, 1, displacement, 8)
}
fn e(m: Mnemonic, args: impl Into<Vec<Arg>>) -> Effect {
    Effect(m, args.into())
}

fn decode(region: Region<'_>) -> Result<Vec<Instruction>, String> {
    if region.va == 0
        || region.bytes.is_empty()
        || region.bytes.len() > 1024
        || region.va.checked_add(region.bytes.len() as u32).is_none()
    {
        return Err("CRT errno: code extent".into());
    }
    let mut decoder =
        Decoder::with_ip(32, region.bytes, u64::from(region.va), DecoderOptions::NONE);
    let mut result = Vec::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        let raw =
            &region.bytes[(i.ip32() - region.va) as usize..(i.next_ip32() - region.va) as usize];
        if i.is_invalid()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || result.len() >= 128
            || raw.first().is_some_and(|v| {
                matches!(
                    v,
                    0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65
                )
            })
        {
            return Err("CRT errno: instruction/prefix policy".into());
        }
        result.push(i);
    }
    Ok(result)
}
fn effect(i: &Instruction) -> Result<Effect, String> {
    let mut args = Vec::new();
    for n in 0..i.op_count() {
        args.push(match i.op_kind(n) {
            OpKind::Register => reg(i.op_register(n)),
            OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32 => {
                imm(i.immediate(n) as u32)
            }
            OpKind::NearBranch32 => Arg::Target(i.near_branch32()),
            OpKind::Memory => Arg::Memory(
                i.memory_base(),
                i.memory_index(),
                i.memory_index_scale(),
                i.memory_displacement32(),
                if i.mnemonic() == Mnemonic::Lea {
                    32
                } else {
                    match i.memory_size() {
                        MemorySize::UInt8 => 8,
                        MemorySize::UInt32 => 32,
                        _ => return Err("CRT errno: memory width".into()),
                    }
                },
            ),
            _ => return Err("CRT errno: operand kind".into()),
        });
    }
    Ok(Effect(i.mnemonic(), args))
}
fn immediate(i: &Instruction, n: u32) -> Result<u32, String> {
    if !matches!(
        i.op_kind(n),
        OpKind::Immediate8 | OpKind::Immediate8to32 | OpKind::Immediate32
    ) {
        return Err("CRT errno: expected derived immediate".into());
    }
    Ok(i.immediate(n) as u32)
}
fn displacement(i: &Instruction) -> Result<u32, String> {
    if !i.op_kinds().any(|n| n == OpKind::Memory) {
        return Err("CRT errno: expected derived address".into());
    }
    Ok(i.memory_displacement32())
}
fn check(actual: &[Instruction], expected: Vec<Effect>, label: &str) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format!("CRT errno: {label} complete instruction count"));
    }
    for (index, (a, b)) in actual.iter().zip(expected).enumerate() {
        if effect(a)? != b {
            return Err(format!("CRT errno: {label} instruction/effect {index}"));
        }
    }
    Ok(())
}
fn inside(region: Region<'_>, module: (u32, u32)) -> bool {
    region.va >= module.0
        && region
            .va
            .checked_add(region.bytes.len() as u32)
            .is_some_and(|end| end <= module.1)
}
fn overlap(a: Region<'_>, b: Region<'_>) -> bool {
    u64::from(a.va) < u64::from(b.va) + b.bytes.len() as u64
        && u64::from(b.va) < u64::from(a.va) + a.bytes.len() as u64
}

/// Prove all instructions and all table reads. The immutable table must be
/// bound by the enclosing image owner; this proof never authorizes live module
/// mutation or unproved startup/locale/invalid-parameter callback effects.
pub(crate) fn prove(
    mapper: Region<'_>,
    search: Region<'_>,
    updater: Region<'_>,
    table: Region<'_>,
    module: (u32, u32),
) -> Result<ErrorMapProof, String> {
    use Mnemonic::*;
    use Register::*;
    let regions = [mapper, search, updater, table];
    if module.0 == 0
        || module.0 >= module.1
        || regions.iter().any(|r| !inside(*r, module))
        || (0..regions.len())
            .any(|a| (a + 1..regions.len()).any(|b| overlap(regions[a], regions[b])))
        || !table.va.is_multiple_of(4)
    {
        return Err("CRT errno: image bounds or code/data alias".into());
    }
    let m = decode(mapper)?;
    let s = decode(search)?;
    let u = decode(updater)?;
    if m.len() != 38 || s.len() != 56 || u.len() != 16 {
        return Err("CRT errno: complete helper graph".into());
    }
    let direct_low = immediate(&m[5], 1)?;
    let direct_high = immediate(&m[7], 1)?;
    let direct_base = displacement(&m[9])?;
    let search_high = immediate(&m[11], 1)?;
    let count = immediate(&m[13], 0)?;
    let table_address = immediate(&m[14], 0)?;
    let first_bias = displacement(&m[22])?;
    let first_width = immediate(&m[23], 1)?;
    let first_result = immediate(&m[25], 0)?;
    let second_width_mask = immediate(&m[28], 0)?;
    let second_bias = displacement(&m[29])?;
    let final_add = immediate(&m[34], 1)?;
    if count == 0
        || count > 256
        || table.bytes.len() != count as usize * 8
        || table_address != table.va
        || direct_low > direct_high
        || direct_high - direct_low >= 256
        || direct_high > search_high
    {
        return Err("CRT errno: table/direct extent or resource bound".into());
    }
    let first_address = u64::from(direct_base) + u64::from(direct_low) * 8;
    let last_address = u64::from(direct_base) + u64::from(direct_high) * 8;
    if first_address < u64::from(table.va) + 4
        || last_address + 4 > u64::from(table.va) + table.bytes.len() as u64
        || (first_address - u64::from(table.va)) % 8 != 4
    {
        return Err("CRT errno: complete direct value-word bounds".into());
    }
    let direct_row = ((first_address - u64::from(table.va) - 4) / 8) as usize;
    let rows: Vec<_> = table
        .bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|r| {
            (
                u32::from_le_bytes(r[..4].try_into().unwrap()),
                u32::from_le_bytes(r[4..].try_into().unwrap()),
            )
        })
        .collect();
    if rows.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err("CRT errno: immutable search table ordering/uniqueness".into());
    }
    let mt = |index: usize| Arg::Target(m[index].ip32());
    check(
        &m,
        vec![
            e(Mov, [reg(EDI), reg(EDI)]),
            e(Push, [reg(EBP)]),
            e(Mov, [reg(EBP), reg(ESP)]),
            e(Push, [reg(ESI)]),
            e(Mov, [reg(ESI), mem(EBP, 8)]),
            e(Cmp, [reg(ESI), imm(direct_low)]),
            e(Jb, [mt(22)]),
            e(Cmp, [reg(ESI), imm(direct_high)]),
            e(Ja, [mt(11)]),
            e(Mov, [reg(EAX), indexed(None, ESI, 8, direct_base)]),
            e(Jmp, [mt(35)]),
            e(Cmp, [reg(ESI), imm(search_high)]),
            e(Ja, [mt(22)]),
            e(Push, [imm(count)]),
            e(Push, [imm(table_address)]),
            e(Push, [reg(ESI)]),
            e(Call, [Arg::Target(search.va)]),
            e(Add, [reg(ESP), imm(12)]),
            e(Test, [reg(EAX), reg(EAX)]),
            e(Je, [mt(22)]),
            e(Mov, [reg(EAX), mem(EAX, 4)]),
            e(Jmp, [mt(35)]),
            e(Lea, [reg(ECX), mem(ESI, first_bias as i32)]),
            e(Cmp, [reg(ECX), imm(first_width)]),
            e(Ja, [mt(28)]),
            e(Push, [imm(first_result)]),
            e(Pop, [reg(EAX)]),
            e(Jmp, [mt(35)]),
            e(Push, [imm(second_width_mask)]),
            e(Lea, [reg(EAX), mem(ESI, second_bias as i32)]),
            e(Pop, [reg(ECX)]),
            e(Cmp, [reg(ECX), reg(EAX)]),
            e(Sbb, [reg(EAX), reg(EAX)]),
            e(And, [reg(EAX), reg(ECX)]),
            e(Add, [reg(EAX), imm(final_add)]),
            e(Pop, [reg(ESI)]),
            e(Pop, [reg(EBP)]),
            e(Ret, []),
        ],
        "mapper",
    )?;
    let st = |index: usize| Arg::Target(s[index].ip32());
    check(
        &s,
        vec![
            e(Mov, [reg(EDI), reg(EDI)]),
            e(Push, [reg(EBP)]),
            e(Mov, [reg(EBP), reg(ESP)]),
            e(Sub, [reg(ESP), imm(12)]),
            e(Mov, [reg(ECX), mem(EBP, 16)]),
            e(Xor, [reg(EDX), reg(EDX)]),
            e(Push, [reg(EBX)]),
            e(Push, [reg(ESI)]),
            e(Mov, [reg(ESI), mem(EBP, 8)]),
            e(Lea, [reg(EAX), mem(ECX, -1)]),
            e(Push, [reg(EDI)]),
            e(Mov, [reg(EDI), mem(EBP, 12)]),
            e(Mov, [mem(EBP, -12), reg(EAX)]),
            e(Mov, [reg(EAX), reg(ECX)]),
            e(Shr, [reg(EAX), imm(1)]),
            e(Je, [st(49)]),
            e(Test, [reg(CL), imm(1)]),
            e(Lea, [reg(EBX), mem(EAX, -1)]),
            e(Cmovne, [reg(EBX), reg(EAX)]),
            e(Lea, [reg(ECX), indexed(EBX, EDX, 1, 0)]),
            e(Mov, [mem(EBP, -8), reg(ECX)]),
            e(Lea, [reg(ECX), indexed(EDI, ECX, 8, 0)]),
            e(Mov, [reg(ESI), mem(ECX, 0)]),
            e(Mov, [mem(EBP, -4), reg(ESI)]),
            e(Mov, [reg(ESI), mem(EBP, 8)]),
            e(Cmp, [reg(ESI), mem(ECX, 0)]),
            e(Je, [st(47)]),
            e(Cmp, [reg(ESI), mem(EBP, -4)]),
            e(Mov, [reg(ECX), reg(EAX)]),
            e(Mov, [reg(EAX), mem(EBP, -8)]),
            e(Cmovb, [reg(ECX), reg(EBX)]),
            e(Inc, [reg(EAX)]),
            e(Cmp, [reg(ESI), mem(EBP, -4)]),
            e(Mov, [reg(EBX), mem(EBP, -8)]),
            e(Dec, [reg(EBX)]),
            e(Cmovae, [reg(EDX), reg(EAX)]),
            e(Cmp, [reg(ESI), mem(EBP, -4)]),
            e(Cmovae, [reg(EBX), mem(EBP, -12)]),
            e(Mov, [mem(EBP, -12), reg(EBX)]),
            e(Cmp, [reg(EDX), reg(EBX)]),
            e(Jbe, [st(13)]),
            e(Xor, [reg(EAX), reg(EAX)]),
            e(Pop, [reg(EDI)]),
            e(Pop, [reg(ESI)]),
            e(Pop, [reg(EBX)]),
            e(Leave, []),
            e(Ret, []),
            e(Mov, [reg(EAX), reg(ECX)]),
            e(Jmp, [st(42)]),
            e(Test, [reg(ECX), reg(ECX)]),
            e(Je, [st(41)]),
            e(Lea, [reg(EAX), indexed(EDI, EDX, 8, 0)]),
            e(Xor, [reg(ECX), reg(ECX)]),
            e(Cmp, [reg(ESI), mem(EAX, 0)]),
            e(Cmovne, [reg(EAX), reg(ECX)]),
            e(Jmp, [st(42)]),
        ],
        "search",
    )?;
    check(
        &u,
        vec![
            e(Mov, [reg(EDI), reg(EDI)]),
            e(Push, [reg(EBP)]),
            e(Mov, [reg(EBP), reg(ESP)]),
            e(Mov, [reg(EAX), mem(EBP, 8)]),
            e(Push, [reg(ESI)]),
            e(Mov, [reg(ESI), mem(EBP, 12)]),
            e(Push, [reg(EAX)]),
            e(Mov, [byte(ESI, 0x24), imm(1)]),
            e(Mov, [mem(ESI, 0x20), reg(EAX)]),
            e(Call, [Arg::Target(mapper.va)]),
            e(Pop, [reg(ECX)]),
            e(Mov, [byte(ESI, 0x1c), imm(1)]),
            e(Mov, [mem(ESI, 0x18), reg(EAX)]),
            e(Pop, [reg(ESI)]),
            e(Pop, [reg(EBP)]),
            e(Ret, []),
        ],
        "owned context updater",
    )?;
    // Full instruction/edge checks above preserve the exact carry consumers:
    // INC/DEC leave CF unchanged, while the following CMP refreshes it before
    // every CMOV. Memory CMOV sources are initialized local words on all paths.
    // Search rank is candidate count: every nonterminal iteration replaces it
    // with floor(n/2) or floor(n/2)-1. With n<=256 at most ten visits suffice.
    Ok(ErrorMapProof {
        rows,
        direct_low,
        direct_high,
        direct_row,
        search_high,
        first_bias,
        first_width,
        first_result,
        second_bias,
        second_width_mask,
        final_add,
        mapper: mapper.va,
        updater: updater.va,
    })
}

impl ErrorMapProof {
    /// Maximum transient bytes below updater entry SP, including nested CALL
    /// return words and all original search locals/saved registers.
    pub fn temporary_bytes(&self) -> u32 {
        68
    }
    pub fn rows(&self) -> &[(u32, u32)] {
        &self.rows
    }
    pub fn source(&self, prefix: &str) -> Result<String, String> {
        if prefix.is_empty()
            || !prefix.as_bytes()[0].is_ascii_alphabetic()
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("CRT errno: emitted identifier".into());
        }
        Ok(format!(
            r#"
// Complete decoded mapper/search/updater effects; immutable image-owned table.
// Entry/FILE/locale/PTD initialization and later destructor writeback are separate.
fn {p}_map(error:u32)->Result<u32,&'static str>{{
 const ROWS:&[(u32,u32)]=&{rows:?};
 if error>={lo}u32 && error<={hi}u32{{return Ok(ROWS[{row}usize+(error-{lo}u32)as usize].1);}}
 if error>={lo}u32 && error<={search_hi}u32{{
  let(mut count,mut low,mut high)=(ROWS.len()as u32,0u32,ROWS.len()as u32-1);
  let mut exhausted=true;
  for _ in 0..10{{
   let half=count>>1;
   if half==0{{if count!=0{{let row=ROWS.get(low as usize).ok_or("CRT errno search full bounds")?;if error==row.0{{return Ok(row.1);}}}}exhausted=false;break;}}
   let relative=if count&1!=0{{half}}else{{half-1}};
   let middle=low.checked_add(relative).ok_or("CRT errno search index overflow")?;
   let row=ROWS.get(middle as usize).ok_or("CRT errno search full bounds")?;
   if error==row.0{{return Ok(row.1);}}
   if error<row.0{{count=relative;high=middle.wrapping_sub(1);}}
   else{{count=half;low=middle.checked_add(1).ok_or("CRT errno search index overflow")?;}}
   if low>high{{exhausted=false;break;}}
  }}
  if exhausted{{return Err("CRT errno search rank exhausted");}}
 }}
 if error.wrapping_add({bias1}u32)<={width1}u32{{return Ok({result1}u32);}}
 let carry={width2}u32<error.wrapping_add({bias2}u32);
 Ok((0u32.wrapping_sub(u32::from(carry))&{width2}u32).wrapping_add({add}u32))
}}
fn {p}_apply(rt:&mut CrtStreamRuntime,context:CrtPointer,error:u32)->Result<u32,&'static str>{{
 rt.validate_error_context(context)?;
 rt.store(rt.offset(context,0x24)?,8,CrtValue::scalar(1))?;
 rt.store(rt.offset(context,0x20)?,32,CrtValue::scalar(error))?;
 let mapped={p}_map(error)?;
 rt.store(rt.offset(context,0x1c)?,8,CrtValue::scalar(1))?;
 rt.store(rt.offset(context,0x18)?,32,CrtValue::scalar(mapped))?;
 Ok(mapped)
}}
"#,
            p = prefix,
            rows = self.rows,
            lo = self.direct_low,
            hi = self.direct_high,
            row = self.direct_row,
            search_hi = self.search_high,
            bias1 = self.first_bias,
            width1 = self.first_width,
            result1 = self.first_result,
            bias2 = self.second_bias,
            width2 = self.second_width_mask,
            add = self.final_add
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    struct Assembly {
        origin: u32,
        bytes: Vec<u8>,
        labels: BTreeMap<&'static str, usize>,
        fix: Vec<(usize, &'static str)>,
    }
    impl Assembly {
        fn new(origin: u32) -> Self {
            Self {
                origin,
                bytes: vec![],
                labels: BTreeMap::new(),
                fix: vec![],
            }
        }
        fn raw(&mut self, b: &[u8]) {
            self.bytes.extend_from_slice(b);
        }
        fn word(&mut self, n: u32) {
            self.raw(&n.to_le_bytes());
        }
        fn label(&mut self, n: &'static str) {
            assert!(self.labels.insert(n, self.bytes.len()).is_none());
        }
        fn branch(&mut self, condition: Option<u8>, label: &'static str) {
            if let Some(c) = condition {
                self.raw(&[0x0f, c]);
            } else {
                self.raw(&[0xe9]);
            }
            self.fix.push((self.bytes.len(), label));
            self.word(0);
        }
        fn call(&mut self, target: u32) {
            self.raw(&[0xe8]);
            self.word(target.wrapping_sub(self.origin + self.bytes.len() as u32 + 4));
        }
        fn push(&mut self, value: u32) {
            self.raw(&[0x68]);
            self.word(value);
        }
        fn finish(mut self) -> Vec<u8> {
            for (at, label) in self.fix {
                let target = self.labels[label];
                self.bytes[at..at + 4]
                    .copy_from_slice(&(target as u32).wrapping_sub(at as u32 + 4).to_le_bytes());
            }
            self.bytes
        }
    }
    struct Fixture {
        base: u32,
        map: Vec<u8>,
        search: Vec<u8>,
        update: Vec<u8>,
        table: Vec<u8>,
    }
    impl Fixture {
        fn new(base: u32, rows: &[(u32, u32)]) -> Self {
            let (map_va, search_va, update_va, table_va) =
                (base + 0x1000, base + 0x2000, base + 0x3000, base + 0x4000);
            let mut a = Assembly::new(map_va);
            a.raw(&[0x8b, 0xff, 0x55, 0x8b, 0xec, 0x56, 0x8b, 0x75, 8]);
            a.raw(&[0x83, 0xfe, 1]);
            a.branch(Some(0x82), "fallback");
            a.raw(&[0x83, 0xfe, 2]);
            a.branch(Some(0x87), "search");
            a.raw(&[0x8b, 4, 0xf5]);
            a.word(table_va - 4);
            a.branch(None, "done");
            a.label("search");
            a.raw(&[0x81, 0xfe]);
            a.word(1000);
            a.branch(Some(0x87), "fallback");
            a.push(rows.len() as u32);
            a.push(table_va);
            a.raw(&[0x56]);
            a.call(search_va);
            a.raw(&[0x83, 0xc4, 12, 0x85, 0xc0]);
            a.branch(Some(0x84), "fallback");
            a.raw(&[0x8b, 0x40, 4]);
            a.branch(None, "done");
            a.label("fallback");
            a.raw(&[0x8d, 0x4e, 0xec, 0x83, 0xf9, 3]);
            a.branch(Some(0x87), "second");
            a.push(99);
            a.raw(&[0x58]);
            a.branch(None, "done");
            a.label("second");
            a.push(5);
            a.raw(&[0x8d, 0x86]);
            a.word(0u32.wrapping_sub(100));
            a.raw(&[0x59, 0x3b, 0xc8, 0x1b, 0xc0, 0x23, 0xc1, 0x83, 0xc0, 11]);
            a.label("done");
            a.raw(&[0x5e, 0x5d, 0xc3]);
            let map = a.finish();
            let mut a = Assembly::new(search_va);
            a.raw(&[
                0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 12, 0x8b, 0x4d, 16, 0x33, 0xd2, 0x53,
                0x56, 0x8b, 0x75, 8, 0x8d, 0x41, 0xff, 0x57, 0x8b, 0x7d, 12, 0x89, 0x45, 0xf4,
            ]);
            a.label("loop");
            a.raw(&[0x8b, 0xc1, 0xd1, 0xe8]);
            a.branch(Some(0x84), "last");
            a.raw(&[
                0xf6, 0xc1, 1, 0x8d, 0x58, 0xff, 0x0f, 0x45, 0xd8, 0x8d, 0x0c, 0x13, 0x89, 0x4d,
                0xf8, 0x8d, 0x0c, 0xcf, 0x8b, 0x31, 0x89, 0x75, 0xfc, 0x8b, 0x75, 8, 0x3b, 0x31,
            ]);
            a.branch(Some(0x84), "found");
            a.raw(&[
                0x3b, 0x75, 0xfc, 0x8b, 0xc8, 0x8b, 0x45, 0xf8, 0x0f, 0x42, 0xcb, 0x40, 0x3b, 0x75,
                0xfc, 0x8b, 0x5d, 0xf8, 0x4b, 0x0f, 0x43, 0xd0, 0x3b, 0x75, 0xfc, 0x0f, 0x43, 0x5d,
                0xf4, 0x89, 0x5d, 0xf4, 0x3b, 0xd3,
            ]);
            a.branch(Some(0x86), "loop");
            a.label("none");
            a.raw(&[0x33, 0xc0]);
            a.label("return");
            a.raw(&[0x5f, 0x5e, 0x5b, 0xc9, 0xc3]);
            a.label("found");
            a.raw(&[0x8b, 0xc1]);
            a.branch(None, "return");
            a.label("last");
            a.raw(&[0x85, 0xc9]);
            a.branch(Some(0x84), "none");
            a.raw(&[0x8d, 4, 0xd7, 0x33, 0xc9, 0x3b, 0x30, 0x0f, 0x45, 0xc1]);
            a.branch(None, "return");
            let search = a.finish();
            let mut a = Assembly::new(update_va);
            a.raw(&[
                0x8b, 0xff, 0x55, 0x8b, 0xec, 0x8b, 0x45, 8, 0x56, 0x8b, 0x75, 12, 0x50, 0xc6,
                0x46, 0x24, 1, 0x89, 0x46, 0x20,
            ]);
            a.call(map_va);
            a.raw(&[
                0x59, 0xc6, 0x46, 0x1c, 1, 0x89, 0x46, 0x18, 0x5e, 0x5d, 0xc3,
            ]);
            let update = a.finish();
            let table = rows
                .iter()
                .flat_map(|(a, b)| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
                .collect();
            Self {
                base,
                map,
                search,
                update,
                table,
            }
        }
        fn proof(&self) -> Result<ErrorMapProof, String> {
            prove(
                Region {
                    va: self.base + 0x1000,
                    bytes: &self.map,
                },
                Region {
                    va: self.base + 0x2000,
                    bytes: &self.search,
                },
                Region {
                    va: self.base + 0x3000,
                    bytes: &self.update,
                },
                Region {
                    va: self.base + 0x4000,
                    bytes: &self.table,
                },
                (self.base, self.base + 0x10000),
            )
        }
    }
    fn rows() -> Vec<(u32, u32)> {
        vec![(1, 71), (2, 72), (4, 74), (100, 170), (1000, 1070)]
    }
    fn compile_run(source: &str, name: &str) {
        let dir = std::env::temp_dir().join(format!("w2l-errno-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("check.rs");
        let output = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        std::fs::write(&input, source).unwrap();
        let compiled = std::process::Command::new("rustc")
            .args(["--edition=2021", "-Awarnings"])
            .arg(&input)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = std::process::Command::new(&output).output().unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn relocated_instruction_graphs_derive_constants_and_all_input_partition_edges() {
        let table = rows();
        let a = Fixture::new(0x100000, &table).proof().unwrap();
        let b = Fixture::new(0x500000, &table).proof().unwrap();
        assert_eq!(a.source("errno").unwrap(), b.source("errno").unwrap());
        assert_eq!(a.rows(), &table);
        assert_eq!(a.temporary_bytes(), 68);
        let mut inputs: BTreeSet<u32> = (0..1100).collect();
        for x in [
            0,
            1,
            2,
            3,
            4,
            19,
            20,
            23,
            24,
            99,
            100,
            105,
            106,
            1000,
            1001,
            0x7fffffff,
            0x80000000,
            u32::MAX,
        ] {
            inputs.insert(x);
        }
        // Oracle uses direct mathematical range membership and a linear lookup,
        // not the lowered binary search, carry-mask arithmetic or native result.
        let expected: Vec<_> = inputs
            .into_iter()
            .map(|x| {
                let answer = if x == 1 {
                    71
                } else if x == 2 {
                    72
                } else if let Some((_, v)) = table.iter().find(|(k, _)| *k == x) {
                    *v
                } else if (20..=23).contains(&x) {
                    99
                } else if (100..=105).contains(&x) {
                    11
                } else {
                    16
                };
                (x, answer)
            })
            .collect();
        let source = a.source("errno").unwrap();
        let map_only = source.split("fn errno_apply").next().unwrap();
        compile_run(&format!("{map_only}\nfn main(){{for(input,want)in {expected:?}{{assert_eq!(errno_map(input),Ok(want),\"input {{input}}\");}}}}"),"partitions");
    }
    #[test]
    fn maximum_search_rank_covers_every_table_key_gap_and_unsigned_extreme() {
        let table: Vec<_> = (0..256u32)
            .map(|k| (k * 3 + 1, k.wrapping_mul(977).wrapping_add(10000)))
            .collect();
        let proof = Fixture::new(0x100000, &table).proof().unwrap();
        let expected: Vec<_> = (0..1100)
            .chain([u32::MAX, 0x80000000])
            .map(|x| {
                let value = if x == 1 {
                    table[0].1
                } else if x == 2 {
                    table[1].1
                } else if let Some((_, v)) = table.iter().find(|(k, _)| *k == x) {
                    *v
                } else if (20..=23).contains(&x) {
                    99
                } else if (100..=105).contains(&x) {
                    11
                } else {
                    16
                };
                (x, value)
            })
            .collect();
        let source = proof.source("limit").unwrap();
        compile_run(&format!("{}\nfn main(){{for(input,want)in {expected:?}{{assert_eq!(limit_map(input),Ok(want),\"input {{input}}\");}}}}",source.split("fn limit_apply").next().unwrap()),"maximum-rank");
    }
    #[test]
    fn effect_mutations_table_aliases_and_hidden_helpers_reject() {
        let base = Fixture::new(0x100000, &rows());
        // Independent mutations target carry preservation, branch direction,
        // protected stack restoration, callback target and context write width.
        for (which, needle, offset, replace) in [
            (0, &[0x1b, 0xc0][..], 0, 0x33),
            (0, &[0x83, 0xc4, 12][..], 2, 16),
            (1, &[0x0f, 0x43, 0xd0][..], 1, 0x42),
            (1, &[0x0f, 0x86][..], 1, 0x82),
            (1, &[0x5f, 0x5e, 0x5b, 0xc9][..], 0, 0x5e),
            (2, &[0xc6, 0x46, 0x24, 1][..], 2, 0x1c),
            (2, &[0x89, 0x46, 0x18][..], 0, 0x88),
        ] {
            let mut f = Fixture::new(base.base, &rows());
            let code = match which {
                0 => &mut f.map,
                1 => &mut f.search,
                _ => &mut f.update,
            };
            let at = code
                .windows(needle.len())
                .position(|v| v == needle)
                .unwrap();
            code[at + offset] = replace;
            assert!(f.proof().is_err(), "{which} {needle:?}");
        }
        let mut f = Fixture::new(base.base, &rows());
        f.map.push(0x90);
        assert!(f.proof().is_err());
        let mut f = Fixture::new(base.base, &rows());
        f.table[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(f.proof().is_err());
        let mut f = Fixture::new(base.base, &rows());
        f.table.pop();
        assert!(f.proof().is_err());
        let mut f = Fixture::new(base.base, &rows());
        let at = f
            .map
            .windows(4)
            .position(|b| b == (base.base + 0x4000).to_le_bytes())
            .unwrap();
        f.map[at..at + 4].copy_from_slice(&(base.base + 0x1000).to_le_bytes());
        assert!(f.proof().is_err());
        assert!(base.proof().unwrap().source("bad();").is_err());
    }
    #[test]
    fn emitted_context_writes_preserve_order_and_prior_effects_on_failure() {
        let source = Fixture::new(0x100000, &rows())
            .proof()
            .unwrap()
            .source("errno")
            .unwrap();
        // Small independent storage contract double: this checks the generated
        // updater sequence; production memory/identity tests are separate.
        let runtime = r#"
#[derive(Clone,Copy)]struct CrtPointer{owner:u64,at:u32}
struct CrtValue(u32);impl CrtValue{fn scalar(x:u32)->Self{Self(x)}}
struct CrtStreamRuntime{live:bool,owner:u64,fail:usize,log:Vec<(u32,u8,u32)>}
impl CrtStreamRuntime{
 fn validate_error_context(&self,p:CrtPointer)->Result<(),&'static str>{if !self.live||p.owner!=self.owner||p.at!=0x8000{Err("owner/context")}else{Ok(())}}
 fn offset(&self,p:CrtPointer,n:i64)->Result<CrtPointer,&'static str>{Ok(CrtPointer{at:p.at.checked_add(n as u32).ok_or("range")?,..p})}
 fn store(&mut self,p:CrtPointer,width:u8,v:CrtValue)->Result<(),&'static str>{if self.log.len()==self.fail{return Err("injected storage failure");}self.log.push((p.at,width,v.0));Ok(())}
}
fn main(){
 let expected=[(0x8024,8,1),(0x8020,32,4),(0x801c,8,1),(0x8018,32,74)];
 for fail in 0..=4{let mut rt=CrtStreamRuntime{live:true,owner:7,fail,log:vec![]};let got=errno_apply(&mut rt,CrtPointer{owner:7,at:0x8000},4);assert_eq!(got,if fail==4{Ok(74)}else{Err("injected storage failure")});assert_eq!(rt.log,&expected[..fail]);}
 for(owner,live,at)in[(8,true,0x8000),(7,false,0x8000),(7,true,0x8004)]{let mut rt=CrtStreamRuntime{live,owner:7,fail:4,log:vec![]};assert!(errno_apply(&mut rt,CrtPointer{owner,at},4).is_err());assert!(rt.log.is_empty());}
}
"#;
        compile_run(&(source + runtime), "context-order");
    }

    #[test]
    fn emitted_updater_uses_actual_checked_memory_identity_and_byte_initialization() {
        let proof = Fixture::new(0x100000, &rows()).proof().unwrap();
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        // Embed the production emitted runtime without compiling its own tests
        // a second time or counting those inherited functions as new coverage.
        let runtime = include_str!("crt_stream_runtime.rs")
            .split_once("r#\"")
            .unwrap()
            .1
            .split_once("\"#;")
            .unwrap()
            .0;
        let body = r#"
fn main(){
 let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();
 let ctx=rt.map_region(0x8000,40,CrtRegionKind::Context,None).unwrap();
 assert_eq!(errno_apply(&mut rt,ctx,4),Ok(74));
 for(offset,width,want)in[(0x24,8,1),(0x20,32,4),(0x1c,8,1),(0x18,32,74)]{assert_eq!(rt.load(rt.offset(ctx,offset).unwrap(),width).unwrap().known_scalar(),Ok(want));}
 assert!(rt.load(ctx,32).unwrap().known_scalar().is_err());
 assert!(rt.load(rt.offset(ctx,0x1c).unwrap(),32).unwrap().known_scalar().is_err());
 assert_eq!((rt.errno,rt.doserrno),(None,None)); // PTD destructor is a later original effect.
 let wrong=rt.map_region(0x9000,40,CrtRegionKind::Stack,None).unwrap();assert!(errno_apply(&mut rt,wrong,4).is_err());
 let short=rt.map_region(0xa000,39,CrtRegionKind::Context,None).unwrap();assert!(errno_apply(&mut rt,short,4).is_err());
 let mut foreign=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let foreign_ctx=foreign.map_region(0x8000,40,CrtRegionKind::Context,None).unwrap();assert!(errno_apply(&mut rt,foreign_ctx,4).is_err());
 let aliased=rt.map_region(0xb000,40,CrtRegionKind::Context,None).unwrap();let referent=rt.map_region(0xc000,4,CrtRegionKind::Input,Some(&[1,2,3,4])).unwrap();
 rt.store(rt.offset(aliased,0x18).unwrap(),32,CrtValue::Pointer(referent)).unwrap();assert!(errno_apply(&mut rt,aliased,4).is_err());assert!(rt.load(rt.offset(aliased,0x24).unwrap(),8).unwrap().known_scalar().is_err());
 rt.memory.release(ctx.cap,ctx.owner).unwrap();assert!(errno_apply(&mut rt,ctx,4).is_err());
}
"#;
        compile_run(
            &format!(
                "mod guest_memory{{{memory}}}\n{runtime}\n{}{body}",
                proof.source("errno").unwrap()
            ),
            "checked-memory",
        );
    }
}
