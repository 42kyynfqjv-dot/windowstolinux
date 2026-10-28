//! Certificates for bounded original integer-formatting instruction graphs.
//!
//! These graphs preserve runtime arguments and emit the original instructions.
//! Their typed entry domains are component premises, not evidence of complete
//! CRT initialization, C++ exception closure, or whole-image eligibility.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::BTreeMap;

#[path = "crt_formatter_length.rs"]
mod length;
pub(crate) use length::LengthProof;
#[path = "crt_formatter_magnitude.rs"]
mod magnitude;
// Deliberate component API; the whole formatter composition is still gated.
#[allow(unused_imports)]
pub(crate) use magnitude::MagnitudeProof;
#[path = "crt_formatter_state.rs"]
mod state;
pub(crate) use state::StateProof;
#[path = "crt_formatter_modifier.rs"]
mod modifier;
pub(crate) use modifier::ModifierProof;
#[path = "crt_formatter_parser.rs"]
mod parser;
// Deliberate component API; the whole formatter composition is still gated.
#[allow(unused_imports)]
pub(crate) use parser::{ParserBindings, ParserEffect, ParserProof};
#[path = "crt_formatter_output.rs"]
mod output;
// Deliberate component API; the whole formatter composition is still gated.
#[allow(unused_imports)]
pub(crate) use output::{OutputProof, SpanProof};
#[path = "crt_formatter_locale.rs"]
mod locale;
// Deliberate component API; the whole formatter composition is still gated.
#[allow(unused_imports)]
pub(crate) use locale::{ClassificationProof, ValidationProof};

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub bytes: &'a [u8],
    pub origin: u32,
}
fn reg(index: u8) -> Reg {
    Reg {
        index,
        width: 32,
        shift: 0,
    }
}
fn r(index: u8) -> Operand {
    Operand::Reg(reg(index))
}
fn byte(index: u8) -> Operand {
    Operand::Reg(Reg {
        index,
        width: 8,
        shift: 0,
    })
}
fn imm(value: u32) -> Operand {
    Operand::Immediate(value)
}
fn address(base: u8, offset: i32) -> Address {
    Address {
        base: Some(base),
        index: None,
        scale: 1,
        displacement: offset as u32,
    }
}
fn mem(base: u8, offset: i32) -> Operand {
    Operand::Memory(address(base, offset), 32)
}
fn mem8(base: u8, offset: i32) -> Operand {
    Operand::Memory(address(base, offset), 8)
}
fn ordinary(op: Operation) -> Op {
    Op::Ordinary(op)
}
fn bin(op: Binary, d: Operand, s: Operand) -> Op {
    ordinary(Operation::Binary(op, d, s))
}
fn mov(d: Operand, s: Operand) -> Op {
    bin(Binary::Move, d, s)
}
fn push(v: Operand) -> Op {
    ordinary(Operation::Push(v))
}
fn pop(index: u8) -> Op {
    ordinary(Operation::Pop(reg(index)))
}
fn lea(index: u8, base: u8, offset: i32) -> Op {
    ordinary(Operation::Address(reg(index), address(base, offset)))
}
fn compare(graph: &Graph, expected: Vec<Op>) -> Result<(), String> {
    if graph.nodes.len() != expected.len() {
        return Err("formatter complete normalized graph length".into());
    }
    for ((pc, node), expected) in graph.nodes.iter().zip(expected) {
        if node.op != expected {
            return Err(format!(
                "formatter original effect mismatch at {pc:#x}: {:?}",
                node.op
            ));
        }
    }
    Ok(())
}

/// Original radix-ten conversion into a backwards bounded owned buffer. The
/// quotient strictly decreases when nonzero, while positive precision decreases
/// each iteration. With precision<=10 and any u32 magnitude there are <=10 writes.
/// DIV sees EDX=0 and divisor10, so neither divide-by-zero nor quotient overflow
/// is possible. Its remainder0..9 makes the original alphabetic-digit edge dead.
pub(crate) struct DecimalProof {
    graph: Graph,
    capacity: Graph,
    pub capacity_call: u32,
    pub inline_offset: u32,
    pub external_pointer_offset: u32,
    pub capacity_bytes: u32,
    pub precision_offset: u32,
    pub result_pointer_offset: u32,
    pub result_count_offset: u32,
}
impl DecimalProof {
    pub fn prove(decimal: Region<'_>, capacity: Region<'_>) -> Result<Self, String> {
        let capacity_graph = Graph::decode(capacity.bytes, capacity.origin)?;
        let cpcs: Vec<_> = capacity_graph.nodes.keys().copied().collect();
        let cops: Vec<_> = capacity_graph.nodes.values().map(|n| &n.op).collect();
        if cops.len() != 7 {
            return Err("formatter capacity graph length".into());
        }
        let Op::Ordinary(Operation::Binary(
            Binary::Compare,
            Operand::Memory(a, 32),
            Operand::Immediate(0),
        )) = cops[0]
        else {
            return Err("formatter external buffer pointer test".into());
        };
        if a.base != Some(1) || a.index.is_some() || a.scale != 1 {
            return Err("formatter capacity owner".into());
        }
        let external = a.displacement;
        let Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Reg(dst),
            Operand::Immediate(capacity_bytes),
        )) = cops[2]
        else {
            return Err("formatter inline capacity".into());
        };
        if *dst != reg(0)
            || *capacity_bytes < 10
            || *capacity_bytes > 4096
            || external
                != capacity_bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(4))
                    .ok_or("formatter capacity arithmetic")?
        {
            return Err("formatter inline array/capacity relation".into());
        }
        let capacity_bytes = *capacity_bytes;
        compare(
            &capacity_graph,
            vec![
                bin(Binary::Compare, mem(1, external as i32), imm(0)),
                ordinary(Operation::Branch(Condition::NotEqual, cpcs[4])),
                mov(r(0), imm(capacity_bytes)),
                ordinary(Operation::Return),
                mov(r(0), mem(1, external as i32 - 4)),
                ordinary(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 1,
                }),
                ordinary(Operation::Return),
            ],
        )?;
        let graph = Graph::decode(decimal.bytes, decimal.origin)?;
        let pcs: Vec<_> = graph.nodes.keys().copied().collect();
        let ops: Vec<_> = graph.nodes.values().map(|n| &n.op).collect();
        if ops.len() != 56 {
            return Err("formatter decimal complete graph".into());
        }
        let Op::Ordinary(Operation::Address(dst, a)) = ops[8] else {
            return Err("formatter inline buffer derivation".into());
        };
        if *dst != reg(1)
            || a.base != Some(7)
            || a.index.is_some()
            || a.scale != 1
            || !a.displacement.is_multiple_of(4)
            || a.displacement < 16
            || a.displacement > 256
        {
            return Err("formatter inline object layout".into());
        }
        let inline = a.displacement;
        let field = |index: usize, source: bool| -> Result<u32, String> {
            let Op::Ordinary(Operation::Binary(_, d, s)) = ops[index] else {
                return Err("formatter scalar field operation".into());
            };
            let Operand::Memory(a, 32) = (if source { s } else { d }) else {
                return Err("formatter scalar field width".into());
            };
            if a.base != Some(7)
                || a.index.is_some()
                || a.scale != 1
                || !a.displacement.is_multiple_of(4)
                || a.displacement >= inline
            {
                return Err("formatter scalar field ownership".into());
            }
            Ok(a.displacement)
        };
        let precision = field(20, true)?;
        let output = field(17, false)?;
        let count = field(49, false)?;
        if precision == output || precision == count || output == count {
            return Err("formatter fields alias".into());
        }
        compare(
            &graph,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(r(1)),
                push(r(3)),
                push(r(6)),
                push(r(7)),
                mov(r(7), r(1)),
                lea(1, 7, inline as i32),
                mov(r(6), mem(1, external as i32)),
                bin(Binary::Test, r(6), r(6)),
                ordinary(Operation::ConditionalMove(Condition::Equal, reg(6), reg(1))),
                Op::Call(Target::Direct(capacity.origin)),
                ordinary(Operation::Decrement(reg(6))),
                bin(Binary::Add, r(6), r(0)),
                mov(mem(5, -4), r(6)),
                mov(r(0), r(6)),
                mov(mem(7, output as i32), r(6)),
                mov(r(3), r(6)),
                mov(r(6), mem(5, 8)),
                mov(r(1), mem(7, precision as i32)),
                bin(Binary::Test, r(1), r(1)),
                Op::SignedBranch {
                    condition: SignedCondition::Greater,
                    target: pcs[25],
                },
                bin(Binary::Test, r(6), r(6)),
                ordinary(Operation::Branch(Condition::Equal, pcs[46])),
                lea(0, 1, -1),
                bin(Binary::Xor, r(2), r(2)),
                mov(mem(7, precision as i32), r(0)),
                mov(r(0), r(6)),
                push(imm(10)),
                pop(1),
                Op::DivideUnsigned(r(1)),
                bin(Binary::Add, byte(2), imm(48)),
                mov(r(6), r(0)),
                bin(Binary::Compare, byte(2), imm(57)),
                Op::SignedBranch {
                    condition: SignedCondition::LessEqual,
                    target: pcs[41],
                },
                mov(byte(1), mem8(5, 12)),
                bin(Binary::Xor, byte(1), imm(1)),
                ordinary(Operation::Shift {
                    left: true,
                    dst: Reg {
                        index: 1,
                        width: 8,
                        shift: 0,
                    },
                    count: 5,
                }),
                bin(Binary::Add, byte(1), imm(7)),
                bin(Binary::Add, byte(2), byte(1)),
                mov(mem8(3, 0), byte(2)),
                Op::DecrementMemory(mem(7, output as i32)),
                mov(r(0), mem(7, output as i32)),
                mov(r(3), r(0)),
                ordinary(Operation::Jump(pcs[20])),
                mov(r(6), mem(5, -4)),
                bin(Binary::Sub, r(6), r(0)),
                ordinary(Operation::Increment(reg(0))),
                mov(mem(7, count as i32), r(6)),
                mov(mem(7, output as i32), r(0)),
                pop(7),
                pop(6),
                pop(3),
                ordinary(Operation::Leave),
                Op::ReturnPop(8),
            ],
        )?;
        Ok(Self {
            graph,
            capacity: capacity_graph,
            capacity_call: capacity.origin,
            inline_offset: inline,
            external_pointer_offset: inline + external,
            capacity_bytes,
            precision_offset: precision,
            result_pointer_offset: output,
            result_count_offset: count,
        })
    }
    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn capacity_graph(&self) -> &Graph {
        &self.capacity
    }
    pub fn emit(&self, name: &str, capacity_name: &str) -> Result<String, String> {
        let roles = BTreeMap::new();
        let capacity = super::crt_stream_emit::emit_graph(
            &self.capacity,
            capacity_name,
            |_, _| Err("formatter capacity unexpected call".into()),
            &roles,
            16,
        )?;
        let body = super::crt_stream_emit::emit_body(
            &self.graph,
            |pc, target| {
                if target != Target::Direct(self.capacity_call) {
                    return Err("formatter decimal unproved call".into());
                }
                Ok(format!(
                    "cpu.call(rt,lease,backend,{},{} )?;",
                    pc + self.graph.nodes[&pc].length,
                    capacity_name
                ))
            },
            &roles,
            512,
        )?;
        // Explicit owned entry: no external allocation, both caller words initialized,
        // field separation certified above, and private activation disjoint from object.
        let preflight = format!(
            r#"
rt.check_lock(lease)?;
let entry=CrtCpu::pointer(cpu.r[4])?;let object=CrtCpu::pointer(cpu.r[1])?;
if !matches!(object.kind,CrtRegionKind::Context|CrtRegionKind::Stack|CrtRegionKind::Buffer){{return Err("formatter decimal writable object role");}}
if cpu.returned||cpu.abi!=CrtAbi::Cdecl32Forward||cpu.r[4]!=cpu.entry[4]||entry.kind!=CrtRegionKind::Stack||entry.address()%4!=0||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){{return Err("formatter decimal entry ABI");}}
let private=rt.offset(entry,-24)?;rt.valid(private,36)?;
if rt.overlapping_tags(private.address(),24).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("formatter decimal protected scratch alias");}}
rt.valid(object,{extent})?;
if u64::from(object.address())<u64::from(private.address())+36&&u64::from(private.address())<u64::from(object.address())+{extent}{{return Err("formatter decimal object/frame alias");}}
let precision=rt.load(rt.offset(object,{precision})?,32)?.known_scalar()?;
if precision>10||rt.load(rt.offset(object,{external})?,32)?.known_scalar()?!=0{{return Err("formatter decimal precision/inline domain");}}
rt.load(rt.offset(entry,4)?,32)?.known_scalar()?;rt.load(rt.offset(entry,8)?,32)?.known_scalar()?;
let digits=rt.offset(object,{inline})?;rt.valid(digits,{capacity})?;
if !rt.overlapping_tags(digits.address(),{capacity}).is_empty(){{return Err("formatter decimal writable digits alias typed state");}}
for offset in [{output}i64,{count}i64]{{let p=rt.offset(object,offset)?;if rt.overlapping_tags(p.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("formatter decimal result field protected");}}}}
"#,
            extent = self.external_pointer_offset + 4,
            precision = self.precision_offset,
            external = self.external_pointer_offset,
            inline = self.inline_offset,
            capacity = self.capacity_bytes,
            output = self.result_pointer_offset,
            count = self.result_count_offset
        );
        Ok(format!("{capacity}\nfn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
}

/// A bounded input language, not an output implementation. The original parser
/// still consumes every byte and argument. Validation grants neither a graph
/// certificate nor authority to skip calls/effects in that graph.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FormatDomain {
    pub bytes_before_nul: usize,
    pub consumed_arguments: usize,
    pub output_bound: usize,
}
impl FormatDomain {
    pub fn validate(bytes: &[u8], available_arguments: usize) -> Result<Self, String> {
        if available_arguments > 64 {
            return Err("formatter argument resource cap".into());
        }
        let end = bytes
            .iter()
            .take(4097)
            .position(|&b| b == 0)
            .ok_or("formatter missing bounded terminator")?;
        if end > 4096 {
            return Err("formatter format resource cap".into());
        }
        let (mut at, mut consumed, mut output) = (0usize, 0usize, 0usize);
        while at < end {
            if bytes[at] != b'%' {
                output += 1;
                at += 1;
                continue;
            }
            at += 1;
            if at >= end {
                return Err("formatter incomplete directive".into());
            }
            if bytes[at] == b'%' {
                output += 1;
                at += 1;
                continue;
            }
            if bytes[at] == b'l' {
                at += 1;
                if at >= end {
                    return Err("formatter incomplete long directive".into());
                }
            }
            output += match bytes[at] {
                b'd' | b'i' => 11,
                b'u' => 10,
                _ => return Err("formatter unsupported directive outside entry domain".into()),
            };
            consumed += 1;
            if consumed > 64 || consumed > available_arguments {
                return Err("formatter argument initialization/range".into());
            }
            at += 1;
        }
        if output > 16384 {
            return Err("formatter output resource cap".into());
        }
        Ok(Self {
            bytes_before_nul: end,
            consumed_arguments: consumed,
            output_bound: output,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_domain_tracks_argument_reads_without_inventing_trailing_values() {
        assert_eq!(
            FormatDomain::validate(b"\0%q", 64).unwrap(),
            FormatDomain {
                bytes_before_nul: 0,
                consumed_arguments: 0,
                output_bound: 0
            }
        );
        assert_eq!(
            FormatDomain::validate(b"%u/%ld/%i/%%\0", 4).unwrap(),
            FormatDomain {
                bytes_before_nul: 12,
                consumed_arguments: 3,
                output_bound: 36
            }
        );
        assert!(FormatDomain::validate(b"%u%ld\0", 1).is_err());
        assert!(FormatDomain::validate(b"\0", 65).is_err());
    }
    #[test]
    fn format_domain_rejects_unclosed_or_unproved_directives_before_effects() {
        for bytes in [
            &b"%\0"[..],
            &b"%l\0"[..],
            &b"%llu\0"[..],
            &b"%n\0"[..],
            &b"%08u\0"[..],
            &b"%.3d\0"[..],
            &b"%s\0"[..],
            &b"%*d\0"[..],
            &b"abc"[..],
        ] {
            assert!(FormatDomain::validate(bytes, 64).is_err(), "{bytes:?}");
        }
        let mut maximum = vec![b'!'; 4096];
        maximum.push(0);
        assert_eq!(
            FormatDomain::validate(&maximum, 0).unwrap().output_bound,
            4096
        );
        maximum.insert(0, b'!');
        assert!(FormatDomain::validate(&maximum, 0).is_err());
        let mut arguments = b"%u".repeat(64);
        arguments.push(0);
        assert_eq!(
            FormatDomain::validate(&arguments, 64).unwrap().output_bound,
            640
        );
        arguments.splice(0..0, b"%u".iter().copied());
        assert!(FormatDomain::validate(&arguments, 64).is_err());
    }
}
