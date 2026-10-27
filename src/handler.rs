//! Experimental integer-context handler slice compiler. Not whole-PE admission.
#[allow(dead_code)]
#[path = "stream/graph.rs"]
mod graph;
use graph::{Address, Binary, Operand, Operation};

#[derive(Clone, Copy, PartialEq)]
enum Value {
    Unknown,
    Context,
    Stack,
    Scalar(Option<u32>),
}
pub struct Proven {
    source: String,
}
impl Proven {
    pub fn emit(self) -> String {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code() -> Vec<u8> {
        vec![
            0x8b, 0x4c, 0x24, 0x0c, 0x83, 0x81, 0xb8, 0, 0, 0, 2, 0xc7, 0x81, 0xb0, 0, 0, 0, 42, 0,
            0, 0, 0x31, 0xc0, 0xc3,
        ]
    }
    #[test]
    fn literal_context_effect_and_resume_proof() {
        let a = prove(&code(), 0x2000, 0x1000, 0x1002, true).unwrap().emit();
        assert!(a.contains("c[8]=c[8].wrapping_add(2u32)"));
        assert!(a.contains("c[0]=42u32"));
        assert_eq!(
            a,
            prove(&code(), 0x3000, 0x1000, 0x1002, true).unwrap().emit()
        );
        assert!(prove(&code(), 0x2000, 0x1000, 0x1003, true).is_err());
        assert!(prove(&code(), 0x2000, 0x1000, 0x1002, false).is_err());
    }
    #[test]
    fn unknown_owner_protected_context_and_root_search_reject() {
        for (index, value) in [(3, 8), (13, 0xc4), (13, 0xc0), (13, 0xb4), (2, 0x20)] {
            let mut b = code();
            b[index] = value;
            assert!(prove(&b, 0x2000, 0x1000, 0x1002, true).is_err());
        }
        let mut b = code();
        b.splice(21..23, [0xb8, 1, 0, 0, 0]);
        assert!(prove(&b, 0x2000, 0x1000, 0x1002, true).is_err());
        for end in 0..code().len() {
            assert!(prove(&code()[..end], 0x2000, 0x1000, 0x1002, true).is_err());
        }
    }
}
fn field(a: &Address, r: &[Value; 8]) -> Result<usize, String> {
    if a.index.is_some() || a.base.is_none_or(|b| r[b as usize] != Value::Context) {
        return Err("handler: context ownership".into());
    }
    [176, 172, 168, 164, 196, 180, 160, 156, 184, 192]
        .iter()
        .position(|&o| o == a.displacement)
        .ok_or("handler: field outside integer context".into())
}
fn scalar(v: Value) -> Result<Option<u32>, String> {
    if let Value::Scalar(v) = v {
        Ok(v)
    } else {
        Err("handler: unknown or pointer scalar".into())
    }
}
/// ABI premise: x86 raw handler third stack argument is a complete, writable
/// same-thread integer CONTEXT. Fault/continuation IPs come from the caller's
/// validated instruction boundaries. This slice API does not establish that premise.
pub fn prove(
    code: &[u8],
    origin: u32,
    fault: u32,
    continuation: u32,
    continuable: bool,
) -> Result<Proven, String> {
    if !continuable {
        return Err("handler: noncontinuable event".into());
    }
    let g = graph::decode(code, origin, origin)?;
    let mut r = [Value::Unknown; 8];
    r[4] = Value::Stack;
    let mut fields = [None; 10];
    fields[8] = Some(fault);
    let mut source=String::from("// Integer CONTEXT slice; requires the documented raw-handler ABI.\n#[allow(unused_assignments,unused_variables)]\npub fn handler(c:&mut [u32;10])->u32 { let mut r=[0u32;8];\n");
    let mut pc = origin;
    let mut visited = 0;
    loop {
        visited += 1;
        if visited > 128 {
            return Err("handler: resource budget".into());
        }
        let node = g.nodes.get(&pc).ok_or("handler: missing instruction")?;
        match &node.operation {
            Operation::Return => {
                if r[0] != Value::Scalar(Some(0)) || fields[8] != Some(continuation) {
                    return Err("handler: unproved contained resume".into());
                }
                if visited != g.nodes.len() {
                    return Err("handler: unvisited instruction".into());
                }
                source.push_str("r[0] }\n");
                return Ok(Proven { source });
            }
            Operation::Binary(op, dst, src) => {
                let (value, expression) = match src {
                    Operand::Immediate(v) => (Value::Scalar(Some(*v)), format!("{v}u32")),
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 => {
                        let v = r[reg.index as usize];
                        if v == Value::Unknown && !(*op == Binary::Xor && dst == src) {
                            return Err("handler: unknown register".into());
                        }
                        (v, format!("r[{}]", reg.index))
                    }
                    Operand::Memory(a, 32)
                        if a.base == Some(4)
                            && a.index.is_none()
                            && a.displacement == 12
                            && r[4] == Value::Stack =>
                    {
                        (Value::Context, String::new())
                    }
                    Operand::Memory(a, 32) => {
                        let i = field(a, &r)?;
                        (Value::Scalar(fields[i]), format!("c[{i}]"))
                    }
                    _ => return Err("handler: operand form".into()),
                };
                let (old, place, register) = match dst {
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 && reg.index != 4 => (
                        r[reg.index as usize],
                        format!("r[{}]", reg.index),
                        Some(reg.index as usize),
                    ),
                    Operand::Memory(a, 32) => {
                        let i = field(a, &r)?;
                        (Value::Scalar(fields[i]), format!("c[{i}]"), None)
                    }
                    _ => return Err("handler: destination".into()),
                };
                let same = dst == src;
                let (new, rhs) = match op {
                    Binary::Move => (value, expression),
                    Binary::Xor if same && register.is_some() => {
                        (Value::Scalar(Some(0)), "0".into())
                    }
                    Binary::Add | Binary::Sub => {
                        let a = scalar(old)?;
                        let b = scalar(value)?;
                        let add = *op == Binary::Add;
                        (
                            Value::Scalar(a.zip(b).map(|(x, y)| {
                                if add {
                                    x.wrapping_add(y)
                                } else {
                                    x.wrapping_sub(y)
                                }
                            })),
                            format!(
                                "{place}.wrapping_{}({expression})",
                                if add { "add" } else { "sub" }
                            ),
                        )
                    }
                    _ => return Err("handler: unsupported effect".into()),
                };
                if let Some(i) = register {
                    r[i] = new;
                } else {
                    let Operand::Memory(a, 32) = dst else {
                        unreachable!()
                    };
                    let i = field(a, &r)?;
                    // Saved stack/frame and flags need separate restoration proofs.
                    if matches!(i, 4 | 5 | 9) {
                        return Err("handler: protected restoration field".into());
                    }
                    fields[i] = scalar(new)?;
                }
                if new != Value::Context {
                    source.push_str(&format!("{place}={rhs};\n"));
                } else if register.is_none() {
                    return Err("handler: pointer escape".into());
                }
            }
            _ => return Err("handler: control or effect outside slice proof".into()),
        }
        let next = pc
            .checked_add(node.length)
            .ok_or("handler: instruction overflow")?;
        if node.successors != [next] {
            return Err("handler: unproved successor".into());
        }
        pc = next;
    }
}
