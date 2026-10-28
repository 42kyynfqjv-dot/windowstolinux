//! Straight-line original cleanup instructions under an explicit helper ABI.
//! The caller owns two initialized u32 cells and a protected call/return adapter.
//! RET ends that helper invocation; this does not model arbitrary guest stacks.
use super::graph::{self, Address, Binary, Operand, Operation};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Unknown,
    Cells,
    Stack,
    Scalar,
}

fn cell(address: &Address, registers: &[Value; 8]) -> Result<usize, String> {
    if address.index.is_some()
        || address
            .base
            .is_none_or(|base| registers[base as usize] != Value::Cells)
    {
        return Err("cleanup: cell ownership".into());
    }
    match address.displacement {
        0 => Ok(0),
        4 => Ok(1),
        _ => Err("cleanup: complete aligned cell bounds".into()),
    }
}

/// Return statements for a private `fn(cells: &mut [u32; 2]) -> Result<(), _>`.
/// The complete proof runs before any source is returned. Initial working
/// registers are unknown; context cells are fully initialized, exclusively owned
/// for this invocation, and cannot escape or alias protected return metadata.
/// The adapter observes only these cells: EAX/ECX/EDX and working arithmetic
/// flags are clobbered/unknown on return. This is not a scalar-return callback
/// certificate. Its enclosing entry contract must also exclude unmodeled
/// debug/control-flag effects and establish valid stack/segment access.
pub(crate) fn prove_cleanup(code: &[u8], origin: u32) -> Result<String, String> {
    let graph = graph::decode(code, origin, origin)?;
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("cleanup: extent overflow")?;
    let mut registers = [Value::Unknown; 8];
    registers[4] = Value::Stack;
    let mut source = String::from("let mut r=[0u32;8];\n");
    let mut pc = origin;
    let mut count = 0;
    loop {
        count += 1;
        if count > 128 {
            return Err("cleanup: instruction budget".into());
        }
        let node = graph.nodes.get(&pc).ok_or("cleanup: missing instruction")?;
        let next = pc
            .checked_add(node.length)
            .ok_or("cleanup: instruction overflow")?;
        match &node.operation {
            Operation::Return => {
                if next != end || count != graph.nodes.len() || !node.successors.is_empty() {
                    return Err("cleanup: terminal extent".into());
                }
                source.push_str("return Ok(());\n");
                return Ok(source);
            }
            Operation::Binary(op, dst, src) => {
                let (value, expression) = match src {
                    Operand::Immediate(value) => (Value::Scalar, format!("{value}u32")),
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 => {
                        let value = registers[reg.index as usize];
                        if matches!(value, Value::Unknown | Value::Stack)
                            && !(*op == Binary::Xor && dst == src)
                        {
                            return Err("cleanup: unknown scalar or raw stack read".into());
                        }
                        (value, format!("r[{}]", reg.index))
                    }
                    Operand::Memory(address, 32)
                        if address.base == Some(4)
                            && address.index.is_none()
                            && address.displacement == 4
                            && registers[4] == Value::Stack =>
                    {
                        (Value::Cells, String::new())
                    }
                    Operand::Memory(address, 32) => (
                        Value::Scalar,
                        format!("cells[{}]", cell(address, &registers)?),
                    ),
                    _ => return Err("cleanup: operand form".into()),
                };
                let (old, place, register) = match dst {
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 && reg.index <= 2 => (
                        registers[reg.index as usize],
                        format!("r[{}]", reg.index),
                        Some(reg.index as usize),
                    ),
                    Operand::Memory(address, 32) => (
                        Value::Scalar,
                        format!("cells[{}]", cell(address, &registers)?),
                        None,
                    ),
                    _ => return Err("cleanup: protected or partial destination".into()),
                };
                let (new, rhs) = match op {
                    Binary::Move => (value, expression),
                    Binary::Xor if dst == src && register.is_some() => {
                        (Value::Scalar, "0u32".into())
                    }
                    Binary::Add | Binary::Sub if old == Value::Scalar && value == Value::Scalar => {
                        let operation = if *op == Binary::Add { "add" } else { "sub" };
                        (
                            Value::Scalar,
                            format!("{place}.wrapping_{operation}({expression})"),
                        )
                    }
                    _ => return Err("cleanup: unproved scalar effect".into()),
                };
                if let Some(index) = register {
                    registers[index] = new;
                } else if new != Value::Scalar {
                    return Err("cleanup: pointer escape".into());
                }
                if new == Value::Scalar {
                    source.push_str(&format!("{place}={rhs};\n"));
                } else if new != Value::Cells {
                    return Err("cleanup: uninitialized effect".into());
                }
            }
            _ => return Err("cleanup: control or effect outside helper proof".into()),
        }
        if node.successors != [next] {
            return Err("cleanup: unproved successor".into());
        }
        pc = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> Vec<u8> {
        // Load owned cells; trace=trace*16+2; local+=3; return to adapter.
        vec![
            0x8b, 0x4c, 0x24, 4, 0x8b, 1, 1, 0xc0, 1, 0xc0, 1, 0xc0, 1, 0xc0, 0x83, 0xc0, 2, 0x89,
            1, 0x83, 0x41, 4, 3, 0xc3,
        ]
    }

    #[test]
    fn original_operations_are_deterministic_and_wrapping() {
        let source = prove_cleanup(&body(), 0x3000).unwrap();
        assert_eq!(source, prove_cleanup(&body(), 0x4000).unwrap());
        assert_eq!(source.matches("r[0]=r[0].wrapping_add(r[0]);").count(), 4);
        assert!(source.contains("cells[1]=cells[1].wrapping_add(3u32);"));
    }

    #[test]
    fn ownership_initialization_protected_registers_and_cells_reject() {
        for opcode in [0xbb, 0xbc, 0xbd, 0xbe, 0xbf] {
            let mut bytes = vec![opcode, 0, 0, 0, 0];
            bytes.extend(body());
            assert!(prove_cleanup(&bytes, 0).is_err());
        }
        for bytes in [
            &[0x8b, 0x4c, 0x24, 8, 0x8b, 1, 0xc3][..], // Wrong argument.
            &[0x8b, 1, 0xc3],                          // Unknown owner.
            &[0x89, 0xc2, 0xc3],                       // Unknown EAX read.
            &[0x89, 0xe0, 0xc3],                       // Unmodeled raw ESP.
            &[0x8b, 0x4c, 0x24, 4, 0x89, 9, 0xc3],     // Owner escape.
            &[0x8b, 0x4c, 0x24, 4, 0x83, 0xc1, 4, 0xc3], // Pointer arithmetic.
            &[0x8b, 0x4c, 0x24, 4, 0x8b, 0x41, 1, 0xc3], // Misaligned word.
            &[0x8b, 0x4c, 0x24, 4, 0x8b, 0x41, 8, 0xc3], // Out of range.
            &[0x8b, 0x4c, 0x24, 4, 0x8a, 1, 0xc3],     // Partial width.
        ] {
            assert!(prove_cleanup(bytes, 0).is_err(), "accepted {bytes:02x?}");
        }
    }

    #[test]
    fn control_truncation_and_complete_extent_reject() {
        let bytes = body();
        for end in 0..bytes.len() {
            assert!(prove_cleanup(&bytes[..end], 0).is_err());
        }
        for suffix in [0x90, 0xcc] {
            let mut padded = bytes.clone();
            padded.push(suffix);
            assert!(prove_cleanup(&padded, 0).is_err());
        }
        for bytes in [&[0xeb, 0, 0xc3][..], &[0x74, 0, 0xc3], &[0xc2, 4, 0]] {
            assert!(prove_cleanup(bytes, 0).is_err());
        }
        assert!(prove_cleanup(&body(), u32::MAX - 4).is_err());
        let mut too_many = [0x31, 0xc0].repeat(128);
        too_many.push(0xc3);
        assert!(prove_cleanup(&too_many, 0).is_err());
    }

    #[test]
    fn prefixes_indexed_addresses_and_alias_ownership_remain_explicit() {
        for prefix in [
            0xf0, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67,
        ] {
            let mut prefixed = vec![prefix];
            prefixed.extend(body());
            assert!(prove_cleanup(&prefixed, 0).is_err(), "prefix {prefix:02x}");
        }
        // An owned base plus even a known-zero index is outside the exact cell
        // form. An absolute scalar address cannot acquire ownership either.
        for code in [
            &[0x8b, 0x4c, 0x24, 4, 0x31, 0xd2, 0x8b, 4, 0x11, 0xc3][..],
            &[0xa1, 0, 0, 0, 0, 0xc3],
            &[0x8b, 0x4c, 0x24, 4, 0x8b, 9, 0x8b, 1, 0xc3],
        ] {
            assert!(prove_cleanup(code, 0).is_err(), "accepted {code:02x?}");
        }
        // EDX retains ownership when ECX is overwritten by a cell read. The
        // memory source must be resolved before the destination loses its tag.
        let source = prove_cleanup(
            &[
                0x8b, 0x4c, 0x24, 4, 0x89, 0xca, 0x8b, 0x41, 4, 0x83, 0xe8, 0xff, 0x89, 2, 0x8b,
                0x0a, 0x83, 0xc1, 0x80, 0x89, 0x4a, 4, 0xc3,
            ],
            0,
        )
        .unwrap();
        assert!(source.contains("r[0]=r[0].wrapping_sub(4294967295u32)"));
        assert!(source.contains("r[1]=r[1].wrapping_add(4294967168u32)"));
        assert!(source.contains("cells[1]=r[1]"));
    }
}
