//! Original continuation instructions up to a terminal RET observation boundary.
//! RET itself is not executed: no guest stack pop or caller transfer is implied.
use super::graph::{self, Binary, Operand, Operation};

/// Prove a bounded MOV-only continuation over a complete integer context.
/// The parent certificate must bind these bytes and this entry to the resumed
/// activation. Statements operate on an owned `c: [u32; 10]` and return it with
/// IP pointing at the terminal RET, before that instruction executes.
pub(crate) fn prove_to_return_boundary(code: &[u8], origin: u32) -> Result<String, String> {
    let graph = graph::decode(code, origin, origin)?;
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("continuation: extent overflow")?;
    let mut pc = origin;
    let mut count = 0;
    let mut source =
        format!("if c[8]!={origin}u32 {{ return Err(\"continuation entry context\"); }}\n");
    loop {
        count += 1;
        if count > 128 {
            return Err("continuation: instruction budget".into());
        }
        let node = graph.nodes.get(&pc).ok_or("continuation: missing node")?;
        let next = pc
            .checked_add(node.length)
            .ok_or("continuation: instruction overflow")?;
        match &node.operation {
            Operation::Return => {
                if next != end || count != graph.nodes.len() || !node.successors.is_empty() {
                    return Err("continuation: terminal extent".into());
                }
                source.push_str(&format!(
                    "c[8]={pc}u32; // Observe before RET; guest stack is unchanged.\nreturn Ok(c);\n"
                ));
                return Ok(source);
            }
            Operation::Binary(Binary::Move, Operand::Reg(dst), src)
                if dst.width == 32 && dst.shift == 0 && dst.index <= 2 =>
            {
                let rhs = match src {
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 => {
                        format!("c[{}]", reg.index)
                    }
                    Operand::Immediate(value) => format!("{value}u32"),
                    _ => return Err("continuation: non-scalar move".into()),
                };
                source.push_str(&format!("c[{}]={rhs};\n", dst.index));
            }
            _ => return Err("continuation: unproved instruction effect".into()),
        }
        if node.successors != [next] {
            return Err("continuation: unproved successor".into());
        }
        pc = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_register_moves_end_before_ret_without_stack_or_flags_changes() {
        // MOV EDX,EAX; MOV EAX,ECX; RET. Values are restored guest registers,
        // rather than handler working registers or a fixture result constant.
        let source = prove_to_return_boundary(&[0x89, 0xc2, 0x89, 0xc8, 0xc3], 0x1200).unwrap();
        assert!(source.contains("c[2]=c[0];\nc[0]=c[1];"));
        assert!(source.contains("c[8]=4612u32"));
        assert!(!source.contains("c[4]="));
        assert!(!source.contains("c[9]="));
        assert_eq!(
            source,
            prove_to_return_boundary(&[0x89, 0xc2, 0x89, 0xc8, 0xc3], 0x1200).unwrap()
        );
        assert!(
            prove_to_return_boundary(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3], 0)
                .unwrap()
                .contains("c[0]=4294967295u32")
        );
    }

    #[test]
    fn protected_register_partial_width_memory_and_flag_effects_reject() {
        for code in [
            &[0x89, 0xc3, 0xc3][..], // MOV EBX,EAX
            &[0x89, 0xc4, 0xc3],     // MOV ESP,EAX
            &[0x89, 0xc5, 0xc3],     // MOV EBP,EAX
            &[0x89, 0xc6, 0xc3],     // MOV ESI,EAX
            &[0x89, 0xc7, 0xc3],     // MOV EDI,EAX
            &[0x88, 0xc2, 0xc3],     // MOV DL,AL
            &[0x89, 0x10, 0xc3],     // MOV [EAX],EDX
            &[0x8b, 0x10, 0xc3],     // MOV EDX,[EAX]
            &[0x01, 0xc2, 0xc3],     // ADD EDX,EAX
            &[0x31, 0xc0, 0xc3],     // XOR EAX,EAX
            &[0x40, 0xc3],           // INC EAX
        ] {
            assert!(
                prove_to_return_boundary(code, 0x1000).is_err(),
                "accepted {code:02x?}"
            );
        }
    }

    #[test]
    fn branches_truncation_trailing_bytes_and_budgets_reject() {
        for code in [
            &[][..],
            &[0x89, 0xc2],
            &[0xc3, 0x90],
            &[0xc3, 0xcc],
            &[0xeb, 0x00, 0xc3],
            &[0x74, 0x00, 0xc3],
            &[0xc2, 0x04, 0x00],
        ] {
            assert!(
                prove_to_return_boundary(code, 0x1000).is_err(),
                "accepted {code:02x?}"
            );
        }
        assert!(prove_to_return_boundary(&[0xc3], u32::MAX).is_err());
        let mut at_limit = [0x89, 0xc2].repeat(127);
        at_limit.push(0xc3);
        assert!(prove_to_return_boundary(&at_limit, 0).is_ok());
        let mut over_limit = [0x89, 0xc2].repeat(128);
        over_limit.push(0xc3);
        assert!(prove_to_return_boundary(&over_limit, 0).is_err());
    }
}
