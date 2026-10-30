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
        for opcode in [0xbb, 0xbd, 0xbe, 0xbf] {
            let mut clobber = vec![opcode, 1, 0, 0, 0];
            clobber.extend(code());
            assert!(prove(&clobber, 0x2000, 0x1000, 0x1002, true).is_err());
        }
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
    let mut source=String::from("// Integer CONTEXT slice; requires the documented raw-handler ABI.\n#[allow(unused_assignments,unused_variables)]\npub fn handler(c:&mut [u32;10])->Result<u32, &'static str> { let mut r=[0u32;8];\n");
    source.push_str(&format!(
        "if c[8]!={fault} {{ return Err(\"handler slice context precondition\"); }}\n"
    ));
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
                source.push_str("Ok(r[0]) }\n");
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
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 && reg.index <= 2 => (
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

#[path = "handler_continuation.rs"]
mod continuation;

/// A contained resume instruction slice, not a whole-image startup certificate.
/// The harness supplies a complete integer context at the decoded UD2 entry.
/// Original FS registration, guest stack return, and unwind are outside this cut.
pub fn prove_event(
    handler_code: &[u8],
    handler_origin: u32,
    event_code: &[u8],
    event_origin: u32,
) -> Result<Proven, String> {
    if !event_code.starts_with(&[0x0f, 0x0b]) {
        return Err("handler event: expected decoded UD2".into());
    }
    let resume = event_origin
        .checked_add(2)
        .ok_or("handler event: IP overflow")?;
    let end = event_origin
        .checked_add(u32::try_from(event_code.len()).map_err(|_| "handler event: extent")?)
        .ok_or("handler event: extent overflow")?;
    let handler_end = handler_origin
        .checked_add(
            u32::try_from(handler_code.len()).map_err(|_| "handler event: handler extent")?,
        )
        .ok_or("handler event: handler overflow")?;
    if event_origin < handler_end && handler_origin < end {
        return Err("handler event: overlapping code ownership".into());
    }
    let handler = prove(handler_code, handler_origin, event_origin, resume, true)?.emit();
    let continuation = continuation::prove_to_return_boundary(&event_code[2..], resume)?;
    let storage = include_str!("linker/activation.rs");
    let source = format!(
        r#"
// Contained UD2 resume slice. Stops before guest RET; no whole-PE admission.
#[allow(dead_code)]
mod owned {{
{storage}
{handler}
fn continuation(mut c:[u32;10])->Result<[u32;10], &'static str> {{
{continuation}
}}
fn context(c:[u32;10])->Context {{ Context {{registers: std::array::from_fn(|i|Some(c[i])),ip:Some(c[8]),flags:Some(c[9])}} }}
fn words(c:&Context)->Result<[u32;10], &'static str> {{
 let mut out=[0;10];
 for (i,v) in c.registers.iter().enumerate() {{ out[i]=v.ok_or("incomplete context")?; }}
 out[8]=c.ip.ok_or("incomplete IP")?; out[9]=c.flags.ok_or("incomplete flags")?; Ok(out)
}}
pub fn event(c:[u32;10])->Result<[u32;10], &'static str> {{
 if c[8]!={event_origin} {{return Err("event IP precondition");}}
 if c[9] & !0x8d5 != 0x202 {{return Err("unsupported event flags");}}
 let captured=context(c);
 let mut stack=Stack::new(1).map_err(|_|"activation allocation")?;
 let frame=stack.push(0,0,captured.clone()).map_err(|_|"activation frame")?;
 // Continuability is derived from the admitted UD2 event, not a runtime caller flag.
 stack.begin_search(captured,true).map_err(|_|"event capture")?;
 let ticket=stack.capture_contained_resume().map_err(|_|"event ownership")?;
 let mut edited=words(stack.event_context().map_err(|_|"event context")?)?;
 if handler(&mut edited)?!=0 {{return Err("disposition proof mismatch");}}
 let restored=stack.commit_contained_resume(ticket,context(edited),{resume}).map_err(|_|"restoration invariant")?;
 if stack.top().map(|f|f.id)!=Some(frame) {{return Err("activation identity changed");}}
 continuation(words(&restored)?)
}}
}}
pub use owned::event;
"#
    );
    Ok(Proven { source })
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "linker/activation.rs"]
mod activation_tests;

#[cfg(test)]
mod event_tests {
    use super::*;
    fn handler() -> Vec<u8> {
        vec![
            0x8b, 0x4c, 0x24, 0x0c, 0x83, 0x81, 0xb8, 0, 0, 0, 2, 0xc7, 0x81, 0xb0, 0, 0, 0, 42, 0,
            0, 0, 0x31, 0xc0, 0xc3,
        ]
    }
    #[test]
    fn event_certificate_rejects_missing_fault_boundaries_overlap_and_root_search() {
        let h = handler();
        for event in [
            &[0x90, 0x90, 0x89, 0xc2, 0xc3][..],
            &[0x0f, 0x0b, 0x8b],
            &[0x0f, 0x0b, 0xeb, 0, 0xc3],
            &[0x0f, 0x0b, 0x89, 0xc2, 0xc3, 0x90],
        ] {
            assert!(prove_event(&h, 0x2000, event, 0x1000).is_err());
        }
        let e = [0x0f, 0x0b, 0x89, 0xc2, 0xc3];
        assert!(prove_event(&h, 0x1000, &e, 0x1000).is_err());
        assert!(prove_event(&h, 0x2000, &e, u32::MAX - 1).is_err());
        let mut wrong = h.clone();
        wrong[10] = 1;
        assert!(prove_event(&wrong, 0x2000, &e, 0x1000).is_err());
        let mut search = h.clone();
        search.splice(21..23, [0xb8, 1, 0, 0, 0]);
        assert!(prove_event(&search, 0x2000, &e, 0x1000).is_err());
    }
    #[test]
    fn emitted_owned_event_executes_original_continuation_without_cleanup() {
        let e = [0x0f, 0x0b, 0x89, 0xc2, 0xc3];
        let source = prove_event(&handler(), 0x2000, &e, 0x1000).unwrap().emit();
        assert_eq!(
            source,
            prove_event(&handler(), 0x2000, &e, 0x1000).unwrap().emit()
        );
        let dir = std::env::temp_dir().join(format!("w2l-event-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("event.rs");
        let exe = dir.join(if cfg!(windows) { "event.exe" } else { "event" });
        std::fs::write(&path,source+"\nfn main(){let c=[10,11,12,13,32768,33024,16,17,4096,514];let mut bad=c;bad[8]=4097;assert!(event(bad).is_err());for flags in [0x302,0x10202,0x20202,0x4202,0x3202,0x602,0] {bad=c;bad[9]=flags;assert!(event(bad).is_err());}assert_eq!(event(c).unwrap(),[42,11,42,13,32768,33024,16,17,4100,514]);}").unwrap();
        let compile = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        assert!(std::process::Command::new(&exe).status().unwrap().success());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
