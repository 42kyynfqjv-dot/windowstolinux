//! Original finally-helper instructions over a proved live parent frame.
//! This does not select a Windows handler or reconstruct EH4 metadata.
use super::graph::{self, Address, Binary, Operand, Operation};
use iced_x86::{Code, Decoder, DecoderOptions};
use std::collections::{BTreeMap, BTreeSet};

/// The adapter must validate live ownership on every operation. Cleanup acts on
/// the dispatcher's private pair; outer stores happen only at their decoded
/// MOV instructions after successful return. An error is terminal for this call
/// and retains already executed writes. No method grants a restoration receipt.
#[allow(dead_code)] // Included only by the checked CRT field composition.
pub(crate) const LIVE_EFFECTS: &str = r#"
trait LiveFinallyEffects {
 type Error;
 fn require_cursor(&mut self, expected:i32)->Result<(),Self::Error>;
 fn read_cursor(&mut self)->Result<i32,Self::Error>;
 fn write_cursor(&mut self,value:i32)->Result<(),Self::Error>;
 fn read_cell(&mut self,index:usize)->Result<u32,Self::Error>;
 fn write_cell(&mut self,index:usize,value:u32)->Result<(),Self::Error>;
 fn write_global(&mut self,index:usize,value:u32)->Result<(),Self::Error>;
 fn dispatch(&mut self)->Result<(),Self::Error>;
 fn cleanup(&mut self,action:usize,private:&mut[u32;2])->Result<(),Self::Error>;
}
"#;

#[derive(Clone)]
enum Value {
    Unknown,
    FrameWord(i32),
    Scalar(String),
}

pub(crate) struct ProvenFunclet {
    /// Body for a helper with cells, cursor, globals and a proven dispatch callback.
    pub source: String,
    /// Checked effects at original instruction points; no final copy-back.
    #[allow(dead_code)] // Legacy slice entry points use the array-backed emitter.
    pub live_source: String,
    /// Derived from original argument order, not supplied semantic field names.
    pub local_offset: i32,
    pub cursor_offset: i32,
    /// Global observation indices in original store order.
    pub global_writes: Vec<usize>,
    /// Own maximum below helper entry ESP, including Dispatch CALL's return
    /// word. Its caller still owns the existing funclet return word separately.
    pub temporary_bytes: u32,
    pub dispatch_entry_depth: u32,
}
impl ProvenFunclet {
    pub fn with_dispatch_depth(&self, dispatch_temporary_bytes: u32) -> Result<u32, String> {
        Ok(self.temporary_bytes.max(
            self.dispatch_entry_depth
                .checked_add(dispatch_temporary_bytes)
                .ok_or("funclet: nested temporary stack overflow")?,
        ))
    }
}

fn frame_word(address: &Address, words: &BTreeMap<i32, u32>) -> Result<i32, String> {
    let offset = address.displacement as i32;
    if address.base != Some(5)
        || address.index.is_some()
        || offset >= 0
        || offset % 4 != 0
        || !words.contains_key(&offset)
    {
        return Err("funclet: initialized parent scalar ownership".into());
    }
    Ok(offset)
}

/// `scalar_words` must come from the parent frame proof, excluding saved return,
/// SEH record/TryLevel, cookie, pointers and uninitialized storage. Its numeric
/// values are not baked into native output: later scopes see live updated cells.
/// `globals` binds disjoint initialized-or-writable scalar image cells; the
/// enclosing image proof must exclude aliases with code and protected metadata.
///
/// Emitted body parameters: `cells: &mut [u32;2]` (trace/local),
/// `cursor: &mut i32`, `globals: &mut [Option<u32>]`, and
/// `dispatch: impl FnOnce(&mut [u32;2], &mut i32) -> Result<(), Error>`.
/// The parent adapter checks live frame generation before entry, and issues a
/// cleanup receipt only after this entire body succeeds. RET is that protected
/// helper-return boundary; volatile working registers/flags are not observations.
pub(crate) fn prove_funclet(
    code: &[u8],
    origin: u32,
    dispatch_va: u32,
    scalar_words: &BTreeMap<i32, u32>,
    globals: &BTreeMap<u32, usize>,
) -> Result<ProvenFunclet, String> {
    if code.is_empty() || code.len() > 1024 || scalar_words.len() > 256 || globals.len() > 64 {
        return Err("funclet: resource bounds".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("funclet: code overflow")?;
    let mut indices = BTreeSet::new();
    for (&address, &index) in globals {
        if address % 4 != 0
            || address.checked_add(4).is_none()
            || index >= 64
            || !indices.insert(index)
        {
            return Err("funclet: global field ownership".into());
        }
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut registers: [Value; 8] = std::array::from_fn(|_| Value::Unknown);
    // Helper return storage is protected at ESP+0. This vector only contains
    // original PUSH arguments below it; ADD ESP can never consume the return.
    let mut arguments: Vec<i32> = Vec::new();
    let mut roles: Option<(i32, i32)> = None;
    let mut source = String::new();
    let mut live_source = String::new();
    let mut global_writes = Vec::new();
    let mut serial = 0;
    let mut count = 0;
    let mut temporary_bytes = 0;
    let mut dispatch_entry_depth = None;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        count += 1;
        if instruction.is_invalid() || count > 64 {
            return Err("funclet: instruction boundary/budget".into());
        }
        let at = (instruction.ip() as u32 - origin) as usize;
        let bytes = &code[at..at + instruction.len()];
        if instruction.code() == Code::Call_rel32_32 {
            if bytes.first() != Some(&0xe8)
                || bytes.len() != 5
                || instruction.near_branch32() != dispatch_va
                || roles.is_some()
                || arguments.len() != 2
                || arguments[0] == arguments[1]
            {
                return Err("funclet: bound call/argument ownership".into());
            }
            // cdecl pushes the second (local) pointer before the first (cursor).
            roles = Some((arguments[0], arguments[1]));
            let depth = u32::try_from(arguments.len())
                .ok()
                .and_then(|n| n.checked_mul(4))
                .and_then(|n| n.checked_add(4))
                .ok_or("funclet: CALL temporary stack overflow")?;
            temporary_bytes = temporary_bytes.max(depth);
            dispatch_entry_depth = Some(depth);
            source.push_str("dispatch(cells,cursor)?;\n");
            live_source.push_str("effects.dispatch()?;\n");
            for index in [0, 1, 2] {
                registers[index] = Value::Unknown;
            }
            continue;
        }
        match graph::normalized(&instruction, bytes)? {
            Operation::Address(reg, address)
                if reg.width == 32 && reg.shift == 0 && reg.index <= 2 =>
            {
                registers[reg.index as usize] =
                    Value::FrameWord(frame_word(&address, scalar_words)?);
            }
            Operation::Push(Operand::Reg(reg))
                if reg.width == 32 && reg.shift == 0 && reg.index <= 2 =>
            {
                let Value::FrameWord(offset) = registers[reg.index as usize] else {
                    return Err("funclet: pointer argument provenance".into());
                };
                if arguments.len() >= 2 || roles.is_some() {
                    return Err("funclet: argument stack budget/phase".into());
                }
                arguments.push(offset);
                temporary_bytes = temporary_bytes.max(u32::try_from(arguments.len()).unwrap() * 4);
            }
            Operation::Binary(Binary::Add, Operand::Reg(reg), Operand::Immediate(amount))
                if reg.index == 4 && reg.width == 32 && reg.shift == 0 =>
            {
                let words = usize::try_from(amount / 4).map_err(|_| "funclet: stack amount")?;
                if roles.is_none() || amount == 0 || amount % 4 != 0 || words > arguments.len() {
                    return Err("funclet: protected return/argument cleanup".into());
                }
                arguments.truncate(arguments.len() - words);
            }
            Operation::Binary(Binary::Move, dst, src) => {
                let value = match src {
                    Operand::Immediate(value) => Value::Scalar(format!("{value}u32")),
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 && reg.index <= 2 => {
                        registers[reg.index as usize].clone()
                    }
                    Operand::Memory(address, 32) => {
                        let offset = frame_word(&address, scalar_words)?;
                        let (local, cursor) =
                            roles.ok_or("funclet: scalar read before bound call")?;
                        let expression = if offset == local {
                            "cells[1]"
                        } else if offset == cursor {
                            "*cursor as u32"
                        } else {
                            return Err("funclet: scalar outside borrowed caller fields".into());
                        };
                        let name = format!("f{serial}");
                        serial += 1;
                        source.push_str(&format!("let {name}:u32={expression};\n"));
                        let live = if offset == local {
                            "effects.read_cell(1)?"
                        } else {
                            "effects.read_cursor()? as u32"
                        };
                        live_source.push_str(&format!("let {name}:u32={live};\n"));
                        Value::Scalar(name)
                    }
                    _ => return Err("funclet: unsupported value read".into()),
                };
                if matches!(value, Value::Unknown) {
                    return Err("funclet: unknown/clobbered register read".into());
                }
                match dst {
                    Operand::Reg(reg) if reg.width == 32 && reg.shift == 0 && reg.index <= 2 => {
                        registers[reg.index as usize] = value;
                    }
                    Operand::Memory(address, 32)
                        if address.base.is_none() && address.index.is_none() =>
                    {
                        let Value::Scalar(expression) = value else {
                            return Err("funclet: pointer escape".into());
                        };
                        let index = *globals
                            .get(&address.displacement)
                            .ok_or("funclet: unbound global store")?;
                        source.push_str(&format!(
                            "*globals.get_mut({index}).ok_or(Error::Range)?=Some({expression});\n"
                        ));
                        live_source
                            .push_str(&format!("effects.write_global({index},{expression})?;\n"));
                        global_writes.push(index);
                    }
                    _ => return Err("funclet: protected/non-scalar destination".into()),
                }
            }
            Operation::Return => {
                let (local_offset, cursor_offset) =
                    roles.ok_or("funclet: missing dispatcher call")?;
                if !arguments.is_empty()
                    || decoder.can_decode()
                    || instruction.next_ip() != u64::from(end)
                {
                    return Err("funclet: complete return extent/stack proof".into());
                }
                source.push_str("Ok(())\n");
                live_source.push_str("Ok(())\n");
                return Ok(ProvenFunclet {
                    source,
                    live_source,
                    local_offset,
                    cursor_offset,
                    global_writes,
                    temporary_bytes,
                    dispatch_entry_depth: dispatch_entry_depth
                        .ok_or("funclet: missing Dispatch stack depth")?,
                });
            }
            _ => return Err("funclet: unsupported reachable effect".into()),
        }
    }
    Err("funclet: missing return".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: u32 = 0x1000;
    const DISPATCH: u32 = 0x2000;
    fn code(local: i8, cursor: i8, globals: bool) -> Vec<u8> {
        let mut code = vec![
            0x8d,
            0x45,
            local as u8,
            0x50,
            0x8d,
            0x45,
            cursor as u8,
            0x50,
            0xe8,
        ];
        code.extend(DISPATCH.wrapping_sub(ORIGIN + 13).to_le_bytes());
        code.extend([0x83, 0xc4, 8]);
        if globals {
            code.extend([0x8b, 0x45, local as u8, 0xa3]);
            code.extend(0x5000u32.to_le_bytes());
            code.extend([0x8b, 0x45, cursor as u8, 0xa3]);
            code.extend(0x5004u32.to_le_bytes());
        }
        code.push(0xc3);
        code
    }
    fn words() -> BTreeMap<i32, u32> {
        BTreeMap::from([(-28, 100), (-32, 0), (-44, 900), (-48, 2)])
    }
    fn globals() -> BTreeMap<u32, usize> {
        BTreeMap::from([(0x5000, 1), (0x5004, 0)])
    }
    fn prove(bytes: &[u8]) -> Result<ProvenFunclet, String> {
        prove_funclet(bytes, ORIGIN, DISPATCH, &words(), &globals())
    }
    #[test]
    fn displaced_original_pointer_layout_and_global_destinations_are_derived() {
        for (local, cursor) in [(-28, -32), (-44, -48)] {
            let proof = prove(&code(local, cursor, true)).unwrap();
            assert_eq!(
                (proof.local_offset, proof.cursor_offset),
                (local as i32, cursor as i32)
            );
            assert_eq!(proof.global_writes, [1, 0]);
            assert!(proof.source.contains("dispatch(cells,cursor)?"));
            assert_eq!(
                proof.source,
                prove(&code(local, cursor, true)).unwrap().source
            );
        }
        // Swapping arguments derives swapped roles; the parent scope proof must
        // reject cursor100 rather than claiming the original cursor0 is used.
        let swapped = prove(&code(-32, -28, false)).unwrap();
        assert_eq!((swapped.local_offset, swapped.cursor_offset), (-32, -28));
    }
    #[test]
    fn nested_temporary_extent_includes_argument_and_original_call_words() {
        let bytes = code(-28, -32, false);
        let proof = prove(&bytes).unwrap();
        // PUSH local, PUSH cursor, CALL return: 12 below funclet entry ESP.
        assert_eq!(proof.temporary_bytes, 12);
        assert_eq!(proof.dispatch_entry_depth, 12);
        assert_eq!(proof.with_dispatch_depth(24).unwrap(), 36);
        assert_eq!(proof.with_dispatch_depth(60).unwrap(), 72);
        assert!(proof.with_dispatch_depth(u32::MAX).is_err());
        // Equivalent two-step original argument cleanup cannot erase peak depth.
        let mut split = bytes.clone();
        split.splice(13..16, [0x83, 0xc4, 4, 0x83, 0xc4, 4]);
        let split = prove(&split).unwrap();
        assert_eq!(split.temporary_bytes, 12);
        assert_eq!(split.with_dispatch_depth(24).unwrap(), 36);
        let mut protected = bytes;
        protected[15] = 12;
        assert!(prove(&protected).is_err());
    }
    #[test]
    fn protected_uninitialized_alias_call_stack_and_clobber_mutations_reject() {
        for (local, cursor) in [(0, -32), (-4, -32), (-30, -32), (-28, -28), (-36, -32)] {
            assert!(prove(&code(local, cursor, false)).is_err());
        }
        let good = code(-28, -32, true);
        for (at, value) in [(9, 0), (15, 12), (18, 0xfc), (19, 0x89)] {
            let mut bad = good.clone();
            bad[at] = value;
            assert!(prove(&bad).is_err(), "accepted mutation {at}");
        }
        let mut unknown = code(-28, -32, false);
        unknown.pop();
        unknown.extend([0xa3, 0, 0x50, 0, 0, 0xc3]);
        assert!(prove(&unknown).is_err());
        let mut escaped = code(-28, -32, false);
        escaped.splice(3..3, [0xa3, 0, 0x50, 0, 0]);
        assert!(prove(&escaped).is_err());
        for end in 0..good.len() {
            assert!(prove(&good[..end]).is_err());
        }
        let mut padded = good.clone();
        padded.push(0x90);
        assert!(prove(&padded).is_err());
        assert!(prove_funclet(&good, u32::MAX - 4, DISPATCH, &words(), &globals()).is_err());
        assert!(prove_funclet(
            &good,
            ORIGIN,
            DISPATCH,
            &words(),
            &BTreeMap::from([(0x5000, 0), (0x5004, 0)])
        )
        .is_err());
    }

    #[test]
    fn live_funclet_reads_after_dispatch_and_retains_first_global_on_later_failure() {
        let p = prove(&code(-44, -48, true)).unwrap();
        let source = format!(
            r#"
        #[derive(Debug)]struct Failure;
        struct Effects{{local:u32,cursor:i32,globals:[Option<u32>;2],fail:bool}}
        impl Effects{{
         fn dispatch(&mut self)->Result<(),Failure>{{self.local=self.local.wrapping_add(7);self.cursor=-1;Ok(())}}
         fn read_cell(&mut self,i:usize)->Result<u32,Failure>{{assert_eq!(i,1);Ok(self.local)}}
         fn read_cursor(&mut self)->Result<i32,Failure>{{Ok(self.cursor)}}
         fn write_global(&mut self,i:usize,v:u32)->Result<(),Failure>{{if self.fail&&i==0{{return Err(Failure)}}self.globals[i]=Some(v);Ok(())}}
        }}
        fn run(effects:&mut Effects)->Result<(),Failure>{{{}}}
        fn main(){{for fail in [false,true]{{let mut e=Effects{{local:900,cursor:2,globals:[None;2],fail}};assert_eq!(run(&mut e).is_err(),fail);assert_eq!((e.local,e.cursor),(907,-1));assert_eq!(e.globals,[if fail{{None}}else{{Some(u32::MAX)}},Some(907)]);}}}}
        "#,
            p.live_source
        );
        let dir = std::env::temp_dir().join(format!("w2l-funclet-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.rs");
        let bin = dir.join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::write(&file, source).unwrap();
        let out = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(std::process::Command::new(&bin).status().unwrap().success());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn native_postcall_observations_use_live_values_and_store_failure_cannot_succeed() {
        let proof = prove(&code(-44, -48, true)).unwrap();
        let source = format!(
            "#[derive(Debug,PartialEq)]enum Error{{Range}}\n\
             fn run(cells:&mut[u32;2],cursor:&mut i32,globals:&mut[Option<u32>],\
             dispatch:impl FnOnce(&mut[u32;2],&mut i32)->Result<(),Error>)->Result<(),Error>{{{}}}\n\
             fn action(c:&mut[u32;2],k:&mut i32)->Result<(),Error>{{\
             c[0]=c[0].wrapping_add(9);c[1]=c[1].wrapping_add(7);*k=-1;Ok(())}}\n\
             fn main(){{let mut c=[1,100];let mut k=0;let mut g=[None;2];\
             assert_eq!(run(&mut c,&mut k,&mut g,action),Ok(()));\
             assert_eq!((c,k,g),([10,107],-1,[Some(u32::MAX),Some(107)]));\
             c=[u32::MAX,u32::MAX];k=2;let mut short=[None];\
             assert_eq!(run(&mut c,&mut k,&mut short,action),Err(Error::Range));\
             assert_eq!((c,k,short),([8,6],-1,[None]));}}",
            proof.source
        );
        let directory = std::env::temp_dir().join(format!("w2l-funclet-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("test.rs");
        let binary = directory.join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::write(&file, source).unwrap();
        let result = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(std::process::Command::new(binary)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
