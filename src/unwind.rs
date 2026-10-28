//! Experimental original cleanup/restore slices under an explicit orchestration cut.
#[path = "cleanup.rs"]
mod cleanup;
#[allow(dead_code)]
#[path = "crt_shutdown.rs"]
mod crt_shutdown;
#[cfg(test)]
#[path = "crt_shutdown_tests.rs"]
mod crt_shutdown_tests;
#[path = "dispatch.rs"]
mod dispatch;
#[allow(dead_code)]
#[path = "dispatch_contract.rs"]
mod dispatch_contract;
#[allow(dead_code)]
#[path = "dispatch_emit.rs"]
mod dispatch_emit;
#[allow(dead_code)]
#[path = "dispatch_execution.rs"]
mod dispatch_execution;
#[allow(dead_code)]
#[path = "dispatch_support.rs"]
mod dispatch_support;
#[allow(dead_code)]
#[path = "exception_event.rs"]
mod exception_event;
#[path = "frame_init.rs"]
mod frame_init;
#[path = "frame_landing.rs"]
mod frame_landing;
#[path = "frame_memory.rs"]
mod frame_memory;
#[path = "frame_proof.rs"]
mod frame_proof;
#[path = "frame_unwind.rs"]
pub mod frame_unwind;
#[path = "funclet.rs"]
mod funclet;
#[allow(dead_code)]
#[path = "stream/graph.rs"]
mod graph;
#[path = "handler_bridge.rs"]
mod handler_bridge;
#[path = "handler_checks.rs"]
mod handler_checks;
#[path = "handler_context.rs"]
mod handler_context;
#[allow(dead_code)]
#[path = "handler_dispatch.rs"]
mod handler_dispatch;
#[path = "handler_guard.rs"]
mod handler_guard;
#[allow(dead_code)]
#[path = "local_unwind.rs"]
mod local_unwind;
#[allow(dead_code)]
#[path = "main_completion.rs"]
mod main_completion;
#[cfg(test)]
#[path = "main_completion_review_tests.rs"]
mod main_completion_review_tests;
#[allow(dead_code)]
#[path = "main_return.rs"]
mod main_return;
#[cfg(test)]
#[path = "main_return_tests.rs"]
mod main_return_tests;
#[allow(dead_code)]
#[path = "raise_call.rs"]
mod raise_call;
#[cfg(test)]
#[path = "raise_contract_tests.rs"]
mod raise_contract_tests;
#[cfg(test)]
#[path = "raised_review_tests.rs"]
mod raised_review_tests;
#[cfg(test)]
#[path = "reported_review_tests.rs"]
mod reported_review_tests;
#[path = "selection.rs"]
mod selection;
#[allow(dead_code)]
#[path = "stdio_effect.rs"]
mod stdio_effect;
#[allow(dead_code)]
#[path = "thread_registry.rs"]
mod thread_registry;
#[allow(dead_code)]
#[path = "unwind_bridges.rs"]
mod unwind_bridges;
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

pub struct Proven {
    source: String,
}
impl Proven {
    pub fn emit(self) -> String {
        self.source
    }
}
/// Original authored dispatcher code and its separately owned trace cell.
/// These are image RVAs; no application identity selects emitted behavior.
pub struct Dispatcher<'a> {
    pub code: &'a [u8],
    pub rva: u32,
    pub trace_rva: u32,
}
fn restore_body(code: &[u8], origin: u32) -> Result<String, String> {
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut owner = None;
    let mut fields = BTreeSet::new();
    let mut source = String::new();
    let mut count = 0;
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        if i.is_invalid()
            || count > 8
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.memory_index() != Register::None
        {
            return Err("restore: instruction policy".into());
        }
        if i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Memory
        {
            if owner.is_none() {
                if !matches!(i.op0_register(), Register::ECX | Register::EDX)
                    || i.memory_base() != Register::ESP
                    || i.memory_displacement32() != 4
                {
                    return Err("restore: saved context argument".into());
                }
                owner = Some(i.op0_register());
                continue;
            }
            if Some(i.memory_base()) != owner {
                return Err("restore: pointer ownership".into());
            }
            let (index, offset) = match i.op0_register() {
                Register::EAX => (0, 176),
                Register::ESP => (4, 196),
                Register::EBP => (5, 180),
                _ => return Err("restore: protected register".into()),
            };
            if i.memory_displacement32() != offset || !fields.insert(index) {
                return Err("restore: context field binding".into());
            }
            source.push_str(&format!("context[{index}]=view.read_saved({index})?;\n"));
        } else if i.mnemonic() == Mnemonic::Jmp
            && i.op0_kind() == OpKind::Memory
            && Some(i.memory_base()) == owner
            && i.memory_displacement32() == 184
            && i.code() == Code::Jmp_rm32
        {
            if decoder.can_decode() || fields != BTreeSet::from([0, 4, 5]) {
                return Err("restore: incomplete terminal transfer".into());
            }
            source.push_str("context[8]=view.read_saved(8)?;\nOk(())\n");
            return Ok(source);
        } else {
            return Err("restore: unsupported effect".into());
        }
    }
    Err("restore: missing transfer".into())
}

#[allow(clippy::too_many_arguments)] // Explicit independently bound slice regions and entry cut.
pub fn prove(
    table: &[u8],
    base: u32,
    table_rva: u32,
    blocks: &[(u32, Vec<u8>)],
    restore: &[u8],
    restore_rva: u32,
    target: u32,
    target_bytes: &[u8],
    active: &[i32],
    selected: usize,
) -> Result<Proven, String> {
    prove_with_dispatch(
        table,
        base,
        table_rva,
        blocks,
        restore,
        restore_rva,
        target,
        target_bytes,
        active,
        selected,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_with_dispatch(
    table: &[u8],
    base: u32,
    table_rva: u32,
    blocks: &[(u32, Vec<u8>)],
    restore: &[u8],
    restore_rva: u32,
    target: u32,
    target_bytes: &[u8],
    active: &[i32],
    selected: usize,
    dispatcher: Option<Dispatcher<'_>>,
) -> Result<Proven, String> {
    if blocks.is_empty()
        || blocks.len() > 32
        || table.is_empty()
        || !table.len().is_multiple_of(8)
        || table.len() > 256
        || active.is_empty()
        || active.len() > 8
        || selected >= active.len()
    {
        return Err("unwind: metadata budget".into());
    }
    let mut ranges = Vec::new();
    let mut add_range = |start: u32, len: usize| -> Result<(), String> {
        let end = start
            .checked_add(u32::try_from(len).map_err(|_| "unwind: size")?)
            .ok_or("unwind: range overflow")?;
        base.checked_add(end)
            .ok_or("unwind: image address overflow")?;
        if len == 0 || ranges.iter().any(|&(a, b)| start < b && a < end) {
            return Err("unwind: overlapping owned regions".into());
        }
        ranges.push((start, end));
        Ok(())
    };
    add_range(table_rva, table.len())?;
    add_range(restore_rva, restore.len())?;
    add_range(target, target_bytes.len())?;
    if let Some(d) = &dispatcher {
        add_range(d.rva, d.code.len())?;
        add_range(d.trace_rva, 4)?;
    }
    let mut decoder = Decoder::with_ip(32, target_bytes, u64::from(target), DecoderOptions::NONE);
    if !decoder.can_decode() || decoder.decode().is_invalid() {
        return Err("unwind: target instruction boundary".into());
    }
    let mut functions = String::new();
    let mut bound = BTreeMap::new();
    for (index, (rva, code)) in blocks.iter().enumerate() {
        add_range(*rva, code.len())?;
        if bound.insert(*rva, index).is_some() {
            return Err("unwind: duplicate target".into());
        }
        let body = cleanup::prove_cleanup(code, *rva)?;
        functions.push_str(&format!(
            "fn cleanup_{index}(cells:&mut[u32;2])->Result<(),Error>{{\n{body}\n}}\n"
        ));
    }
    let rows: Vec<_> = table
        .as_chunks::<8>()
        .0
        .iter()
        .map(|row| {
            (
                i32::from_le_bytes(row[..4].try_into().unwrap()),
                u32::from_le_bytes(row[4..].try_into().unwrap()),
            )
        })
        .collect();
    for &(parent, va) in &rows {
        if parent < -1
            || parent >= rows.len() as i32
            || !va.checked_sub(base).is_some_and(|r| bound.contains_key(&r))
        {
            return Err("unwind: unbound scope metadata".into());
        }
    }
    if let Some(d) = &dispatcher {
        let bindings = bound
            .iter()
            .map(|(&rva, &index)| (base + rva, index))
            .collect();
        for (index, &(parent, target_va)) in rows.iter().enumerate() {
            let body = dispatch::prove_dispatch(
                d.code,
                base + d.rva,
                base + table_rva,
                &rows,
                base + d.trace_rva,
                &bindings,
                index as i32,
            )?;
            if body.parent != parent || body.action != bindings[&target_va] {
                return Err("unwind: dispatcher disagrees with bound scope effects".into());
            }
            functions.push_str(&format!(
                "fn dispatch_{index}(cells:&mut[u32;2],cursor:&mut i32)->Result<(),Error>{{\n{}\n}}\n",
                body.source));
        }
    }
    let chain = |start: i32| -> Result<Vec<usize>, String> {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut at = start;
        while at != -1 {
            let i = usize::try_from(at).map_err(|_| "unwind: active scope")?;
            if i >= rows.len() || !seen.insert(i) {
                return Err("unwind: scope cycle or index".into());
            }
            chain.push(i);
            at = rows[i].0;
        }
        Ok(chain)
    };
    for i in 0..rows.len() {
        chain(i as i32)?;
    }
    let mut specs = Vec::new();
    let mut owned = BTreeSet::new();
    for (frame, &at) in active.iter().enumerate() {
        let indices = chain(at)?;
        if frame < selected && !indices.is_empty() {
            return Err("unwind: frame below selected cut".into());
        }
        let mut scopes = Vec::new();
        for i in indices {
            if !owned.insert(i) {
                return Err("unwind: aliased active scopes".into());
            }
            let action = if dispatcher.is_some() {
                i
            } else {
                bound[&(rows[i].1 - base)]
            };
            scopes.push(format!("Scope{{scope:{i},action:{action}}}"));
        }
        specs.push(format!("FrameSpec{{scopes:vec![{}]}}", scopes.join(",")));
    }
    let restore = restore_body(restore, restore_rva)?;
    let arms = if dispatcher.is_some() {
        rows.iter().enumerate().map(|(i, &(parent, _))|
            format!("{i}=>{{let mut cursor={i}i32;dispatch_{i}(&mut cells,&mut cursor)?;if cursor!={parent}i32{{return Err(Error::Order)}}}},"))
            .collect::<String>()
    } else {
        blocks
            .iter()
            .enumerate()
            .map(|(i, _)| format!("{i}=>cleanup_{i}(&mut cells)?,"))
            .collect::<String>()
    };
    let runtime = include_str!("linker/unwind_runtime.rs");
    let frames = active.len();
    let specs = specs.join(",");
    let source = format!(
        r#"
#[allow(dead_code)]
mod owned {{
{runtime}
{functions}
#[derive(Debug,PartialEq,Eq)]
pub struct Outcome {{pub trace:u32,pub locals:Vec<Option<u32>>,pub live:Vec<bool>,pub restored:[Option<u32>;10]}}
pub fn unwind(locals:&[u32],saved:[u32;10],current:[u32;10],trace:u32)->Result<Outcome,&'static str>{{
 if locals.len()!={frames}||saved[8]!={target} {{return Err("unwind slice input boundary");}}
 if current[9] & !0x8d5 != 0x202 {{return Err("unsupported unwind entry flags");}}
 let specs=vec![{specs}];
 let inputs=locals.iter().enumerate().map(|(i,&local)|FrameInput{{cells:vec![Some(local)],context:if i=={selected}{{saved}}else{{current}}}}).collect();
 let mut machine=Machine::new(specs,inputs,{selected},Some(trace)).map_err(|_|"unwind ownership")?;
 machine.context=current;
 while let Some(request)=machine.next_cleanup().map_err(|_|"unwind phase")? {{
  let action=request.action();
  machine.execute_cleanup(request,|view|{{let mut cells=[view.read_trace()?,view.read_word(0)?];match action{{{arms}_=>return Err(Error::Order)}};view.write_trace(cells[0])?;view.write_word(0,cells[1])?;Ok(())}}).map_err(|_|"cleanup invariant")?;
 }}
 let context=machine.restore({target},|view,context|{{{restore}}}).map_err(|_|"restoration invariant")?;
 let mut restored=context.map(Some);restored[1]=None;restored[2]=None;restored[9]=None;
 Ok(Outcome{{trace:machine.trace.ok_or("unknown trace")?,locals:machine.frames.iter().map(|f|f.cells[0]).collect(),live:machine.frames.iter().map(|f|f.live).collect(),restored}})
}}
}}
pub use owned::{{unwind,Outcome}};
"#
    );
    Ok(Proven { source })
}
#[cfg(test)]
#[allow(dead_code)]
#[path = "linker/unwind_runtime.rs"]
mod runtime_tests;

#[cfg(test)]
#[path = "unwind_tests.rs"]
mod tests;
