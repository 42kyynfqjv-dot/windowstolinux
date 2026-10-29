//! Instruction-derived owned search up to an unexecuted global-unwind call.
//! This component boundary never grants restoration or PE admission.
use super::{
    crt_stream_emit::{self, PathStep},
    crt_stream_ir::{Op, Target},
    handler_dispatch::{Action, DispatchProof},
    selection::OriginalFilter,
};
use std::collections::BTreeMap;

pub(crate) struct Input<'a> {
    pub proof: &'a DispatchProof,
    pub origin: u32,
    pub code: &'a [u8],
    pub table_va: u32,
    pub table: &'a [u8],
    pub bridge: u32,
    pub filters: &'a BTreeMap<u32, OriginalFilter<'a>>,
}

pub(crate) fn emit(input: Input<'_>, name: &str) -> Result<String, String> {
    let stop = input
        .proof
        .actions
        .iter()
        .position(|a| matches!(a, Action::GlobalUnwind { .. }))
        .ok_or("owned search: no global boundary")?;
    let Action::GlobalUnwind {
        pc: stop_pc,
        target: stop_target,
        preserved_level,
        ..
    } = &input.proof.actions[stop]
    else {
        unreachable!()
    };
    if input.proof.source_table != input.table {
        return Err("owned search: scope table differs from semantic proof".into());
    }
    if input.proof.instructions.first().map(|s| s.pc) != Some(input.origin)
        || input.code.is_empty()
        || input.code.len() > 1024
        || input.origin.checked_add(input.code.len() as u32).is_none()
        || input.table.is_empty()
        || input.table.len() > 4096
    {
        return Err("owned search: entry/table extent".into());
    }
    let end = input
        .proof
        .instructions
        .iter()
        .position(|s| s.pc == *stop_pc)
        .ok_or("owned search: missing original call")?;
    let mut path = Vec::new();
    for (index, s) in input.proof.instructions[..=end].iter().enumerate() {
        let offset =
            s.pc.checked_sub(input.origin)
                .ok_or("owned search: instruction before source")? as usize;
        let limit = offset
            .checked_add(s.bytes.len())
            .ok_or("owned search: source extent overflow")?;
        if input.code.get(offset..limit) != Some(&s.bytes[..]) {
            return Err("owned search: changed original instruction".into());
        }
        path.push(PathStep {
            pc: s.pc,
            bytes: &s.bytes,
            next: if index == end { None } else { s.next },
        });
    }
    let mut actions = BTreeMap::new();
    let mut functions = String::new();
    for action in &input.proof.actions[..stop] {
        let Action::Filter {
            pc,
            bridge,
            scope,
            target,
            proof,
            ..
        } = action
        else {
            return Err("owned search: earlier effect needs live binding".into());
        };
        let filter = input
            .filters
            .get(target)
            .ok_or("owned search: filter absent")?;
        let row = usize::try_from(*scope)
            .ok()
            .and_then(|s| s.checked_mul(12))
            .and_then(|s| s.checked_add(20))
            .ok_or("owned search: row offset")?;
        if *bridge != input.bridge
            || filter.origin != *target
            || input.table.get(row..row + 4) != Some(&target.to_le_bytes())
            || actions.insert(*pc, action).is_some()
        {
            return Err("owned search: filter/table/bridge binding".into());
        }
        functions.push_str(&format!("fn search_filter_{pc}(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{if cpu.r[5]!=CrtValue::Pointer(frame.owner_frame()?){{return Err(\"owned search filter EBP\");}}{}}}\n",proof.live_body()));
    }
    let mut consumed = 0;
    let body = crt_stream_emit::emit_proved_path(
        &path,
        |pc, target| {
            if pc == *stop_pc {
                if target != Target::Direct(*stop_target) {
                    return Err("owned search: changed global boundary".into());
                }
                return Ok("objects.validate(frame,cpu)?;let owner=frame.owner_frame()?;if cpu.r[1]!=CrtValue::Pointer(frame.rt.offset(owner,-16)?)||cpu.r[2]!=CrtValue::Pointer(objects.record){return Err(\"owned global call entry\");}return Ok(());".into());
            }
            let Some(Action::Filter {
                bridge,
                scope,
                target: filter,
                proof,
                ..
            }) = actions.get(&pc).copied()
            else {
                return Err("owned search: unbound path call".into());
            };
            if target != Target::Direct(*bridge) {
                return Err("owned search: changed filter call".into());
            }
            consumed += 1;
            let raw = input.filters[filter].bytes;
            Ok(format!(
                r#"
objects.validate(frame,cpu)?;
if cpu.r[7].known_scalar()? != {scope}u32||cpu.r[1].known_scalar()? != {filter}u32||cpu.r[2]!=CrtValue::Pointer(frame.owner_frame()?){{return Err("owned table-selected filter provenance");}}
let target=frame.rt.resolve_absolute({filter},CrtRegionKind::Module)?;cpu.r[1]=CrtValue::Pointer(target);
let value=frame.call(cpu,{continuation},|f,child|owned_filter_bridge(f,child,target,&{raw:?},|g,k|{{search_filter_{pc}(g,k)?;k.finish(g.rt)}}))?;
if value!=CrtValue::scalar({result}u32){{return Err("owned filter disagrees with semantic proof");}}
"#,
                continuation = pc + 5,
                result = proof.result() as u32
            ))
        },
        &BTreeMap::new(),
        |_, op| {
            Ok(if matches!(op, Op::Call(_)) {
                String::new()
            } else {
                "let rt=&mut *frame.rt;".into()
            })
        },
    )?;
    if consumed != actions.len() {
        return Err("owned search: unused filter effect".into());
    }
    let raw = input.code;
    let table = input.table;
    Ok(format!(
        r#"{functions}
fn {name}(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,objects:&CrtOwnedPrefixInput)->RegistryResult<()>{{
 let result=(||{{
 objects.validate(frame,cpu)?;let entry=CrtCpu::pointer(cpu.entry[4])?;let bp=frame.rt.offset(entry,-4)?;let owner=frame.owner_frame()?;
 let pair=frame.rt.offset(bp,-28)?;let table=frame.rt.resolve_absolute({table_va},CrtRegionKind::Module)?;
 if frame.storage.pair_return!=Some((entry,cpu.return_id))||frame.storage.image.try_level!={preserved_level}||frame.scope_address()!={table_va}
  ||cpu.r[4]!=CrtValue::Pointer(frame.rt.offset(bp,-40)?)||cpu.r[5]!=CrtValue::Pointer(bp)||cpu.r[0]!=CrtValue::Pointer(pair)
  ||cpu.r[3]!=CrtValue::Pointer(frame.rt.offset(owner,-16)?)||cpu.r[6]!=CrtValue::Pointer(owner)||cpu.r[7]!=CrtValue::scalar({preserved_level}i32 as u32)
  ||frame.rt.load(frame.rt.offset(bp,-8)?,32)?!=CrtValue::Pointer(table)||frame.rt.load(frame.rt.offset(bp,-16)?,32)?!=CrtValue::Pointer(owner){{return Err("owned search prefix state");}}
 let original_regions:&[(u32,&[u8])]=&[({origin}u32,&{raw:?}[..]),({table_va}u32,&{table:?}[..])];
 for &(base,expected)in original_regions{{
  let p=frame.rt.resolve_absolute(base,CrtRegionKind::Module)?;frame.rt.valid(p,expected.len()as u32)?;
  for(i,&byte)in expected.iter().enumerate(){{if frame.rt.load(frame.rt.offset(p,i as i64)?,8)?.known_scalar()?!=u32::from(byte){{return Err("owned search original bytes changed");}}}}
 }}
 {body}
 }})();if result.is_err(){{frame.failed=true;}}result
}}
"#,
        origin = input.origin,
        table_va = input.table_va
    ))
}

/// Lower the separately proved selected-caller phase after GlobalUnwind returns.
pub(crate) fn emit_post_global(input: Input<'_>, name: &str) -> Result<String, String> {
    let global = input
        .proof
        .actions
        .iter()
        .find_map(|a| match a {
            Action::GlobalUnwind {
                pc,
                preserved_level,
                ..
            } => Some((*pc, *preserved_level)),
            _ => None,
        })
        .ok_or("post caller missing global effect")?;
    let transfer = input
        .proof
        .actions
        .iter()
        .find_map(|a| match a {
            Action::Transfer {
                pc,
                bridge,
                landing,
                ..
            } => Some((*pc, *bridge, *landing)),
            _ => None,
        })
        .ok_or("post caller missing transfer")?;
    let start = input
        .proof
        .instructions
        .iter()
        .position(|s| s.pc == global.0)
        .ok_or("post caller missing global instruction")?
        + 1;
    let stop = input
        .proof
        .instructions
        .iter()
        .position(|s| s.pc == transfer.0)
        .ok_or("post caller missing transfer instruction")?;
    if start > stop || input.proof.source_table != input.table {
        return Err("post caller proof/table mismatch".into());
    }
    let mut path = Vec::new();
    for (index, s) in input.proof.instructions[start..=stop].iter().enumerate() {
        let at =
            s.pc.checked_sub(input.origin)
                .ok_or("post caller source origin")? as usize;
        let end = at.checked_add(s.bytes.len()).ok_or("post caller extent")?;
        if input.code.get(at..end) != Some(s.bytes.as_slice()) {
            return Err("post caller changed instruction".into());
        }
        path.push(PathStep {
            pc: s.pc,
            bytes: &s.bytes,
            next: if start + index == stop { None } else { s.next },
        });
    }
    let mut guard = None;
    let mut store = None;
    let mut seen = false;
    for action in &input.proof.actions {
        match action {
            Action::ValidateGuards { pc, target, .. } if *pc > global.0 && *pc < transfer.0 => {
                if guard.replace((*pc, *target)).is_some() {
                    return Err("post caller duplicate guard".into());
                }
            }
            Action::StoreTryLevel { pc, before, after } if *pc > global.0 && *pc < transfer.0 => {
                if store.replace((*pc, *before, *after)).is_some() {
                    return Err("post caller duplicate store".into());
                }
            }
            Action::LocalUnwind { pc, .. } if *pc > global.0 && *pc < transfer.0 => {
                return Err("post caller local unwind needs independent binding".into())
            }
            _ => (),
        }
    }
    let guard = guard.ok_or("post caller missing guard")?;
    let store = store.ok_or("post caller missing scope store")?;
    let body = crt_stream_emit::emit_proved_path_with_store(
        &path,
        |pc, target| {
            if pc == guard.0 && target == Target::Direct(guard.1) {
                return Ok(format!("post.validate(frame,cpu)?;owned_delivery_prefix_helpers::main_guard_call(frame,cpu,{})?;",pc+5));
            }
            if pc == transfer.0 && target == Target::Direct(transfer.1) {
                seen = true;
                return Ok(format!(
                    "return post.transfer_cut(frame,cpu,{});",
                    transfer.2
                ));
            }
            Err("post caller unbound call".into())
        },
        &BTreeMap::new(),
        |_, op| {
            Ok(
                if matches!(
                    op,
                    Op::Call(_)
                        | Op::Ordinary(super::graph::Operation::Binary(
                            super::graph::Binary::Move,
                            super::graph::Operand::Memory(_, 32),
                            _
                        ))
                ) {
                    String::new()
                } else {
                    "let rt=&mut *frame.rt;".into()
                },
            )
        },
        |pc, address, width| {
            if pc != store.0
                || width != 32
                || address.base != Some(0)
                || address.index.is_some()
                || address.displacement != 12
            {
                return Err("post caller unproved store".into());
            }
            Ok(Some(format!(
                "post.store_scope(frame,cpu,v,{},{})?;",
                store.1, store.2
            )))
        },
    )?;
    if !seen {
        return Err("post caller transfer not emitted".into());
    }
    let raw = input.code;
    let table = input.table;
    let origin = input.origin;
    let table_va = input.table_va;
    let expected_level = global.1;
    Ok(format!(
        r#"fn {name}(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,post:&mut CrtOwnedPostUnwind<'_>)->RegistryResult<CrtValue>{{let result=(||{{post.validate(frame,cpu)?;if frame.scope_address()!={table_va}||frame.storage.image.try_level!={expected_level}||cpu.r[7]!=CrtValue::scalar({expected_level}i32 as u32){{return Err("post caller proof entry differs");}}if post.stored{{return Err("post caller already executed");}}for(base,bytes)in [({origin}u32,&{raw:?}[..]),({table_va}u32,&{table:?}[..])]{{let p=frame.rt.resolve_absolute(base,CrtRegionKind::Module)?;for(i,b)in bytes.iter().enumerate(){{if frame.rt.load(frame.rt.offset(p,i as i64)?,8)?.known_scalar()?!=*b as u32{{return Err("post caller code/table changed");}}}}}}{body}}})();if result.is_err(){{frame.failed=true;}}result}}"#
    ))
}

/// Original nonreturning bridge up to its checked indirect jump. The receipt
/// retains its live CALL slot; it cannot restore Machine or abandon that slot.
pub(crate) fn emit_selected(
    code: &[u8],
    origin: u32,
    notification: &[u8],
    notify: u32,
    binding: super::unwind_bridges::NotificationBinding,
) -> Result<String, String> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    let n = super::unwind_bridges::prove_notification(notification, notify, binding)?;
    super::unwind_bridges::prove_selected(code, origin, notify, &n)?;
    let instructions: Vec<_> = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE)
        .into_iter()
        .collect();
    let call = instructions
        .iter()
        .find(|i| i.mnemonic() == Mnemonic::Call)
        .ok_or("selected call missing")?;
    let jump = instructions.last().ok_or("selected jump missing")?;
    let a = (call.ip() as u32 - origin) as usize;
    let b = (call.next_ip() as u32 - origin) as usize;
    let c = (jump.ip() as u32 - origin) as usize;
    let prefix = crt_stream_emit::emit_linear_fragment(
        &super::crt_stream_ir::Graph::decode_linear_fragment(&code[..a], origin)?,
        &BTreeMap::new(),
    )?;
    let tail = crt_stream_emit::emit_linear_fragment(
        &super::crt_stream_ir::Graph::decode_linear_fragment(&code[b..c], call.next_ip() as u32)?,
        &BTreeMap::new(),
    )?;
    let continuation = call.next_ip() as u32;
    Ok(format!(
        r#"
struct CrtSelectedJump{{ticket:u64,slot:CrtPointer,id:u64,owner:CrtPointer,landing:CrtPointer,anchor:guest_memory::Capability,event:u64,source:RegistrationId,entry:[CrtValue;8],caller:u64}}
fn selected_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{prefix}}}
fn selected_tail(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{tail}}}
fn owned_selected_bridge(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu)->RegistryResult<CrtSelectedJump>{{let result=(||{{
 frame.validate()?;cpu.validate_active(frame.rt)?;
 let(ticket,landing,caller,caller_sp)=frame.storage.selected_cut.ok_or("selected missing single-use caller cut")?;
 let owner=frame.owner_frame()?;let target=frame.rt.resolve_absolute(landing,CrtRegionKind::Module)?;
 if cpu.return_id!=caller||cpu.r[4]!=CrtValue::Pointer(caller_sp)||frame.storage.image.try_level!= -2||frame.registry.target_ready()?!=frame.storage.id||frame.machine.current!=frame.machine.selected||cpu.return_id!=frame.active||cpu.r[1]!=CrtValue::scalar(landing)||cpu.r[2]!=CrtValue::Pointer(owner){{return Err("selected live caller identity");}}
 let p=frame.rt.resolve_absolute({origin},CrtRegionKind::Module)?;for(i,b)in {code:?}.into_iter().enumerate(){{if frame.rt.load(frame.rt.offset(p,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("selected original code changed");}}}}
 let sp=CrtCpu::pointer(cpu.r[4])?;let low=frame.rt.offset(sp,-64)?;frame.rt.valid(low,64)?;frame.registry.range(low.address(),u64::from(sp.address()))?;
 if sp.cap!=frame.storage.entry.cap||sp.address()>=frame.storage.image.esp||frame.rt.overlapping_tags(low.address(),64).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){{return Err("selected occupied scratch");}}
 let id=frame.rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("selected call identity exhausted")?;frame.rt.generation=id;let id=id|(1u64<<63);
 if frame.rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){{return Err("selected call identity collision");}}
 frame.storage.selected_cut=None;frame.storage.selected_jump=Some(id);cpu.push(frame.rt,CrtValue::ProtectedReturn(id))?;let slot=CrtCpu::pointer(cpu.r[4])?;
 selected_prefix(frame.rt,cpu)?;
 // Original CALL executes with its actual child stack and RET 4 cleanup.
 frame.call_pop(cpu,{continuation},4,|f,k|selected_notify_child(f,k,target))?;
 selected_tail(frame.rt,cpu)?;
 if cpu.r[4]!=CrtValue::Pointer(slot)||cpu.r[5]!=CrtValue::Pointer(owner)||cpu.r[6]!=CrtValue::scalar(landing)||frame.rt.load(slot,32)?!=CrtValue::ProtectedReturn(id){{return Err("selected jump state changed");}}
 Ok(CrtSelectedJump{{ticket,slot,id,owner,landing:target,anchor:frame.rt.anchor,event:frame.machine.event,source:frame.storage.id,entry:cpu.entry,caller:cpu.return_id}})
 }})();if result.is_err(){{frame.failed=true;}}result}}
"#
    ))
}

/// Bind the original first landing instruction. Further context stores and
/// continuation activation remain a separate owned transition.
pub(crate) fn emit_landing_pivot(code: &[u8], origin: u32) -> Result<String, String> {
    let graph = super::crt_stream_ir::Graph::decode_linear_fragment(code, origin)?;
    // Only the proven saved-ESP pivot; no supplied register snapshot can replace it.
    if code != [0x8b, 0x65, 0xe8] {
        return Err("landing requires original full-word saved ESP load".into());
    }
    let body = crt_stream_emit::emit_linear_fragment(&graph, &BTreeMap::new())?;
    Ok(format!(
        r#"
fn landing_pivot_instruction(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{body}}}
fn owned_landing_pivot(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,jump:CrtSelectedJump)->RegistryResult<()>{{let result=(||{{
 frame.validate()?;
 let entry=CrtCpu::pointer(jump.entry[4])?;let owner=frame.owner_frame()?;
 if jump.anchor!=frame.rt.anchor||jump.event!=frame.machine.event||jump.source!=frame.storage.id||frame.storage.selected_jump!=Some(jump.id)||frame.registry.target_ready()?!=jump.source||frame.machine.current!=frame.machine.selected||jump.owner!=owner||jump.landing.address()!={origin}||cpu.entry!=jump.entry||cpu.return_id!=jump.caller||frame.active!=jump.caller||cpu.returned||cpu.r[4]!=CrtValue::Pointer(jump.slot)||cpu.r[5]!=CrtValue::Pointer(owner)||cpu.r[6]!=CrtValue::scalar({origin}){{return Err("landing stale jump/activation");}}
 if frame.storage.pair_return!=Some((entry,jump.caller))||entry.cap!=jump.slot.cap||entry.address().checked_add(20).is_none_or(|n|n>frame.storage.image.esp)||jump.slot.address()>=entry.address(){{return Err("landing abandoned stack identity");}}
 let saved=frame.rt.offset(owner,-24)?;let key=i32::try_from(i64::from(saved.address())-i64::from(frame.storage.entry.address())).map_err(|_|"landing saved ESP offset")?;
 let expected=frame.rt.resolve_absolute(frame.storage.image.esp,CrtRegionKind::Stack)?;
 if frame.storage.image.words.get(&key)!=Some(&FrameWord::StackAddress(expected.address()))||frame.storage.protected.get(&key)!=Some(&CrtValue::Pointer(expected))||frame.rt.load(saved,32)?!=CrtValue::Pointer(expected){{return Err("landing saved ESP provenance");}}
 let p=frame.rt.resolve_absolute({origin},CrtRegionKind::Module)?;for(i,b)in {code:?}.into_iter().enumerate(){{if frame.rt.load(frame.rt.offset(p,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("landing original pivot changed");}}}}
 let mut allowed=std::collections::BTreeMap::from([(jump.slot.address(),CrtValue::ProtectedReturn(jump.id)),(entry.address(),CrtValue::ProtectedReturn(jump.caller))]);
 for(offset,reg)in [(-4,5),(-36,3),(-40,6),(-44,7)]{{let p=frame.rt.offset(entry,offset)?;let v=jump.entry[reg];if frame.rt.load(p,32)?!=v{{return Err("landing handler saved slot changed");}}allowed.insert(p.address(),v);}}
 for(id,at)in [(jump.id,jump.slot.address()),(jump.caller,entry.address())]{{if frame.rt.tags.iter().filter(|(_,v)|**v==CrtValue::ProtectedReturn(id)).map(|(p,_)|*p).collect::<Vec<_>>()!=vec![at]{{return Err("landing return alias");}}}}
 let n=expected.address().checked_sub(jump.slot.address()).ok_or("landing stack direction")?;frame.rt.valid(jump.slot,n)?;frame.registry.range(jump.slot.address(),u64::from(expected.address()))?;
 for(at,v)in frame.rt.overlapping_tags(jump.slot.address(),n){{if matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))&&allowed.get(&at)!=Some(&v){{return Err("landing unowned abandoned control slot");}}}}
 let pair_slot=frame.rt.offset(owner,-20)?;
 // Successful delivery callbacks may leave inert bytes below this selected
 // activation. Only a non-stack or still-live Main-frame alias can outlive
 // the pivot; the exception-pair field is explicitly stripped below.
 for(&at,&v)in &frame.rt.tags{{if matches!(v,CrtValue::Pointer(p) if p.cap==jump.slot.cap&&p.address()>=jump.slot.address()&&p.address()<expected.address())&&at!=pair_slot.address(){{let inert_lower_stack=frame.rt.regions.iter().any(|r|r.pointer.cap==jump.slot.cap&&at>=r.pointer.base&&u64::from(at)<u64::from(r.pointer.base)+u64::from(r.pointer.size)&&at<jump.slot.address());if !inert_lower_stack{{return Err("landing escaped abandoned pointer");}}}}}}
 // All fallible ownership, bytes and range checks precede retirement. The
 // immediately executed MOV reads only the already-protected saved-ESP word.
 frame.rt.memory.forget(jump.slot.address(),n).map_err(|_|"landing retirement range")?;
 frame.rt.tags.retain(|at,_|*at<jump.slot.address()||*at>=expected.address());frame.rt.partial.retain(|at,_|*at<jump.slot.address()||*at>=expected.address());
 // The original frame's exception-pair field keeps its numeric bytes, but
 // its ended handler borrow cannot retain dereference authority.
 frame.rt.tags.remove(&pair_slot.address());
 frame.storage.input=None;frame.storage.pair_return=None;frame.storage.selected_jump=None;
 landing_pivot_instruction(frame.rt,cpu)?;
 if cpu.r[4]!=CrtValue::Pointer(expected){{return Err("landing pivot result");}}frame.validate()?;Ok(())
 }})();if result.is_err(){{frame.failed=true;}}result}}
"#
    ))
}
