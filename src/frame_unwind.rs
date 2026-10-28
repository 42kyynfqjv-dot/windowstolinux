//! Composition of original instruction fragments at explicit live-frame cuts.
//! This API is deliberately separate from PE admission: unknown calls between
//! cuts, incoming Windows dispatch, and the path to manual Restore remain open.
use super::{
    cleanup, dispatch, frame_proof, funclet, handler_bridge, restore_body, selection, Proven,
};
use iced_x86::{Decoder, DecoderOptions, Register};
use std::collections::{BTreeMap, BTreeSet};

pub struct Region {
    pub va: u32,
    pub bytes: Vec<u8>,
}
pub struct Frame {
    pub prefix: Region,
    pub table: Region,
    pub activation: Option<Region>,
}
pub struct Input {
    pub cookie_va: u32,
    pub handler_va: u32,
    pub frames: Vec<Frame>,
    pub filters: Vec<Region>,
    pub landings: Vec<Region>,
    pub funclets: Vec<Region>,
    pub cleanups: Vec<Region>,
    pub dispatcher: Region,
    pub dispatch_table: Region,
    pub trace_va: u32,
    pub globals: Vec<u32>,
    pub normalizer: Region,
    pub feature_va: u32,
    pub installer: Region,
    pub restore: Region,
    pub target: Region,
    pub event_code: u32,
}

fn ranges(input: &Input) -> Result<(), String> {
    let mut ranges = Vec::new();
    let mut add = |va: u32, size: usize| -> Result<(), String> {
        let end = va
            .checked_add(u32::try_from(size).map_err(|_| "fragment size")?)
            .ok_or("fragment range overflow")?;
        if va == 0 || size == 0 || size > 8192 || ranges.iter().any(|&(a, b)| va < b && a < end) {
            return Err("fragment overlapping/empty/oversized regions".into());
        }
        ranges.push((va, end));
        Ok(())
    };
    for f in &input.frames {
        add(f.prefix.va, f.prefix.bytes.len())?;
        add(f.table.va, f.table.bytes.len())?;
        if let Some(a) = &f.activation {
            add(a.va, a.bytes.len())?;
        }
    }
    for region in input
        .filters
        .iter()
        .chain(&input.landings)
        .chain(&input.funclets)
        .chain(&input.cleanups)
        .chain([
            &input.dispatcher,
            &input.dispatch_table,
            &input.normalizer,
            &input.installer,
            &input.restore,
            &input.target,
        ])
    {
        add(region.va, region.bytes.len())?;
    }
    for &va in input
        .globals
        .iter()
        .chain([&input.cookie_va, &input.trace_va, &input.feature_va])
    {
        if va % 4 != 0 {
            return Err("fragment unaligned scalar binding".into());
        }
        add(va, 4)?;
    }
    Ok(())
}

/// Emit only an explicitly labelled fragment composition. No selected frame,
/// cursor, local initialization or EH4 level is accepted as a caller assertion.
/// Original code derives those values. A noncontiguous activation is retained
/// as a cut and cannot be promoted to a continuous original-entry certificate.
pub fn prove_fragments(input: &Input) -> Result<Proven, String> {
    if input.frames.is_empty()
        || input.frames.len() > 8
        || input.cleanups.is_empty()
        || input.cleanups.len() > 32
        || input.funclets.len() > 32
        || input.filters.len() > 32
        || input.landings.len() > 32
        || input.globals.len() > 32
    {
        return Err("fragment composition budget".into());
    }
    ranges(input)?;
    let scopes = input.frames.iter().map(|f| f.table.va).collect();
    let handlers = BTreeSet::from([input.handler_va]);
    let mut frames = Vec::new();
    let mut activations = Vec::new();
    let mut tables = Vec::new();
    let mut layouts = Vec::new();
    let mut functions = String::new();
    let mut evidence =
        vec!["// Original instruction-fragment composition; NOT whole-PE admission.".to_string()];
    let mut initialize = String::new();
    let mut levels = Vec::new();
    let targets = input
        .filters
        .iter()
        .chain(&input.funclets)
        .chain(&input.landings)
        .map(|r| r.va)
        .collect();
    // Handler landing points are not executed here. Their full image-bound
    // provenance is checked by the evidence harness, not inferred from a row.
    for landing in &input.landings {
        let mut decoder = Decoder::with_ip(
            32,
            &landing.bytes,
            u64::from(landing.va),
            DecoderOptions::NONE,
        );
        if !decoder.can_decode() || decoder.decode().is_invalid() {
            return Err("fragment landing boundary".into());
        }
    }
    for (index, f) in input.frames.iter().enumerate() {
        let proof = frame_proof::prove_frame(
            &f.prefix.bytes,
            f.prefix.va,
            input.cookie_va,
            &scopes,
            &handlers,
        )?;
        if proof.scope_va() != f.table.va
            || proof.handler_va() != input.handler_va
            || proof.record_offset() != -16
            || proof.try_level_offset() != -4
        {
            return Err("fragment registration/frame-base relation".into());
        }
        let table = selection::parse_eh4(&f.table.bytes, &targets)?;
        proof.validate_eh4_header(table.cookie_header())?;
        if !proof.ordinary_words().contains(&-20) {
            return Err("fragment missing owned exception-pointers word".into());
        }
        let activation = f
            .activation
            .as_ref()
            .map(|a| proof.prove_initializer_fragment(&a.bytes, a.va))
            .transpose()?;
        if activation.as_ref().is_some_and(|a| {
            a.writes()
                .keys()
                .any(|&offset| offset != proof.try_level_offset())
        }) {
            return Err("fragment activation changes dependent scalar state".into());
        }
        let level = activation
            .as_ref()
            .and_then(|a| a.try_level())
            .unwrap_or(proof.try_level());
        evidence.push(format!("// Frame {index}: original prefix {:#x}..{:#x}, EBP offset {}, guards {:?}, saved slots {:?}.",f.prefix.va,proof.end(),proof.ebp_offset(),proof.guard_offsets(),proof.saved_slots()));
        if let Some(a) = &activation {
            evidence.push(format!("// Separate initializer {:#x}..{:#x}; UNPROVED intervening gap {:?}. Same-live-frame preservation is a cut premise.",a.entry(),a.end(),a.gap()));
        }
        let mut temporaries = BTreeSet::new();
        for row in f.table.bytes[16..].as_chunks::<12>().0 {
            let va = u32::from_le_bytes(row[4..8].try_into().unwrap());
            if va == 0 {
                continue;
            }
            let code = input
                .filters
                .iter()
                .find(|r| r.va == va)
                .ok_or("fragment filter bytes missing")?;
            let mut decoder =
                Decoder::with_ip(32, &code.bytes, u64::from(va), DecoderOptions::NONE);
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    return Err("fragment malformed filter".into());
                }
                if instruction.memory_base() == Register::EBP {
                    let offset = instruction.memory_displacement32() as i32;
                    if offset != -20 {
                        if !proof.ordinary_words().contains(&offset)
                            || proof.scalar_words().contains_key(&offset)
                        {
                            return Err(
                                "fragment filter temporary aliases initialized or protected state"
                                    .into(),
                            );
                        }
                        temporaries.insert(offset);
                    }
                }
            }
        }
        let layout = selection::FilterLayout {
            start: proof.esp_offset(),
            end: 0,
            exception_pointers_offset: -20,
            writable_words: temporaries.into_iter().collect(),
        };
        functions.push_str(&format!("fn frame_{index}<P:Clone>(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:P)->Result<FrameImage<P>,&'static str>{{ {} }}\n",proof.initializer_body()));
        if let Some(a) = &activation {
            functions.push_str(&format!("fn activate_{index}<P>(image:&mut FrameImage<P>)->Result<(),&'static str>{{ {} }}\n",a.body()));
        }
        initialize.push_str(&format!("let mut entry_registers=[None;8];entry_registers[4]=Some(next_sp);entry_registers[5]=caller_ebp;let mut image=frame_{index}(next_sp,cookie,entry_registers,predecessor.clone())?;\n"));
        if activation.is_some() {
            initialize.push_str(&format!("activate_{index}(&mut image)?;\n"));
        }
        initialize.push_str(&format!("if image.try_level!={level} {{return Err(\"derived EH4 level\");}}\npredecessor=Predecessor::Frame{{owner,index:{index}}};caller_ebp=Some(image.ebp);next_sp=image.esp.checked_sub(4).ok_or(\"nested stack address\")?;images.push(image);\n"));
        frames.push(proof);
        activations.push(activation);
        tables.push(table);
        layouts.push(layout);
        levels.push(level);
    }
    let args = frames.last().unwrap().pending_arguments();
    if args != [input.event_code, 0, 0, 0] {
        return Err("fragment event arguments not instruction-derived RaiseException cut".into());
    }
    let selection_inputs: Vec<_> = frames
        .iter()
        .enumerate()
        .map(|(i, _)| selection::FrameSelection {
            table: &tables[i],
            try_level: levels[i],
            layout: &layouts[i],
        })
        .collect();
    let filters = input
        .filters
        .iter()
        .map(|r| {
            (
                r.va,
                selection::OriginalFilter {
                    origin: r.va,
                    bytes: &r.bytes,
                },
            )
        })
        .collect();
    let selected = selection::select_frames(&selection_inputs, &filters, input.event_code)?;
    evidence.push(format!("// Filter-derived selected frame {}, EH4 scope {}, landing {:#x}; landing instructions are not executed.",selected.selected_frame(),selected.selected_scope(),selected.target()));

    // Each filter body is decoded, not an expected-result stencil. The installed
    // pair and pre-filter normalization contracts are composed below.
    let normalizer = selection::prove_code_identity(
        &input.normalizer.bytes,
        input.normalizer.va,
        &BTreeSet::from([input.feature_va]),
        input.event_code,
    )?;
    functions.push_str(&format!(
        "fn normalize(code:u32,_feature:i32)->Result<u32,&'static str>{{ {} }}\n",
        normalizer.body()
    ));
    evidence.push(format!("// Event normalizer: {} proved return paths over unknown initialized feature word; cookie/context helpers remain unproved.",normalizer.proved_return_paths()));
    let mut filter_runs = String::new();
    for (index, step) in selected.filters().iter().enumerate() {
        let frame = step.frame;
        let installer = handler_bridge::prove_installer(
            &input.installer.bytes,
            input.installer.va,
            &handler_bridge::InstallerLayout {
                handler_start: -28,
                handler_end: 0,
                owner_start: frames[frame].esp_offset(),
                owner_end: 0,
                writable_handler_words: vec![-28, -24],
                writable_owner_words: vec![-20],
            },
        )?;
        evidence.push(format!("// Filter frame {}, scope {}; pointer installer ends {:#x}, handler pair {}, owner slot {}. Earlier handler calls are an explicit cut.",frame,step.scope,installer.end(),installer.handler_pair_offset(),installer.owner_pair_offset()));
        functions.push_str(&format!("fn install_{index}<E,C>(state:&mut BridgeMemory<E,C>)->Result<InstalledPair<'_,E,C>,&'static str>{{ {} }}\n",installer.body()));
        functions.push_str(&format!("fn filter_{index}(code:u32,words:&mut[Option<u32>])->Result<i32,&'static str>{{ {} }}\n",step.proof.body()));
        let offsets = &layouts[frame].writable_words;
        filter_runs.push_str(&format!(r#"
{{
 let image=&mut images[{frame}];
 let bp=i32::try_from(i64::from(image.ebp)-i64::from(image.entry_sp)).map_err(|_|"filter frame base")?;
 if !matches!(image.words.get(&(bp-20)),Some(FrameWord::Unknown|FrameWord::Scalar(_))) {{return Err("filter owner slot");}}
 let mut bridge=BridgeMemory::new((owner,{frame}usize,event_code),(owner,{frame}usize,current),std::collections::BTreeMap::from([(-28,BridgeWord::Vacant),(-24,BridgeWord::Vacant)]),std::collections::BTreeMap::from([(-20,BridgeWord::Vacant)]))?;
 let identity=bridge.identity();
 let pair=install_{index}(&mut bridge)?;
 let &(event_owner,event_frame,code)=pair.record(identity)?;
 let &(context_owner,context_frame,_)=pair.context(identity)?;
 if event_owner!=owner||context_owner!=owner||event_frame!={frame}||context_frame!={frame} {{return Err("filter event/frame identity");}}
 let slots={offsets:?};
 let mut temporaries=Vec::new();
 for offset in slots {{temporaries.push(match image.words.get(&(bp+offset)){{Some(FrameWord::Unknown)=>None,Some(FrameWord::Scalar(value))=>Some(*value),_=>return Err("filter temporary ownership")}});}}
 if filter_{index}(code,&mut temporaries)?!={result} {{return Err("filter runtime/proof disagreement");}}
 for (offset,value) in slots.into_iter().zip(temporaries) {{if let Some(value)=value{{image.words.insert(bp+offset,FrameWord::Scalar(value));}}}}
 bridge.invalidate();
}}
"#,result=step.proof.result()));
    }

    let mut cleanup_bindings = BTreeMap::new();
    for (index, region) in input.cleanups.iter().enumerate() {
        if cleanup_bindings.insert(region.va, index).is_some() {
            return Err("duplicate cleanup".into());
        }
        functions.push_str(&format!(
            "fn cleanup_{index}(cells:&mut[u32;2])->Result<(),Error>{{ {} }}\n",
            cleanup::prove_cleanup(&region.bytes, region.va)?
        ));
    }
    if input.dispatch_table.bytes.is_empty()
        || !input.dispatch_table.bytes.len().is_multiple_of(8)
        || input.dispatch_table.bytes.len() > 256
    {
        return Err("fragment custom table extent".into());
    }
    let rows: Vec<_> = input
        .dispatch_table
        .bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|r| {
            (
                i32::from_le_bytes(r[..4].try_into().unwrap()),
                u32::from_le_bytes(r[4..].try_into().unwrap()),
            )
        })
        .collect();
    for (index, &(parent, target)) in rows.iter().enumerate() {
        if parent < -1 || parent >= rows.len() as i32 || !cleanup_bindings.contains_key(&target) {
            return Err("fragment custom table binding".into());
        }
        let mut at = index as i32;
        let mut seen = BTreeSet::new();
        while at != -1 {
            if !seen.insert(at) {
                return Err("fragment custom table cycle".into());
            }
            at = rows[at as usize].0;
            if at < -1 || at >= rows.len() as i32 {
                return Err("fragment custom parent".into());
            }
        }
        let proof = dispatch::prove_dispatch(
            &input.dispatcher.bytes,
            input.dispatcher.va,
            input.dispatch_table.va,
            &rows,
            input.trace_va,
            &cleanup_bindings,
            index as i32,
        )?;
        if proof.parent != parent || proof.action != cleanup_bindings[&target] {
            return Err("fragment dispatcher effect mismatch".into());
        }
        functions.push_str(&format!(
            "fn dispatch_{index}(cells:&mut[u32;2],cursor:&mut i32)->Result<(),Error>{{ {} }}\n",
            proof.source
        ));
    }
    let globals: BTreeMap<_, _> = input
        .globals
        .iter()
        .enumerate()
        .map(|(i, &va)| (va, i))
        .collect();
    let funclets: BTreeMap<_, _> = input.funclets.iter().map(|r| (r.va, r)).collect();
    let mut known_cursors = BTreeMap::new();
    let mut cursor_slots = vec![None; frames.len()];
    let mut specs: Vec<Vec<String>> = vec![Vec::new(); frames.len()];
    let mut arms = String::new();
    let offsets: Vec<Vec<i32>> = frames
        .iter()
        .map(|f| {
            f.ordinary_words()
                .iter()
                .copied()
                .filter(|&o| o != -20)
                .collect()
        })
        .collect();
    for (action, &(frame, scope, va)) in selected.cleanups().iter().enumerate() {
        let original = funclets
            .get(&va)
            .ok_or("fragment missing complete finally instructions")?;
        let proof = funclet::prove_funclet(
            &original.bytes,
            va,
            input.dispatcher.va,
            frames[frame].scalar_words(),
            &globals,
        )?;
        evidence.push(format!("// Cleanup action {action}: original funclet {va:#x}, complete post-call global writes {:?}.",proof.global_writes));
        let cursor = *known_cursors
            .entry((frame, proof.cursor_offset))
            .or_insert(frames[frame].scalar_words()[&proof.cursor_offset] as i32);
        let row = usize::try_from(cursor)
            .ok()
            .and_then(|i| rows.get(i))
            .ok_or("fragment custom cursor outside initialized table")?;
        known_cursors.insert((frame, proof.cursor_offset), row.0);
        let local = offsets[frame]
            .iter()
            .position(|&o| o == proof.local_offset)
            .ok_or("fragment local mapping")?;
        let cursor_slot = offsets[frame]
            .iter()
            .position(|&o| o == proof.cursor_offset)
            .ok_or("fragment cursor mapping")?;
        if cursor_slots[frame].is_some_and(|s| s != cursor_slot) {
            return Err("fragment conflicting cursor owners".into());
        }
        cursor_slots[frame] = Some(cursor_slot);
        functions.push_str(&format!("fn funclet_{action}(cells:&mut[u32;2],cursor:&mut i32,globals:&mut[Option<u32>],dispatch:impl FnOnce(&mut[u32;2],&mut i32)->Result<(),Error>)->Result<(),Error>{{ {} }}\n",proof.source));
        specs[frame].push(format!("Scope{{scope:{scope},action:{action}}}"));
        arms.push_str(&format!("{action}=>{{let mut cells=[view.read_trace()?,view.read_word({})?];let mut cursor=view.read_word({})? as i32;funclet_{action}(&mut cells,&mut cursor,&mut globals,dispatch_{cursor})?;view.write_trace(cells[0])?;view.write_word({},cells[1])?;view.write_word({},cursor as u32)?;}},\n",local*4,cursor_slot*4,local*4,cursor_slot*4));
    }
    let mut decode = Decoder::with_ip(
        32,
        &input.target.bytes,
        u64::from(input.target.va),
        DecoderOptions::NONE,
    );
    if !decode.can_decode() || decode.decode().is_invalid() {
        return Err("fragment restore target boundary".into());
    }
    let restore = restore_body(&input.restore.bytes, input.restore.va)?;
    let selected_frame = selected.selected_frame();
    let selected_target = selected.target();
    let target = input.target.va;
    let specs = specs
        .iter()
        .map(|s| format!("FrameSpec{{scopes:vec![{}]}}", s.join(",")))
        .collect::<Vec<_>>()
        .join(",");
    let offsets_literal = format!(
        "vec![{}]",
        offsets
            .iter()
            .map(|o| format!("vec!{o:?}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let cursors_literal = format!("vec!{cursor_slots:?}");
    let runtime = include_str!("linker/unwind_runtime.rs");
    let types = frame_proof::EMITTED_TYPES;
    let bridge_types = handler_bridge::EMITTED_TYPES;
    let event = input.event_code;
    let global_count = input.globals.len();
    let evidence = evidence.join("\n");
    let source = format!(
        r#"
{evidence}
#[allow(dead_code)]
mod composed {{
{runtime}
{types}
{bridge_types}
{functions}
#[derive(Clone,Debug,PartialEq,Eq)]
enum Predecessor {{ Borrowed{{owner:u64}},Frame{{owner:u64,index:usize}} }}
#[derive(Debug,PartialEq,Eq)]
pub struct Outcome {{pub trace:u32,pub frame_words:Vec<Vec<Option<u32>>>,pub offsets:Vec<Vec<i32>>,pub globals:Vec<Option<u32>>,pub cursors:Vec<Option<i32>>,pub live:Vec<bool>,pub restored:[Option<u32>;10],pub selected_frame:usize,pub selected_target:u32}}
pub fn run_fragments(entry_sp:u32,cookie:u32,saved:[u32;10],current:[u32;10],feature:i32,initial_trace:u32)->Result<Outcome,&'static str>{{
 if saved[8]!={target} || current[9]&!0x8d5!=0x202 {{return Err("fragment context boundary");}}
 let owner=OWNERS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|"fragment identity exhaustion")?;
 let mut predecessor=Predecessor::Borrowed{{owner}};
 let mut next_sp=entry_sp;let mut images=Vec::new();let mut caller_ebp=None;
 {initialize}
 let event_code=normalize({event}u32,feature)?;
 {filter_runs}
 let offsets:Vec<Vec<i32>>={offsets_literal};
 let cursor_slots:Vec<Option<usize>>={cursors_literal};
 let mut inputs=Vec::new();
 for (i,image) in images.iter().enumerate() {{
  let mut cells=Vec::new();
  let bp=i64::from(image.ebp)-i64::from(image.entry_sp);
  for &offset in &offsets[i] {{
   let key=i32::try_from(bp+i64::from(offset)).map_err(|_|"frame word offset")?;
   cells.push(match image.words.get(&key) {{Some(FrameWord::Scalar(value))=>Some(*value),Some(FrameWord::Unknown)=>None,_=>return Err("frame scalar ownership")}});
  }}
  inputs.push(FrameInput{{cells,context:if i=={selected_frame}{{saved}}else{{current}}}});
 }}
 let mut machine=Machine::new(vec![{specs}],inputs,{selected_frame},Some(initial_trace)).map_err(|_|"fragment ownership")?;
 machine.context=current;
 let mut globals=vec![None;{global_count}];
 while let Some(request)=machine.next_cleanup().map_err(|_|"fragment cleanup phase")? {{
  let action=request.action();
  machine.execute_cleanup(request,|view|{{match action {{{arms}_=>return Err(Error::Order)}} Ok(())}}).map_err(|_|"fragment complete cleanup receipt")?;
 }}
 let context=machine.restore({target},|view,context|{{{restore}}}).map_err(|_|"fragment restoration")?;
 let mut restored=context.map(Some);restored[1]=None;restored[2]=None;restored[9]=None;
 let cursors=machine.frames.iter().zip(cursor_slots).map(|(f,s)|s.and_then(|s|f.cells[s]).map(|v|v as i32)).collect();
 Ok(Outcome{{trace:machine.trace.ok_or("unknown trace")?,frame_words:machine.frames.iter().map(|f|f.cells.clone()).collect(),offsets,globals,cursors,live:machine.frames.iter().map(|f|f.live).collect(),restored,selected_frame:{selected_frame},selected_target:{selected_target}}})
}}
}}
pub use composed::{{run_fragments,Outcome}};
"#
    );
    Ok(Proven { source })
}

#[cfg(test)]
#[path = "frame_unwind_tests.rs"]
mod tests;
