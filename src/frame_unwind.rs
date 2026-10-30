//! Composition of original instruction fragments at explicit live-frame cuts.
//! This API is deliberately separate from PE admission: unknown calls between
//! cuts, incoming Windows dispatch, and the path to manual Restore remain open.
use super::{
    cleanup, dispatch, frame_init, frame_landing, frame_memory, frame_proof, funclet,
    handler_bridge, handler_checks, handler_context, handler_guard, restore_body, selection,
    Proven,
};
use iced_x86::{Code, Decoder, DecoderOptions, Register};
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
    pub calls: Vec<Region>,
    pub raise_exception_iat: u32,
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

/// Additional original regions needed to remove the initializer and supplied
/// saved-context cuts. This is still a bounded exception-delivery composition,
/// never an ordinary PE entry or loader certificate.
pub struct Connected {
    pub initializer: Region,
    pub fill_helper: Region,
    pub fill_features: [u32; 2],
    pub module_iat: u32,
    pub module_base: u32,
    pub module_size: u32,
    pub selected_landing: Region,
    pub handler_prefix: Region,
    pub guard_helper: Region,
    pub security_helper: Region,
    pub context_helper: Region,
    pub context_selector: u32,
}

/// Reporting and normal function return at an explicit initialized CRT-state
/// boundary. The linked formatter and process startup are not certified here.
pub struct Reported {
    pub completion: Region,
    pub printf_wrapper: Region,
    pub iob_accessor: Region,
    pub options_accessor: Region,
    pub formatter: u32,
    pub format: Region,
    /// Addresses only. Runtime scalar contents must be explicitly supplied.
    pub entry_globals: Vec<u32>,
}

fn ranges(input: &Input) -> Result<Vec<(u32, u32)>, String> {
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
        .chain(&input.calls)
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
        .chain([&input.raise_exception_iat])
    {
        if va % 4 != 0 {
            return Err("fragment unaligned scalar binding".into());
        }
        add(va, 4)?;
    }
    Ok(ranges)
}

/// Emit only an explicitly labelled fragment composition. No selected frame,
/// cursor, local initialization or EH4 level is accepted as a caller assertion.
/// Original code derives those values. A noncontiguous activation is retained
/// as a cut and cannot be promoted to a continuous original-entry certificate.
pub fn prove_fragments(input: &Input) -> Result<Proven, String> {
    prove_composition(input, None, None, false, None)
}

pub fn prove_connected(input: &Input, connected: &Connected) -> Result<Proven, String> {
    prove_composition(input, Some(connected), None, false, None)
}

pub use super::dispatch_contract::Dispatch;

/// Original handler/local-unwind composition, still separate from PE admission.
pub fn prove_dispatched(
    input: &Input,
    connected: &Connected,
    dispatch: &Dispatch,
) -> Result<Proven, String> {
    prove_composition(input, Some(connected), Some(dispatch), false, None)
}

/// Execute the original software-exception call in a closed, same-thread
/// delivery domain. Captured Windows registers remain opaque; the original
/// selected landing constructs a distinct restoration context. This is an
/// invocation component, not authority to skip process startup or admit a PE.
pub fn prove_raised(
    input: &Input,
    connected: &Connected,
    dispatch: &Dispatch,
) -> Result<Proven, String> {
    prove_composition(input, Some(connected), Some(dispatch), true, None)
}

pub fn prove_reported(
    input: &Input,
    connected: &Connected,
    dispatch: &Dispatch,
    reported: &Reported,
) -> Result<Proven, String> {
    prove_composition(input, Some(connected), Some(dispatch), true, Some(reported))
}

fn prove_composition(
    input: &Input,
    connected: Option<&Connected>,
    dispatch_input: Option<&Dispatch>,
    raised: bool,
    reported: Option<&Reported>,
) -> Result<Proven, String> {
    if input.frames.is_empty()
        || input.frames.len() > 8
        || input.calls.len() != input.frames.len()
        || input.cleanups.is_empty()
        || input.cleanups.len() > 32
        || input.funclets.len() > 32
        || input.filters.len() > 32
        || input.landings.len() > 32
        || input.globals.len() > 32
    {
        return Err("fragment composition budget".into());
    }
    let mut bound_ranges = ranges(input)?;
    if let Some(extra) = connected {
        if extra.module_base == 0
            || extra.module_base % 4096 != 0
            || extra.module_size == 0
            || extra.module_size > 512 * 1024 * 1024
            || extra.module_base.checked_add(extra.module_size).is_none()
        {
            return Err("connected module base identity".into());
        }
        for (va, size) in [
            (extra.initializer.va, extra.initializer.bytes.len()),
            (extra.fill_helper.va, extra.fill_helper.bytes.len()),
            (extra.module_iat, 4),
            (extra.fill_features[0], 4),
            (extra.fill_features[1], 4),
            (extra.guard_helper.va, extra.guard_helper.bytes.len()),
            (extra.security_helper.va, extra.security_helper.bytes.len()),
            (extra.context_helper.va, extra.context_helper.bytes.len()),
            (extra.context_selector, 4),
        ] {
            let end = va
                .checked_add(u32::try_from(size).map_err(|_| "connected extent")?)
                .ok_or("connected range overflow")?;
            if va == 0 || size == 0 || bound_ranges.iter().any(|&(a, b)| va < b && a < end) {
                return Err("connected overlapping bound regions".into());
            }
            bound_ranges.push((va, end));
        }
        // The longer landing contains the same original landing prefix and
        // target observation bytes already bound by Input. Those subregions
        // must match exactly; all other overlap remains forbidden.
        let start = extra.selected_landing.va;
        let end = start
            .checked_add(extra.selected_landing.bytes.len() as u32)
            .ok_or("connected landing overflow")?;
        for region in input.landings.iter().chain([&input.target]) {
            if region.va >= start
                && region
                    .va
                    .checked_add(region.bytes.len() as u32)
                    .is_some_and(|e| e <= end)
            {
                let at = (region.va - start) as usize;
                if extra.selected_landing.bytes[at..at + region.bytes.len()] != region.bytes {
                    return Err("connected landing byte provenance".into());
                }
            }
        }
        for &(a, b) in &bound_ranges {
            if start < b
                && a < end
                && !input
                    .landings
                    .iter()
                    .chain([&input.target])
                    .any(|r| r.va == a && r.va + r.bytes.len() as u32 == b)
            {
                return Err("connected landing aliases another region".into());
            }
        }
        bound_ranges.push((start, end));
        let prefix_end = extra
            .handler_prefix
            .va
            .checked_add(extra.handler_prefix.bytes.len() as u32)
            .ok_or("connected prefix overflow")?;
        if extra.handler_prefix.va != input.handler_va {
            return Err("connected original handler identity".into());
        }
        let installer = &input.installer;
        if installer.va < extra.handler_prefix.va
            || installer.va.checked_add(installer.bytes.len() as u32) != Some(prefix_end)
            || extra.handler_prefix.bytes[(installer.va - extra.handler_prefix.va) as usize..]
                != installer.bytes
        {
            return Err("connected prefix/installer byte provenance".into());
        }
        for &(a, b) in &bound_ranges {
            if extra.handler_prefix.va < b
                && a < prefix_end
                && !(a == installer.va && b == prefix_end)
            {
                return Err("connected prefix region alias".into());
            }
        }
        bound_ranges.push((extra.handler_prefix.va, prefix_end));
        let end = extra.module_base + extra.module_size;
        if bound_ranges
            .iter()
            .any(|&(a, b)| a < extra.module_base || b > end)
        {
            return Err("connected region outside owned module image".into());
        }
        // Stack ownership excludes the complete module mapping, including gaps
        // and virtual tails, not just bytes accessed by this bounded program.
        bound_ranges.push((extra.module_base, end));
    }
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
    let mut connected_initialization = None;
    let mut handler_temporary_bytes = 0u32;
    let prefix_proof = connected
        .map(|extra| {
            handler_checks::prove_prefix(
                &extra.handler_prefix.bytes,
                extra.handler_prefix.va,
                &handler_checks::Bindings {
                    normalizer_va: input.normalizer.va,
                    guard_va: extra.guard_helper.va,
                    context_va: extra.context_helper.va,
                    cookie_va: input.cookie_va,
                    installer_va: input.installer.va,
                },
            )
        })
        .transpose()?;
    if let Some(prefix) = &prefix_proof {
        prefix.require_search_flags(0)?;
        if prefix.handler_allocation != 28
            || prefix.owner_pair_offset != -20
            || prefix.handler_pair_offset != -28
            || prefix.installer_start != input.installer.va
            || prefix.end != input.installer.va + input.installer.bytes.len() as u32
        {
            return Err("connected handler prefix layout".into());
        }
        evidence.push(format!(
            "// Original handler calls {:?}; flags mask {:#x}, excluded unwind edge {:#x}.",
            prefix.calls, prefix.exception_flags_mask, prefix.exception_flags_branch
        ));
        handler_temporary_bytes = prefix.temporary_bytes;
    }
    let context_proof = connected
        .map(|extra| {
            handler_context::prove_context_check(
                &extra.context_helper.bytes,
                extra.context_helper.va,
                extra.context_selector,
            )
        })
        .transpose()?;
    if let Some(context) = &context_proof {
        if !raised {
            functions.push_str(&format!("impl ThreadContext{{fn check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{ {} }} }}\n",context.body()));
        }
        evidence.push(format!("// Context selector at {:#x} remains runtime unknown; bypass value {:#x}, original failure INT29 code {} excluded by same-thread valid-context entry boundary.",context.selector_va(),context.bypass_selector(),context.failure_code()));
        let call = prefix_proof
            .as_ref()
            .unwrap()
            .calls
            .iter()
            .find(|c| c.effect == handler_checks::CallEffect::ValidateContext)
            .ok_or("connected context call depth")?;
        handler_temporary_bytes = handler_temporary_bytes.max(
            call.entry_depth
                .checked_add(context.temporary_bytes())
                .ok_or("connected context depth")?,
        );
    }
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
        if let Some(extra) = connected {
            let guard = handler_guard::prove_guard(
                &extra.guard_helper.bytes,
                extra.guard_helper.va,
                &extra.security_helper.bytes,
                extra.security_helper.va,
                input.cookie_va,
                table.cookie_header(),
                &proof,
            )?;
            functions.push_str(&format!("fn guard_{index}<P>(memory:&FrameMemory<P>,cookie:u32)->Result<(),&'static str>{{ {} }}\n",guard.body()));
            let call = prefix_proof
                .as_ref()
                .unwrap()
                .calls
                .iter()
                .find(|c| c.effect == handler_checks::CallEffect::ValidateGuards)
                .ok_or("connected guard call depth")?;
            handler_temporary_bytes = handler_temporary_bytes.max(
                call.entry_depth
                    .checked_add(guard.temporary_bytes())
                    .ok_or("connected handler depth")?,
            );
            evidence.push(format!("// Original frame {index} guard offsets {:?}; mismatches excluded before guest effects, original failure target {:#x} retained.",guard.checked_offsets(),guard.failure_target()));
        }
        if !proof.ordinary_words().contains(&-20) {
            return Err("fragment missing owned exception-pointers word".into());
        }
        let activation = f
            .activation
            .as_ref()
            .map(|a| proof.prove_initializer_fragment(&a.bytes, a.va))
            .transpose()?;
        let initialized = if index == 0 {
            connected
                .map(|extra| {
                    if activation.is_some() {
                        return Err(
                            "connected initializer cannot coexist with an asserted activation cut"
                                .into(),
                        );
                    }
                    frame_init::prove_initializer(
                        &proof,
                        &extra.initializer.bytes,
                        extra.initializer.va,
                        &frame_init::FillHelper {
                            code: &extra.fill_helper.bytes,
                            origin: extra.fill_helper.va,
                            feature_words: extra.fill_features,
                        },
                        extra.module_iat,
                    )
                })
                .transpose()?
        } else {
            None
        };
        if activation.as_ref().is_some_and(|a| {
            a.writes()
                .keys()
                .any(|&offset| offset != proof.try_level_offset())
        }) {
            return Err("fragment activation changes dependent scalar state".into());
        }
        let level = initialized
            .as_ref()
            .map(|p| p.try_level())
            .or_else(|| activation.as_ref().and_then(|a| a.try_level()))
            .unwrap_or(proof.try_level());
        evidence.push(format!("// Frame {index}: original prefix {:#x}..{:#x}, EBP offset {}, guards {:?}, saved slots {:?}.",f.prefix.va,proof.end(),proof.ebp_offset(),proof.guard_offsets(),proof.saved_slots()));
        if let Some(a) = &activation {
            evidence.push(format!("// Separate initializer {:#x}..{:#x}; UNPROVED intervening gap {:?}. Same-live-frame preservation is a cut premise.",a.entry(),a.end(),a.gap()));
        }
        if let Some(p) = &initialized {
            evidence.push(format!("// Original connected initializer {:#x}..{:#x}: byte fill {:?}, owned module result at {}; helper instructions verified for all admitted alignment/feature classes.",connected.unwrap().initializer.va,p.end(),p.fill_range(),p.module_slot()));
            functions.push_str(&format!("fn initialize_owned<P>(memory:&mut FrameMemory<P>,module:GuestModule)->Result<(),&'static str>{{ {} }}\n",p.body()));
        }
        let initializer_touches = |offset: i32| {
            initialized.as_ref().is_some_and(|p| {
                let (start, length) = p.fill_range();
                p.module_slot() == offset
                    || p.initialized_words().contains(&offset)
                    || (i64::from(offset) < i64::from(start) + i64::from(length)
                        && i64::from(start) < i64::from(offset) + 4)
            })
        };
        if initializer_touches(-20) {
            return Err("fragment initializer aliases exception pair owner slot".into());
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
                            || initializer_touches(offset)
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
        initialize.push_str(&format!("let mut entry_registers=[None;8];entry_registers[4]=Some(next_sp);entry_registers[5]=caller_ebp;let mut image=frame_{index}(next_sp,cookie,entry_registers,predecessor.clone())?;\nvalidate_frame_extent(image.esp,image.entry_sp,&bound_ranges,&stack_ranges)?;stack_ranges.push((u64::from(image.esp),u64::from(image.entry_sp)+4));\n"));
        if activation.is_some() {
            initialize.push_str(&format!("activate_{index}(&mut image)?;\n"));
        }
        if let Some(initialized) = &initialized {
            let ordinary: Vec<_> = proof.ordinary_words().iter().copied().collect();
            initialize.push_str(&format!("let initializer_low=image.esp.checked_sub({}).ok_or(\"initializer temporary stack underflow\")?;if initializer_low<thread_limit{{return Err(\"initializer temporary thread stack\");}}validate_frame_extent(initializer_low,image.entry_sp,&bound_ranges,&stack_ranges[..stack_ranges.len()-1])?;\n{{let mut memory=FrameMemory::new(&mut image,owner,&{ordinary:?})?;initialize_owned(&mut memory,GuestModule{{owner,base:{}}})?;}}\n",initialized.temporary_bytes(),connected.unwrap().module_base));
        }
        initialize.push_str(&format!(
            "if image.try_level!={level} {{return Err(\"derived EH4 level\");}}\n"
        ));
        if dispatch_input.is_some() {
            initialize.push_str(&format!("let binding=machine.binding({index}).map_err(|_|\"registration binding\")?;let registration=registry.install_frame(binding,&image)?;registrations.push(registration);predecessor=registry.head()?;\n"));
        } else {
            initialize.push_str(&format!(
                "predecessor=Predecessor::Frame{{owner,index:{index}}};\n"
            ));
        }
        initialize.push_str("caller_ebp=Some(image.ebp);next_sp=image.esp.checked_sub(4).ok_or(\"nested stack address\")?;images.push(image);\n");
        frames.push(proof);
        activations.push(activation);
        tables.push(table);
        layouts.push(layout);
        levels.push(level);
        if initialized.is_some() {
            connected_initialization = initialized;
        }
    }
    let args = frames.last().unwrap().pending_arguments();
    if args != [input.event_code, 0, 0, 0] {
        return Err("fragment event arguments not instruction-derived RaiseException cut".into());
    }
    // Bind original direct calls, not a caller-asserted nesting order. The
    // separate Main activation cut still cannot certify its preceding gap.
    for (index, call) in input.calls.iter().enumerate() {
        let end = if let (0, Some(initialized)) = (index, &connected_initialization) {
            initialized.end()
        } else {
            activations[index]
                .as_ref()
                .map_or(frames[index].end(), |a| a.end())
        };
        if call.va != end {
            return Err("fragment call is not contiguous with proved frame cut".into());
        }
        let mut decoder =
            Decoder::with_ip(32, &call.bytes, u64::from(call.va), DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || decoder.can_decode() {
            return Err("fragment incomplete call boundary".into());
        }
        if index + 1 < frames.len() {
            if instruction.code() != Code::Call_rel32_32
                || call.bytes.len() != 5
                || call.bytes[0] != 0xe8
                || instruction.near_branch32() != input.frames[index + 1].prefix.va
                || !frames[index].pending_arguments().is_empty()
            {
                return Err("fragment original direct-call/frame order".into());
            }
        } else if call.bytes.len() != 6
            || call.bytes[..2] != [0xff, 0x15]
            || instruction.memory_displacement32() != input.raise_exception_iat
        {
            return Err("fragment original RaiseException IAT call binding".into());
        }
        evidence.push(format!("// Original call at {:#x} binds frame step {index}; OS exception delivery itself remains an external cut.",call.va));
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
    let raise_call = if raised {
        let call = input.calls.last().ok_or("raised missing original call")?;
        Some(super::raise_call::prove_call(
            frames.last().ok_or("raised missing original frame")?,
            &call.bytes,
            call.va,
            input.raise_exception_iat,
            input.event_code,
        )?)
    } else {
        None
    };
    let dispatch_bundle = dispatch_input
        .map(|d| {
            super::dispatch_contract::prove_bundle(
                input,
                connected.ok_or("dispatcher requires connected initialization")?,
                d,
                &frames,
                &layouts,
                &levels,
                &selected,
            )
        })
        .transpose()?;
    let landing_proof = connected
        .map(|extra| {
            if selected.target() != extra.selected_landing.va {
                return Err("connected landing selection identity".into());
            }
            let frame = &frames[selected.selected_frame()];
            frame_landing::prove_landing(
                &extra.selected_landing.bytes,
                extra.selected_landing.va,
                &input.restore.bytes,
                input.restore.va,
                frame_landing::Layout {
                    ordinary_words: frame.ordinary_words(),
                    stack_words: frame.stack_words(),
                    stack_offset: frame.esp_offset(),
                    try_level_offset: frame.try_level_offset(),
                },
            )
        })
        .transpose()?;
    let reporting = reported.map(|report| -> Result<_,String> {
        use super::main_completion::{Bindings,Layout,Word};
        let extra=connected.ok_or("report requires original connected initialization")?;
        let d=dispatch_input.ok_or("report requires original dispatch")?;
        let landing=landing_proof.as_ref().ok_or("report requires original landing")?;
        if !raised || selected.selected_frame()!=0 || report.completion.va!=landing.end || report.entry_globals.len()>16 {
            return Err("report original completion continuity/root frame".into());
        }
        let end=extra.module_base.checked_add(extra.module_size).ok_or("report module overflow")?;
        fn region(r:&Region)->super::stdio_effect::Region<'_>{super::stdio_effect::Region{code:r.bytes.as_slice(),origin:r.va}}
        let wrapper=super::stdio_effect::prove_wrapper(region(&report.printf_wrapper),region(&report.iob_accessor),region(&report.options_accessor),report.formatter,(extra.module_base,end))?;
        let format=super::stdio_effect::prove_format(&report.format.bytes)?;
        // The module envelope is an exclusion against stacks, not an alias
        // among its own members. Every concrete reporting role is disjoint.
        let mut occupied:Vec<_>=bound_ranges.iter().copied().filter(|r|*r!=(extra.module_base,end)).collect();
        for r in [&d.full_handler,&d.local_body,&d.local_wrapper,&d.nested_handler,&d.filter_bridge,&d.selected_bridge,&d.global_bridge,&d.notification,&d.cleanup_bridge] {
            occupied.push((r.va,r.va.checked_add(r.bytes.len() as u32).ok_or("report dispatcher overflow")?));
        }
        for va in d.notification_words.into_iter().chain([d.rtl_unwind_iat]) {occupied.push((va,va.checked_add(4).ok_or("report dispatch data overflow")?));}
        let mut add=|va:u32,len:usize|->Result<(),String>{
            let high=va.checked_add(u32::try_from(len).map_err(|_|"report extent")?).ok_or("report extent overflow")?;
            if len==0||len>8192||va<extra.module_base||high>end||occupied.iter().any(|&(a,b)|va<b&&a<high){return Err("report role alias/outside module".into());}
            occupied.push((va,high));Ok(())
        };
        for r in [&report.completion,&report.printf_wrapper,&report.iob_accessor,&report.options_accessor,&report.format] {add(r.va,r.bytes.len())?;}
        add(report.formatter,1)?;add(wrapper.stdout_address(),56)?;add(wrapper.options_address(),8)?;
        for &va in &report.entry_globals {if va%4!=0{return Err("report unaligned entry scalar".into());}add(va,4)?;}
        let frame=&frames[0];
        let initialized=connected_initialization.as_ref().ok_or("report missing initializer effects")?;
        let mut words:BTreeMap<_,_>=frame.ordinary_words().iter().map(|&at|(at,Word::Uninitialized)).collect();
        for &at in frame.scalar_words().keys().chain(initialized.initialized_words().iter()) {
            if !words.contains_key(&at){return Err("report initialized word outside ordinary frame".into());}words.insert(at,Word::Scalar);
        }
        words.insert(initialized.module_slot(),Word::Module);
        for (&at,kind) in &landing.final_words {
            if !words.contains_key(&at){return Err("report landing word outside ordinary frame".into());}
            words.insert(at,match kind {frame_landing::InitializedWord::Scalar=>Word::Scalar,frame_landing::InitializedWord::Stack=>Word::Stack,frame_landing::InitializedWord::Continuation=>Word::Continuation});
        }
        let globals:BTreeMap<_,_>=std::iter::once(input.trace_va).chain(input.globals.iter().copied()).chain(report.entry_globals.iter().copied()).enumerate().map(|(index,va)|(va,index)).collect();
        if globals.len()!=1+input.globals.len()+report.entry_globals.len(){return Err("report global authority alias".into());}
        let completion=super::main_completion::prove(&report.completion.bytes,report.completion.va,&Layout{words,esp:frame.esp_offset(),saved:frame.saved_slots().clone(),guards:frame.guard_offsets().iter().copied().collect(),predecessor:frame.record_offset()},&Bindings{module_base:extra.module_base,module_size:extra.module_size,globals,printf:report.printf_wrapper.va,format:report.format.va,security_check:extra.security_helper.va})?;
        if completion.argument_count!=format.arguments(){return Err("report original variadic/format arity".into());}
        evidence.push(format!("// Original reporting call {:#x}, {} scalar arguments, output bound {} bytes. CRT wrapper requirements remain unresolved effect boundaries: {:?}. Explicit entry-scalar addresses {:?}; values are runtime inputs, not zero initialization assumptions.",completion.printf_pc,completion.argument_count,format.max_bytes(),wrapper.required_effects(),report.entry_globals));
        Ok((completion,wrapper))
    }).transpose()?;
    evidence.push(format!("// Filter-derived selected frame {}, EH4 scope {}, landing {:#x}; landing {}.",selected.selected_frame(),selected.selected_scope(),selected.target(),if connected.is_some(){"is executed from original context stores through nonlocal transfer and observation stores"}else{"instructions are not executed"}));

    // Each filter body is decoded, not an expected-result stencil. The installed
    // pair and pre-filter normalization contracts are composed below.
    let normalizer = selection::prove_code_identity(
        &input.normalizer.bytes,
        input.normalizer.va,
        &BTreeSet::from([input.feature_va]),
        input.event_code,
    )?;
    if let Some(prefix) = &prefix_proof {
        let call = prefix
            .calls
            .iter()
            .find(|c| c.effect == handler_checks::CallEffect::NormalizeRecordCode)
            .ok_or("connected normalizer depth")?;
        handler_temporary_bytes = handler_temporary_bytes.max(
            call.entry_depth
                .checked_add(normalizer.temporary_bytes())
                .ok_or("connected normalizer depth overflow")?,
        );
    }
    functions.push_str(&format!(
        "fn normalize(code:u32,_feature:i32)->Result<u32,&'static str>{{ {} }}\n",
        normalizer.body()
    ));
    evidence.push(format!("// Event normalizer: {} proved return paths over unknown initialized feature word; cookie/context helper status is specified by the composition mode.",normalizer.proved_return_paths()));
    let mut filter_runs = String::new();
    let mut dispatched_filters = BTreeMap::new();
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
        let filter_call = if dispatch_input.is_some() {
            let at =
                16 + usize::try_from(step.scope).map_err(|_| "dispatch filter scope")? * 12 + 4;
            let filter_target = u32::from_le_bytes(
                input.frames[frame]
                    .table
                    .bytes
                    .get(at..at + 4)
                    .ok_or("dispatch filter row")?
                    .try_into()
                    .unwrap(),
            );
            format!(
                r#"
 let mut registers=unknown_packet();
 let filter_code=BridgeValue::Capability(DispatchCapability::Code{{owner,frame:{frame},address:{filter_target}}});
 let filter_frame=BridgeValue::Capability(DispatchCapability::Frame{{owner,index:{frame},binding:bindings[{frame}]}});
 registers[1]=filter_code.clone();registers[2]=filter_frame.clone();
 let BridgeExit::Return{{registers,cleanup}}=original_filter_bridge(&registers,|kind,target,entry,args,resume|{{
  if kind!=BridgeCall::Filter||target!=&filter_code||entry[5]!=filter_frame||!args.is_empty()||resume.is_some(){{return Err("original filter bridge authority");}}
  let value=filter_{index}(code,&mut temporaries)?;
  let mut reply=unknown_packet();reply[0]=BridgeValue::Scalar(value as u32);reply[4]=call_return(entry.clone(),4)?[4].clone();
  Ok(BridgeReply{{registers:reply,resume:None}})
 }})? else{{return Err("original filter bridge return");}};
 if cleanup!=0||registers[0]!=BridgeValue::Scalar({result}i32 as u32){{return Err("filter runtime/proof disagreement");}}
"#,
                result = step.proof.result()
            )
        } else {
            format!("if filter_{index}(code,&mut temporaries)?!={} {{return Err(\"filter runtime/proof disagreement\");}}",step.proof.result())
        };
        // Only the event-owned opaque identity is shared between handlers in
        // raised mode. Guest CALL registers are not a captured Windows CONTEXT.
        let context_value = if raised {
            "raised_event.identity()"
        } else {
            "current"
        };
        let snippet = format!(
            r#"
{{
 let image=&mut images[{frame}];
 let bp=i32::try_from(i64::from(image.ebp)-i64::from(image.entry_sp)).map_err(|_|"filter frame base")?;
 if !matches!(image.words.get(&(bp-20)),Some(FrameWord::Unknown|FrameWord::Scalar(_))) {{return Err("filter owner slot");}}
 let mut bridge=BridgeMemory::new((owner,{frame}usize,event_code),(owner,{frame}usize,{context_value}),std::collections::BTreeMap::from([(-28,BridgeWord::Vacant),(-24,BridgeWord::Vacant)]),std::collections::BTreeMap::from([(-20,BridgeWord::Vacant)]))?;
 let identity=bridge.identity();
 let pair=install_{index}(&mut bridge)?;
 let &(event_owner,event_frame,code)=pair.record(identity)?;
 let &(context_owner,context_frame,_)=pair.context(identity)?;
 if event_owner!=owner||context_owner!=owner||event_frame!={frame}||context_frame!={frame} {{return Err("filter event/frame identity");}}
 let slots={offsets:?};
 let mut temporaries=Vec::new();
 for offset in slots {{temporaries.push(match image.words.get(&(bp+offset)){{Some(FrameWord::Unknown)=>None,Some(FrameWord::Scalar(value))=>Some(*value),_=>return Err("filter temporary ownership")}});}}
 {filter_call}
 for (offset,value) in slots.into_iter().zip(temporaries) {{if let Some(value)=value{{image.words.insert(bp+offset,FrameWord::Scalar(value));}}}}
 bridge.invalidate();
}}
"#
        );
        filter_runs.push_str(&snippet);
        dispatched_filters.insert((frame, step.scope), snippet);
    }

    let mut cleanup_bindings = BTreeMap::new();
    let mut cleanup_depths = BTreeMap::new();
    for (index, region) in input.cleanups.iter().enumerate() {
        if cleanup_bindings.insert(region.va, index).is_some() {
            return Err("duplicate cleanup".into());
        }
        let proof = cleanup::prove_cleanup_effects(&region.bytes, region.va)?;
        cleanup_depths.insert(index, proof.temporary_bytes);
        functions.push_str(&format!(
            "fn cleanup_{index}(cells:&mut[u32;2])->Result<(),Error>{{ {} }}\n",
            proof.source
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
    let mut dispatch_depths = BTreeMap::new();
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
        dispatch_depths.insert(
            index as i32,
            proof.with_cleanup_depth(cleanup_depths[&proof.action])?,
        );
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
    let mut owned_arms = String::new();
    let mut initialized_globals = BTreeSet::new();
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
        initialized_globals.extend(proof.global_writes.iter().copied());
        evidence.push(format!("// Cleanup action {action}: original funclet {va:#x}, complete post-call global writes {:?}.",proof.global_writes));
        let cursor = *known_cursors
            .entry((frame, proof.cursor_offset))
            .or_insert(frames[frame].scalar_words()[&proof.cursor_offset] as i32);
        let row = usize::try_from(cursor)
            .ok()
            .and_then(|i| rows.get(i))
            .ok_or("fragment custom cursor outside initialized table")?;
        handler_temporary_bytes =
            handler_temporary_bytes.max(proof.with_dispatch_depth(dispatch_depths[&cursor])?);
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
        // EH4's TryLevel advances before the finally call. This is distinct
        // from both the lifecycle request cursor and the authored custom cursor.
        let row_at = 16 + usize::try_from(scope).map_err(|_| "connected scope index")? * 12;
        let eh_parent = i32::from_le_bytes(
            input.frames[frame]
                .table
                .bytes
                .get(row_at..row_at + 4)
                .ok_or("connected EH4 parent")?
                .try_into()
                .unwrap(),
        );
        let try_transition = if dispatch_input.is_some() {
            String::new()
        } else {
            format!("memory.write_try_level({eh_parent}).map_err(|_|Error::Identity)?;")
        };
        owned_arms.push_str(&format!(r#"{action}=>{{
          if frame!={frame} || lease_scope!=Some({scope}) || lease_action!=Some({action}) {{return Err(Error::Identity);}}
          let mut cells=[trace.read()?,memory.read_u32({local_offset}).map_err(|_|Error::Uninitialized)?];
          let mut cursor=memory.read_u32({cursor_offset}).map_err(|_|Error::Uninitialized)? as i32;
          {try_transition}
          funclet_{action}(&mut cells,&mut cursor,&mut globals,dispatch_{cursor})?;
          trace.write(cells[0])?;
          memory.write_u32({local_offset},cells[1]).map_err(|_|Error::Identity)?;
          memory.write_u32({cursor_offset},cursor as u32).map_err(|_|Error::Identity)?;
        }},"#,local_offset=proof.local_offset,cursor_offset=proof.cursor_offset));
    }
    // This bounded reporting adapter maps every supplied cleanup-global role.
    // Require original executed writes for all of them before emission rather
    // than padding unused or unknown cells with zero at runtime.
    if reported.is_some()
        && (0..input.globals.len()).any(|index| !initialized_globals.contains(&index))
    {
        return Err("report cleanup global initialization not proved".into());
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
    let bound_ranges = format!("{bound_ranges:?}");
    let mut evidence = evidence.join("\n");
    if let Some(landing) = &landing_proof {
        if landing.target != input.target.va {
            return Err("connected original transfer target mismatch".into());
        }
        let memory_types = frame_memory::EMITTED_TYPES;
        let context_types = handler_context::EMITTED_TYPES;
        let ordinary: Vec<Vec<i32>> = frames
            .iter()
            .map(|p| p.ordinary_words().iter().copied().collect())
            .collect();
        let ordinary = format!(
            "vec![{}]",
            ordinary
                .iter()
                .map(|v| format!("vec!{v:?}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let prepare = &landing.prepare_source;
        let restored_body = &landing.restore_source;
        let observations = &landing.observation_source;
        let context_offset = landing.context_offset;
        let landing_end = landing.end;
        let captures = &landing.observations;
        let landing_temporary = landing.temporary_bytes();
        let mut guard_runs = String::new();
        for frame in (selected_frame..frames.len()).rev() {
            guard_runs.push_str(&format!("{{let memory=&FrameMemory::new(&mut images[{frame}],owner,&ordinary[{frame}])?;let code=normalize(event_code,feature)?;if code!=event_code{{return Err(\"normalizer identity\");}}guard_{frame}(memory,cookie)?;thread_context.check(owner,selector)?;}}\n"));
        }
        let mut support = String::new();
        let mut setup = String::new();
        let run_name = if reported.is_some() {
            "run_reported"
        } else if raised {
            "run_raised"
        } else if dispatch_input.is_some() {
            "run_dispatched"
        } else {
            "run_connected"
        };
        let composition_boundary = if reported.is_some() {
            "Original Main reporting predicates, variadic routing and protected normal return execute after the original selected handler. Owned initialized stdout/options, public integer-printf semantics and buffering policy are explicit external effect boundaries: the linked formatter, FILE initialization, CRT entry and process-exit flush are NOT proved. Not whole-PE admission."
        } else if raised {
            "The original software-exception CALL supplies this event. Closed same-thread delivery with valid captured stack and no debugger/vectored interception is an explicit domain, not established startup. Captured registers remain unknown. Original selected handler, cleanup and restoration execute; unsupported delivery outcomes reject before emission. Not whole-PE admission."
        } else if dispatch_input.is_some() {
            "Original handler routing, local FS effects, helper bridges, cleanup and restoration execute. Windows delivery and the closed RtlUnwind external contract remain boundaries; arbitrary nested/collided dispatch and the later Main/CRT epilog are not admitted."
        } else {
            "Connected original initialization and selected landing; Windows delivery, handler search/RtlUnwind and thread-registration teardown remain explicit cuts."
        };
        let lifecycle = if raised {
            "new_dispatch_known"
        } else if dispatch_input.is_some() {
            "new_dispatch"
        } else {
            "new_owned"
        };
        let outcome_fields = if dispatch_input.is_some() {
            "pub notification_writes:Vec<(u32,u32,u32)>,pub linked_registrations:Vec<bool>,"
        } else {
            ""
        };
        let outcome_values = if dispatch_input.is_some() {
            "notification_writes:notification.try_borrow().map_err(|_|\"notification observation alias\")?.writes.iter().map(|(address,value)|match value{BridgeValue::Scalar(n)=>Ok((*address,0,*n)),BridgeValue::Capability(DispatchCapability::Code{address:target,..})=>Ok((*address,1,*target)),BridgeValue::Capability(DispatchCapability::Frame{index,..})=>Ok((*address,2,*index as u32)),_=>Err(\"notification observation type\")}).collect::<Result<_,_>>()?,linked_registrations:registry.frames.iter().map(|frame|frame.linked).collect(),"
        } else {
            ""
        };
        let predecessor_setup = if let (Some(d), Some(bundle)) =
            (dispatch_input, dispatch_bundle.as_ref())
        {
            support = super::dispatch_support::emit(input, d, bundle, &owned_arms)?;
            handler_temporary_bytes = handler_temporary_bytes
                .checked_add(bundle.temporary_bytes)
                .ok_or("dispatcher scratch sum")?;
            // One original handler remains live while RtlUnwind invokes each
            // younger handler. Reserve a disjoint private nested activation;
            // no numerical Windows dispatcher stack placement is asserted.
            handler_temporary_bytes = handler_temporary_bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(16))
                .ok_or("dispatcher nested scratch")?;
            setup=format!("let mut registry=ThreadRegistry::new(owner,thread_limit,thread_base,&{bound_ranges},{}u32)?;let mut registrations=Vec::new();let mut predecessor=registry.head()?;let notification=std::cell::RefCell::new(NotificationState::new(owner,{:?})?);",input.cookie_va,d.notification_words);
            ""
        } else {
            "let mut predecessor=Predecessor::Borrowed{owner};"
        };
        let cleanup_run = if let (Some(d), Some(bundle)) =
            (dispatch_input, dispatch_bundle.as_ref())
        {
            super::dispatch_emit::emit_control(bundle, d, selected_frame, &dispatched_filters)?
        } else {
            format!(
                r#"
 {guard_runs}
 {filter_runs}
 while let Some(request)=machine.next_cleanup().map_err(|_|"connected cleanup phase")?{{
  let action=request.action();
  machine.execute_owned_cleanup(request,|lease,trace|{{
    let frame=lease.frame_index();let lease_scope=lease.scope();let lease_action=lease.action();let binding=*bindings.get(frame).ok_or(Error::Identity)?;
    lease.bind_storage(binding)?;
    let memory=&mut FrameMemory::new(images.get_mut(binding.frame_index()).ok_or(Error::Identity)?,binding.owner(),&ordinary[frame]).map_err(|_|Error::Identity)?;
    lease.perform(||{{match action {{{owned_arms}_=>return Err(Error::Order)}} Ok(())}})?;Ok(())
  }}).map_err(|_|"connected original cleanup receipt")?;
 }}
"#
            )
        };
        let signature = if reported.is_some() {
            "entry_sp:u32,cookie:u32,feature:i32,initial_trace:u32,thread_limit:u32,thread_base:u32,selector:u32,entry_globals:&[u32],stdio_options:[u32;2],policy:ReportPolicy,mut sink:impl FnMut(&[u8])->std::io::Result<usize>"
        } else if raised {
            "entry_sp:u32,cookie:u32,feature:i32,initial_trace:u32,thread_limit:u32,thread_base:u32,selector:u32"
        } else {
            "entry_sp:u32,cookie:u32,current:[u32;10],feature:i32,initial_trace:u32,thread_limit:u32,thread_base:u32,selector:u32,handler_sp:u32"
        };
        let flags_check = if raised {
            ""
        } else {
            "if current[9]&!0x8d5!=0x202 {return Err(\"connected current flags boundary\");}"
        };
        let machine_context = if raised { "[None;10]" } else { "current" };
        let context_setup = if raised {
            ""
        } else {
            "let thread_context=ThreadContext::new(owner,thread_limit,thread_base,current[4])?;"
        };
        let mut event_support = String::new();
        let invocation_setup = if let Some(call) = &raise_call {
            event_support.push_str(super::exception_event::EMITTED_TYPES);
            // The helper's second lowering consumes only the proven same-thread
            // bounds capability, never a made-up numeric captured ESP.
            functions.push_str(&format!("impl CapturedContext{{fn check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{ {} }} }}\n",context_proof.as_ref().ok_or("raised context proof")?.projection_body()));
            evidence.push_str(&format!("\n// Original RaiseException CALL {:#x}, protected continuation {:#x}, IAT {:#x}, argument cells {:?}; guest registers {:?}, known flags {:?}. No Windows CONTEXT equality asserted.",call.call_pc(),call.next_pc(),call.iat(),call.arguments(),call.registers(),call.known_flags()));
            format!("let raising_frame=images.len().checked_sub(1).ok_or(\"raised empty frames\")?;let mut raised_event=OwnedExceptionEvent::from_raise(&mut machine,&registry,bindings[raising_frame],&images[raising_frame],RaiseSite{{instruction:{},return_ip:{},iat:{},code:{},caller_sp_offset:{},callee_sp_offset:{}}},{handler_temporary_bytes})?;let handler_sp=raised_event.handler_sp();let thread_context=raised_event.captured_context();",call.call_pc(),call.next_pc(),call.iat(),call.event_code(),call.caller_sp_offset(),call.callee_sp_offset())
        } else {
            String::new()
        };
        let event_value = if raised {
            "raised_event.code()".to_string()
        } else {
            format!("{event}u32")
        };
        let finish_event = if raised {
            "raised_event.finish(&machine,&registry)?;"
        } else {
            ""
        };
        let transfer_event = if raised {
            "raised_event.begin_restoration(&machine,&registry)?;"
        } else {
            ""
        };
        let mut report_support = String::new();
        let mut report_run = String::new();
        let mut report_fields = String::new();
        let mut report_values = String::new();
        let mut report_exports = String::new();
        let outcome_derive = if reported.is_some() {
            "#[derive(Debug)]"
        } else {
            "#[derive(Debug,PartialEq,Eq)]"
        };
        if let (Some(report), Some((completion, wrapper))) = (reported, reporting.as_ref()) {
            report_support.push_str(super::main_completion::EMITTED_TYPES);
            report_support.push_str(super::stdio_effect::EMITTED_TYPES);
            report_support.push_str(super::main_return::EMITTED_TYPES);
            report_support.push_str(r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ReportPolicy {ImmediateProjection,Deferred}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ReportFlush {Success,Failure}
pub struct ReportOutput {inner:OwnedStdio,owner:u64,logical:Option<u32>}
impl std::fmt::Debug for ReportOutput {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.debug_struct("ReportOutput").field("logical_count",&self.logical).field("written_bytes",&self.inner.written_bytes()).field("pending_bytes",&self.inner.pending_bytes()).field("stream_error",&self.inner.stream_error).finish()}}
impl ReportOutput {
 pub fn logical_count(&self)->Option<u32>{self.logical}
 pub fn pending_bytes(&self)->&[u8]{self.inner.pending_bytes()}
 pub fn written_bytes(&self)->usize{self.inner.written_bytes()}
 pub fn stream_error(&self)->bool{self.inner.stream_error}
 /// An explicitly requested component flush, never an implicit CRT exit.
 pub fn flush(&mut self,sink:impl FnMut(&[u8])->std::io::Result<usize>)->Result<ReportFlush,&'static str>{self.inner.flush(self.owner,sink).map(|r|match r{FlushResult::Success=>ReportFlush::Success,FlushResult::Failure=>ReportFlush::Failure})}
}
"#);
            let wrapper_body = wrapper.body();
            functions.push_str(&format!("fn reporting_printf(stdio:&mut OwnedStdio,owner:u64,request:PrintRequest<'_>,sink:impl FnMut(&[u8])->std::io::Result<usize>)->Result<Option<u32>,&'static str>{{if request.call_pc!={}u32||request.target!={}u32||request.format!={}u32{{return Err(\"report bound original printf call\");}}let format:&[u8]=&{:?};let arguments=request.arguments;let result=(||->Result<PrintResult,&'static str>{{{wrapper_body}}})();result.map(PrintResult::word)}}\n",completion.printf_pc,report.printf_wrapper.va,report.format.va,report.format.bytes));
            let scratch = completion
                .temporary_bytes()
                .checked_add(wrapper.temporary_bytes())
                .ok_or("report nested scratch overflow")?;
            let completion_body = completion.source();
            report_run = format!(
                r#"
 if entry_globals.len()!={extra_count}{{return Err("report explicit initialized entry scalar count");}}
 let mut reporting_globals=Vec::with_capacity(1+globals.len()+entry_globals.len());
 reporting_globals.push(machine.trace.ok_or("report unknown trace")?);
 reporting_globals.extend(globals.iter().map(|n|n.ok_or("report uninitialized global scalar")).collect::<Result<Vec<_>,_>>()?);
 reporting_globals.extend_from_slice(entry_globals);
 let mut report_stdio=OwnedStdio::new(owner,{stdout},{options},stdio_options,match policy{{ReportPolicy::ImmediateProjection=>OutputPolicy::ImmediateProjection,ReportPolicy::Deferred=>OutputPolicy::Deferred}})?;
 let report_low=images[{selected_frame}].esp.checked_sub({scratch}).ok_or("report temporary stack underflow")?;
 if report_low<thread_limit{{return Err("report temporary stack thread bounds");}}
 validate_frame_extent(report_low,images[{selected_frame}].esp,&bound_ranges,&[])?;
 let plan=NormalReturnPlan{{pops:vec!{pops:?},cookie_offset:{cookie_offset},security_target:{security_target},return_offset:{return_offset}}};
 let mut logical_count=None;
 let main_return;
 {{
  let mut session=NormalReturnSession::new(&mut machine,&mut registry,bindings[{selected_frame}],&images[{selected_frame}],&raised_event,plan)?;
  let original=(||->Result<CompletionOutcome<RegistryHead>,&'static str>{{
   let memory=&mut FrameMemory::new(&mut images[{selected_frame}],owner,&ordinary[{selected_frame}])?;
   let globals=&mut reporting_globals;
   let mut printf=|request:PrintRequest<'_>|->Result<Option<u32>,&'static str>{{let value=reporting_printf(&mut report_stdio,owner,request,&mut sink)?;logical_count=value;Ok(value)}};
   let mut effects=|effect:CompletionEffect<'_,RegistryHead>|session.apply(effect);
   {completion_body}
  }})();
  let outcome=original?;let receipt=session.finish(&outcome)?;main_return=receipt.value;
 }}
 let returned=machine.owned_context.ok_or("report missing returned register state")?;
 let report=ReportOutput{{inner:report_stdio,owner,logical:logical_count}};
"#,
                extra_count = report.entry_globals.len(),
                stdout = wrapper.stdout_address(),
                options = wrapper.options_address(),
                pops = completion.pops,
                cookie_offset = completion.cookie_offset,
                security_target = completion.security_target,
                return_offset = completion.return_offset
            );
            report_fields =
                "pub main_return:u32,pub returned:[Option<u32>;10],pub report:ReportOutput,".into();
            report_values = "main_return,returned,report,".into();
            report_exports = ",ReportPolicy,ReportFlush,ReportOutput".into();
        }
        let source = format!(
            r#"
{evidence}
// {composition_boundary}
// Restored state is instruction-derived from CONTEXT {context_offset}; observation end {landing_end:#x}, stores {captures:?}.
#[allow(dead_code)]
mod composed {{
{runtime}
{types}
{memory_types}
{context_types}
{bridge_types}
{support}
{event_support}
{report_support}
{functions}
#[derive(Clone,Debug,PartialEq,Eq)]
enum Predecessor {{Borrowed{{owner:u64}},Frame{{owner:u64,index:usize}}}}
fn validate_frame_extent(low:u32,entry_sp:u32,bound:&[(u32,u32)],stacks:&[(u64,u64)])->Result<(),&'static str>{{
 let low=u64::from(low);let high=u64::from(entry_sp)+4;
 if low>=high||high>1u64<<32||bound.iter().any(|&(a,b)|low<u64::from(b)&&u64::from(a)<high)||stacks.iter().any(|&(a,b)|low<b&&a<high){{return Err("guest stack aliases bound image or another frame");}} Ok(())
}}
{outcome_derive}
pub struct Outcome {{{report_fields}{outcome_fields}pub trace:u32,pub frame_words:Vec<Vec<Option<u32>>>,pub offsets:Vec<Vec<i32>>,pub globals:Vec<Option<u32>>,pub cursors:Vec<Option<i32>>,pub live:Vec<bool>,pub restored:[Option<u32>;10],pub selected_frame:usize,pub selected_target:u32}}
pub fn {run_name}({signature})->Result<Outcome,&'static str>{{
 {flags_check}
 let mut machine=Machine::{lifecycle}(vec![{specs}],{selected_frame},{machine_context},Some(initial_trace)).map_err(|_|"connected lifecycle")?;
 let owner=machine.owner();{predecessor_setup}
 {setup}
 {context_setup}
 if entry_sp.checked_add(4).is_none_or(|end|end>thread_base)||entry_sp<thread_limit{{return Err("connected entry thread stack");}}
 let bound_ranges={bound_ranges};let mut stack_ranges=Vec::new();let mut next_sp=entry_sp;let mut images=Vec::new();let mut caller_ebp=None;
 {initialize}
 if images.iter().any(|image|image.esp<thread_limit){{return Err("connected frame outside owned thread stack");}}
 // Attach private frame identity once to the actual image at its creation index.
 let bindings:Vec<_>=(0..images.len()).map(|i|machine.binding(i)).collect::<Result<_,_>>().map_err(|_|"connected image binding")?;
 {invocation_setup}
 let handler_low=handler_sp.checked_sub({handler_temporary_bytes}).ok_or("handler scratch underflow")?;
 if handler_low<thread_limit||handler_sp.checked_add(4).is_none_or(|end|end>thread_base){{return Err("handler scratch thread bounds");}}
 validate_frame_extent(handler_low,handler_sp,&bound_ranges,&stack_ranges)?;
 let ordinary:Vec<Vec<i32>>={ordinary};
 let event_code=normalize({event_value},feature)?;
 let mut globals=vec![None;{global_count}];
 {cleanup_run}
 {transfer_event}
 let restored=machine.restore_owned({target},|lease,_current|{{
  let binding=bindings[{selected_frame}];lease.bind_storage(binding)?;
  lease.perform(||{{
   let memory=&mut FrameMemory::new(&mut images[binding.frame_index()],binding.owner(),&ordinary[binding.frame_index()]).map_err(|_|Error::Identity)?;
   let original=(||->Result<[Option<u32>;10],&'static str>{{
    let low=memory.stack_pointer().checked_sub({landing_temporary}).ok_or("landing scratch underflow")?;
    if low<thread_limit{{return Err("landing scratch thread limit");}}
    validate_frame_extent(low,memory.stack_pointer(),&bound_ranges,&[])?;
    {prepare}
    {restored_body}
    {observations}
    if landing_target!={target}{{return Err("connected target identity");}}
    Ok(landing_context)
   }})();
   original.map_err(|_|Error::Restoration)
  }})
 }}).map_err(|_|"connected original landing/restoration")?;
 {finish_event}
 {report_run}
 let offsets:Vec<Vec<i32>>={offsets_literal};let cursor_slots:Vec<Option<usize>>={cursors_literal};
 let mut frame_words=Vec::new();
 for (index,image) in images.iter().enumerate(){{
  let bp=i64::from(image.ebp)-i64::from(image.entry_sp);let mut values=Vec::new();
  for &offset in &offsets[index]{{let key=i32::try_from(bp+i64::from(offset)).map_err(|_|"connected observation offset")?;
   values.push(match image.words.get(&key){{Some(FrameWord::Scalar(n)|FrameWord::StackAddress(n)|FrameWord::Continuation(n))=>Some(*n),Some(FrameWord::ModuleBase{{owner:o,base}})if *o==owner=>Some(*base),Some(FrameWord::Bytes(bytes))=>match *bytes{{[Some(a),Some(b),Some(c),Some(d)]=>Some(u32::from_le_bytes([a,b,c,d])),_=>None}},Some(FrameWord::Unknown)=>None,_=>return Err("connected observation type")}});
  }}frame_words.push(values);
 }}
 let cursors=frame_words.iter().zip(cursor_slots).map(|(words,slot)|slot.and_then(|s|words[s]).map(|n|n as i32)).collect();
 let outcome=Outcome{{{report_values}{outcome_values}trace:machine.trace.ok_or("connected unknown trace")?,frame_words,offsets,globals,cursors,live:machine.frames.iter().map(|f|f.live).collect(),restored,selected_frame:{selected_frame},selected_target:{selected_target}}};
 Ok(outcome)
}}
}}
pub use composed::{{{run_name},Outcome{report_exports}}};
"#
        );
        return Ok(Proven { source });
    }
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
fn validate_frame_extent(low:u32,entry_sp:u32,bound:&[(u32,u32)],stacks:&[(u64,u64)])->Result<(),&'static str>{{
 let low=u64::from(low);let high=u64::from(entry_sp)+4;
 if low>=high || high>1u64<<32 || bound.iter().any(|&(a,b)|low<u64::from(b)&&u64::from(a)<high)
  || stacks.iter().any(|&(a,b)|low<b&&a<high) {{return Err("guest stack aliases bound image or another frame");}}
 Ok(())
}}
#[derive(Debug,PartialEq,Eq)]
pub struct Outcome {{pub trace:u32,pub frame_words:Vec<Vec<Option<u32>>>,pub offsets:Vec<Vec<i32>>,pub globals:Vec<Option<u32>>,pub cursors:Vec<Option<i32>>,pub live:Vec<bool>,pub restored:[Option<u32>;10],pub selected_frame:usize,pub selected_target:u32}}
pub fn run_fragments(entry_sp:u32,cookie:u32,saved:[u32;10],current:[u32;10],feature:i32,initial_trace:u32)->Result<Outcome,&'static str>{{
 if saved[8]!={target} || current[9]&!0x8d5!=0x202 {{return Err("fragment context boundary");}}
 let owner=OWNERS.fetch_update(Ordering::Relaxed,Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|"fragment identity exhaustion")?;
 let mut predecessor=Predecessor::Borrowed{{owner}};
 let bound_ranges={bound_ranges};let mut stack_ranges=Vec::new();
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

#[cfg(test)]
#[path = "frame_review_tests.rs"]
mod review_tests;

#[cfg(test)]
#[path = "filter_review_tests.rs"]
mod filter_review_tests;

#[cfg(test)]
#[path = "connected_review_tests.rs"]
mod connected_review_tests;
