//! Compile-time binding of original handler, local-unwind and bridge code.
//!
//! A Bundle is not an entry/admission certificate. In particular the Windows
//! dispatcher and RtlUnwind must still satisfy the explicit external contracts;
//! a successful helper proof cannot manufacture their effects or unlink order.
use super::{
    frame_proof,
    frame_unwind::{Connected, Input, Region},
    handler_checks, handler_context, handler_dispatch, handler_guard, local_unwind, selection,
    unwind_bridges,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Dispatch {
    pub full_handler: Region,
    pub local_body: Region,
    pub local_wrapper: Region,
    pub nested_handler: Region,
    pub filter_bridge: Region,
    pub selected_bridge: Region,
    pub global_bridge: Region,
    pub notification: Region,
    pub cleanup_bridge: Region,
    pub rtl_unwind_iat: u32,
    /// Action, target and frame, in that order. Instruction stores bind them.
    pub notification_words: [u32; 3],
}

pub(crate) struct FramePlan {
    pub frame: usize,
    pub search: handler_dispatch::DispatchProof,
    /// Only the explicit flags=2 delivery class is proved here. This does not
    /// authorize nested/collided delivery or infer the OS invocation schedule.
    pub unwind: handler_dispatch::DispatchProof,
    pub scope: local_unwind::ScopeGraph,
    pub guard: handler_guard::GuardProof,
}

pub(crate) struct Bundle {
    pub bindings: handler_dispatch::Bindings,
    pub local_bindings: local_unwind::Bindings,
    pub prefix: handler_checks::PrefixProof,
    pub context: handler_context::ContextCheckProof,
    pub normalizer: selection::CodeIdentity,
    pub frames: Vec<FramePlan>,
    pub body: local_unwind::Proof,
    pub wrapper: local_unwind::Proof,
    pub nested: local_unwind::Proof,
    pub filter: unwind_bridges::BridgeProof,
    pub transfer: unwind_bridges::BridgeProof,
    pub global: unwind_bridges::BridgeProof,
    pub notification: unwind_bridges::BridgeProof,
    pub cleanup: unwind_bridges::BridgeProof,
    pub cleanup_trace: Vec<(usize, i32, u32)>,
    /// Per-activation private scratch excluding arbitrary callee/OS stacks.
    /// `callback_sites` are additional obligations for enclosing frame proofs.
    pub temporary_bytes: u32,
    pub callback_sites: Vec<CallbackSite>,
    /// Separate nested-handler activation, not added as a guessed OS stack.
    pub nested_temporary_bytes: u32,
    pub bound_ranges: Vec<(u32, u32)>,
    pub external_requirements: &'static [ExternalRequirement],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallbackSite {
    pub kind: CallbackKind,
    /// Below the original handler entry ESP, including callback return word.
    pub entry_depth: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallbackKind {
    Filter,
    Finally,
    WindowsUnwind,
}

/// Required facts, deliberately not Boolean attestations or admission tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalRequirement {
    WindowsSearchDelivery,
    RtlUnwindTargetPreservationAndContinuation,
    TemporaryRegistrationAndNestedDelivery,
    OriginalFinallyProtectedMetadataFootprint,
    NotificationObjectLifetime,
}
const EXTERNAL_REQUIREMENTS: &[ExternalRequirement] = &[
    ExternalRequirement::WindowsSearchDelivery,
    ExternalRequirement::RtlUnwindTargetPreservationAndContinuation,
    ExternalRequirement::TemporaryRegistrationAndNestedDelivery,
    ExternalRequirement::OriginalFinallyProtectedMetadataFootprint,
    ExternalRequirement::NotificationObjectLifetime,
];

fn extent(region: &Region) -> Result<(u32, u32), String> {
    let size = u32::try_from(region.bytes.len()).map_err(|_| "dispatch bundle region size")?;
    if region.va == 0 || size == 0 || size > 8192 {
        return Err("dispatch bundle region extent".into());
    }
    Ok((
        region.va,
        region
            .va
            .checked_add(size)
            .ok_or("dispatch bundle region overflow")?,
    ))
}
fn contained(parent: &Region, child: &Region) -> Result<(), String> {
    let (a, b) = extent(parent)?;
    let (c, d) = extent(child)?;
    if c < a || d > b || parent.bytes[(c - a) as usize..(d - a) as usize] != child.bytes {
        return Err("dispatch bundle overlapping regions disagree".into());
    }
    Ok(())
}
fn add_depth(a: u32, b: u32) -> Result<u32, String> {
    a.checked_add(b)
        .ok_or_else(|| "dispatch bundle scratch overflow".into())
}

/// Validate all bindings inside the explicitly declared original module. This
/// checks provenance consistency, not PE-loader permission or startup closure.
fn regions(input: &Input, c: &Connected, d: &Dispatch) -> Result<Vec<(u32, u32)>, String> {
    let module_end = c
        .module_base
        .checked_add(c.module_size)
        .ok_or("dispatch bundle module overflow")?;
    if c.module_base == 0 || c.module_size == 0 {
        return Err("dispatch bundle empty module".into());
    }
    if input.handler_va != d.full_handler.va || c.handler_prefix.va != d.full_handler.va {
        return Err("dispatch bundle registered handler identity".into());
    }
    contained(&d.full_handler, &c.handler_prefix)?;
    contained(&c.handler_prefix, &input.installer)?;
    contained(&c.selected_landing, &input.target)?;
    let mut all: Vec<&Region> = vec![
        &d.full_handler,
        &d.local_body,
        &d.local_wrapper,
        &d.nested_handler,
        &d.filter_bridge,
        &d.selected_bridge,
        &d.global_bridge,
        &d.notification,
        &d.cleanup_bridge,
        &input.dispatcher,
        &input.dispatch_table,
        &input.normalizer,
        &input.restore,
        &c.initializer,
        &c.fill_helper,
        &c.selected_landing,
        &c.guard_helper,
        &c.security_helper,
        &c.context_helper,
    ];
    for frame in &input.frames {
        all.push(&frame.prefix);
        all.push(&frame.table);
        if let Some(a) = &frame.activation {
            all.push(a);
        }
    }
    all.extend(input.calls.iter());
    all.extend(input.filters.iter());
    all.extend(input.funclets.iter());
    all.extend(input.cleanups.iter());
    for landing in &input.landings {
        let (a, b) = extent(landing)?;
        let (c0, d0) = extent(&c.selected_landing)?;
        if a < d0 && c0 < b {
            contained(&c.selected_landing, landing)?;
        } else {
            all.push(landing);
        }
    }
    let mut ranges = Vec::new();
    for r in all {
        let (a, b) = extent(r)?;
        if a < c.module_base || b > module_end || ranges.iter().any(|&(x, y)| a < y && x < b) {
            return Err("dispatch bundle conflicting or outside-module region".into());
        }
        ranges.push((a, b));
    }
    let words = [
        input.cookie_va,
        input.raise_exception_iat,
        input.trace_va,
        input.feature_va,
        c.module_iat,
        c.context_selector,
        c.fill_features[0],
        c.fill_features[1],
        d.rtl_unwind_iat,
        d.notification_words[0],
        d.notification_words[1],
        d.notification_words[2],
    ];
    // Distinct roles cannot share storage. In particular notification stores
    // must not alias guards, IAT cells, feature words or cleanup observations.
    for a in words.into_iter().chain(input.globals.iter().copied()) {
        let b = a.checked_add(4).ok_or("dispatch bundle word overflow")?;
        if !a.is_multiple_of(4)
            || a < c.module_base
            || b > module_end
            || ranges.iter().any(|&(x, y)| a < y && x < b)
        {
            return Err("dispatch bundle aliased/outside-module scalar or IAT".into());
        }
        ranges.push((a, b));
    }
    Ok(ranges)
}

fn trace(
    graph: &local_unwind::ScopeGraph,
    frame: usize,
    before: i32,
    stop: i32,
    after: i32,
) -> Result<Vec<(usize, i32, u32)>, String> {
    let mut at = before;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    while at != -2 && (stop == -2 || (at as u32) > (stop as u32)) {
        if at < 0 || !seen.insert(at) {
            return Err("dispatch bundle cleanup ancestry".into());
        }
        let row = graph
            .rows()
            .get(at as usize)
            .ok_or("dispatch bundle cleanup level")?;
        if row.filter == 0 {
            result.push((frame, at, row.handler));
        }
        at = row.parent;
    }
    if after != at {
        return Err("dispatch bundle cleanup stop mismatch".into());
    }
    Ok(result)
}
fn local_trace(
    plan: &handler_dispatch::DispatchProof,
    graph: &local_unwind::ScopeGraph,
    frame: usize,
) -> Result<Vec<(usize, i32, u32)>, String> {
    let mut result = Vec::new();
    for action in &plan.actions {
        if let handler_dispatch::Action::LocalUnwind {
            before,
            stop,
            after,
            ..
        } = action
        {
            result.extend(trace(graph, frame, *before, *stop, *after)?);
        }
    }
    Ok(result)
}

/// The enclosing compiler already derives `frames`, activation `levels`, filter
/// layouts and selection from original bytes. We check their binding again and
/// compare the separately decoded handler/local-unwind route with that result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_bundle(
    input: &Input,
    c: &Connected,
    d: &Dispatch,
    frames: &[frame_proof::ProvenFrame],
    layouts: &[selection::FilterLayout],
    levels: &[i32],
    selected: &selection::Selection,
) -> Result<Bundle, String> {
    let bound_ranges = regions(input, c, d)?;
    if frames.len() != input.frames.len()
        || frames.len() != layouts.len()
        || frames.len() != levels.len()
        || frames.is_empty()
        || frames.len() > 8
        || selected.selected_frame() >= frames.len()
    {
        return Err("dispatch bundle frame cardinality".into());
    }
    let prefix = handler_checks::prove_prefix(
        &c.handler_prefix.bytes,
        c.handler_prefix.va,
        &handler_checks::Bindings {
            normalizer_va: input.normalizer.va,
            guard_va: c.guard_helper.va,
            context_va: c.context_helper.va,
            cookie_va: input.cookie_va,
            installer_va: input.installer.va,
        },
    )?;
    let suffix_offset = usize::try_from(
        prefix
            .end
            .checked_sub(d.full_handler.va)
            .ok_or("dispatch bundle suffix start")?,
    )
    .map_err(|_| "dispatch bundle suffix offset")?;
    let suffix = d
        .full_handler
        .bytes
        .get(suffix_offset..)
        .filter(|b| !b.is_empty())
        .ok_or("dispatch bundle absent original suffix")?;
    let context = handler_context::prove_context_check(
        &c.context_helper.bytes,
        c.context_helper.va,
        c.context_selector,
    )?;
    let normalizer = selection::prove_code_identity(
        &input.normalizer.bytes,
        input.normalizer.va,
        &BTreeSet::from([input.feature_va]),
        input.event_code,
    )?;
    let notification = unwind_bridges::prove_notification(
        &d.notification.bytes,
        d.notification.va,
        unwind_bridges::NotificationBinding {
            action_word: d.notification_words[0],
            target_word: d.notification_words[1],
            frame_word: d.notification_words[2],
        },
    )?;
    let filter = unwind_bridges::prove_filter(&d.filter_bridge.bytes, d.filter_bridge.va)?;
    let cleanup = unwind_bridges::prove_call(&d.cleanup_bridge.bytes, d.cleanup_bridge.va)?;
    let transfer = unwind_bridges::prove_selected(
        &d.selected_bridge.bytes,
        d.selected_bridge.va,
        d.notification.va,
        &notification,
    )?;
    let global =
        unwind_bridges::prove_global(&d.global_bridge.bytes, d.global_bridge.va, d.rtl_unwind_iat)?;
    let local_bindings = local_unwind::Bindings {
        body: d.local_body.va,
        nested_handler: d.nested_handler.va,
        cookie: input.cookie_va,
        notify: d.notification.va,
        invoke: d.cleanup_bridge.va,
        check_cookie: c.security_helper.va,
    };
    let body = local_unwind::prove(
        &d.local_body.bytes,
        d.local_body.va,
        local_unwind::Kind::Body,
        &local_bindings,
    )?;
    let wrapper = local_unwind::prove(
        &d.local_wrapper.bytes,
        d.local_wrapper.va,
        local_unwind::Kind::Wrapper,
        &local_bindings,
    )?;
    let nested = local_unwind::prove(
        &d.nested_handler.bytes,
        d.nested_handler.va,
        local_unwind::Kind::NestedHandler,
        &local_bindings,
    )?;
    if body.callee_pop_bytes != 0 || wrapper.callee_pop_bytes != 8 || nested.callee_pop_bytes != 0 {
        return Err("dispatch bundle local helper cleanup ABI".into());
    }
    let bindings = handler_dispatch::Bindings {
        filter_bridge: d.filter_bridge.va,
        global_unwind: d.global_bridge.va,
        local_unwind: d.local_wrapper.va,
        guard: c.guard_helper.va,
        selected_transfer: d.selected_bridge.va,
        cookie: input.cookie_va,
    };
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
        .collect::<BTreeMap<_, _>>();
    if filters.len() != input.filters.len() {
        return Err("dispatch bundle duplicate filter identity".into());
    }
    let executable = input
        .filters
        .iter()
        .chain(input.funclets.iter())
        .chain(input.landings.iter())
        .map(|r| r.va)
        .collect::<BTreeSet<_>>();
    let mut plans = Vec::new();
    let mut guard_depth = 0;
    for index in (selected.selected_frame()..frames.len()).rev() {
        let frame = &frames[index];
        let table = &input.frames[index].table;
        if frame.handler_va() != input.handler_va || frame.scope_va() != table.va {
            return Err("dispatch bundle frame handler/table identity".into());
        }
        let header: [i32; 4] = std::array::from_fn(|i| {
            table
                .bytes
                .get(i * 4..i * 4 + 4)
                .and_then(|b| b.try_into().ok())
                .map(i32::from_le_bytes)
                .unwrap_or(i32::MIN)
        });
        let guard = handler_guard::prove_guard(
            &c.guard_helper.bytes,
            c.guard_helper.va,
            &c.security_helper.bytes,
            c.security_helper.va,
            input.cookie_va,
            header,
            frame,
        )?;
        guard_depth = guard_depth.max(guard.temporary_bytes());
        let scope = local_unwind::prove_scope_graph(&table.bytes, &executable)?;
        let search = handler_dispatch::prove_dispatch(
            suffix,
            prefix.end,
            &prefix,
            bindings,
            handler_dispatch::Entry::Search,
            &table.bytes,
            levels[index],
            input.event_code,
            &filters,
            &layouts[index],
            &executable,
        )?;
        let unwind = handler_dispatch::prove_dispatch(
            suffix,
            prefix.end,
            &prefix,
            bindings,
            handler_dispatch::Entry::Unwind {
                flags: handler_dispatch::KnownFlags {
                    mask: u32::MAX,
                    value: 2,
                },
            },
            &table.bytes,
            levels[index],
            input.event_code,
            &filters,
            &layouts[index],
            &executable,
        )?;
        match search.actions.last() {
            Some(handler_dispatch::Action::Transfer { scope, landing, .. })
                if index == selected.selected_frame()
                    && *scope == selected.selected_scope()
                    && *landing == selected.target() => {}
            Some(handler_dispatch::Action::ReturnDisposition { value: 1, .. })
                if index > selected.selected_frame() => {}
            _ => return Err("dispatch bundle search/selection disagreement".into()),
        }
        if !matches!(
            unwind.actions.last(),
            Some(handler_dispatch::Action::ReturnDisposition { value: 1, .. })
        ) {
            return Err("dispatch bundle unwind disposition".into());
        }
        plans.push(FramePlan {
            frame: index,
            search,
            unwind,
            scope,
            guard,
        });
    }
    let mut cleanup_trace = Vec::new();
    for p in &plans {
        cleanup_trace.extend(local_trace(
            if p.frame == selected.selected_frame() {
                &p.search
            } else {
                &p.unwind
            },
            &p.scope,
            p.frame,
        )?);
    }
    if cleanup_trace != selected.cleanups() {
        return Err("dispatch bundle original cleanup/selection trace disagreement".into());
    }

    // Each private helper's stack is added at the actual caller entry depth.
    // Unknown callback implementations and recursive OS delivery have their own
    // typed entry sites, never zero-sized or silently bounded implementations.
    let mut body_depth = body.temporary_bytes;
    for e in &body.effects {
        let child = match e.effect {
            local_unwind::Effect::Notify => notification.temporary_bytes,
            local_unwind::Effect::InvokeFinally => cleanup.temporary_bytes,
            _ => 0,
        };
        body_depth = body_depth.max(add_depth(e.entry_depth, child)?);
    }
    let mut wrapper_depth = wrapper.temporary_bytes;
    for e in &wrapper.effects {
        if e.effect == local_unwind::Effect::LocalUnwind {
            wrapper_depth = wrapper_depth.max(add_depth(e.entry_depth, body_depth)?);
        }
    }
    let mut transfer_depth = transfer.temporary_bytes;
    for call in &transfer.calls {
        transfer_depth =
            transfer_depth.max(add_depth(call.entry_depth, notification.temporary_bytes)?);
    }
    let mut temporary_bytes = prefix.temporary_bytes;
    for call in &prefix.calls {
        let child = match call.effect {
            handler_checks::CallEffect::NormalizeRecordCode => normalizer.temporary_bytes(),
            handler_checks::CallEffect::ValidateGuards => guard_depth,
            handler_checks::CallEffect::ValidateContext => context.temporary_bytes(),
        };
        temporary_bytes = temporary_bytes.max(add_depth(call.entry_depth, child)?);
    }
    let wrapper_body_entry = wrapper
        .effects
        .iter()
        .find(|e| e.effect == local_unwind::Effect::LocalUnwind)
        .ok_or("dispatch bundle wrapper/body call")?
        .entry_depth;
    let body_invoke_entry = body
        .effects
        .iter()
        .find(|e| e.effect == local_unwind::Effect::InvokeFinally)
        .ok_or("dispatch bundle body/finally call")?
        .entry_depth;
    let cleanup_entry = cleanup
        .calls
        .first()
        .ok_or("dispatch bundle cleanup bridge call")?
        .entry_depth;
    let mut nested_temporary_bytes = nested.temporary_bytes;
    for e in &nested.effects {
        if e.effect == local_unwind::Effect::ReenterLocalUnwind {
            nested_temporary_bytes =
                nested_temporary_bytes.max(add_depth(e.entry_depth, body_depth)?);
        }
    }
    let mut callback_sites = Vec::new();
    for p in &plans {
        for plan in [&p.search, &p.unwind] {
            temporary_bytes = temporary_bytes.max(plan.temporary_bytes);
            for action in &plan.actions {
                let (pc, child, callback) = match action {
                    handler_dispatch::Action::Filter { pc, .. } => (
                        *pc,
                        filter.temporary_bytes,
                        Some((
                            CallbackKind::Filter,
                            filter
                                .calls
                                .first()
                                .ok_or("dispatch bundle filter call")?
                                .entry_depth,
                        )),
                    ),
                    handler_dispatch::Action::GlobalUnwind { pc, .. } => (
                        *pc,
                        global.temporary_bytes,
                        Some((
                            CallbackKind::WindowsUnwind,
                            global
                                .calls
                                .first()
                                .ok_or("dispatch bundle Windows call")?
                                .entry_depth,
                        )),
                    ),
                    handler_dispatch::Action::LocalUnwind { pc, .. } => (
                        *pc,
                        wrapper_depth,
                        Some((
                            CallbackKind::Finally,
                            add_depth(
                                wrapper_body_entry,
                                add_depth(body_invoke_entry, cleanup_entry)?,
                            )?,
                        )),
                    ),
                    handler_dispatch::Action::ValidateGuards { pc, .. } => (*pc, guard_depth, None),
                    handler_dispatch::Action::Transfer { pc, .. } => (*pc, transfer_depth, None),
                    _ => continue,
                };
                let entry = plan
                    .call_depths
                    .iter()
                    .find(|&&(at, _)| at == pc)
                    .ok_or("dispatch bundle missing original call depth")?
                    .1;
                temporary_bytes = temporary_bytes.max(add_depth(entry, child)?);
                if let Some((kind, depth)) = callback {
                    callback_sites.push(CallbackSite {
                        kind,
                        entry_depth: add_depth(entry, depth)?,
                    });
                }
            }
        }
    }
    Ok(Bundle {
        bindings,
        local_bindings,
        prefix,
        context,
        normalizer,
        frames: plans,
        body,
        wrapper,
        nested,
        filter,
        transfer,
        global,
        notification,
        cleanup,
        cleanup_trace,
        temporary_bytes,
        callback_sites,
        nested_temporary_bytes,
        bound_ranges,
        external_requirements: EXTERNAL_REQUIREMENTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn region(va: u32) -> Region {
        Region {
            va,
            bytes: vec![0x90; 8],
        }
    }
    fn fixture() -> (Input, Connected, Dispatch) {
        let input = Input {
            cookie_va: 0x7000,
            handler_va: 0x2000,
            frames: vec![super::super::frame_unwind::Frame {
                prefix: region(0x1000),
                table: region(0x1100),
                activation: Some(region(0x1200)),
            }],
            calls: vec![region(0x1300)],
            raise_exception_iat: 0x7004,
            filters: vec![region(0x1400)],
            landings: vec![region(0x4000)],
            funclets: vec![region(0x1500)],
            cleanups: vec![region(0x1600)],
            dispatcher: region(0x1700),
            dispatch_table: region(0x1800),
            trace_va: 0x7008,
            globals: vec![0x700c],
            normalizer: region(0x1900),
            feature_va: 0x7010,
            installer: Region {
                va: 0x2004,
                bytes: vec![0x90; 4],
            },
            restore: region(0x1a00),
            target: region(0x4010),
            event_code: 7,
        };
        let c = Connected {
            initializer: region(0x1b00),
            fill_helper: region(0x1c00),
            fill_features: [0x7014, 0x7018],
            module_iat: 0x701c,
            module_base: 0x1000,
            module_size: 0x7000,
            selected_landing: Region {
                va: 0x4000,
                bytes: vec![0x90; 24],
            },
            handler_prefix: region(0x2000),
            guard_helper: region(0x1d00),
            security_helper: region(0x1e00),
            context_helper: region(0x1f00),
            context_selector: 0x7020,
        };
        let d = Dispatch {
            full_handler: Region {
                va: 0x2000,
                bytes: vec![0x90; 64],
            },
            local_body: region(0x2100),
            local_wrapper: region(0x2200),
            nested_handler: region(0x2300),
            filter_bridge: region(0x2400),
            selected_bridge: region(0x2500),
            global_bridge: region(0x2600),
            notification: region(0x2700),
            cleanup_bridge: region(0x2800),
            rtl_unwind_iat: 0x7024,
            notification_words: [0x7028, 0x702c, 0x7030],
        };
        (input, c, d)
    }
    #[test]
    fn module_binding_requires_exact_original_subregions_and_distinct_roles() {
        let (i, c, d) = fixture();
        let ranges = regions(&i, &c, &d).unwrap();
        assert!(ranges.contains(&(0x2000, 0x2040)));
        assert!(
            !ranges.contains(&(0x2004, 0x2008)),
            "contained installer has one owner"
        );
        for change in 0..10 {
            let (mut i, mut c, mut d) = fixture();
            match change {
                0 => i.handler_va = 0x2010,
                1 => c.handler_prefix.bytes[0] = 0xcc,
                2 => i.installer.bytes[0] = 0xcc,
                3 => d.notification_words[0] = i.cookie_va,
                4 => d.rtl_unwind_iat = c.context_selector,
                5 => d.local_body.va = d.global_bridge.va,
                6 => c.module_size = 0x1000,
                7 => i.target.bytes[1] = 0xcc,
                8 => d.notification_words[2] = u32::MAX - 1,
                9 => i.filters.push(Region {
                    va: d.filter_bridge.va,
                    bytes: d.filter_bridge.bytes.clone(),
                }),
                _ => unreachable!(),
            }
            assert!(regions(&i, &c, &d).is_err(), "binding mutation {change}");
        }
    }
    fn graph(rows: &[(i32, u32, u32)]) -> local_unwind::ScopeGraph {
        let mut bytes = vec![0; 16];
        let mut code = BTreeSet::new();
        for &(parent, filter, handler) in rows {
            bytes.extend(parent.to_le_bytes());
            bytes.extend(filter.to_le_bytes());
            bytes.extend(handler.to_le_bytes());
            code.insert(handler);
            if filter != 0 {
                code.insert(filter);
            }
        }
        local_unwind::prove_scope_graph(&bytes, &code).unwrap()
    }
    #[test]
    fn original_unsigned_stop_is_not_replaced_by_ancestor_equality() {
        // Acyclic but deliberately nonmonotone numbering: 3 -> 0 -> 2 -> -2.
        // Original unsigned compare with target1 stops at0, before that row's
        // callback. An ancestry-until-equality implementation would misexecute.
        let g = graph(&[
            (2, 0, 0x1000),
            (-2, 0x1200, 0x1300),
            (-2, 0, 0x1400),
            (0, 0, 0x1500),
        ]);
        assert_eq!(trace(&g, 4, 3, 1, 0).unwrap(), vec![(4, 3, 0x1500)]);
        assert!(trace(&g, 4, 3, 1, 1).is_err());
        assert_eq!(
            trace(&g, 4, 3, -2, -2).unwrap(),
            vec![(4, 3, 0x1500), (4, 0, 0x1000), (4, 2, 0x1400)]
        );
        assert!(trace(&g, 4, -1, -2, -2).is_err());
    }
    #[test]
    fn local_trace_retains_original_order_and_requires_matching_after_state() {
        let g = graph(&[(-2, 0, 0x1000), (0, 0x1100, 0x1200), (1, 0, 0x1300)]);
        let plan = handler_dispatch::DispatchProof {
            event_code: 0,        // Routing-only fixture; no normalizer composition.
            source_table: vec![], // Scratch-accounting fixture, not an emission certificate.
            actions: vec![handler_dispatch::Action::LocalUnwind {
                pc: 0x4000,
                target: 0x5000,
                arguments: vec![],
                before: 2,
                stop: -2,
                after: -2,
            }],
            instructions: vec![],
            final_level: -2,
            temporary_bytes: 0,
            call_depths: vec![],
            unexecuted_calls: vec![],
        };
        assert_eq!(
            local_trace(&plan, &g, 7).unwrap(),
            vec![(7, 2, 0x1300), (7, 0, 0x1000)]
        );
        assert_eq!(EXTERNAL_REQUIREMENTS.len(), 5);
    }
}
