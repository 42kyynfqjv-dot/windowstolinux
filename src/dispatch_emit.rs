//! Emit the instruction-derived handler action stream under an explicit closed
//! callback / opaque predecessor boundary. No host dispatcher is inferred here.
use super::{
    dispatch_contract::{Bundle, Dispatch, FramePlan},
    handler_dispatch::Action,
};
use std::collections::BTreeMap;

fn guard(frame: usize, image: &str) -> String {
    format!("{{let memory=&FrameMemory::new({image},owner,&ordinary[{frame}])?;guard_{frame}(memory,cookie)?;}}\n")
}
fn prefix(frame: usize, image: &str) -> String {
    format!("if normalize(event_code,feature)?!=event_code{{return Err(\"dispatch normalizer identity\");}}\n{}thread_context.check(owner,selector)?;\n",guard(frame,image))
}
fn local(
    action: &Action,
    frame: usize,
    image: &str,
    registry: &str,
    sp: &str,
) -> Result<String, String> {
    let Action::LocalUnwind {
        before,
        stop,
        after,
        ..
    } = action
    else {
        return Err("dispatch emit local action".into());
    };
    Ok(format!("execute_local_frame({frame},{stop},{before},{after},{registry},{image},&mut machine,bindings[{frame}],&ordinary[{frame}],&mut globals,&notification,owner,cookie,{sp})?;\n"))
}
fn emit_unwind(plan: &FramePlan) -> Result<String, String> {
    let frame = plan.frame;
    let mut out = prefix(frame, "&mut *image");
    if !matches!(
        plan.unwind.actions.last(),
        Some(Action::ReturnDisposition { value: 1, .. })
    ) {
        return Err("dispatch emit unwind exit".into());
    }
    for (index, action) in plan.unwind.actions.iter().enumerate() {
        match action {
            Action::LocalUnwind { .. } => out.push_str(&local(
                action,
                frame,
                "&mut *image",
                "&mut *registry",
                "nested_handler_sp",
            )?),
            Action::ValidateGuards { .. } => out.push_str(&guard(frame, "&mut *image")),
            Action::ReturnDisposition { value: 1, .. }
                if index + 1 == plan.unwind.actions.len() =>
            {
                out.push_str("Ok(1u32)\n")
            }
            _ => return Err("dispatch emit unclosed unwind action".into()),
        }
    }
    Ok(format!(
        r#"
{{
 let id=registrations[{frame}];
 let(disposition,completion)=registry.execute_handler(id,&mut images[{frame}],|registry,image|{{
  {out}
 }})?;
 if disposition!=1{{return Err("original unwind disposition");}}
 // This normal form is justified only by opaque predecessor effects and
 // non-raising callbacks; it does not assert intermediate Windows FS values.
 complete_unwind_frame(&mut registry,id,completion,&images[{frame}])?;
 machine.retire_dispatched(bindings[{frame}]).map_err(|_|"dispatch frame retirement")?;
}}
"#
    ))
}
fn selected_tail(plan: &FramePlan, start: usize) -> Result<String, String> {
    let frame = plan.frame;
    let mut body = String::new();
    for (index, action) in plan.search.actions.iter().enumerate().skip(start) {
        match action {
            Action::LocalUnwind{..}=>body.push_str(&local(action,frame,"&mut *image","&mut *registry","handler_sp")?),
            Action::StoreTryLevel{before,after,..}=>body.push_str(&format!("if image.try_level!={before}{{return Err(\"selected stale TryLevel\");}}FrameMemory::new(&mut *image,owner,&ordinary[{frame}])?.write_try_level({after})?;\n")),
            Action::ValidateGuards{..}=>body.push_str(&guard(frame,"&mut *image")),
            Action::Transfer{landing,..} if index+1==plan.search.actions.len()=>body.push_str(&format!("execute_selected_bridge({frame},{landing},bindings[{frame}],&notification,owner)?;Ok(())\n")),
            _=>return Err("dispatch emit unclosed selected continuation".into()),
        }
    }
    if !matches!(plan.search.actions.last(), Some(Action::Transfer { .. })) {
        return Err("dispatch emit absent selected transfer".into());
    }
    Ok(format!(
        r#"
if registry.target_ready()?!=registrations[{frame}]{{return Err("dispatch target readiness");}}
let(_,selected_completion)=registry.execute_handler(registrations[{frame}],&mut images[{frame}],|registry,image|{{
 {body}
}})?;
let _=selected_completion; // Selected registration stays live after its jump.
machine.finish_selected_dispatch(bindings[{frame}]).map_err(|_|"selected dispatch phase")?;
"#
    ))
}

/// The caller supplies original filter snippets indexed by proven frame/scope.
/// The output consumes the Bundle's actual decoded actions. The runtime adapter
/// must close its external requirements; this function is not PE admission.
pub(crate) fn emit_control(
    bundle: &Bundle,
    d: &Dispatch,
    selected: usize,
    filters: &BTreeMap<(usize, i32), String>,
) -> Result<String, String> {
    if bundle.frames.is_empty()
        || bundle.frames.last().map(|p| p.frame) != Some(selected)
        || bundle
            .frames
            .windows(2)
            .any(|w| w[0].frame.checked_sub(1) != Some(w[1].frame))
    {
        return Err("dispatch emit frame plan order".into());
    }
    let selected_plan = bundle.frames.last().unwrap();
    let globals = selected_plan
        .search
        .actions
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, Action::GlobalUnwind { .. }))
        .collect::<Vec<_>>();
    if globals.len() != 1 {
        return Err("dispatch emit unique selected global unwind".into());
    }
    let (global_index, global_action) = globals[0];
    let Action::GlobalUnwind {
        preserved_level, ..
    } = global_action
    else {
        unreachable!()
    };
    let call = bundle
        .global
        .calls
        .first()
        .ok_or("dispatch emit global call certificate")?;
    let continuation = call
        .continuation
        .ok_or("dispatch emit original unwind continuation")?;
    let nested_depth = bundle
        .temporary_bytes
        .checked_add(4)
        .ok_or("dispatch emit nested scratch overflow")?;
    let mut out = format!("let _containment=registry.contain(registrations[{selected}])?;\n");
    let mut consumed = BTreeMap::new();
    for plan in &bundle.frames {
        let frame = plan.frame;
        out.push_str(&format!(
            "registry.validate_frame(registrations[{frame}],&images[{frame}])?;\n"
        ));
        out.push_str(&prefix(frame, &format!("&mut images[{frame}]")));
        for (index, action) in plan.search.actions.iter().enumerate() {
            if frame == selected && index >= global_index {
                break;
            }
            match action {
                Action::Filter { scope, .. } => {
                    let key = (frame, *scope);
                    let code = filters
                        .get(&key)
                        .ok_or("dispatch emit missing original filter body")?;
                    if consumed.insert(key, ()).is_some() {
                        return Err("dispatch emit repeated filter body authority".into());
                    }
                    out.push_str(code);
                }
                Action::ValidateGuards { .. } => {
                    out.push_str(&guard(frame, &format!("&mut images[{frame}]")))
                }
                Action::ReturnDisposition { value: 1, .. }
                    if frame != selected && index + 1 == plan.search.actions.len() => {}
                _ => return Err("dispatch emit unclosed search action".into()),
            }
        }
    }
    if consumed.len() != filters.len() {
        return Err("dispatch emit unused filter body authority".into());
    }
    let mut younger = String::new();
    for plan in bundle.frames.iter().filter(|p| p.frame > selected) {
        younger.push_str(&emit_unwind(plan)?);
    }
    out.push_str(&format!(r#"
{{
 if images[{selected}].try_level!={preserved_level}{{return Err("global unwind selected TryLevel");}}
 let target_frame=BridgeValue::Capability(DispatchCapability::Frame{{owner,index:{selected},binding:bindings[{selected}]}});
 let record=BridgeValue::Capability(DispatchCapability::Exception{{owner,event:event_code}});
 let mut registers=unknown_packet();registers[1]=target_frame.clone();registers[2]=record.clone();
 let nested_handler_sp=handler_sp.checked_sub({nested_depth}).ok_or("nested handler scratch underflow")?;
 let BridgeExit::Return{{registers:returned,cleanup}}=original_global_bridge(&registers,|kind,target,entry,args,resume|{{
  if kind!=BridgeCall::GlobalUnwind||target!=&BridgeValue::Scalar({iat})||resume!=Some({continuation})
   ||args!=[target_frame.clone(),BridgeValue::Scalar({continuation}),record.clone(),BridgeValue::Scalar(0)]{{return Err("original RtlUnwind call binding");}}
  {younger}
  registry.validate_frame(registrations[{selected}],&images[{selected}])?;
  if images[{selected}].try_level!={preserved_level}{{return Err("RtlUnwind target frame preservation");}}
  let mut reply=unknown_packet();reply[0]=BridgeValue::Scalar(0);reply[4]=call_return(entry.clone(),20)?[4].clone();
  Ok(BridgeReply{{registers:reply,resume:Some({continuation})}})
 }})? else{{return Err("original global wrapper continuation");}};
 if cleanup!=0||returned[0]!=BridgeValue::Scalar(0){{return Err("original global wrapper return");}}
}}
"#,iat=d.rtl_unwind_iat));
    out.push_str(&selected_tail(selected_plan, global_index + 1)?);
    Ok(out)
}
