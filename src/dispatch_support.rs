//! Emit shared effect adapters around the original instruction certificates.
use super::{
    dispatch_contract::{Bundle, Dispatch},
    frame_unwind::Input,
};

pub(crate) fn emit(
    input: &Input,
    d: &Dispatch,
    b: &Bundle,
    owned_arms: &str,
) -> Result<String, String> {
    let mut s = String::new();
    s.push_str(super::thread_registry::EMITTED_TYPES);
    s.push_str(super::local_unwind::EMITTED_TYPES);
    s.push_str(super::unwind_bridges::EMITTED_TYPES);
    s.push_str(super::dispatch_execution::EMITTED_TYPES);
    for (name, proof) in [
        ("filter", &b.filter),
        ("selected", &b.transfer),
        ("global", &b.global),
        ("cleanup", &b.cleanup),
    ] {
        s.push_str(&format!("fn original_{name}_bridge(registers:&DispatchPacket,mut invoke:impl FnMut(BridgeCall,&BridgeValue<DispatchCapability>,&DispatchPacket,&[BridgeValue<DispatchCapability>],Option<u32>)->Result<BridgeReply<DispatchCapability>,&'static str>)->Result<BridgeExit<DispatchCapability>,&'static str>{{type T=DispatchCapability;{}}}\n",proof.body()));
    }
    s.push_str(&format!("fn original_notification(registers:&DispatchPacket,argument:&BridgeValue<DispatchCapability>,mut store:impl FnMut(u32,&BridgeValue<DispatchCapability>)->Result<(),&'static str>)->Result<BridgeExit<DispatchCapability>,&'static str>{{type T=DispatchCapability;{}}}\n",b.notification.body()));
    s.push_str(&format!("fn original_local_body(effects:&mut impl LocalUnwindEffects,target_level:i32,exception_flags:u32)->Result<Option<i32>,&'static str>{{{}}}\n",b.body.source));
    s.push_str(&format!("fn original_local_wrapper(effects:&mut impl LocalUnwindEffects,target_level:i32,exception_flags:u32)->Result<Option<i32>,&'static str>{{{}}}\n",b.wrapper.source));
    let binding_arms = b
        .cleanup_trace
        .iter()
        .enumerate()
        .map(|(action, (frame, scope, handler))| format!("({frame},{scope},{handler})=>{action},"))
        .collect::<String>();
    let mut local_arms = String::new();
    for p in &b.frames {
        let rows = p
            .scope
            .rows()
            .iter()
            .map(|r| {
                format!(
                    "LocalScope{{parent:{},filter:{},handler:{}}}",
                    r.parent, r.filter, r.handler
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        local_arms.push_str(&format!(
            "{}=>({},vec![{}]),",
            p.frame, input.frames[p.frame].table.va, rows
        ));
    }
    let body_call = b
        .wrapper
        .effects
        .iter()
        .find(|e| e.effect == super::local_unwind::Effect::LocalUnwind)
        .ok_or("dispatcher wrapper missing body effect")?;
    let mut call_depths = Vec::new();
    for p in &b.frames {
        for plan in [&p.search, &p.unwind] {
            for a in &plan.actions {
                if let super::handler_dispatch::Action::LocalUnwind {
                    pc,
                    before,
                    stop,
                    after,
                    ..
                } = a
                {
                    let depth = plan
                        .call_depths
                        .iter()
                        .find(|(at, _)| at == pc)
                        .ok_or("dispatcher local call depth")?
                        .1;
                    call_depths.push(format!(
                        "({},{before},{stop},{after})=>{},",
                        p.frame,
                        depth
                            .checked_add(body_call.entry_depth)
                            .ok_or("dispatcher body depth")?
                    ));
                }
            }
        }
    }
    let local_depths = call_depths.join("");
    let nested = d.nested_handler.va;
    let cookie_address = input.cookie_va;
    let notification_va = d.notification.va;
    s.push_str(&format!(r#"
fn complete_unwind_frame(registry:&mut ThreadRegistry,id:RegistrationId,receipt:HandlerCompletion,image:&FrameImage<RegistryHead>)->Result<(),&'static str>{{
 // Normal form of an opaque predecessor effect: admitted guest callbacks
 // cannot observe whether Windows unlinks immediately before or after them.
 // This does not assert equality of intermediate raw Windows FS traces.
 registry.unlink_head(id)?;registry.retire_frame(receipt,image)
}}
fn notify_original(frame:usize,binding:OwnedFrameBinding,target:u32,reason:u32,notification:&std::cell::RefCell<NotificationState>,owner:u64)->Result<(),&'static str>{{
 let mut registers=unknown_packet();registers[0]=BridgeValue::Capability(DispatchCapability::Code{{owner,frame,address:target}});
 registers[5]=BridgeValue::Capability(DispatchCapability::Frame{{owner,index:frame,binding}});
 let mut state=notification.try_borrow_mut().map_err(|_|"notification alias")?;
 let BridgeExit::Return{{cleanup,..}}=original_notification(&registers,&BridgeValue::Scalar(reason),|address,value|state.store(address,value))? else{{return Err("notification original return");}};
 if cleanup!=4{{return Err("notification original stack effect");}}state.require(owner,frame,binding,target,reason)
}}
fn execute_selected_bridge(frame:usize,landing:u32,binding:OwnedFrameBinding,notification:&std::cell::RefCell<NotificationState>,owner:u64)->Result<(),&'static str>{{
 let mut registers=unknown_packet();let target=BridgeValue::Capability(DispatchCapability::Code{{owner,frame,address:landing}});
 let frame_value=BridgeValue::Capability(DispatchCapability::Frame{{owner,index:frame,binding}});
 registers[1]=target.clone();registers[2]=frame_value.clone();
 let BridgeExit::Jump{{registers,target:actual}}=original_selected_bridge(&registers,|kind,target,entry,args,resume|{{
  if kind!=BridgeCall::Notification||target!=&BridgeValue::Scalar({notification_va})||args!=[BridgeValue::Scalar(1)]||resume.is_some(){{return Err("selected notification binding");}}
  let BridgeExit::Return{{mut registers,cleanup}}=original_notification(entry,&args[0],|address,value|notification.try_borrow_mut().map_err(|_|"notification alias")?.store(address,value))? else{{return Err("selected notification return");}};
  if cleanup!=4{{return Err("selected notification cleanup");}}
  if registers[4]!=BridgeValue::PrivateStack(0){{return Err("notification relative return stack");}}
  registers[4]=entry[4].clone();
  Ok(BridgeReply{{registers:call_return(registers,4+cleanup)?,resume:None}})
 }})? else{{return Err("selected original nonlocal jump");}};
 if actual!=target||registers[5]!=frame_value||registers[6]!=target||[0usize,1,2,3,7].into_iter().any(|i|registers[i]!=BridgeValue::Scalar(0)){{return Err("selected original clobber/target contract");}}
 notification.try_borrow().map_err(|_|"notification alias")?.require(owner,frame,binding,landing,1)
}}
fn execute_original_finally(frame:usize,handler:u32,scope:i32,image:&mut FrameImage<RegistryHead>,machine:&mut Machine,binding:OwnedFrameBinding,ordinary:&[i32],mut globals:&mut Vec<Option<u32>>,notification:&std::cell::RefCell<NotificationState>,owner:u64)->Result<(),&'static str>{{
 notification.try_borrow().map_err(|_|"notification alias")?.require(owner,frame,binding,handler,0x101)?;
 let action=match(frame,scope,handler){{{binding_arms}_=>return Err("unbound original finally")}};
 let request=machine.next_cleanup().map_err(|_|"original finally phase")?.ok_or("original finally missing request")?;
 if request.action()!=action{{return Err("original finally action order");}}
 let mut registers=unknown_packet();let target=BridgeValue::Capability(DispatchCapability::Code{{owner,frame,address:handler}});
 registers[0]=target.clone();registers[5]=BridgeValue::Capability(DispatchCapability::Frame{{owner,index:frame,binding}});
 let mut performed=false;
 let BridgeExit::Return{{cleanup,..}}=original_cleanup_bridge(&registers,|kind,actual,entry,args,resume|{{
  if performed||kind!=BridgeCall::Cleanup||actual!=&target||!args.is_empty()||resume.is_some()||entry[5]!=registers[5]{{return Err("finally bridge authority");}}
  performed=true;
  machine.execute_owned_cleanup(request,|lease,trace|{{
   let lease_scope=lease.scope();let lease_action=lease.action();
   if lease.frame_index()!=frame{{return Err(Error::Identity);}}lease.bind_storage(binding)?;
   let memory=&mut FrameMemory::new(image,binding.owner(),ordinary).map_err(|_|Error::Identity)?;
   lease.perform(||{{match action{{{owned_arms}_=>return Err(Error::Order)}}Ok(())}})
  }}).map_err(|_|"original finally owned effects")?;
  let mut reply=unknown_packet();reply[4]=call_return(entry.clone(),4)?[4].clone();Ok(BridgeReply{{registers:reply,resume:None}})
 }})? else{{return Err("original finally return");}};
 if !performed||cleanup!=0{{return Err("original finally completion");}}Ok(())
}}
struct LocalWrapper<F>{{invoke:F}}
impl<F:FnMut(i32)->Result<(),&'static str>> LocalUnwindEffects for LocalWrapper<F>{{
 fn local_unwind(&mut self,target:i32)->Result<(),&'static str>{{(self.invoke)(target)}}
 fn install_temporary(&mut self,_:u32,_:u32)->Result<(),&'static str>{{Err("wrapper unexpected FS effect")}}
 fn restore_previous_head(&mut self)->Result<(),&'static str>{{Err("wrapper unexpected FS effect")}}
 fn decode_scope(&mut self)->Result<(),&'static str>{{Err("wrapper unexpected scope effect")}}
 fn read_try_level(&mut self)->Result<i32,&'static str>{{Err("wrapper unexpected scope effect")}}
 fn scope_row(&mut self,_:i32)->Result<LocalScope,&'static str>{{Err("wrapper unexpected scope effect")}}
 fn write_try_level(&mut self,_:i32)->Result<(),&'static str>{{Err("wrapper unexpected scope effect")}}
 fn notify(&mut self,_:u32,_:u32)->Result<(),&'static str>{{Err("wrapper unexpected notification")}}
 fn invoke_finally(&mut self,_:u32,_:u32)->Result<(),&'static str>{{Err("wrapper unexpected callback")}}
 fn check_temporary_cookie(&mut self)->Result<(),&'static str>{{Err("wrapper unexpected nested effect")}}
 fn reenter_local_unwind(&mut self)->Result<(),&'static str>{{Err("wrapper unexpected nested effect")}}
 fn write_collided_record(&mut self)->Result<(),&'static str>{{Err("wrapper unexpected nested effect")}}
}}
#[allow(clippy::too_many_arguments)]
fn execute_local_frame(frame:usize,stop:i32,before:i32,after:i32,registry:&mut ThreadRegistry,image:&mut FrameImage<RegistryHead>,machine:&mut Machine,binding:OwnedFrameBinding,ordinary:&[i32],globals:&mut Vec<Option<u32>>,notification:&std::cell::RefCell<NotificationState>,owner:u64,cookie:u32,handler_sp:u32)->Result<(),&'static str>{{
 if image.try_level!=before{{return Err("original local entry level");}}
 let(scope_address,rows)=match frame{{{local_arms}_=>return Err("original local frame")}};
 let depth=match(frame,before,stop,after){{{local_depths}_=>return Err("original local call site")}};
 let body_entry=handler_sp.checked_sub(depth).ok_or("original local call depth")?;
 let id=registry.registration(binding)?;
 let entry=LocalEntry{{entry_sp:body_entry,handler:{nested},cookie_address:{cookie_address},cookie,target_level:stop}};
 let mut invoked=false;
 let mut wrapper=LocalWrapper{{invoke:|target:i32|{{
  if invoked||target!=stop{{return Err("original local wrapper argument/order");}}invoked=true;
  registry.execute_local(id,image,entry,|record,image|{{
   let mut effects=OriginalLocal{{record,image,owner,frame,binding,ordinary,scope_address,rows:&rows,pending:None,written:false,notified:false,
    finally:|handler,scope,image:&mut FrameImage<RegistryHead>|execute_original_finally(frame,handler,scope,image,machine,binding,ordinary,globals,notification,owner),
    notification:|handler,reason|notify_original(frame,binding,handler,reason,notification,owner)}};
   if original_local_body(&mut effects,target,0)?.is_some(){{return Err("original local fabricated result");}}Ok(())
  }})
 }}}};
 if original_local_wrapper(&mut wrapper,stop,0)?.is_some(){{return Err("original wrapper fabricated result");}}
 if !invoked||image.try_level!=after{{return Err("original local required postcondition");}}Ok(())
}}
"#));
    Ok(s)
}
