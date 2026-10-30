//! Connect a completed original Main return to one pre-bound CRT instance.
//! This grants local teardown authority only. It does not replace the original
//! exit callback traversal, flush instructions, or Windows process termination.
pub(crate) const EMITTED_TYPES: &str = r#"
struct CrtReturnBinding {
 anchor:guest_memory::Capability,thread:u64,registry:RegistryIdentity,
 owner:u64,event:u64,frame:FrameId,
}
impl CrtReturnBinding {
 /// Bind before Main's normal-return session starts, while its finished event
 /// and linked selected frame still identify the stream caller. Equal numeric
 /// owner/thread labels do not make separate memory arenas interchangeable.
 fn bind(runtime:&CrtStreamRuntime,machine:&Machine,registry:&ThreadRegistry,event:&OwnedExceptionEvent)->Result<Self,&'static str>{
  registry.available()?;
  let binding=machine.owned_binding(machine.selected).map_err(|_|"CRT return binding selected frame")?;
  let registration=registry.registration(binding)?;
  if machine.phase!=Phase::Done||!machine.owned_storage||!machine.explicit_dispatch
   ||event.captured.lifetime.get()!=EventLifetime::Finished||event.identity.owner!=machine.owner()
   ||event.identity.event!=machine.event||event.identity.registry!=registry.identity
   ||registry.target_ready()?!=registration||runtime.owner!=machine.owner()
   ||runtime.thread!=registry.identity.instance||runtime.initialization.is_some()
   ||runtime.shutdown.is_some()||runtime.closed||!runtime.locks.is_empty()||!runtime.descriptor_locks.is_empty(){
   return Err("CRT return binding unfinished event/runtime identity/phase");
  }
  runtime.identity_range(runtime.file(),0)?;
  Ok(Self{anchor:runtime.anchor,thread:runtime.thread,registry:registry.identity,
   owner:machine.owner(),event:machine.event,frame:binding.frame})
 }
 /// Consumes both independent lifecycle authorities. Validation happens before
 /// the CRT phase change, with no synthesized successful flush or exit result.
 fn begin(self,runtime:&mut CrtStreamRuntime,machine:&Machine,registry:&ThreadRegistry,receipt:NormalReturnReceipt)->Result<CrtShutdown,&'static str>{
  if runtime.anchor!=self.anchor||runtime.thread!=self.thread||runtime.owner!=self.owner
   ||registry.identity!=self.registry||receipt.registry!=self.registry||receipt.owner!=self.owner
   ||receipt.event!=self.event||receipt.frame!=self.frame{
   return Err("CRT return receipt foreign runtime/event/frame");
  }
  registry.validate_returned_event(machine,self.owner,self.event,self.frame)?;
  let context=machine.owned_context.ok_or("CRT returned context absent")?;
  if context!=receipt.context||context[0]!=Some(receipt.value)||context[4]!=Some(receipt.caller_sp){
   return Err("CRT return receipt observed value/stack mismatch");
  }
  runtime.begin_shutdown(CrtShutdownReceipt{anchor:self.anchor,thread:self.thread,event:self.event})
 }
}
"#;
