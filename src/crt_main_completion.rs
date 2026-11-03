//! Single owner for original completion, live bytes, native calls and return effects.
//! Formatter binding remains an explicit compiler contract, not a symbol shortcut.
pub(crate) const EMITTED_TYPES: &str = r#"
struct CrtMainCompletion<'a,F>{rt:&'a mut CrtStreamRuntime,storage:&'a mut CrtOwnedStorage,cpu:&'a mut CrtCpu,session:NormalReturnSession<'a>,globals:Vec<CrtPointer>,format:CrtPointer,printf_pc:u32,printf_target:u32,security_continuation:u32,security:fn(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>,printf:F}
impl<'a,F> CrtMainCompletion<'a,F> where F:FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&mut NormalReturnSession<'a>,PrintRequest<'_>)->RegistryResult<CrtValue>{
 fn frame_pointer(&self)->u32{self.storage.image.ebp}
 fn stack_pointer(&self)->u32{self.storage.image.esp}
 fn key(&self,o:i32)->RegistryResult<i32>{i32::try_from(i64::from(self.frame_pointer())+i64::from(o)-i64::from(self.storage.image.entry_sp)).map_err(|_|"completion live key")}
 fn at(&self,o:i32)->RegistryResult<CrtPointer>{if o%4!=0||!self.storage.ordinary.contains(&o){return Err("completion live ordinary word");}let p=self.rt.offset(self.storage.entry,i64::from(self.key(o)?))?;self.rt.valid(p,4)?;Ok(p)}
 fn preflight_call_stack(&self,n:u32)->RegistryResult<()>{self.cpu.validate_active(self.rt)?;if n>128||n%4!=0||self.cpu.return_id!=self.storage.return_id||self.cpu.r[4]!=CrtValue::Pointer(self.rt.resolve_absolute(self.stack_pointer(),CrtRegionKind::Stack)?)||self.session.phase!=NormalReturnPhase::Linked{return Err("completion live call entry");}let p=self.rt.offset(CrtCpu::pointer(self.cpu.r[4])?,-i64::from(n))?;self.rt.valid(p,n)?;self.session.registry.range(p.address(),u64::from(self.stack_pointer()))?;if !self.rt.overlapping_tags(p.address(),n).is_empty(){return Err("completion live call scratch");}Ok(())}
 fn cookie(&self)->RegistryResult<u32>{self.rt.load(self.rt.resolve_absolute(self.session.registry.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()}
 fn read_global(&self,i:usize)->RegistryResult<u32>{let p=*self.globals.get(i).ok_or("completion live global index")?;if p.kind!=CrtRegionKind::Module{return Err("completion live global role");}self.rt.load(p,32)?.known_scalar()}
 fn read_u32(&self,o:i32)->RegistryResult<u32>{self.rt.load(self.at(o)?,32)?.known_scalar()}
 fn write_u32(&mut self,o:i32,n:u32)->RegistryResult<()>{let p=self.at(o)?;if !self.rt.overlapping_tags(p.address(),4).is_empty(){return Err("completion live scalar/typed overwrite");}self.rt.store(p,32,CrtValue::scalar(n))}
 fn read_stack(&self,o:i32)->RegistryResult<u32>{let p=CrtCpu::pointer(self.rt.load(self.at(o)?,32)?)?;if p.kind!=CrtRegionKind::Stack||p.cap!=self.storage.entry.cap{return Err("completion live stack provenance");}self.rt.valid(p,0)?;Ok(p.address())}
 fn read_module(&self,o:i32)->RegistryResult<u32>{let p=CrtCpu::pointer(self.rt.load(self.at(o)?,32)?)?;if p.kind!=CrtRegionKind::Module{return Err("completion live module provenance");}self.rt.valid(p,1)?;Ok(p.address())}
 fn read_continuation(&self,o:i32)->RegistryResult<u32>{self.read_module(o)}
 fn protected(&self,o:i32)->RegistryResult<CrtValue>{let key=self.key(o)?;let v=*self.storage.protected.get(&key).ok_or("completion live protected metadata")?;let p=self.rt.offset(self.storage.entry,i64::from(key))?;if self.rt.load(p,32)?!=v{return Err("completion live protected corruption");}Ok(v)}
 fn read_predecessor(&self,o:i32)->RegistryResult<RegistryHead>{let key=self.key(o)?;let p=match self.storage.image.words.get(&key){Some(FrameWord::Borrowed(p))=>*p,_=>return Err("completion live predecessor")};if !matches!(self.protected(o)?,CrtValue::ThreadHead(_)){return Err("completion live thread tag");}Ok(p)}
 fn read_saved(&self,o:i32,reg:u8)->RegistryResult<Option<u32>>{let key=self.key(o)?;let v=match self.storage.image.words.get(&key){Some(FrameWord::Saved(r,v))if *r==reg=>*v,_=>return Err("completion live saved schema")};let actual=self.protected(o)?;if v.is_some()&&actual.known_scalar().ok()!=v{return Err("completion live saved bits");}Ok(v)}
 fn read_guard(&self,o:i32)->RegistryResult<(u32,u32,u32)>{let key=self.key(o)?;let triple=match self.storage.image.words.get(&key){Some(FrameWord::Guard{frame,cookie,bits})=>(*frame,*cookie,*bits),_=>return Err("completion live guard schema")};if self.protected(o)?.known_scalar()?!=triple.2{return Err("completion live guard bits");}Ok(triple)}
 fn require_return(&self,o:i32)->RegistryResult<()>{if self.key(o)?!=0||self.protected(o)?!=CrtValue::ProtectedReturn(self.storage.return_id)||self.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.storage.return_id)).count()!=1{return Err("completion live return root");}Ok(())}
 fn push(&mut self,n:u32,is_format:bool)->RegistryResult<()>{let v=if is_format{if n!=self.format.address()||self.format.kind!=CrtRegionKind::Module{return Err("completion live format identity");}CrtValue::Pointer(self.format)}else{CrtValue::scalar(n)};self.cpu.push(self.rt,v)}
 fn scalar_register(&mut self,i:usize,n:u32)->RegistryResult<()>{if i>=8||i==4||i==5{return Err("completion live register index");}self.cpu.r[i]=CrtValue::scalar(n);Ok(())}
 fn unknown_flags(&mut self){self.cpu.flags=CrtFlags::unknown();}
 fn cleanup(&mut self,n:u32)->RegistryResult<()>{let expected=self.cpu.binary(self.rt,1,self.cpu.r[4],CrtValue::scalar(n),32)?;self.cpu.discard(self.rt,n)?;if self.cpu.r[4]!=expected{return Err("completion live cleanup result");}Ok(())}
 fn restore_frame_stack(&mut self)->RegistryResult<()>{self.cpu.r[4]=CrtValue::Pointer(self.rt.resolve_absolute(self.frame_pointer(),CrtRegionKind::Stack)?);Ok(())}
 fn printf(&mut self,request:PrintRequest<'_>)->RegistryResult<Option<u32>>{if request.call_pc!=self.printf_pc||request.target!=self.printf_target||request.format!=self.format.address(){return Err("completion live printf binding");}let p=CrtCpu::pointer(self.cpu.r[4])?;if self.rt.load(p,32)?!=CrtValue::Pointer(self.format){return Err("completion live format stack");}for(i,&n)in request.arguments.iter().enumerate(){if self.rt.load(self.rt.offset(p,4+i as i64*4)?,32)?!=CrtValue::scalar(n){return Err("completion live variadic stack");}}let f=&mut self.printf;let session=&mut self.session;let value=self.cpu.call_activation(self.rt,request.call_pc.checked_add(5).ok_or("completion printf continuation")?,0,|rt,cpu|f(rt,cpu,session,request))?;Ok(value.known_scalar().ok())}
 fn effect(&mut self,effect:CompletionEffect<'_,RegistryHead>)->RegistryResult<()>{match &effect{
 CompletionEffect::RestorePredecessor(p)=>{if self.read_predecessor(i32::try_from(i64::from(self.storage.image.record)-i64::from(self.frame_pointer())).map_err(|_|"completion live predecessor offset")?)?!=**p{return Err("completion live FS predecessor");}},
 CompletionEffect::Pop{offset,register,..}=>{let expected=self.protected(*offset)?;let p=self.rt.resolve_absolute(frame_address(self.frame_pointer(),*offset)?,CrtRegionKind::Stack)?;if self.cpu.r[4]!=CrtValue::Pointer(p)||self.rt.load(p,32)?!=expected{return Err("completion live POP position");}let v=self.cpu.pop(self.rt)?;self.cpu.r[*register as usize]=v;},
 CompletionEffect::Cookie{offset,frame,cookie,bits,target}=>{if self.read_guard(*offset)?!=(*frame,*cookie,*bits)||self.cookie()?!=*cookie||*target!=self.session.plan.security_target{return Err("completion live security check");}self.cpu.call_activation(self.rt,self.security_continuation,0,self.security)?;},
 CompletionEffect::Return{value,..}=>{self.require_return(4)?;self.cpu.r[0]=CrtValue::scalar(*value);self.cpu.finish(self.rt)?;},
 }self.session.apply(effect)}
 fn finish(&mut self,outcome:&CompletionOutcome<RegistryHead>)->RegistryResult<NormalReturnReceipt>{self.session.finish(outcome)}
}
"#;

pub(crate) fn emit_security(code: &[u8], origin: u32) -> Result<String, String> {
    let proof = super::crt_stream_callees::prove_security(code, origin)?;
    let graph = super::crt_stream_ir::Graph::decode_linear_fragment(&code[..6], origin)?;
    let roles =
        std::collections::BTreeMap::from([(proof.cookie(), "CrtRegionKind::Module".to_string())]);
    let body = super::crt_stream_emit::emit_linear_fragment(&graph, &roles)?;
    Ok(format!(
        r#"fn completion_security_cmp(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{body}}}
fn original_completion_security(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;let p=rt.resolve_absolute({origin},CrtRegionKind::Module)?;for(i,b)in {code:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("completion changed security code");}}}}completion_security_cmp(rt,cpu)?;if !cpu.condition(0)?{{return Err("completion unproved security failure");}}cpu.finish(rt)}}"#
    ))
}
