//! Generated arithmetic and typed operand primitives for compiled CRT graphs.
//! No instruction decoder or opcode interpreter is present in generated output.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug)]
struct CrtFlags{cf:Option<bool>,zf:Option<bool>,sf:Option<bool>,of:Option<bool>}
impl CrtFlags{fn unknown()->Self{Self{cf:None,zf:None,sf:None,of:None}}}
/// The constructor admits an explicit 32-bit cdecl function-boundary contract,
/// including DF=0. It is not a capture of unknown Windows thread flags.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtAbi{Cdecl32Forward}
struct CrtCpu{abi:CrtAbi,r:[CrtValue;8],xmm:[[CrtValue;4];8],entry:[CrtValue;8],flags:CrtFlags,return_id:u64,return_site:Option<(u64,u32)>,steps:u32,returned:bool,return_pop:u16}
/// A compiler-proved aligned frame may copy CALL return bits into ordinary
/// storage. Only the original protected slot authorizes RET. No entry-boundary
/// CPU with an unknown numeric continuation can issue this lease.
struct CrtAlignedActivation{anchor:guest_memory::Capability,thread:u64,fiber:Option<CrtFiber>,entry:CrtPointer,identity:u64,pc:u32,mirror:Option<CrtPointer>,claimed_continuation:Option<u32>,done:bool}
impl CrtAlignedActivation{
 fn begin(rt:&CrtStreamRuntime,cpu:&CrtCpu)->Result<Self,&'static str>{
  cpu.validate_active(rt)?;rt.memory.validate(rt.anchor,rt.file_view.owner).map_err(|_|"CRT aligned runtime lifetime")?;let entry=CrtCpu::pointer(cpu.entry[4])?;
  let (identity,pc)=cpu.return_site.ok_or("CRT aligned return bits unavailable")?;
  if identity!=cpu.return_id||pc==0||cpu.r[4]!=cpu.entry[4]||entry.address()%4!=0{return Err("CRT aligned entry identity");}
  Ok(Self{anchor:rt.anchor,thread:rt.thread,fiber:rt.fiber,entry,identity,pc,mirror:None,claimed_continuation:None,done:false})
 }
 fn live(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu)->Result<(),&'static str>{
  if self.anchor!=rt.anchor||self.thread!=rt.thread||self.fiber!=rt.fiber||self.done||cpu.return_id!=self.identity||cpu.return_site!=Some((self.identity,self.pc))||cpu.entry[4]!=CrtValue::Pointer(self.entry){return Err("CRT aligned activation lifetime");}
  cpu.validate_active(rt)?;rt.memory.validate(self.anchor,rt.file_view.owner).map_err(|_|"CRT aligned runtime lifetime")?;
  if let Some(p)=self.mirror{if rt.load(p,32)?!=CrtValue::scalar(self.pc){return Err("CRT aligned return mirror changed");}}
  Ok(())
 }
 /// A consumer-bound post-body fragment is single-use, including on failure.
 fn claim_continuation(&mut self,rt:&CrtStreamRuntime,cpu:&CrtCpu,pc:u32)->Result<(),&'static str>{
  self.live(rt,cpu)?;if pc==0||self.claimed_continuation.is_some(){return Err("CRT aligned continuation already consumed");}self.claimed_continuation=Some(pc);Ok(())
 }
 fn copy_return(&mut self,rt:&mut CrtStreamRuntime,cpu:&CrtCpu,destination:CrtPointer,value:CrtValue)->Result<(),&'static str>{
  self.live(rt,cpu)?;let sp=CrtCpu::pointer(cpu.r[4])?;
  if self.mirror.is_some()||value!=CrtValue::ProtectedReturn(self.identity)||destination.cap!=self.entry.cap||destination.owner!=self.entry.owner||destination.kind!=CrtRegionKind::Stack||destination.address()%4!=0||destination.address()<sp.address()||destination.address().checked_add(4).is_none_or(|end|end>self.entry.address()){
   return Err("CRT aligned return copy authority/range");
  }
  rt.store(destination,32,CrtValue::scalar(self.pc))?;self.mirror=Some(destination);Ok(())
 }
 fn finish(&mut self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{
  self.live(rt,cpu)?;if self.mirror.is_none(){return Err("CRT aligned mirror missing");}
  let value=cpu.finish(rt)?;self.done=true;Ok(value)
 }
}
/// Local to one emitted graph invocation. It is never a CrtValue, memory tag,
/// public pointer conversion, or transferable continuation receipt.
struct CrtAddressRelation { anchor:guest_memory::Capability,thread:u64,fiber:Option<CrtFiber>,entry:CrtPointer,identity:u64,site:Option<(u64,u32)>,return_pop:u16,source:CrtPointer,destination:CrtPointer,source_arg:u32,destination_arg:u32,register:usize,bits:u32 }
impl CrtAddressRelation {
 fn subtract(rt:&CrtStreamRuntime,cpu:&mut CrtCpu,source_register:usize,destination_register:usize,source_arg:u32,destination_arg:u32)->Result<(Self,CrtValue),&'static str>{
  cpu.validate_active(rt)?;
  if source_register>=8||destination_register>=8||source_register==destination_register||source_register==4||destination_register==4||source_arg==destination_arg||[source_arg,destination_arg].iter().any(|n|*n==0||*n>256||*n%4!=0){return Err("CRT relation operand contract");}
  let entry=CrtCpu::pointer(cpu.entry[4])?;let source=CrtCpu::pointer(cpu.r[source_register])?;let destination=CrtCpu::pointer(cpu.r[destination_register])?;
  rt.identity_range(source,0)?;rt.identity_range(destination,0)?;
  if rt.load(rt.offset(entry,i64::from(source_arg))?,32)?!=CrtValue::Pointer(source)||rt.load(rt.offset(entry,i64::from(destination_arg))?,32)?!=CrtValue::Pointer(destination){return Err("CRT relation argument identity");}
  // Compute the original SUB flags and result from observed addresses. No
  // register obtains pointer authority from this scalar displacement.
  let value=cpu.binary_number(rt,2,CrtValue::Pointer(source),CrtValue::Pointer(destination))?;
  let relation=Self{anchor:rt.anchor,thread:rt.thread,fiber:rt.fiber,entry,identity:cpu.return_id,site:cpu.return_site,return_pop:cpu.return_pop,source,destination,source_arg,destination_arg,register:source_register,bits:value.known_scalar()?};Ok((relation,value))
 }
 fn load(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,displacement:usize,cursor:usize,width:u8)->Result<CrtValue,&'static str>{
  cpu.validate_active(rt)?;
  if rt.closed||self.anchor!=rt.anchor||self.thread!=rt.thread||self.fiber!=rt.fiber||self.identity!=cpu.return_id||self.site!=cpu.return_site||self.return_pop!=cpu.return_pop||cpu.entry[4]!=CrtValue::Pointer(self.entry)||displacement!=self.register||cursor>=8||cpu.r[displacement]!=CrtValue::scalar(self.bits){return Err("CRT relation activation/operand lifetime");}
  rt.identity_range(self.source,0)?;rt.identity_range(self.destination,0)?;
  if rt.load(rt.offset(self.entry,i64::from(self.source_arg))?,32)?!=CrtValue::Pointer(self.source)||rt.load(rt.offset(self.entry,i64::from(self.destination_arg))?,32)?!=CrtValue::Pointer(self.destination){return Err("CRT relation argument changed");}
  let current=CrtCpu::pointer(cpu.r[cursor])?;
  if (CrtPointer{address:self.destination.address(),..current})!=self.destination{return Err("CRT relation cursor authority");}
  rt.identity_range(current,0)?;
  let delta=current.address().checked_sub(self.destination.address()).ok_or("CRT relation backwards cursor")?;
  let source=rt.offset(self.source,i64::from(delta))?;
  if current.address().wrapping_add(self.bits)!=source.address(){return Err("CRT relation address arithmetic");}
  // Read only through the original source bounds, including partial knowledge.
  rt.load(source,width)
 }
}
impl CrtCpu{
 fn new(sp:CrtPointer,return_id:u64)->Result<Self,&'static str>{if sp.kind!=CrtRegionKind::Stack||return_id==0{return Err("CRT cpu entry authority");}let mut r=std::array::from_fn(|i|CrtValue::OpaqueSaved(i as u8));r[4]=CrtValue::Pointer(sp);Ok(Self{abi:CrtAbi::Cdecl32Forward,r,xmm:[[CrtValue::Scalar{bits:0,known:0};4];8],entry:r,flags:CrtFlags::unknown(),return_id,return_site:None,steps:0,returned:false,return_pop:0})}
 /// Bound stdcall adapter; index is the proven native global-object slot,
 /// not an extra guest argument. Original code/target binding remains required.
 fn native_sync_call(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,function:CrtFunction,index:u32)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;if self.return_pop!=12||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT synchronization stdcall frame");}
  let sp=Self::pointer(self.r[4])?;let p=Self::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
  let spin=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
  let result=rt.native_sync_initialize(init,function,index,p,spin,flags)?;self.clobber(CrtValue::scalar(result));self.finish_pop(rt,12)
 }
 /// Checked native FlsAlloc ABI, with callback ownership from the mapped image.
 fn native_fls_alloc_call(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;
  if self.return_pop!=4||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT FLS allocation stdcall frame");}
  let sp=Self::pointer(self.r[4])?;let value=rt.load(rt.offset(sp,4)?,32)?;
  let callback=match value{CrtValue::Scalar{bits:0,known:u32::MAX}=>None,CrtValue::Scalar{bits,known:u32::MAX}=>Some((image,rt.process_image_code(image,bits,1)?)),CrtValue::Pointer(p)=>{if rt.process_image_code(image,p.address(),1)?!=p{return Err("CRT FLS callback image/alias");}Some((image,p))},_=>return Err("CRT FLS callback provenance")};
  let id=rt.native_fls_allocate(init,callback)?;self.clobber(CrtValue::scalar(id.index));self.finish_pop(rt,4)
 }
 /// Successful bounded Buffer allocation only. Flags0 preserves unknown bytes;
 /// flags8 alone requests zeroing. No supplied NULL or exception outcome.
 fn native_heap_buffer_call(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;
  if self.return_pop!=12||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&r|self.r[r]!=self.entry[r]){return Err("CRT native HeapAlloc ABI");}
  let sp=Self::pointer(self.r[4])?;rt.offset(sp,16)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),16).map_err(|_|"CRT native HeapAlloc stack permission")?;
  let CrtValue::Heap(heap)=rt.load(rt.offset(sp,4)?,32)?else{return Err("CRT native HeapAlloc canonical heap")};
  let flags=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let size=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
  let p=rt.native_heap_allocate(init,heap,flags,size)?;self.clobber(CrtValue::Pointer(p));self.finish_pop(rt,12)
 }
 /// Forward REP MOVSB/MOVSD within the explicit cdecl ABI. Scalar knowledge and data
 /// pointer aliases are copied, never control authority. Each completed word
 /// commits its write and cursor/count progress; a later rejection retains it.
 fn repeat_move_dwords(&mut self,rt:&mut CrtStreamRuntime,max_words:u32)->Result<(),&'static str>{self.repeat_move_units(rt,32,max_words)}
 fn repeat_move_units(&mut self,rt:&mut CrtStreamRuntime,width:u8,max_words:u32)->Result<(),&'static str>{
  self.validate_active(rt)?;if !matches!(width,8|32){return Err("CRT repeated copy width");}let stride=u32::from(width)/8;
  if self.abi!=CrtAbi::Cdecl32Forward||max_words==0||max_words>262144{return Err("CRT repeated copy ABI/count domain");}
  let mut remaining=self.r[1].known_scalar()?;
  if remaining>max_words{return Err("CRT repeated copy count bound");}
  while remaining!=0{
   self.tick(u32::MAX)?;
   let src=Self::pointer(self.r[6])?;let dst=Self::pointer(self.r[7])?;
   let value=rt.load(src,width)?;
   if matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)|CrtValue::Dispatcher(_)){return Err("CRT repeated copy control authority");}
   rt.store(dst,width,value)?;
   // Effective-address formation preserves the old capability and bounds. It
   // never resolves an out-of-range next address into an unrelated allocation.
   self.r[6]=CrtValue::Pointer(rt.effective_address(src,src.address().wrapping_add(stride))?);
   self.r[7]=CrtValue::Pointer(rt.effective_address(dst,dst.address().wrapping_add(stride))?);
   remaining-=1;self.r[1]=CrtValue::scalar(remaining);
  }Ok(())
 }
 /// Owned initialization XCHG preserves flags; XADD uses original sum flags.
 /// All knowledge/lifetime/permission checks precede the scalar write.
 fn exchange_initializing_scalar(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage,p:CrtPointer,register:usize,add:bool)->Result<(),&'static str>{
  let value=self.r.get(register).ok_or("CRT initializing atomic register")?.known_scalar()?;
  let old=rt.exchange_initializing_scalar(init,image,p,value,add)?;
  if add{self.binary(rt,1,CrtValue::scalar(old),CrtValue::scalar(value),32)?;}
  self.r[register]=CrtValue::scalar(old);Ok(())
 }
 fn increment_initializing_scalar(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage,p:CrtPointer)->Result<(),&'static str>{
  let old=rt.exchange_initializing_scalar(init,image,p,1,true)?;let cf=self.flags.cf;self.binary(rt,1,CrtValue::scalar(old),CrtValue::scalar(1),32)?;self.flags.cf=cf;Ok(())
 }
 fn exchange_add_reference(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage,lease:CrtGlobalLock,p:CrtPointer,register:usize)->Result<(),&'static str>{
  let addend=self.r.get(register).ok_or("CRT XADD register")?.known_scalar()?;
  let old=rt.add_module_reference(init,image,lease,p,addend)?;
  self.binary(rt,1,CrtValue::scalar(old),CrtValue::scalar(addend),32)?;
  self.r[register]=CrtValue::scalar(old);Ok(())
 }
 fn increment_reference(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage,lease:CrtGlobalLock,p:CrtPointer)->Result<(),&'static str>{
  let old=rt.increment_module_reference(init,image,lease,p)?;let cf=self.flags.cf;
  self.binary(rt,1,CrtValue::scalar(old),CrtValue::scalar(1),32)?;self.flags.cf=cf;Ok(())
 }
 fn native_fls_get_call(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,fiber:CrtFiber)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;if self.return_pop!=4||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT FLS getter stdcall frame");}
  let sp=Self::pointer(self.r[4])?;rt.offset(sp,8)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),8).map_err(|_|"CRT FLS getter stack permission")?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;
  let value=rt.native_fls_read(init,fiber,index)?;self.clobber(value);self.finish_pop(rt,4)
 }
 fn native_fls_set_call(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,fiber:CrtFiber)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;if self.return_pop!=8||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT FLS setter stdcall frame");}
  let sp=Self::pointer(self.r[4])?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let value=rt.load(rt.offset(sp,8)?,32)?;
  if matches!(value,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT FLS setter protected argument");}
  let ok=rt.native_fls_set(init,fiber,index,value)?;self.clobber(CrtValue::scalar(u32::from(ok)));self.finish_pop(rt,8)
 }
 fn virtual_protect_call(&mut self,rt:&mut CrtStreamRuntime,image:CrtProcessImage)->Result<CrtValue,&'static str>{
  self.validate_active(rt)?;
  if self.return_pop!=16||self.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT protection stdcall frame");}
  let sp=Self::pointer(self.r[4])?;rt.offset(sp,20)?;
  let address=rt.load(rt.offset(sp,4)?,32)?;let size=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let output=Self::pointer(rt.load(rt.offset(sp,16)?,32)?)?;
  let target=match address{CrtValue::Pointer(p)=>p,CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(image,bits,size)?,_=>return Err("CRT protection address authority")};
  // Restrict the API output to outside the protected return/argument slots.
  if output.cap==sp.cap&&u64::from(output.address())<u64::from(sp.address())+20&&u64::from(sp.address())<u64::from(output.address())+4{return Err("CRT protection ABI output alias");}
  rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),20).map_err(|_|"CRT protection return stack permission")?;
  rt.protect_image_data(image,target,size,flags,output)?;
  // Success does not guarantee LastError preservation. Unknown stays unknown.
  rt.last_os_error=None;self.clobber(CrtValue::scalar(1));self.finish_pop(rt,16)
 }
 fn tick(&mut self,budget:u32)->Result<(),&'static str>{self.steps=self.steps.checked_add(1).ok_or("CRT instruction counter overflow")?;if self.steps>budget{return Err("CRT certified instruction bound exceeded");}Ok(())}
 fn bits(v:CrtValue)->Result<(u32,u32),&'static str>{match v{CrtValue::Module(m)=>Ok((m.handle,u32::MAX)),CrtValue::Function(f)=>Ok((f.address,u32::MAX)),CrtValue::Scalar{bits,known}=>Ok((bits,known)),CrtValue::Pointer(p)=>Ok((p.address(),u32::MAX)),CrtValue::ProcessHandle(h)=>Ok((h.handle,u32::MAX)),CrtValue::Handle(h)=>Ok((h.handle,u32::MAX)),CrtValue::OpaqueSaved(_)|CrtValue::NonZero{..}=>Ok((0,0)),CrtValue::Heap(_)|CrtValue::Dispatcher(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)=>Err("CRT protected control bits")}}
 fn number(v:CrtValue)->Result<u32,&'static str>{let(b,k)=Self::bits(v)?;if k!=u32::MAX{return Err("CRT unknown scalar bits observed");}Ok(b)}
 fn pointer(v:CrtValue)->Result<CrtPointer,&'static str>{match v{CrtValue::Pointer(p)=>Ok(p),_=>Err("CRT pointer provenance")}}
 fn mask(width:u8)->Result<u32,&'static str>{match width{8=>Ok(255),16=>Ok(65535),32=>Ok(u32::MAX),_=>Err("CRT operand width")}}
 fn get(&self,index:usize,width:u8,shift:u8)->Result<CrtValue,&'static str>{let v=*self.r.get(index).ok_or("CRT register index")?;if width==32&&shift==0{return Ok(v);}let mask=Self::mask(width)?;if shift as u16+width as u16>32{return Err("CRT register slice");}let(b,k)=Self::bits(v)?;Ok(CrtValue::Scalar{bits:(b>>shift)&mask,known:((k>>shift)&mask)|!mask})}
 fn set(&mut self,index:usize,width:u8,shift:u8,v:CrtValue)->Result<(),&'static str>{if index>=8{return Err("CRT register index");}if width==32&&shift==0{self.r[index]=v;return Ok(());}let mask=Self::mask(width)?;if shift as u16+width as u16>32{return Err("CRT register slice");}let(b,k)=Self::bits(v)?;let(old,known)=if matches!(self.r[index],CrtValue::Heap(_)){(0,0)}else{Self::bits(self.r[index])?};let field=mask<<shift;self.r[index]=CrtValue::Scalar{bits:(old&!field)|((b&mask)<<shift),known:(known&!field)|((k&mask)<<shift)};Ok(())}
 /// x86 computes the effective address modulo 2^32. Only an already owned
 /// base (or an explicitly bound image displacement) can supply authority;
 /// wrapping index arithmetic never manufactures a different capability.
 fn address(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtPointer,&'static str>{
  let p=self.form_address(rt,base,index,scale,displacement,absolute)?;rt.identity_range(p,0)?;Ok(p)
 }
 fn form_address(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtPointer,&'static str>{
  if !matches!(scale,1|2|4|8){return Err("CRT address scale");}
  let (p,extra)=if let Some(b)=base{
   match self.r[b]{
    CrtValue::Pointer(p)=>{let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT address adds two pointers");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,displacement.wrapping_add(extra))},
    scalar=>{let b=Self::number(scalar)?;if let Some(kind)=absolute{let p=rt.resolve_absolute(displacement,kind)?;let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT image index adds pointer");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,b.wrapping_add(extra))}
      else if let Some(i)=index{let p=Self::pointer(self.r[i])?;if scale!=1{return Err("CRT scaled pointer index");}(p,b.wrapping_add(displacement))}
      else{return Err("CRT scalar address lacks provenance");}}
   }
  }else{let p=rt.resolve_absolute(displacement,absolute.ok_or("CRT unbound absolute role")?)?;let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT absolute index adds pointer");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,extra)};
  let address=p.address().wrapping_add(extra);rt.effective_address(p,address)
 }
 fn push(&mut self,rt:&mut CrtStreamRuntime,v:CrtValue)->Result<(),&'static str>{let p=rt.offset(Self::pointer(self.r[4])?,-4)?;rt.store(p,32,v)?;self.r[4]=CrtValue::Pointer(p);Ok(())}
 fn pop(&mut self,rt:&mut CrtStreamRuntime)->Result<CrtValue,&'static str>{let p=Self::pointer(self.r[4])?;let v=rt.load(p,32)?;rt.consume_stack(p,v)?;self.r[4]=CrtValue::Pointer(rt.offset(p,4)?);Ok(v)}
 fn discard(&mut self,rt:&mut CrtStreamRuntime,bytes:u32)->Result<(),&'static str>{if bytes%4!=0||bytes>256{return Err("CRT cdecl argument cleanup");}let start=Self::pointer(self.r[4])?;for i in 0..bytes/4{let p=rt.offset(start,i64::from(i)*4)?;let v=rt.load(p,32)?;if matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT cleanup crosses protected word");}}for _ in 0..bytes/4{self.pop(rt)?;}Ok(())}
 fn leave(&mut self,rt:&mut CrtStreamRuntime)->Result<(),&'static str>{self.r[4]=CrtValue::Pointer(Self::pointer(self.r[5])?);self.r[5]=self.pop(rt)?;Ok(())}
 /// Check a live interrupted/active call without pretending it has returned.
 fn validate_active(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  let entry=Self::pointer(self.entry[4])?;let sp=Self::pointer(self.r[4])?;
  if self.returned||self.return_id==0||entry.cap!=sp.cap||entry.owner!=sp.owner||sp.address()>entry.address()||rt.load(entry,32)?!=CrtValue::ProtectedReturn(self.return_id)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.return_id)).count()!=1{return Err("CRT active caller lifetime/return authority");}
  rt.valid(sp,entry.address().checked_sub(sp.address()).and_then(|n|n.checked_add(4)).ok_or("CRT active caller range")?)
 }
 fn finish(&mut self,rt:&mut CrtStreamRuntime)->Result<CrtValue,&'static str>{self.finish_pop(rt,0)}
 fn finish_pop(&mut self,rt:&mut CrtStreamRuntime,bytes:u16)->Result<CrtValue,&'static str>{
  if self.returned{return Err("CRT repeated return");}
  if bytes!=self.return_pop||bytes>256||bytes%4!=0{return Err("CRT unbound RET argument cleanup");}
  if self.r[4]!=self.entry[4]{return Err("CRT caller stack identity");}
  if [3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT callee saved restoration");}
  let p=Self::pointer(self.r[4])?;
  if rt.load(p,32)?!=CrtValue::ProtectedReturn(self.return_id){return Err("CRT original protected return");}
  rt.offset(p,4+i64::from(bytes))?;
  for i in 0..bytes/4{let slot=rt.offset(p,4+i64::from(i)*4)?;if matches!(rt.load(slot,32)?,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT RET cleanup crosses protected word");}}
  self.pop(rt)?;self.discard(rt,u32::from(bytes))?;self.returned=true;Ok(self.r[0])
 }
 /// Execute an already bound native callee with the actual original CALL/RET
 /// state. A fresh identity protects the transient return, not its numeric PC.
 fn call<B:CrtBackend,F>(&mut self,rt:&mut CrtStreamRuntime,lease:CrtLock,backend:&mut B,continuation:u32,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,CrtLock,&mut B)->Result<CrtValue,&'static str>{
  self.call_pop(rt,lease,backend,continuation,0,callee)
 }
 /// Cleanup authority is supplied by the separately validated call binding,
 /// never inferred from whichever RET the callee happens to execute.
 fn call_pop<B:CrtBackend,F>(&mut self,rt:&mut CrtStreamRuntime,lease:CrtLock,backend:&mut B,continuation:u32,return_pop:u16,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,CrtLock,&mut B)->Result<CrtValue,&'static str>{
  rt.check_lock(lease)?;
  self.call_activation(rt,continuation,return_pop,|rt,child|callee(rt,child,lease,backend))
 }
 /// Shared protected CALL/RET mechanism. Lock acquisition and release cannot
 /// require a lock that the original instruction has not yet acquired. Their
 /// independently bound effects validate the exact object and thread instead.
 /// This grants no external-effect or exception-containment certificate.
 fn call_activation<F>(&mut self,rt:&mut CrtStreamRuntime,continuation:u32,return_pop:u16,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>{
  if self.returned||continuation==0||return_pop>256||return_pop%4!=0{return Err("CRT call activation/continuation/cleanup");}
  let before=Self::pointer(self.r[4])?;
  if before.kind!=CrtRegionKind::Stack{return Err("CRT call stack role");}
  let expected_after=rt.offset(before,i64::from(return_pop))?;
  for i in 0..return_pop/4{let p=rt.offset(before,i64::from(i)*4)?;if matches!(rt.load(p,32)?,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT bound call arguments cross protected word");}}
  let slot=rt.offset(before,-4)?;rt.valid(slot,4)?;
  if rt.overlapping_tags(slot.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("CRT call crosses protected state");}
  let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("CRT call identity exhausted")?;
  let identity=generation|(1u64<<63);
  if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(identity)){return Err("CRT call identity collision");}
  rt.generation=generation;self.push(rt,CrtValue::ProtectedReturn(identity))?;
  let mut child=Self{abi:self.abi,r:self.r,xmm:self.xmm,entry:self.r,flags:self.flags,return_id:identity,return_site:Some((identity,continuation)),steps:self.steps,returned:false,return_pop};
  let result=callee(rt,&mut child);
  self.r=child.r;self.xmm=child.xmm;self.flags=child.flags;self.steps=child.steps;
  // A failed/incomplete nested activation leaves its original effects visible,
  // but cannot continue to certify the parent's aligned-return observation.
  let value=match result{Ok(v)=>v,Err(error)=>{self.return_site=None;return Err(error);}};
  if !child.returned||self.r[4]!=CrtValue::Pointer(expected_after)||value!=self.r[0]||rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(identity)){self.return_site=None;return Err("CRT callee missing exact protected RET");}
  Ok(value)
 }
 fn condition(&self,kind:u8)->Result<bool,&'static str>{let z=||self.flags.zf.ok_or("CRT unknown ZF");let c=||self.flags.cf.ok_or("CRT unknown CF");let s=||self.flags.sf.ok_or("CRT unknown SF");let o=||self.flags.of.ok_or("CRT unknown OF");Ok(match kind{0=>z()?,1=>!z()?,2=>c()?,3=>!c()?&&!z()?,4=>c()?||z()?,5=>!c()?,6=>s()?!=o()?,7=>z()?||(s()?!=o()?),8=>!z()?&&(s()?==o()?),9=>s()?==o()?,10=>s()?,11=>!s()?,_=>return Err("CRT condition kind")})}
 /// Numeric address cancellation drops authority; it never resolves a scalar.
 fn binary_number(&mut self,rt:&CrtStreamRuntime,kind:u8,a:CrtValue,b:CrtValue)->Result<CrtValue,&'static str>{
  if !matches!(kind,1|2){return Err("CRT numeric arithmetic kind");}
  for v in [a,b]{if let CrtValue::Pointer(p)=v{rt.identity_range(p,0)?;}}
  let x=Self::number(a)?;let y=Self::number(b)?;
  self.binary(rt,kind,CrtValue::scalar(x),CrtValue::scalar(y),32)
 }
 fn binary(&mut self,rt:&CrtStreamRuntime,kind:u8,a:CrtValue,b:CrtValue,width:u8)->Result<CrtValue,&'static str>{
  if kind==0{return Ok(b);}for v in [a,b]{match v{CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Function(f)=>rt.function_identity(f,None)?,_=>{}}}let mask=Self::mask(width)?;
  // AND with a known zero destroys an opaque heap value without exposing bits.
  if width==32&&kind==4{if let (CrtValue::Heap(h),CrtValue::Scalar{bits:0,known:u32::MAX})|(CrtValue::Scalar{bits:0,known:u32::MAX},CrtValue::Heap(h))=(a,b){rt.heap_identity(h)?;self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:Some(true),sf:Some(false)};return Ok(CrtValue::scalar(0));}}
  if width==32&&kind==8{if let(CrtValue::Heap(x),CrtValue::Heap(y))=(a,b){if x!=y{return Err("CRT distinct opaque heap comparison");}rt.heap_identity(x)?;self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:Some(false),sf:None};return Ok(CrtValue::Scalar{bits:0,known:0});}}

  // Clearing low address bits can retain a checked stack or heap-buffer capability.
  // This is checked same-object arithmetic, never a scalar-to-pointer cast.
  if width==32&&kind==4{if let(CrtValue::Pointer(p),CrtValue::Scalar{bits:mask,known:u32::MAX})=(a,b){
   let alignment=(!mask).checked_add(1);
   if matches!(p.kind,CrtRegionKind::Stack|CrtRegionKind::Buffer)&&alignment.is_some_and(|n|n>=4&&n.is_power_of_two()){
    let address=p.address()&mask;let q=rt.offset(p,i64::from(address)-i64::from(p.address()))?;
    rt.valid(q,p.address()-address)?;
    if rt.overlapping_tags(q.address(),p.address()-address).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("CRT alignment crosses protected stack");}
    self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:Some(address==0),sf:Some(address&0x80000000!=0)};return Ok(CrtValue::Pointer(q));
   }
  }}
  // A nonzero fact constrains truth, not any particular raw set bit. Distinct
  // results can be disjoint bit patterns, even when both represent TRUE.
  if width==32&&kind==8&&a==b&&matches!(a,CrtValue::NonZero{..}){self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:Some(false),sf:None};return Ok(CrtValue::Scalar{bits:0,known:0});}
  if matches!(kind,3|4|5|8){let(x,kx)=Self::bits(a)?;let(y,ky)=Self::bits(b)?;let(bits,known)=match kind{3=>(x^y,kx&ky),4|8=>(x&y,(kx&ky)|(kx&!x)|(ky&!y)),5=>(x|y,(kx&ky)|(kx&x)|(ky&y)),_=>unreachable!()};let bits=bits&mask;let known=(known&mask)|!mask;let sign=1u32<<(width-1);self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:if bits&known&mask!=0{Some(false)}else if known==u32::MAX{Some(true)}else{None},sf:if known&sign!=0{Some(bits&sign!=0)}else{None}};return Ok(CrtValue::Scalar{bits,known});}
  let x=Self::number(a)?&mask;let y=Self::number(b)?&mask;let sign=1u32<<(width-1);
  let (bits,cf,of)=match kind{1=>{let n=u64::from(x)+u64::from(y);let r=n as u32&mask;(r,n>u64::from(mask),(!(x^y)&(x^r)&sign)!=0)},2|7=>{let r=x.wrapping_sub(y)&mask;(r,x<y,((x^y)&(x^r)&sign)!=0)},3=>(x^y,false,false),4|8=>(x&y,false,false),5=>(x|y,false,false),6=>{let borrow=u32::from(self.flags.cf.ok_or("CRT unknown borrow")?);let r=x.wrapping_sub(y).wrapping_sub(borrow)&mask;(r,u64::from(x)<u64::from(y)+u64::from(borrow),((x^y)&(x^r)&sign)!=0)},_=>return Err("CRT binary kind")};
  self.flags=CrtFlags{cf:Some(cf),zf:Some(bits==0),sf:Some(bits&sign!=0),of:Some(of)};
  if width==32&&matches!(kind,1|2){match(a,b){(CrtValue::Pointer(p),CrtValue::Scalar{known:u32::MAX,..})=>return Ok(CrtValue::Pointer(rt.offset(p,if kind==1{i64::from(y as i32)}else{-i64::from(y as i32)})?)),(CrtValue::Scalar{known:u32::MAX,..},CrtValue::Pointer(p))if kind==1=>return Ok(CrtValue::Pointer(rt.offset(p,i64::from(x as i32))?)),(CrtValue::Pointer(p),CrtValue::Pointer(q))if kind==2=>return Ok(CrtValue::scalar(rt.difference(p,q)?)),_=>{}}}
  Ok(CrtValue::scalar(bits))
 }
 /// CDQ changes EDX only; an unknown sign stays unknown, not zero.
 fn vector_load(&mut self,rt:&CrtStreamRuntime,dst:u8,p:CrtPointer,width:u8,aligned:bool)->Result<(),&'static str>{
  if dst>=8||!matches!(width,64|128){return Err("CRT vector load form");}rt.valid(p,u32::from(width)/8)?;if aligned&&p.address()%16!=0{return Err("CRT vector alignment");}let mut words=[CrtValue::scalar(0);4];for (i,w)in words.iter_mut().enumerate().take(usize::from(width)/32){*w=rt.load(rt.offset(p,i as i64*4)?,32)?;if !matches!(w,CrtValue::Scalar{..}){return Err("CRT vector typed data unbound");}}self.xmm[usize::from(dst)]=words;Ok(())
 }
 /// Legacy MOVD clears upper lanes, preserves low-lane knowledge and flags.
 fn vector_from_dword(&mut self,dst:u8,value:CrtValue)->Result<(),&'static str>{
  if dst>=8||!matches!(value,CrtValue::Scalar{..}){return Err("CRT vector scalar MOVD form");}self.xmm[usize::from(dst)]=[value,CrtValue::scalar(0),CrtValue::scalar(0),CrtValue::scalar(0)];Ok(())
 }
 fn vector_shuffle(&mut self,dst:u8,src:u8,control:u8)->Result<(),&'static str>{
  if dst>=8||src>=8{return Err("CRT vector shuffle form");}let before=self.xmm[usize::from(src)];if before.iter().any(|v|!matches!(v,CrtValue::Scalar{..})){return Err("CRT vector shuffle typed data");}self.xmm[usize::from(dst)]=std::array::from_fn(|n|before[usize::from((control>>(2*n))&3)]);Ok(())
 }
 /// Explicit forward cdecl domain, like REP MOVS. STD remains unsupported.
 /// A completed element advances EDI/ECX; a failed element preserves prior work.
 fn repeat_store_units(&mut self,rt:&mut CrtStreamRuntime,width:u8,bound:u32)->Result<(),&'static str>{
  self.validate_active(rt)?;if self.abi!=CrtAbi::Cdecl32Forward||bound==0||bound>262144{return Err("CRT REP store ABI/count domain");}if !matches!(width,8|32){return Err("CRT REP store width");}let count=self.r[1].known_scalar()?;if count>bound{return Err("CRT REP store bound");}if count==0{return Ok(());}if !matches!(self.r[0],CrtValue::Scalar{..}){return Err("CRT REP store scalar value");}let value=self.get(0,width,0)?;if !matches!(value,CrtValue::Scalar{..}){return Err("CRT REP store scalar value");}
  for _ in 0..count{let p=Self::pointer(self.r[7])?;let next=rt.effective_address(p,p.address().wrapping_add(u32::from(width/8)))?;rt.store(p,width,value)?;self.r[7]=CrtValue::Pointer(next);self.r[1]=CrtValue::scalar(self.r[1].known_scalar()?-1);self.tick(u32::MAX)?;}Ok(())
 }
 fn vector_store(&self,rt:&mut CrtStreamRuntime,src:u8,p:CrtPointer,width:u8,aligned:bool)->Result<(),&'static str>{
  if src>=8||!matches!(width,64|128){return Err("CRT vector store form");}let size=u32::from(width)/8;rt.valid(p,size)?;if matches!(p.kind,CrtRegionKind::File|CrtRegionKind::Descriptor|CrtRegionKind::Input|CrtRegionKind::ProcessData){return Err("CRT vector destination role unbound");}if aligned&&p.address()%16!=0{return Err("CRT vector alignment");}rt.memory.validate_writable(p.cap,p.owner,p.address(),size).map_err(|_|"CRT vector write permission")?;if !rt.overlapping_tags(p.address(),size).is_empty(){return Err("CRT vector typed destination unbound");}for i in 0..usize::from(width)/32{let CrtValue::Scalar{..}=self.xmm[usize::from(src)][i]else{return Err("CRT vector typed data unbound");};rt.ordinary_file_bytes(rt.offset(p,i as i64*4)?,4)?;}
  for i in 0..usize::from(width)/32{rt.store(rt.offset(p,i as i64*4)?,32,self.xmm[usize::from(src)][i])?;}Ok(())
 }
 fn bit_test(&mut self,rt:&CrtStreamRuntime,value:CrtValue,bit:u8)->Result<(),&'static str>{
  if bit>=32{return Err("CRT bit-test index");}match value{CrtValue::Pointer(p)=>rt.identity_range(p,0)?,CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Function(f)=>rt.function_identity(f,None)?,CrtValue::ProcessHandle(h)=>{rt.native_endpoint(h)?;},CrtValue::Handle(h)=>{rt.descriptor(h)?;},_=>{}}let(bits,known)=Self::bits(value)?;let mask=1u32<<bit;self.flags.cf=if known&mask!=0{Some(bits&mask!=0)}else{None};self.flags.of=None;self.flags.sf=None;Ok(())
 }
 /// CDQ changes EDX only; an unknown sign stays unknown, not zero.
 fn sign_dividend(&mut self)->Result<(),&'static str>{let(bits,known)=Self::bits(self.r[0])?;self.r[2]=if known&0x80000000!=0{CrtValue::scalar(if bits&0x80000000!=0{u32::MAX}else{0})}else{CrtValue::Scalar{bits:0,known:0}};Ok(())}
 fn add_carry(&mut self,a:CrtValue,b:CrtValue)->Result<CrtValue,&'static str>{
  let x=Self::number(a)?;let y=Self::number(b)?;let carry=u64::from(self.flags.cf.ok_or("CRT unknown ADC carry")?);
  let full=u64::from(x)+u64::from(y)+carry;let value=full as u32;
  self.flags=CrtFlags{cf:Some(full>u64::from(u32::MAX)),zf:Some(value==0),sf:Some(value&0x80000000!=0),of:Some((!(x^y)&(x^value)&0x80000000)!=0)};Ok(CrtValue::scalar(value))
 }
 /// DIV faults are outside the non-faulting admitted domain. Validate every
 /// operand and both fault conditions before changing registers or flags.
 fn divide_unsigned(&mut self,divisor:CrtValue)->Result<(),&'static str>{
  let divisor=divisor.known_scalar()?;let low=self.r[0].known_scalar()?;let high=self.r[2].known_scalar()?;
  if divisor==0{return Err("CRT unproved DIV zero exception");}
  if high>=divisor{return Err("CRT unproved DIV quotient overflow exception");}
  let dividend=(u64::from(high)<<32)|u64::from(low);let quotient=dividend/u64::from(divisor);let remainder=dividend%u64::from(divisor);
  self.r[0]=CrtValue::scalar(quotient as u32);self.r[2]=CrtValue::scalar(remainder as u32);self.flags=CrtFlags::unknown();Ok(())
 }
 /// Sound per-bit sum for scalar LEA, discarding correlations conservatively.
 fn sum_bits(a:CrtValue,b:CrtValue)->Result<CrtValue,&'static str>{
  let(x,kx)=Self::bits(a)?;let(y,ky)=Self::bits(b)?;let(mut bits,mut known,mut carries)=(0u32,0u32,1u8);
  for bit in 0..32{let mut sums=0u8;let mut next=0u8;for ax in 0..2u32{if kx&(1<<bit)!=0&&ax!=((x>>bit)&1){continue;}for by in 0..2u32{if ky&(1<<bit)!=0&&by!=((y>>bit)&1){continue;}for carry in 0..2u32{if carries&(1<<carry)==0{continue;}let sum=ax+by+carry;sums|=1<<(sum&1);next|=1<<(sum>>1);}}}if sums==1||sums==2{known|=1<<bit;if sums==2{bits|=1<<bit;}}carries=next;}
  Ok(CrtValue::Scalar{bits,known})
 }
 /// LEA with a real capability keeps it. Scalar address bits stay scalar even
 /// if their numeric value coincides with a mapped region: no provenance mint.
 fn lea(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtValue,&'static str>{
  if base.is_some_and(|r|matches!(self.r[r],CrtValue::Pointer(_)))||index.is_some_and(|r|matches!(self.r[r],CrtValue::Pointer(_)))||base.is_none()&&absolute.is_some(){return Ok(CrtValue::Pointer(self.form_address(rt,base,index,scale,displacement,absolute)?));}
  if !matches!(scale,1|2|4|8){return Err("CRT LEA scale");}
  // A register-only identity LEA preserves an opaque saved value exactly.
  // Other arithmetic still uses bit knowledge and cannot recreate this token.
  if index.is_none()&&displacement==0&&absolute.is_none(){if let Some(r)=base{return Ok(self.r[r]);}}
  let a=base.map(|r|self.r[r]).unwrap_or(CrtValue::scalar(0));
  let b=if let Some(r)=index{let(bits,known)=Self::bits(self.r[r])?;let shift=scale.trailing_zeros();CrtValue::Scalar{bits:bits.wrapping_shl(shift),known:known.wrapping_shl(shift)|(scale-1)}}else{CrtValue::scalar(0)};
  Self::sum_bits(Self::sum_bits(a,b)?,CrtValue::scalar(displacement))
 }
 fn zero(&mut self)->CrtValue{self.flags=CrtFlags{cf:Some(false),zf:Some(true),sf:Some(false),of:Some(false)};CrtValue::scalar(0)}
 /// ROR r32,CL: only five count bits are read; no pointer authority is created.
 fn rotate_right32(&mut self,value:CrtValue,count:CrtValue)->Result<CrtValue,&'static str>{
  let(c,k)=Self::bits(count)?;if k&31!=31{return Err("CRT unknown rotate count");}let n=c&31;
  if n==0{return Ok(value);}
  let(b,k)=Self::bits(value)?;let bits=b.rotate_right(n);let known=k.rotate_right(n);
  self.flags.cf=if known&0x80000000!=0{Some(bits&0x80000000!=0)}else{None};
  self.flags.of=if n==1&&known&0xc0000000==0xc0000000{Some(((bits>>31)^(bits>>30))&1!=0)}else{None};
  Ok(CrtValue::Scalar{bits:bits&known,known})
 }
 fn shift(&mut self,value:CrtValue,count:u8,kind:u8,width:u8)->Result<CrtValue,&'static str>{let mask=Self::mask(width)?;let x=Self::number(value)?&mask;let count=count&31;if count==0{return Ok(value);}let sign=1u32<<(width-1);let result=match kind{0=>x.wrapping_shl(u32::from(count))&mask,1=>x.wrapping_shr(u32::from(count)),2=>((((x<<(32-width))as i32)>>(32-width))>>count)as u32&mask,_=>return Err("CRT shift kind")};
  let cf=if kind==2&&count>=width{Some(x&sign!=0)}else if count<width{Some(if kind==0{x&(1<<(width-count))!=0}else{x&(1<<(count-1))!=0})}else{None};let of=if count==1{match kind{0=>cf.map(|c|(result&sign!=0)^c),1=>Some(x&sign!=0),2=>Some(false),_=>None}}else{None};self.flags=CrtFlags{cf,zf:Some(result==0),sf:Some(result&sign!=0),of};Ok(CrtValue::scalar(result))}
 fn multiply(&mut self,value:CrtValue,factor:u32)->Result<CrtValue,&'static str>{let x=Self::number(value)?;let product=i64::from(x as i32)*i64::from(factor as i32);let result=product as u32;let overflow=product!=i64::from(result as i32);self.flags=CrtFlags{cf:Some(overflow),of:Some(overflow),zf:None,sf:None};Ok(CrtValue::scalar(result))}
 fn clobber(&mut self,result:CrtValue){self.xmm=[[CrtValue::Scalar{bits:0,known:0};4];8];self.r[0]=result;self.r[1]=CrtValue::Scalar{bits:0,known:0};self.r[2]=CrtValue::Scalar{bits:0,known:0};self.flags=CrtFlags::unknown();}
}
"#;
