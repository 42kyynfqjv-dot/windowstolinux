//! Private storage/effect kernel for mechanically lifted CRT stream instructions.
//! This does not initialize the Windows CRT or choose its buffering/flush policy.
//! Generated code embeds the existing guest_memory::Space and this source.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtRegionKind {File,Descriptor,Module,Input,Stack,Buffer,Result,Context}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtPointer {cap:guest_memory::Capability,owner:guest_memory::Owner,base:u32,size:u32,address:u32,kind:CrtRegionKind}
impl CrtPointer {fn address(self)->u32{self.address}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtDescriptorId {anchor:guest_memory::Capability,generation:u64,number:u32,handle:u32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtValue {Scalar{bits:u32,known:u32},Pointer(CrtPointer),Handle(CrtDescriptorId),OpaqueSaved(u8),ProtectedReturn(u64)}
impl CrtValue {
 fn scalar(bits:u32)->Self{Self::Scalar{bits,known:u32::MAX}}
 fn known_scalar(self)->Result<u32,&'static str>{match self{Self::Scalar{bits,known:u32::MAX}=>Ok(bits),_=>Err("CRT scalar knowledge/type")}}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtLock {anchor:guest_memory::Capability,thread:u64,serial:u64,depth:usize,record:u32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtInitialization {anchor:guest_memory::Capability,thread:u64,serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtWriteResult {success:bool,written:u32,last_error:Option<u32>}
/// The caller supplies an already owned synchronous endpoint. A failure may
/// have external effects; this layer neither rolls them back nor retries.
trait CrtBackend {
 fn write_once(&mut self,endpoint:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>;
 fn close_once(&mut self,_endpoint:CrtDescriptorId)->Result<bool,&'static str>{Err("CRT close effect unbound")}
}
struct CrtRegion {pointer:CrtPointer,heap:bool}
struct CrtDescriptor {id:CrtDescriptorId,live:bool,record:Option<CrtPointer>}
struct CrtStreamRuntime {
 memory:guest_memory::Space,owner:u64,thread:u64,anchor:guest_memory::Capability,
 regions:Vec<CrtRegion>,retired:Vec<CrtPointer>,tags:std::collections::BTreeMap<u32,CrtValue>,
 partial:std::collections::BTreeMap<u32,(u8,u8)>,descriptors:Vec<CrtDescriptor>,
 locks:Vec<CrtLock>,serial:u64,generation:u64,errno:Option<i32>,doserrno:Option<u32>,last_os_error:Option<u32>,
 locale_generation:u64,locale_live:bool,initialization:Option<u64>,lock_objects:std::collections::BTreeSet<u32>,
}
impl CrtStreamRuntime {
 /// This owner/thread cut creates storage only. Original instructions or an
 /// explicitly declared input state must initialize each observable field.
 fn new(owner:u64,thread:u64,file_address:u32,byte_limit:usize)->Result<Self,&'static str>{Self::file_array(owner,thread,file_address,1,byte_limit)}
 fn file_array(owner:u64,thread:u64,file_address:u32,file_count:u32,byte_limit:usize)->Result<Self,&'static str>{
  if owner==0||thread==0||file_address==0||file_address%4!=0||file_count==0||file_count>16{return Err("CRT runtime owner/thread/FILE array");}
  let size=file_count.checked_mul(56).ok_or("CRT FILE array extent")?;
  let mut memory=guest_memory::Space::new(byte_limit,64).map_err(|_|"CRT memory budget")?;
  let anchor=memory.map(file_address,size,guest_memory::Owner::Module(owner),guest_memory::Permissions::READ_WRITE,false).map_err(|_|"CRT FILE mapping")?;
  let pointer=CrtPointer{cap:anchor,owner:guest_memory::Owner::Module(owner),base:file_address,size,address:file_address,kind:CrtRegionKind::File};
  Ok(Self{memory,owner,thread,anchor,regions:vec![CrtRegion{pointer,heap:false}],retired:vec![],tags:std::collections::BTreeMap::new(),partial:std::collections::BTreeMap::new(),descriptors:vec![],locks:vec![],serial:0,generation:0,errno:None,doserrno:None,last_os_error:None,locale_generation:0,locale_live:false,initialization:None,lock_objects:std::collections::BTreeSet::from([file_address])})
 }
 /// Separate startup-exclusive storage authority, with no preconstructed lock.
 /// Ending it does not attest that original CRT initialization has completed.
 fn new_initializing(owner:u64,thread:u64,file_address:u32,byte_limit:usize)->Result<(Self,CrtInitialization),&'static str>{Self::new_initializing_array(owner,thread,file_address,1,byte_limit)}
 fn new_initializing_array(owner:u64,thread:u64,file_address:u32,file_count:u32,byte_limit:usize)->Result<(Self,CrtInitialization),&'static str>{
  let mut runtime=Self::file_array(owner,thread,file_address,file_count,byte_limit)?;runtime.lock_objects.clear();runtime.initialization=Some(1);
  let token=CrtInitialization{anchor:runtime.anchor,thread,serial:1};Ok((runtime,token))
 }
 fn initialization(&self,token:CrtInitialization)->Result<(),&'static str>{
  if token.anchor!=self.anchor||token.thread!=self.thread||self.initialization!=Some(token.serial){return Err("CRT initialization owner/lifetime");}Ok(())
 }
 fn end_initialization(&mut self,token:CrtInitialization)->Result<(),&'static str>{self.initialization(token)?;if !self.locks.is_empty(){return Err("CRT initialization with live lock lease");}self.initialization=None;Ok(())}
 fn construct_lock(&mut self,token:CrtInitialization,file:CrtPointer)->Result<(),&'static str>{
  self.initialization(token)?;self.file_record(file)?;if !self.lock_objects.insert(file.address){return Err("CRT duplicate lock construction");}Ok(())
 }
 fn destroy_lock(&mut self,token:CrtInitialization,file:CrtPointer)->Result<(),&'static str>{
  self.initialization(token)?;self.file_record(file)?;if self.locks.iter().any(|l|l.record==file.address)||!self.lock_objects.remove(&file.address){return Err("CRT missing/live lock destruction");}Ok(())
 }
 fn file_record(&self,file:CrtPointer)->Result<(),&'static str>{
  let region=self.regions.iter().find(|r|r.pointer.cap==file.cap).ok_or("CRT FILE owner")?;
  if file.kind!=CrtRegionKind::File||region.pointer.kind!=CrtRegionKind::File||file.owner!=region.pointer.owner||file.address<region.pointer.base||(file.address-region.pointer.base)%56!=0||file.address.checked_add(56).is_none_or(|end|u64::from(end)>u64::from(region.pointer.base)+u64::from(region.pointer.size)){return Err("CRT FILE record bounds");}
  self.memory.validate(file.cap,file.owner).map_err(|_|"CRT FILE lifetime")
 }
 fn file(&self)->CrtPointer{self.regions[0].pointer}
 /// Copying already-issued pointer bits does not dereference the pointee or
 /// renew its lifetime. Retired roots remain only as bounded provenance, never
 /// as mappings. Foreign and fabricated tokens cannot enter typed storage.
 fn pointer_transport(&self,p:CrtPointer)->Result<(),&'static str>{
  let root=self.regions.iter().map(|r|r.pointer).chain(self.retired.iter().copied()).find(|r|r.cap==p.cap).ok_or("CRT foreign/unissued pointer value")?;
  if p.owner!=root.owner||p.kind!=root.kind||p.base<root.base||u64::from(p.base)+u64::from(p.size)>u64::from(root.base)+u64::from(root.size)||p.address<p.base||u64::from(p.address)>u64::from(p.base)+u64::from(p.size){return Err("CRT pointer value provenance");}Ok(())
 }
 fn reserve_retirement(&mut self)->Result<(),&'static str>{if self.retired.len()>=4096{return Err("CRT retired provenance budget");}self.retired.try_reserve(1).map_err(|_|"CRT retired provenance storage")}
 fn identity_range(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  let region=self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT stale/foreign pointer")?;
  if region.pointer.owner!=p.owner||region.pointer.kind!=p.kind||p.base<region.pointer.base||u64::from(p.base)+u64::from(p.size)>u64::from(region.pointer.base)+u64::from(region.pointer.size)
   ||p.address<p.base||p.address.checked_add(size).is_none_or(|end|u64::from(end)>u64::from(p.base)+u64::from(p.size)){
   return Err("CRT pointer complete range/identity");
  }
  self.memory.validate(p.cap,p.owner).map_err(|_|"CRT pointer lifetime")?;
  if size!=0{self.memory.validate_range(p.cap,p.owner,p.address,size).map_err(|_|"CRT pointer mapped range")?;}
  Ok(())
 }
 fn valid(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  self.identity_range(p,size)?;let region=self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT pointer identity")?;
  if self.initialization.is_none(){
   if p.kind==CrtRegionKind::File{let record=region.pointer.base+(p.address-region.pointer.base)/56*56;if size!=0&&((p.address-region.pointer.base)%56)+size>56{return Err("CRT access crosses FILE records");}if !self.locks.iter().any(|l|l.record==record){return Err("CRT unlocked FILE record access");}}
   if p.kind==CrtRegionKind::Descriptor&&self.locks.is_empty(){return Err("CRT unlocked descriptor access");}
  }
  Ok(())
 }
 fn offset(&self,p:CrtPointer,delta:i64)->Result<CrtPointer,&'static str>{
  self.identity_range(p,0)?;let address=i64::from(p.address).checked_add(delta).and_then(|n|u32::try_from(n).ok()).ok_or("CRT pointer arithmetic overflow")?;
  let q=CrtPointer{address,..p};self.identity_range(q,0)?;Ok(q)
 }
 fn subrange(&self,p:CrtPointer,size:u32)->Result<CrtPointer,&'static str>{
  if size==0{return Err("CRT empty subrange");}self.identity_range(p,size)?;Ok(CrtPointer{base:p.address,size,..p})
 }
 fn difference(&self,a:CrtPointer,b:CrtPointer)->Result<u32,&'static str>{
  self.identity_range(a,0)?;self.identity_range(b,0)?;if a.cap!=b.cap{return Err("CRT unrelated pointer subtraction");}Ok(a.address.wrapping_sub(b.address))
 }
 fn map_region(&mut self,base:u32,size:u32,kind:CrtRegionKind,initial:Option<&[u8]>)->Result<CrtPointer,&'static str>{
  if kind==CrtRegionKind::Buffer||kind==CrtRegionKind::File&&(self.initialization.is_none()||base%4!=0||size%56!=0)||base==0||size==0||base.checked_add(size).is_none()
   ||initial.is_some_and(|bytes|bytes.len()!=size as usize){return Err("CRT mapped region contract");}
  let next=self.generation.checked_add(1).ok_or("CRT generation budget")?;
  let owner=match kind{CrtRegionKind::Stack|CrtRegionKind::Context=>guest_memory::Owner::Stack(next),_=>guest_memory::Owner::Module(self.owner)};
  let cap=self.memory.map(base,size,owner,guest_memory::Permissions::READ_WRITE,false).map_err(|_|"CRT region bounds/alias/budget")?;
  if let Some(bytes)=initial {if self.memory.write(base,bytes).is_err(){self.memory.release(cap,owner).map_err(|_|"CRT failed mapping rollback")?;return Err("CRT region initialization");}}
  let p=CrtPointer{cap,owner,base,size,address:base,kind};self.regions.push(CrtRegion{pointer:p,heap:false});self.generation=next;Ok(p)
 }
 fn resolve_absolute(&self,address:u32,kind:CrtRegionKind)->Result<CrtPointer,&'static str>{
  let p=self.regions.iter().map(|r|r.pointer).find(|p|p.kind==kind&&address>=p.base&&u64::from(address)<u64::from(p.base)+u64::from(p.size)).ok_or("CRT undeclared absolute region/role")?;
  let q=CrtPointer{address,..p};self.identity_range(q,1)?;Ok(q)
 }
 fn lock(&mut self,thread:u64)->Result<CrtLock,&'static str>{self.lock_file(thread,self.file())}
 fn lock_file(&mut self,thread:u64,file:CrtPointer)->Result<CrtLock,&'static str>{
  self.file_record(file)?;
  if thread!=self.thread||!self.lock_objects.contains(&file.address){return Err("CRT foreign thread/unconstructed lock");}
  let serial=self.serial.checked_add(1).ok_or("CRT lock generation budget")?;
  if self.locks.len()>=32{return Err("CRT recursive lock budget");}
  let token=CrtLock{anchor:self.anchor,thread,serial,depth:self.locks.len(),record:file.address};self.locks.push(token);self.serial=serial;Ok(token)
 }
 fn unlock(&mut self,token:CrtLock)->Result<(),&'static str>{
  if self.locks.last()!=Some(&token){return Err("CRT stale/foreign/out-of-order unlock");}self.locks.pop();Ok(())
 }
 fn check_lock(&self,token:CrtLock)->Result<(),&'static str>{
  if self.locks.last()!=Some(&token){return Err("CRT live exclusive lock required");}Ok(())
 }
 fn overlapping_tags(&self,address:u32,size:u32)->Vec<(u32,CrtValue)>{
  self.tags.iter().filter(|(at,_)|u64::from(**at)<u64::from(address)+u64::from(size)&&u64::from(address)<u64::from(**at)+4).map(|(&a,&v)|(a,v)).collect()
 }
 fn load(&self,p:CrtPointer,width:u8)->Result<CrtValue,&'static str>{
  let size=match width{8=>1,16=>2,32=>4,_=>return Err("CRT load width")};self.valid(p,size)?;
  let tags=self.overlapping_tags(p.address,size);
  if !tags.is_empty(){if width!=32||tags.len()!=1||tags[0].0!=p.address{return Err("CRT partial typed-word read");}
   match tags[0].1{CrtValue::Pointer(q)=>self.pointer_transport(q)?,CrtValue::Handle(h)=>{self.descriptor(h)?;},_=>{}}
   return Ok(tags[0].1);
  }
  let(mut bits,mut known)=(0u32,0u32);for i in 0..size{let a=p.address+i;
   let(byte,mask)=match self.memory.read(a,1){Ok(bytes)=>(bytes[0],255),Err(guest_memory::Fault::Uninitialized)=>self.partial.get(&a).copied().unwrap_or((0,0)),Err(_)=>return Err("CRT scalar read permission/range")};
   bits|=u32::from(byte&mask)<<(i*8);known|=u32::from(mask)<<(i*8);
  }
  Ok(CrtValue::Scalar{bits,known:if width==32{known}else{known|(!0u32<<width)}})
 }
 fn store(&mut self,p:CrtPointer,width:u8,value:CrtValue)->Result<(),&'static str>{
  let size=match width{8=>1,16=>2,32=>4,_=>return Err("CRT store width")};self.valid(p,size)?;
  if matches!(p.kind,CrtRegionKind::Input){return Err("CRT immutable source write");}
  let old=self.overlapping_tags(p.address,size);
  if old.iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_))){return Err("CRT protected saved/return overwrite");}
  if !old.is_empty()&&(width!=32||old.len()!=1||old[0].0!=p.address){return Err("CRT partial pointer/handle overwrite");}
  if p.kind==CrtRegionKind::File{
   let base=self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT FILE identity")?.pointer.base;
   if (p.address-base)%56<8 {
    if width!=32||![0,4].contains(&((p.address-base)%56))||!matches!(value,CrtValue::Pointer(_)|CrtValue::Scalar{bits:0,known:u32::MAX}){return Err("CRT FILE pointer field type");}
   }
  }
  let bits=match value{
   CrtValue::Scalar{bits,..}=>bits,
   CrtValue::Pointer(q)=>{if width!=32{return Err("CRT pointer store width");}self.pointer_transport(q)?;q.address},
   CrtValue::Handle(h)=>{if width!=32{return Err("CRT handle store width");}self.descriptor(h)?;h.handle},
   CrtValue::OpaqueSaved(r)=>{if width!=32||p.kind!=CrtRegionKind::Stack||r>7{return Err("CRT saved-register slot");}0},
   CrtValue::ProtectedReturn(id)=>{if width!=32||p.kind!=CrtRegionKind::Stack||id==0{return Err("CRT protected return slot");}0},
  };
  self.memory.write(p.address,&bits.to_le_bytes()[..size as usize]).map_err(|_|"CRT storage write")?;
  for(at,_)in old{self.tags.remove(&at);}for i in 0..size{self.partial.remove(&(p.address+i));}
  match value{CrtValue::Scalar{bits,known}=>{for i in 0..size{let mask=(known>>(8*i))as u8;if mask!=255{self.memory.forget(p.address+i,1).map_err(|_|"CRT scalar knowledge epoch")?;self.partial.insert(p.address+i,(((bits>>(8*i))as u8)&mask,mask));}}},_=>{self.tags.insert(p.address,value);}}
  Ok(())
 }
 /// A decoded POP/RET consumes precisely its protected stack token. This does
 /// not execute guest control flow or grant return-target authority by itself.
 fn consume_stack(&mut self,p:CrtPointer,expected:CrtValue)->Result<(),&'static str>{
  if p.kind!=CrtRegionKind::Stack||self.load(p,32)?!=expected{return Err("CRT stack consume identity");}
  self.memory.forget(p.address,4).map_err(|_|"CRT stack consume range")?;self.tags.remove(&p.address);for i in 0..4{self.partial.remove(&(p.address+i));}Ok(())
 }
 fn atomic_or(&mut self,lease:CrtLock,p:CrtPointer,bits:u32)->Result<u32,&'static str>{self.atomic(lease,p,bits,true)}
 fn atomic_and(&mut self,lease:CrtLock,p:CrtPointer,bits:u32)->Result<u32,&'static str>{self.atomic(lease,p,bits,false)}
 fn atomic(&mut self,lease:CrtLock,p:CrtPointer,bits:u32,or:bool)->Result<u32,&'static str>{
  self.check_lock(lease)?;if p.address%4!=0||!matches!(p.kind,CrtRegionKind::File|CrtRegionKind::Descriptor){return Err("CRT atomic record operand");}
  let old=self.load(p,32)?.known_scalar()?;let next=if or{old|bits}else{old&bits};self.store(p,32,CrtValue::scalar(next))?;Ok(old)
 }
 fn alloc_buffer(&mut self,lease:CrtLock,size:u32,available:bool)->Result<Option<CrtPointer>,&'static str>{self.check_lock(lease)?;self.allocate(size,false,available)}
 fn alloc_initialization(&mut self,token:CrtInitialization,size:u32,zeroed:bool,available:bool)->Result<Option<CrtPointer>,&'static str>{self.initialization(token)?;self.allocate(size,zeroed,available)}
 fn allocate(&mut self,size:u32,zeroed:bool,available:bool)->Result<Option<CrtPointer>,&'static str>{
  let heap=self.memory.process_heap();
  let address=self.memory.heap_alloc(heap,if zeroed{8}else{0},size,if available{guest_memory::Availability::Available}else{guest_memory::Availability::AllocationFailed}).map_err(|_|"CRT allocation contract/budget")?;
  let Some(base)=address else{return Ok(None)};
  let cap=self.memory.heap_capability(heap,base).map_err(|_|"CRT allocation identity")?;
  let p=CrtPointer{cap,owner:guest_memory::Owner::Heap(0),base,size,address:base,kind:CrtRegionKind::Buffer};self.regions.push(CrtRegion{pointer:p,heap:true});Ok(Some(p))
 }
 fn free_buffer(&mut self,lease:CrtLock,p:CrtPointer)->Result<(),&'static str>{self.check_lock(lease)?;self.free_allocation(p)}
 fn free_initialization(&mut self,token:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{self.initialization(token)?;self.free_allocation(p)}
 fn free_allocation(&mut self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,0)?;if p.kind!=CrtRegionKind::Buffer||p.address!=p.base{return Err("CRT allocation base required");}
  let index=self.regions.iter().position(|r|r.pointer.cap==p.cap&&r.heap).ok_or("CRT allocation ownership")?;let root=self.regions[index].pointer;self.reserve_retirement()?;
  self.memory.heap_free(self.memory.process_heap(),0,p.base).map_err(|_|"CRT allocation lifetime")?;self.regions.remove(index);self.retired.push(root);
  self.tags.retain(|&at,_|at<root.base||u64::from(at)>=u64::from(root.base)+u64::from(root.size));self.partial.retain(|&at,_|at<root.base||u64::from(at)>=u64::from(root.base)+u64::from(root.size));Ok(())
 }
 fn retire_region(&mut self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,0)?;let index=self.regions.iter().position(|r|r.pointer.cap==p.cap).ok_or("CRT region identity")?;let root=self.regions[index].pointer;
  if !matches!(p.kind,CrtRegionKind::Stack|CrtRegionKind::Context|CrtRegionKind::Input|CrtRegionKind::Result)||p.address!=root.base||p.base!=root.base||p.size!=root.size{return Err("CRT complete temporary region required");}
  if self.overlapping_tags(p.base,p.size).iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_))){return Err("CRT retirement before protected restoration");}
  self.reserve_retirement()?;self.memory.release(p.cap,p.owner).map_err(|_|"CRT region release")?;self.regions.remove(index);self.retired.push(root);self.tags.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));self.partial.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));Ok(())
 }
 fn bind_descriptor(&mut self,number:u32,handle:u32)->Result<CrtDescriptorId,&'static str>{
  if self.locks.is_empty()&&self.initialization.is_none()||number>2047||handle==0||handle==u32::MAX||self.descriptors.iter().any(|d|d.live&&(d.id.number==number||d.id.handle==handle)){return Err("CRT descriptor binding/alias");}
  let generation=self.generation.checked_add(1).ok_or("CRT descriptor generation")?;
  let id=CrtDescriptorId{anchor:self.anchor,generation,number,handle};self.descriptors.push(CrtDescriptor{id,live:true,record:None});self.generation=generation;Ok(id)
 }
 fn descriptor(&self,id:CrtDescriptorId)->Result<(),&'static str>{
  if self.locks.is_empty()&&self.initialization.is_none()||id.anchor!=self.anchor||!self.descriptors.iter().any(|d|d.live&&d.id==id){return Err("CRT descriptor owner/lifetime/lock");}Ok(())
 }
 fn bind_descriptor_record(&mut self,lease:CrtLock,id:CrtDescriptorId,record:CrtPointer)->Result<(),&'static str>{
  self.check_lock(lease)?;self.descriptor(id)?;self.valid(record,56)?;
  if record.kind!=CrtRegionKind::Descriptor||record.address%4!=0||self.descriptors.iter().any(|d|d.record.is_some_and(|p|p.cap==record.cap&&p.address==record.address)){return Err("CRT descriptor record alias/role");}
  if self.load(self.offset(record,24)?,32)?!=CrtValue::Handle(id){return Err("CRT descriptor handle field identity");}
  self.load(self.offset(record,40)?,8)?.known_scalar()?;self.load(self.offset(record,41)?,8)?.known_scalar()?;
  let descriptor=self.descriptors.iter_mut().find(|d|d.id==id).ok_or("CRT descriptor binding")?;
  if descriptor.record.is_some(){return Err("CRT repeated descriptor record");}descriptor.record=Some(record);Ok(())
 }
 fn descriptor_record(&self,id:CrtDescriptorId)->Result<CrtPointer,&'static str>{
  self.descriptor(id)?;let record=self.descriptors.iter().find(|d|d.id==id).and_then(|d|d.record).ok_or("CRT descriptor record unbound")?;self.valid(record,56)?;
  if self.load(self.offset(record,24)?,32)?!=CrtValue::Handle(id){return Err("CRT descriptor handle changed");}Ok(record)
 }
 fn require_narrow_descriptor(&self,id:CrtDescriptorId)->Result<CrtPointer,&'static str>{
  let record=self.descriptor_record(id)?;
  if self.load(self.offset(record,40)?,8)?.known_scalar()?!=0x81||self.load(self.offset(record,41)?,8)?.known_scalar()?!=0{return Err("CRT descriptor is not owned open nonappend narrow text");}Ok(record)
 }
 fn write_once(&mut self,id:CrtDescriptorId,source:CrtPointer,count:u32,backend:&mut impl CrtBackend)->Result<CrtWriteResult,&'static str>{
  self.descriptor(id)?;if count>16384{return Err("CRT WriteFile source budget");}self.valid(source,count)?;
  if !self.overlapping_tags(source.address,count).is_empty(){return Err("CRT WriteFile exposes typed object bytes");}
  let bytes=if count==0{&[][..]}else{self.memory.read(source.address,count).map_err(|_|"CRT WriteFile initialized full range")?};
  let outcome=backend.write_once(id,bytes)?;
  if outcome.success&&outcome.written>count||outcome.success&&outcome.last_error.is_some()||!outcome.success&&outcome.last_error.is_none(){return Err("CRT WriteFile backend result contract");}
  self.last_os_error=if outcome.success{None}else{outcome.last_error};Ok(outcome)
 }
 fn last_error(&self)->Result<u32,&'static str>{self.last_os_error.ok_or("CRT unknown thread LastError")}
 /// Only the original error mapper may write these fields; this validates its
 /// owned destination, not any chosen errno/doserrno semantics.
 fn validate_error_context(&self,p:CrtPointer)->Result<(),&'static str>{
  if p.kind!=CrtRegionKind::Context{return Err("CRT error context role");}self.valid(p,0x28)?;
  if !self.overlapping_tags(p.address+0x18,0x10).is_empty(){return Err("CRT error context protected field");}Ok(())
 }
 fn close_once(&mut self,id:CrtDescriptorId,backend:&mut impl CrtBackend)->Result<bool,&'static str>{
  self.descriptor(id)?;let closed=backend.close_once(id)?;if closed{self.descriptors.iter_mut().find(|d|d.id==id).ok_or("CRT close identity")?.live=false;}Ok(closed)
 }
 fn set_errors(&mut self,lease:CrtLock,errno:Option<i32>,doserrno:Option<u32>)->Result<(),&'static str>{self.check_lock(lease)?;self.errno=errno;self.doserrno=doserrno;Ok(())}
 fn initialize_c_locale(&mut self,lease:CrtLock)->Result<u64,&'static str>{self.check_lock(lease)?;if self.locale_live{return Err("CRT duplicate locale ownership");}self.locale_generation=self.locale_generation.checked_add(1).ok_or("CRT locale generation")?;self.locale_live=true;Ok(self.locale_generation)}
 fn check_locale(&self,thread:u64,generation:u64)->Result<(),&'static str>{if thread!=self.thread||!self.locale_live||generation!=self.locale_generation{return Err("CRT locale thread/lifetime");}Ok(())}
 fn retire_locale(&mut self,lease:CrtLock,generation:u64)->Result<(),&'static str>{self.check_lock(lease)?;self.check_locale(self.thread,generation)?;self.locale_live=false;Ok(())}
}
"#;

#[cfg(test)]
mod tests {
    static NEXT_CASE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn native(body: &str) {
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let source = format!(
            "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\nfn main(){{{body}}}",
            super::EMITTED_TYPES
        );
        let case = NEXT_CASE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("w2l-crt-runtime-{}-{case}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("check.rs");
        let binary = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        std::fs::write(&file, source).unwrap();
        let built = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&file)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let run = std::process::Command::new(binary).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    fn owned_cells_unknowns_alias_lifetime_and_explicit_lock_order() {
        native(
            r#"
let mut r=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let f=r.file();assert!(r.load(f,32).is_err());
let a=r.lock(9).unwrap();let b=r.lock(9).unwrap();assert!(r.unlock(a).is_err());r.unlock(b).unwrap();assert!(r.unlock(b).is_err());assert!(r.lock(10).is_err());
let p=r.alloc_buffer(a,32,true).unwrap().unwrap();let ptr=r.offset(f,0).unwrap();let base=r.offset(f,4).unwrap();r.store(ptr,32,CrtValue::Pointer(p)).unwrap();r.store(base,32,CrtValue::Pointer(p)).unwrap();
assert!(r.store(r.offset(ptr,1).unwrap(),8,CrtValue::scalar(0)).is_err());assert!(r.load(ptr,8).is_err());assert!(r.store(ptr,32,CrtValue::scalar(17)).is_err());let inline=r.subrange(r.offset(f,20).unwrap(),2).unwrap();assert!(r.store(inline,32,CrtValue::scalar(1)).is_err());r.store(inline,16,CrtValue::scalar(0x1234)).unwrap();assert!(r.offset(inline,3).is_err());
assert_eq!(r.load(p,32).unwrap(),CrtValue::Scalar{bits:0,known:0});r.store(p,8,CrtValue::scalar(0xab)).unwrap();assert_eq!(r.load(p,32).unwrap(),CrtValue::Scalar{bits:0xab,known:255});
r.store(r.offset(p,1).unwrap(),8,CrtValue::Scalar{bits:0xf7,known:0x0f}).unwrap();assert_eq!(r.load(p,16).unwrap(),CrtValue::Scalar{bits:0x7ab,known:0xffff0fff});
let stack=r.map_region(0x8000,32,CrtRegionKind::Stack,None).unwrap();r.store(stack,32,CrtValue::ProtectedReturn(5)).unwrap();assert!(r.store(stack,32,CrtValue::scalar(0)).is_err());assert!(r.consume_stack(stack,CrtValue::ProtectedReturn(6)).is_err());r.consume_stack(stack,CrtValue::ProtectedReturn(5)).unwrap();assert_eq!(r.load(stack,32).unwrap(),CrtValue::Scalar{bits:0,known:0});
let release=r.alloc_buffer(a,32,true).unwrap().unwrap();r.store(r.offset(release,16).unwrap(),32,CrtValue::Pointer(p)).unwrap();r.store(r.offset(release,24).unwrap(),8,CrtValue::Scalar{bits:7,known:15}).unwrap();let narrow=r.subrange(release,4).unwrap();r.free_buffer(a,narrow).unwrap();let remap=r.map_region(release.address(),32,CrtRegionKind::Input,Some(&[0;32])).unwrap();assert_eq!(r.load(r.offset(remap,16).unwrap(),32).unwrap(),CrtValue::scalar(0));assert_eq!(r.load(r.offset(remap,24).unwrap(),8).unwrap(),CrtValue::scalar(0));
let mut foreign=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();foreign.lock(9).unwrap();assert!(foreign.load(p,8).is_err());assert!(foreign.unlock(a).is_err());assert!(r.map_region(0x4000,16,CrtRegionKind::Module,None).is_err());
let flags=r.offset(f,12).unwrap();r.store(flags,32,CrtValue::scalar(0x42)).unwrap();assert_eq!(r.atomic_or(a,flags,0x10).unwrap(),0x42);assert_eq!(r.load(flags,32).unwrap().known_scalar().unwrap(),0x52);
let locale=r.initialize_c_locale(a).unwrap();assert!(r.check_locale(10,locale).is_err());r.retire_locale(a,locale).unwrap();assert!(r.check_locale(9,locale).is_err());
assert!(r.alloc_buffer(a,16,false).unwrap().is_none());assert_eq!(r.load(ptr,32).unwrap(),CrtValue::Pointer(p));r.free_buffer(a,p).unwrap();assert!(r.load(p,8).is_err());assert_eq!(r.load(ptr,32).unwrap(),CrtValue::Pointer(p));r.store(base,32,CrtValue::Pointer(p)).unwrap();assert_eq!(r.load(base,32).unwrap(),CrtValue::Pointer(p));assert!(r.offset(p,0).is_err());assert!(foreign.store(foreign.file(),32,CrtValue::Pointer(p)).is_err());r.unlock(a).unwrap();assert!(r.load(flags,32).is_err());
"#,
        );
    }

    #[test]
    fn startup_authority_and_per_file_locks_are_distinct_from_live_stream_cut() {
        native(
            r#"
let(mut r,init)=CrtStreamRuntime::new_initializing(7,9,0x4000,32768).unwrap();let a=r.file();assert!(r.lock(9).is_err());
assert!(r.alloc_initialization(init,12,true,false).unwrap().is_none());let table=r.alloc_initialization(init,12,true,true).unwrap().unwrap();assert_eq!(r.load(table,32).unwrap().known_scalar().unwrap(),0);r.free_initialization(init,table).unwrap();assert!(r.load(table,32).is_err());let b=r.map_region(0x5000,56,CrtRegionKind::File,None).unwrap();r.store(r.offset(a,12).unwrap(),32,CrtValue::scalar(0x42)).unwrap();r.store(r.offset(b,12).unwrap(),32,CrtValue::scalar(0x82)).unwrap();r.construct_lock(init,a).unwrap();r.construct_lock(init,b).unwrap();assert!(r.construct_lock(init,a).is_err());
let lease=r.lock_file(9,a).unwrap();assert!(r.end_initialization(init).is_err());r.unlock(lease).unwrap();r.end_initialization(init).unwrap();assert!(r.end_initialization(init).is_err());let lease=r.lock_file(9,a).unwrap();assert_eq!(r.load(r.offset(a,12).unwrap(),32).unwrap().known_scalar().unwrap(),0x42);assert!(r.load(b,32).is_err());assert!(r.load(r.offset(b,12).unwrap(),32).is_err());r.unlock(lease).unwrap();let lease=r.lock_file(9,b).unwrap();assert_eq!(r.load(r.offset(b,12).unwrap(),32).unwrap().known_scalar().unwrap(),0x82);r.unlock(lease).unwrap();
let(mut array,init)=CrtStreamRuntime::new_initializing_array(7,9,0xa000,3,32768).unwrap();let first=array.file();for index in 0..3{let file=array.offset(first,index*56).unwrap();array.construct_lock(init,file).unwrap();array.store(array.offset(file,16).unwrap(),32,CrtValue::scalar(index as u32)).unwrap();}assert!(array.load(array.offset(first,168).unwrap(),8).is_err());array.end_initialization(init).unwrap();for index in 0..3{let file=array.offset(first,i64::from(index)*56).unwrap();let lease=array.lock_file(9,file).unwrap();assert_eq!(array.load(array.offset(file,16).unwrap(),32).unwrap().known_scalar().unwrap(),index);array.unlock(lease).unwrap();}
let ctx=r.map_region(0x8000,40,CrtRegionKind::Context,None).unwrap();r.validate_error_context(ctx).unwrap();r.store(r.offset(ctx,0x1c).unwrap(),8,CrtValue::scalar(1)).unwrap();let wrong=r.map_region(0x9000,40,CrtRegionKind::Stack,None).unwrap();assert!(r.validate_error_context(wrong).is_err());
"#,
        );
    }
    #[test]
    fn single_call_backend_partial_failure_and_close_are_not_flush_policy() {
        native(
            r#"
struct B{calls:usize,closed:bool}impl CrtBackend for B{fn write_once(&mut self,_:CrtDescriptorId,b:&[u8])->Result<CrtWriteResult,&'static str>{self.calls+=1;assert_eq!(b,b"A\r\nZ");Ok(CrtWriteResult{success:true,written:2,last_error:None})}fn close_once(&mut self,_:CrtDescriptorId)->Result<bool,&'static str>{self.closed=true;Ok(true)}}
let mut r=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let lease=r.lock(2).unwrap();let fd=r.bind_descriptor(1,44).unwrap();let data=r.map_region(0x8000,4,CrtRegionKind::Input,Some(b"A\r\nZ")).unwrap();struct Failed;impl CrtBackend for Failed{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{Ok(CrtWriteResult{success:false,written:u32::MAX,last_error:Some(5)})}}
assert!(r.last_error().is_err());let failure=r.write_once(fd,data,4,&mut Failed).unwrap();assert!(!failure.success);assert_eq!(r.last_error().unwrap(),5);
let mut backend=B{calls:0,closed:false};let result=r.write_once(fd,data,4,&mut backend).unwrap();assert!(r.last_error().is_err());assert_eq!(result.written,2);assert_eq!(backend.calls,1);assert_eq!(r.errno,None);assert_eq!(r.doserrno,None);assert!(r.store(data,8,CrtValue::scalar(0)).is_err());
let unknown=r.alloc_buffer(lease,4,true).unwrap().unwrap();assert!(r.write_once(fd,unknown,4,&mut backend).is_err());assert_eq!(backend.calls,1);let record=r.map_region(0x9000,56,CrtRegionKind::Descriptor,None).unwrap();let holder=r.offset(record,24).unwrap();r.store(holder,32,CrtValue::Handle(fd)).unwrap();r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();r.store(r.offset(record,41).unwrap(),8,CrtValue::scalar(0)).unwrap();r.bind_descriptor_record(lease,fd,record).unwrap();assert_eq!(r.require_narrow_descriptor(fd).unwrap(),record);r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0xa1)).unwrap();assert!(r.require_narrow_descriptor(fd).is_err());r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();assert_eq!(r.load(holder,32).unwrap(),CrtValue::Handle(fd));assert!(r.write_once(fd,holder,4,&mut backend).is_err());
assert!(r.close_once(fd,&mut backend).unwrap());assert!(backend.closed);assert!(r.load(holder,32).is_err());assert!(r.write_once(fd,data,4,&mut backend).is_err());assert_eq!(backend.calls,1);r.unlock(lease).unwrap();
"#,
        );
    }
}
