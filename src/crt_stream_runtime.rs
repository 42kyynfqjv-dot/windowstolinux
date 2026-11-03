//! Private storage/effect kernel for mechanically lifted CRT stream instructions.
//! This does not initialize the Windows CRT or choose its buffering/flush policy.
//! Generated code embeds the existing guest_memory::Space and this source.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtRegionKind {File,Descriptor,Module,Input,Stack,Buffer,Result,Context,ThreadData,ProcessData}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtPointer {cap:guest_memory::Capability,owner:guest_memory::Owner,base:u32,size:u32,address:u32,kind:CrtRegionKind}
impl CrtPointer {fn address(self)->u32{self.address}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtProcessHandle {anchor:guest_memory::Capability,serial:u64,handle:u32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtNativeStandards {anchor:guest_memory::Capability,serial:u64,pid:u32}
#[derive(Clone,Copy)]
struct CrtStandardEntry {value:CrtValue,last_error:Option<u32>}
struct CrtEnvironment {anchor:guest_memory::Capability,owner:u64,pid:u32,words:Vec<u8>,next:u32,blocks:Vec<CrtPointer>}
struct CrtNativeEndpoint {id:CrtProcessHandle,file:Option<std::fs::File>,certain:bool}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtCommandLine {anchor:guest_memory::Capability,pid:u32,serial:u64,codepage:u32,narrow:CrtPointer,wide:CrtPointer}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtImageName{anchor:guest_memory::Capability,image:CrtProcessImage,pid:u32,serial:u64,wide:CrtPointer,fact:guest_memory::ReadFact,native:bool}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtDescriptorId {anchor:guest_memory::Capability,generation:u64,number:u32,handle:u32,handle_generation:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtThreadHead {anchor:guest_memory::Capability,thread:u64,registry:u64,epoch:u64,head:[u64;3]}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtDispatcherContext {anchor:guest_memory::Capability,thread:u64,epoch:u64,callback:u64,serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtModule {anchor:guest_memory::Capability,handle:u32,generation:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtModuleReference {module:CrtModule,serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtProcessImage {anchor:guest_memory::Capability,owner:u64,generation:u64,root:CrtPointer}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtFunction {module:CrtModule,address:u32,serial:u64}
/// Fixed native reference budget; serial keys are monotonic, not array indices.
#[derive(Clone)]
struct CrtModuleReferences {slots:[Option<(u64,CrtModuleReference)>;256]}
impl CrtModuleReferences {
 fn new()->Self{Self{slots:[None;256]}}
 fn iter(&self)->impl Iterator<Item=(&u64,&CrtModuleReference)>{self.slots.iter().filter_map(|x|x.as_ref().map(|(k,v)|(k,v)))}
 fn values(&self)->impl Iterator<Item=&CrtModuleReference>{self.iter().map(|(_,v)|v)}
 fn len(&self)->usize{self.values().count()}
 fn is_empty(&self)->bool{self.len()==0}
 fn get(&self,key:&u64)->Option<&CrtModuleReference>{self.iter().find(|(k,_)|*k==key).map(|(_,v)|v)}
 fn contains_key(&self,key:&u64)->bool{self.get(key).is_some()}
 fn insert(&mut self,key:u64,value:CrtModuleReference){
  if let Some(slot)=self.slots.iter_mut().find(|x|x.as_ref().is_some_and(|(k,_)|*k==key)){*slot=Some((key,value));return;}
  *self.slots.iter_mut().find(|x|x.is_none()).expect("checked module reference budget")=Some((key,value));
 }
 fn remove(&mut self,key:&u64)->Option<CrtModuleReference>{self.slots.iter_mut().find(|x|x.as_ref().is_some_and(|(k,_)|k==key)).and_then(Option::take).map(|(_,v)|v)}
}
struct CrtLoadedModule {identity:String,generation:u64,certain:bool}
struct CrtExport {function:CrtFunction,symbol:String,target:CrtModule,callable:bool,api:Option<CrtNativeApi>}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtProviderExport {record:CrtFunction}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtNativeApi {InitializeGlobalCriticalSectionEx,FlsAlloc,FlsSetValue,AreFileApisAnsi}
/// A native registry construction ticket, not a Windows DLL initialization proof.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtNativeProviderReference {reference:CrtModuleReference,function:CrtFunction}
struct CrtProviderBuild {anchor:guest_memory::Capability,thread:u64,serial:u64,handle:u32}
struct CrtNativeProvider {serial:u64,identity:String,root:Option<CrtModuleReference>,exports:Vec<u64>,limit:usize}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtHeap {anchor:guest_memory::Capability,process:guest_memory::ProcessHeap,exceptions:Option<bool>}
/// An explicitly bound, stationary fiber context. This is not a guessed TLS
/// index or proof that original FlsAlloc/callback initialization has run.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtFiber {anchor:guest_memory::Capability,thread:u64,serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtFlsSlot {fiber:CrtFiber,index:u32,serial:u64,allocation:CrtFlsIndex}
/// Process index authority is distinct from each fiber's value lease.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtFlsIndex {anchor:guest_memory::Capability,index:u32,serial:u64}
#[derive(Clone,Copy)]
struct CrtProcessFls {id:CrtFlsIndex,callback:Option<(CrtProcessImage,CrtPointer)>,certain:bool,input_binding:bool,native:bool}
/// Fixed process-index storage. Keys remain independent of physical slots.
type CrtFlsIndices=CrtFlsTable<CrtProcessFls>;
type CrtFlsValues=CrtFlsTable<(CrtFlsSlot,CrtValue)>;
#[derive(Clone,Debug,PartialEq,Eq)]
struct CrtFlsTable<T:Copy> {slots:Box<[Option<(u32,T)>;64]>}
impl<T:Copy> CrtFlsTable<T> {
 fn new()->Self{Self{slots:Box::new([None;64])}}
 fn len(&self)->usize{self.slots.iter().flatten().count()}
 fn is_empty(&self)->bool{self.len()==0}
 fn get(&self,k:&u32)->Option<&T>{self.slots.iter().flatten().find(|(n,_)|n==k).map(|(_,v)|v)}
 fn get_mut(&mut self,k:&u32)->Option<&mut T>{self.slots.iter_mut().flatten().find(|(n,_)|n==k).map(|(_,v)|v)}
 fn contains_key(&self,k:&u32)->bool{self.get(k).is_some()}
 fn insert(&mut self,k:u32,v:T){if let Some(old)=self.get_mut(&k){*old=v;return;}*self.slots.iter_mut().find(|x|x.is_none()).expect("checked FLS index capacity")=Some((k,v));}
 fn remove(&mut self,k:&u32)->Option<T>{self.slots.iter_mut().find(|x|x.as_ref().is_some_and(|(n,_)|n==k)).and_then(Option::take).map(|(_,v)|v)}
}
/// Object view only: the allocation capability, Buffer role and every alias
/// remain unchanged. The view never promises that later writes preserve zeros.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtPtdLayout {Vcruntime,Ucrt}
impl CrtPtdLayout{fn size(self)->u32{match self{Self::Vcruntime=>40,Self::Ucrt=>868}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtHeapPtdView {pointer:CrtPointer,slot:CrtFlsSlot,layout:CrtPtdLayout}
/// Non-Clone, consumed after the protected allocation return. A caller cannot
/// supply its own before-set or transfer the ticket to another runtime/slot.
struct CrtHeapPtdAllocation {anchor:guest_memory::Capability,slot:CrtFlsSlot,before:Vec<guest_memory::Capability>}
/// Single-use API observation. Failure revokes allocation knowledge; it does
/// not claim Windows released the block or left its contents unchanged.
struct CrtHeapFreeEffect {anchor:guest_memory::Capability,thread:u64,serial:u64,pointer:CrtPointer,failed:bool}
/// Canonical FILE-lock membership with fallible metadata reservation.
struct CrtFileLockSet(Vec<u32>);
impl CrtFileLockSet {
 fn first(address:u32)->Result<Self,&'static str>{let mut set=Self(Vec::new());set.reserve()?;set.insert(address);Ok(set)}
 fn reserve(&mut self)->Result<(),&'static str>{self.0.try_reserve(1).map_err(|_|"CRT FILE lock bookkeeping resource")}
 fn contains(&self,p:&u32)->bool{self.0.contains(p)}
 fn insert(&mut self,p:u32)->bool{if self.contains(&p){false}else{self.0.push(p);true}}
 fn remove(&mut self,p:&u32)->bool{if let Some(i)=self.0.iter().position(|n|n==p){self.0.remove(i);true}else{false}}
 fn clear(&mut self){self.0.clear()}
 fn is_empty(&self)->bool{self.0.is_empty()}
 fn len(&self)->usize{self.0.len()}
 fn iter(&self)->std::slice::Iter<'_,u32>{self.0.iter()}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtValue {NonZero{anchor:guest_memory::Capability,serial:u64},Module(CrtModule),Function(CrtFunction),Heap(CrtHeap),Dispatcher(CrtDispatcherContext),Scalar{bits:u32,known:u32},Pointer(CrtPointer),ProcessHandle(CrtProcessHandle),Handle(CrtDescriptorId),ThreadHead(CrtThreadHead),OpaqueSaved(u8),ProtectedReturn(u64)}
impl CrtValue {
 fn scalar(bits:u32)->Self{Self::Scalar{bits,known:u32::MAX}}
 fn known_scalar(self)->Result<u32,&'static str>{match self{Self::Scalar{bits,known:u32::MAX}=>Ok(bits),_=>Err("CRT scalar knowledge/type")}}
}
/// Process policy, not a Windows BOOL bit encoding or the numeric ACP.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtFileApiMode {Ansi,Oem}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtProcessFileMode {anchor:guest_memory::Capability,serial:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtLock {anchor:guest_memory::Capability,thread:u64,serial:u64,depth:usize,record:u32}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtInitialization {anchor:guest_memory::Capability,thread:u64,serial:u64}
/// Instruction access is separate from constructor permission. Implementations
/// validate their live phase before any original instruction or image access.
trait CrtInstructionInputs {
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>;
 fn image(&self)->CrtProcessImage;
 fn initialization_token(&self)->Option<CrtInitialization>;
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtApplicationInputs {anchor:guest_memory::Capability,owner:u64,thread:u64,fiber:Option<CrtFiber>,image:CrtProcessImage,serial:u64}
impl CrtInstructionInputs for CrtApplicationInputs {
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  rt.memory.validate(self.anchor,rt.file_view.owner).map_err(|_|"CRT application arena lifetime")?;
  if rt.application!=Some(*self)||rt.initialization.is_some()||rt.closed||rt.shutdown.is_some()||rt.anchor!=self.anchor||rt.owner!=self.owner||rt.thread!=self.thread||rt.fiber!=self.fiber{return Err("CRT application owner/phase lifetime");}
  rt.process_image(self.image)?;if let Some(f)=self.fiber{rt.check_fiber(f)?;}Ok(())
 }
 fn image(&self)->CrtProcessImage{self.image}
 fn initialization_token(&self)->Option<CrtInitialization>{None}
}

/// Lifecycle identity only; does not initialize or attest locale data objects.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtLocale {anchor:guest_memory::Capability,thread:u64,generation:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtGlobalLock {anchor:guest_memory::Capability,thread:u64,serial:u64,depth:usize,index:u32,storage:CrtPointer}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtRecordLock {anchor:guest_memory::Capability,thread:u64,serial:u64,depth:usize,record:CrtPointer}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtDescriptorLock {anchor:guest_memory::Capability,thread:u64,serial:u64,depth:usize,id:CrtDescriptorId}
/// Constructed only by the validated normal-return/owned-thread bridge.
/// Non-Clone: consuming it is a one-way phase transition, not an input boolean.
struct CrtShutdownReceipt {anchor:guest_memory::Capability,thread:u64,event:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtShutdown {anchor:guest_memory::Capability,thread:u64,serial:u64,event:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtWriteResult {success:bool,written:u32,last_error:Option<u32>}
/// The caller supplies an already owned synchronous endpoint. A failure may
/// have external effects; this layer neither rolls them back nor retries.
trait CrtBackend {
 fn write_once(&mut self,endpoint:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>;
 fn close_once(&mut self,_endpoint:CrtDescriptorId)->Result<bool,&'static str>{Err("CRT close effect unbound")}
}
/// No-read storage lease, not knowledge of a Windows captured register. Only
/// the pending-event adapter issues this; dropping the event revokes every
/// cloned view. Sealed bytes remain inaccessible even after revocation.
#[derive(Clone)]
struct CrtUnobservedContext {
 anchor:guest_memory::Capability,thread:u64,source:[u64;4],context:CrtPointer,
 return_slot:CrtPointer,return_id:u64,selector:CrtPointer,bypass:u32,
 helper:CrtPointer,code:&'static [u8],epoch_live:std::rc::Rc<std::cell::Cell<bool>>,live:std::rc::Rc<std::cell::Cell<bool>>,
}
impl CrtUnobservedContext {
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  let result=(||{
  if !self.live.get()||!self.epoch_live.get()||rt.closed||self.anchor!=rt.anchor||self.thread!=rt.thread
   ||!rt.unobserved_contexts.iter().any(|(p,live)|*p==self.context&&std::rc::Rc::ptr_eq(live,&self.live)){
   return Err("unobserved context expired/foreign lease");
  }
  rt.valid(self.context,716)?;
  for i in (0..716).step_by(4){if self.load_word(rt,i)?!=(CrtValue::Scalar{bits:0,known:0}){return Err("unobserved context storage changed");}}
  if rt.load(self.return_slot,32)?!=CrtValue::ProtectedReturn(self.return_id)
   ||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(self.return_id)).count()!=1{return Err("unobserved context lost source CALL");}
  if rt.load(self.selector,32)?.known_scalar()?!=self.bypass{return Err("unobserved context selector changed");}
  for(i,&b)in self.code.iter().enumerate(){if rt.load(rt.offset(self.helper,i as i64)?,8)?.known_scalar()?!=u32::from(b){return Err("unobserved context helper changed");}}
  Ok(())
  })();if result.is_err(){self.revoke();}result
 }
 /// This checks representation freshness only and grants no guest read.
 fn load_word(&self,rt:&CrtStreamRuntime,offset:i64)->Result<CrtValue,&'static str>{rt.load_unsealed(rt.offset(self.context,offset)?,32)}
 fn require_helper(&self,rt:&CrtStreamRuntime,origin:u32,selector:u32,bypass:u32,code:&[u8])->Result<(),&'static str>{
  self.validate(rt)?;
  if self.helper.address()!=origin||self.selector.address()!=selector||self.bypass!=bypass||self.code!=code{self.revoke();return Err("unobserved context different helper proof");}Ok(())
 }
 fn revoke(&self){self.live.set(false);}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtSListHead{anchor:guest_memory::Capability,header:CrtPointer,serial:u64}
struct CrtRegion {pointer:CrtPointer,heap:bool,file_owner:Option<u32>}
struct CrtDescriptor {id:CrtDescriptorId,live:bool,record:Option<CrtPointer>,record_initialized:bool}
/// Fixed storage for the admitted 32 global objects. No guest operation grows
/// a map or allocates a tracking node. Capacity is a conversion-domain bound,
/// never a Windows BOOL-zero/GetLastError outcome.
struct CrtGlobalSlots<T:Copy> {slots:[Option<T>;32]}
impl<T:Copy> CrtGlobalSlots<T> {
 fn new()->Self{Self{slots:[None;32]}}
 fn get(&self,index:&u32)->Option<&T>{self.slots.get(*index as usize).and_then(Option::as_ref)}
 fn contains_key(&self,index:&u32)->bool{self.get(index).is_some()}
 fn values(&self)->impl Iterator<Item=&T>{self.slots.iter().flatten()}
 fn is_empty(&self)->bool{self.values().next().is_none()}
 fn insert(&mut self,index:u32,value:T){self.slots[index as usize]=Some(value);}
 fn remove(&mut self,index:&u32)->Option<T>{self.slots.get_mut(*index as usize).and_then(Option::take)}
}
/// Recursive leases use the same fixed domain as the object table.
struct CrtGlobalLeases {slots:[Option<CrtGlobalLock>;32],len:usize}
impl CrtGlobalLeases {
 fn new()->Self{Self{slots:[None;32],len:0}}
 fn len(&self)->usize{self.len}
 fn is_empty(&self)->bool{self.len==0}
 fn iter(&self)->impl Iterator<Item=&CrtGlobalLock>{self.slots[..self.len].iter().flatten()}
 fn last(&self)->Option<&CrtGlobalLock>{self.len.checked_sub(1).and_then(|i|self.slots[i].as_ref())}
 fn push(&mut self,value:CrtGlobalLock){self.slots[self.len]=Some(value);self.len+=1;}
 fn pop(&mut self)->Option<CrtGlobalLock>{if self.len==0{return None;}self.len-=1;self.slots[self.len].take()}
}
/// Knowledge of guest state, never a capture of the host floating-point unit.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtX87Word{bits:u16,known:u16}
impl CrtX87Word{fn unknown()->Self{Self{bits:0,known:0}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtX87Register{bits:[u8;10],known:[u8;10]}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtX87State{status:CrtX87Word,control:CrtX87Word,tag:CrtX87Word,opcode:CrtX87Word,ip:[CrtValue;2],dp:[CrtValue;2],registers:[CrtX87Register;8],mxcsr:CrtValue}
impl CrtX87State{
 fn unknown()->Self{let word=CrtX87Word::unknown();let scalar=CrtValue::Scalar{bits:0,known:0};Self{status:word,control:word,tag:word,opcode:word,ip:[scalar;2],dp:[scalar;2],registers:[CrtX87Register{bits:[0;10],known:[0;10]};8],mxcsr:scalar}}
 /// Intel SDM Vol2A FCLEX/FNCLEX: clear bits0..7,15; TOP is unchanged;
 /// C0/C1/C2/C3 are undefined, so discard their knowledge, not just their values.
 fn fnclex(&mut self){self.status=CrtX87Word{bits:self.status.bits&self.status.known&0x3800,known:(self.status.known&0x3800)|0x80ff};}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct CrtX87Context{anchor:guest_memory::Capability,owner:u64,thread:u64,init:CrtInitialization,fiber:Option<Option<CrtFiber>>,state:CrtX87State,mxcsr_mask:Option<u32>}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtUnhandledFilter{Unobserved,Default,Guest(CrtProcessImage,CrtPointer)}
struct CrtStreamRuntime {
 // Diagnostic instruction address only; never grants state authority.
 unhandled_filter:CrtUnhandledFilter,environment:Option<Box<CrtEnvironment>>,fp_boundary:Option<u32>,x87:Option<CrtX87Context>,
 file_view:CrtPointer,main_image:Option<CrtProcessImage>,main_image_regions:Vec<CrtPointer>,loader_cells:std::collections::BTreeMap<u32,(CrtPointer,bool)>,modules:std::collections::BTreeMap<u32,CrtLoadedModule>,module_references:CrtModuleReferences,exports:std::collections::BTreeMap<u64,CrtExport>,providers:std::collections::BTreeMap<u32,CrtNativeProvider>,native_sync:CrtGlobalSlots<(CrtFunction,u32,CrtPointer)>,slist_heads:Box<CrtGlobalSlots<CrtSListHead>>,
 uncertain_allocations:Vec<CrtPointer>,completed_failed_frees:Vec<(guest_memory::Capability,u64)>,heap_ptds:Vec<CrtHeapPtdView>,fiber:Option<CrtFiber>,fls_indices:CrtFlsIndices,fls:CrtFlsValues,
 unobserved_contexts:Vec<(CrtPointer,std::rc::Rc<std::cell::Cell<bool>>)>,heap:Option<CrtHeap>,memory:guest_memory::Space,owner:u64,thread:u64,anchor:guest_memory::Capability,
 dispatchers:std::collections::BTreeMap<u64,CrtDispatcherContext>,regions:Vec<CrtRegion>,retired:Vec<CrtPointer>,tags:std::collections::BTreeMap<u32,CrtValue>,
 partial:std::collections::BTreeMap<u32,(u8,u8)>,descriptors:Vec<CrtDescriptor>,native_endpoints:Vec<CrtNativeEndpoint>,native_standards:Option<(CrtNativeStandards,[CrtStandardEntry;3])>,command_line:Option<CrtCommandLine>,image_name:Option<CrtImageName>,file_mode:Option<(CrtProcessFileMode,CrtFileApiMode)>,
 global_objects:CrtGlobalSlots<CrtPointer>,global_locks:CrtGlobalLeases,record_objects:Vec<CrtPointer>,record_locks:Vec<CrtRecordLock>,locks:Vec<CrtLock>,descriptor_locks:Vec<CrtDescriptorLock>,serial:u64,generation:u64,canonical_errno:bool,errno_cell:Option<CrtPointer>,errno:Option<i32>,doserrno:Option<u32>,last_os_error:Option<u32>,
 locale_generation:u64,locale_live:bool,initialization:Option<u64>,application:Option<CrtApplicationInputs>,shutdown:Option<CrtShutdown>,closed:bool,lock_objects:CrtFileLockSet,
}
impl CrtStreamRuntime {
 const X87_PROFILE:&'static str="w2l-modern-enabled-stationary-x87-v1";
 /// Declared user-mode execution domain: x87 enabled (EM=TS=0), modern
 /// nonwaiting semantics, no legacy DOS-compatible interrupt window. Unknown
 /// initial bytes stay unknown. This is not Windows acquisition or a host read.
 fn configure_x87(&mut self,init:CrtInitialization,profile:&str)->Result<(),&'static str>{
  self.initialization(init)?;if profile!=Self::X87_PROFILE||self.x87.is_some(){return Err("CRT x87 profile unsupported/already bound");}
  self.x87=Some(CrtX87Context{anchor:self.anchor,owner:self.owner,thread:self.thread,init,fiber:None,state:CrtX87State::unknown(),mxcsr_mask:None});Ok(())
 }
 /// Explicit target-platform policy backed by the retained Win2022 original-entry
 /// observation. This produces only the declared controls, not host inheritance
 /// or a universal Windows/XP7 loader guarantee. Original FNCLEX must establish
 /// exception knowledge; status/tag/data/registers remain unknown here.
 const NATIVE_FP_PROFILE:&'static str="w2l-win2022-entry-control-027f-mxcsr-1f80-v1";
 fn initialize_native_fp_profile(&mut self,init:CrtInitialization,profile:&str)->Result<(),&'static str>{
  self.initialization(init)?;
  if profile!=Self::NATIVE_FP_PROFILE||self.x87.is_some(){return Err("CRT initial FP profile unsupported/already bound");}
  if let Some(f)=self.fiber{self.check_fiber(f)?;}
  let mut state=CrtX87State::unknown();state.control=CrtX87Word{bits:0x027f,known:0xffff};state.mxcsr=CrtValue::scalar(0x1f80);
  self.x87=Some(CrtX87Context{anchor:self.anchor,owner:self.owner,thread:self.thread,init,fiber:Some(self.fiber),state,mxcsr_mask:Some(0xffbf)});Ok(())
 }
 fn x87_context(&self,init:CrtInitialization)->Result<CrtX87Context,&'static str>{
  self.initialization(init)?;let mut x=self.x87.ok_or("CRT x87 profile unbound")?;
  if x.anchor!=self.anchor||x.owner!=self.owner||x.thread!=self.thread||x.init!=init{return Err("CRT x87 owner/lifetime");}
  self.memory.validate(x.anchor,self.file_view.owner).map_err(|_|"CRT x87 storage lifetime")?;
  if let Some(f)=self.fiber{self.check_fiber(f)?;}
  if let Some(f)=x.fiber{if f!=self.fiber{return Err("CRT x87 stationary fiber changed");}}else{x.fiber=Some(self.fiber);}
  Ok(x)
 }
 fn clear_x87_exceptions(&mut self,init:CrtInitialization)->Result<(),&'static str>{let mut x=self.x87_context(init)?;x.state.fnclex();self.x87=Some(x);Ok(())}
 // Pending delivery is unsupported, not simulated. Unknown bits cannot prove
 // absence. A masked flag or a known-clear flag proves each exception absent.
 fn wait_x87(&mut self,init:CrtInitialization)->Result<(),&'static str>{
  let mut x=self.x87_context(init)?;let s=x.state.status;let c=x.state.control;
  let absent=(s.known&!s.bits)|(c.known&c.bits);
  if (s.known&s.bits)&(c.known&!c.bits)&0x3f!=0{return Err("CRT pending x87 exception delivery unsupported");}
  if absent&0x3f!=0x3f{return Err("CRT x87 pending exception knowledge");}
  // ES is separately observable. Inconsistent/unknown summary state is not
  // silently reconciled by deriving a guessed hardware environment.
  if s.known&0x80==0||s.bits&0x80!=0{return Err("CRT x87 exception summary unsupported");}
  x.state.status.known&=!0x4700;x.state.status.bits&=x.state.status.known;
  self.x87=Some(x);Ok(())
 }
 fn store_x87_control(&mut self,init:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{
  let mut x=self.x87_context(init)?;let w=x.state.control;
  self.store(p,16,CrtValue::Scalar{bits:u32::from(w.bits&w.known),known:u32::from(w.known)|0xffff0000})?;
  x.state.status.known&=!0x4700;x.state.status.bits&=x.state.status.known;self.x87=Some(x);Ok(())
 }
 fn load_x87_control(&mut self,init:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{
  let mut x=self.x87_context(init)?;
  // Bounded clean-exception domain. Deferred unmasking/summary updates remain
  // rejected before reading/loading until their complete contract is proved.
  if x.state.status.known&0x80ff!=0x80ff||x.state.status.bits&0x80ff!=0{return Err("CRT FLDCW nonclean exception state unsupported");}
  let value=self.load(p,16)?.known_scalar()?;
  // Modern documented fields only; bit6 reads as one. Reserved precision01
  // and other reserved input bits stay outside this domain.
  if value&!0x1f7f!=0||value&0x300==0x100{return Err("CRT FLDCW reserved control unsupported");}
  x.state.control=CrtX87Word{bits:(value as u16)|0x40,known:0xffff};
  x.state.status.known&=!0x4700;x.state.status.bits&=x.state.status.known;self.x87=Some(x);Ok(())
 }
 // An explicit guest instruction domain, not a capture of host register state.
 fn configure_mxcsr_profile(&mut self,init:CrtInitialization,profile:&str)->Result<(),&'static str>{
  let mut x=self.x87_context(init)?;if profile!="w2l-enabled-sse-no-daz-v1"||x.mxcsr_mask.is_some(){return Err("CRT MXCSR profile unsupported/already bound");}
  x.mxcsr_mask=Some(0xffbf);self.x87=Some(x);Ok(())
 }
 fn store_mxcsr(&mut self,init:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{
  let x=self.x87_context(init)?;
  // Only an established scalar snapshot may be observed. The state producer
  // must establish enabled SSE and reserved/optional bits; no host default.
  let value=x.state.mxcsr.known_scalar()?;
  let mask=x.mxcsr_mask.ok_or("CRT MXCSR enabled-state profile unbound")?;
  if value&!mask!=0{return Err("CRT MXCSR reserved bits unsupported");}
  self.store(p,32,CrtValue::scalar(value))?;self.x87=Some(x);Ok(())
 }
 /// This owner/thread cut creates storage only. Original instructions or an
 /// explicitly declared input state must initialize each observable field.
 fn new(owner:u64,thread:u64,file_address:u32,byte_limit:usize)->Result<Self,&'static str>{Self::file_array(owner,thread,file_address,1,byte_limit)}
 fn file_array(owner:u64,thread:u64,file_address:u32,file_count:u32,byte_limit:usize)->Result<Self,&'static str>{
  if owner==0||thread==0||file_address==0||file_address%4!=0||file_count==0||file_count>16{return Err("CRT runtime owner/thread/FILE array");}
  let size=file_count.checked_mul(56).ok_or("CRT FILE array extent")?;
  let mut memory=guest_memory::Space::new(byte_limit,64).map_err(|_|"CRT memory budget")?;
  let anchor=memory.map(file_address,size,guest_memory::Owner::Module(owner),guest_memory::Permissions::READ_WRITE,false).map_err(|_|"CRT FILE mapping")?;
  let pointer=CrtPointer{cap:anchor,owner:guest_memory::Owner::Module(owner),base:file_address,size,address:file_address,kind:CrtRegionKind::File};
  Self::from_file_storage(owner,thread,memory,pointer)
 }
 fn from_file_storage(owner:u64,thread:u64,memory:guest_memory::Space,pointer:CrtPointer)->Result<Self,&'static str>{
  let anchor=pointer.cap;
  Ok(Self{unhandled_filter:CrtUnhandledFilter::Unobserved,environment:None,fp_boundary:None,x87:None,file_view:pointer,main_image:None,main_image_regions:vec![],loader_cells:std::collections::BTreeMap::new(),modules:std::collections::BTreeMap::new(),module_references:CrtModuleReferences::new(),exports:std::collections::BTreeMap::new(),providers:std::collections::BTreeMap::new(),native_sync:CrtGlobalSlots::new(),slist_heads:Box::new(CrtGlobalSlots::new()),uncertain_allocations:vec![],completed_failed_frees:vec![],heap_ptds:vec![],fiber:None,fls_indices:CrtFlsIndices::new(),fls:CrtFlsValues::new(),unobserved_contexts:vec![],heap:None,memory,owner,thread,anchor,dispatchers:std::collections::BTreeMap::new(),regions:vec![CrtRegion{pointer,heap:false,file_owner:None}],retired:vec![],tags:std::collections::BTreeMap::new(),partial:std::collections::BTreeMap::new(),descriptors:vec![],native_endpoints:vec![],native_standards:None,command_line:None,image_name:None,file_mode:None,global_objects:CrtGlobalSlots::new(),global_locks:CrtGlobalLeases::new(),record_objects:vec![],record_locks:vec![],locks:vec![],descriptor_locks:vec![],serial:0,generation:0,canonical_errno:false,errno_cell:None,errno:None,doserrno:None,last_os_error:None,locale_generation:0,locale_live:false,initialization:None,application:None,shutdown:None,closed:false,lock_objects:CrtFileLockSet::first(pointer.base)?})
 }

 /// Initial FILE storage is a bounded role view of the original writable
 /// section. No mapping, copy, lock construction or CRT success is invented.
 fn new_initializing_pe32(owner:u64,thread:u64,file_address:u32,file_count:u32,byte_limit:usize,file:&[u8])->Result<(Self,CrtInitialization),&'static str>{
  if owner==0||thread==0||file_address==0||file_address%4!=0||!(1..=16).contains(&file_count){return Err("CRT runtime owner/thread/FILE array");}
  let size=file_count*56;
  let mut memory=guest_memory::Space::new(byte_limit,64).map_err(|_|"CRT memory budget")?;
  let maps=memory.map_pe32(owner,file).map_err(|_|"CRT PE32 mapping contract")?;
  let regions:Vec<_>=maps.into_iter().map(|(cap,base,size)|CrtPointer{cap,owner:guest_memory::Owner::Module(owner),base,size,address:base,kind:CrtRegionKind::Module}).collect();
  let section=regions.iter().find(|p|file_address>=p.base&&file_address.checked_add(size).is_some_and(|end|u64::from(end)<=u64::from(p.base)+u64::from(p.size))).ok_or("CRT image FILE complete section range")?;
  memory.validate_writable(section.cap,section.owner,file_address,size).map_err(|_|"CRT image FILE writable storage")?;
  let pointer=CrtPointer{base:file_address,address:file_address,size,kind:CrtRegionKind::File,..*section};
  let mut rt=Self::from_file_storage(owner,thread,memory,pointer)?;
  rt.regions=regions.iter().map(|&pointer|CrtRegion{pointer,heap:false,file_owner:None}).collect();
  let image=CrtProcessImage{anchor:rt.anchor,owner,generation:1,root:regions[0]};
  rt.main_image_regions=regions;rt.main_image=Some(image);rt.serial=1;rt.lock_objects.clear();rt.initialization=Some(1);
  let init=CrtInitialization{anchor:rt.anchor,thread,serial:1};Ok((rt,init))
 }
 /// Bootstrap installs the mapped input image once. This is process ownership,
 /// not a LoadLibrary reference and not proof of loader/CRT side effects.
 fn bootstrap_main_image(&mut self,init:CrtInitialization,base:u32,image:&[u8])->Result<CrtProcessImage,&'static str>{
  self.initialization(init)?;
  if self.closed||self.main_image.is_some(){return Err("CRT process image already issued/closed");}
  let size=u32::try_from(image.len()).map_err(|_|"CRT process image size")?;
  if base==0||size==0||base.checked_add(size).is_none(){return Err("CRT process image extent");}
  let generation=self.serial.checked_add(1).ok_or("CRT process image generation")?;
  // Mapping validates overlap/budget before publication. No second image copy
  // or borrowed module token is used as the authoritative object.
  let cap=self.memory.map_image(base,size,self.owner,guest_memory::Permissions::READ,image).map_err(|_|"CRT process image bounds/alias/budget")?;
  let root=CrtPointer{cap,owner:guest_memory::Owner::Module(self.owner),base,size,address:base,kind:CrtRegionKind::Module};
  self.regions.push(CrtRegion{pointer:root,heap:false,file_owner:None});
  let token=CrtProcessImage{anchor:self.anchor,owner:self.owner,generation,root};
  self.main_image_regions=vec![root];self.serial=generation;self.main_image=Some(token);Ok(token)
 }
 /// Map a validated preferred-base PE32 input before creating dependent CRT
 /// cells. Publication is atomic; imports/TLS/entry execution remain unproved.
 fn bootstrap_pe32(&mut self,init:CrtInitialization,file:&[u8])->Result<CrtProcessImage,&'static str>{
  self.initialization(init)?;if self.closed||self.main_image.is_some(){return Err("CRT process image already issued/closed");}
  let generation=self.serial.checked_add(1).ok_or("CRT process image generation")?;
  self.regions.try_reserve(17).map_err(|_|"CRT process image region budget")?;
  let maps=self.memory.map_pe32(self.owner,file).map_err(|_|"CRT PE32 mapping contract")?;
  let regions:Vec<_>=maps.into_iter().map(|(cap,base,size)|CrtPointer{cap,owner:guest_memory::Owner::Module(self.owner),base,size,address:base,kind:CrtRegionKind::Module}).collect();
  let root=regions[0];let token=CrtProcessImage{anchor:self.anchor,owner:self.owner,generation,root};
  self.regions.extend(regions.iter().map(|&pointer|CrtRegion{pointer,heap:false,file_owner:None}));
  self.main_image_regions=regions;self.main_image=Some(token);self.serial=generation;Ok(token)
 }
 fn process_image_pointer(&self,token:CrtProcessImage,address:u32,size:u32)->Result<CrtPointer,&'static str>{
  self.process_image(token)?;let p=self.main_image_regions.iter().find(|p|address>=p.base&&address.checked_add(size).is_some_and(|end|end<=p.base+p.size)).ok_or("CRT process image section range")?;
  if size==0{return Err("CRT process image empty range");}Ok(CrtPointer{address,..*p})
 }
 /// Validate a named original PE import before binding its replacement effect.
 /// Bounded unrelocated PE32 image; a loader-modified IAT needs a separate binding.
 fn process_image_import(&self,image:CrtProcessImage,iat:u32,module:&str,symbol:&str)->Result<(),&'static str>{
  let root=self.process_image(image)?;let base=root.base;
  let word=|a:u32|->Result<u32,&'static str>{self.load(self.process_image_pointer(image,a,4)?,32)?.known_scalar()};
  let add=|a:u32,b:u32|a.checked_add(b).ok_or("CRT import address overflow");
  let string=|rva:u32,want:&str,fold:bool|->Result<bool,&'static str>{
   if want.len()>256{return Err("CRT import name budget");}let a=add(base,rva)?;
   let p=self.process_image_pointer(image,a,want.len() as u32+1)?;
   let bytes=self.memory.read(p.address(),want.len() as u32+1).map_err(|_|"CRT import name read")?;
   Ok(bytes[want.len()]==0&&if fold{bytes[..want.len()].eq_ignore_ascii_case(want.as_bytes())}else{&bytes[..want.len()]==want.as_bytes()})
  };
  let nt=add(base,word(add(base,60)?)?)?;let directory=word(add(nt,128)?)?;let size=word(add(nt,132)?)?;
  if directory==0||size<20||size>1280{return Err("CRT import directory bound");}
  let mut found=false;
  for n in 0..size/20{let d=add(add(base,directory)?,n*20)?;let lookup=word(d)?;let name=word(add(d,12)?)?;let first=word(add(d,16)?)?;
   if lookup==0&&name==0&&first==0{break;}if lookup==0||first==0{return Err("CRT import descriptor unsupported");}
   let start=add(base,first)?;if iat<start||(iat-start)%4!=0{continue;}let index=(iat-start)/4;if index>=512{continue;}
   if !string(name,module,true)?{continue;}let mut terminated=false;for k in 0..=index{if word(add(add(base,lookup)?,k*4)?)?==0{terminated=true;break;}}if terminated{continue;}
   let entry=word(add(add(base,lookup)?,index*4)?)?;if entry&0x80000000!=0{continue;}
   if string(name,module,true)?&&string(add(entry,2)?,symbol,false)?{
    if found||word(iat)?!=entry{return Err("CRT import ambiguous/changed IAT");}found=true;
   }
  }
  if !found{return Err("CRT original named import unbound");}Ok(())
 }
 /// Successful data-page protection only. Invalid ranges/outputs and unsupported
 /// flags reject before effects; no Windows failure error is invented. Scalar
 /// stack output is deliberately narrower than the public Win32 API contract.
 fn protect_image_data(&mut self,image:CrtProcessImage,target:CrtPointer,size:u32,flags:u32,output:CrtPointer)->Result<(),&'static str>{
  if self.process_image_pointer(image,target.address(),size)?!=target{return Err("CRT protection canonical image alias");}
  // Opaque API objects have stronger live-memory contracts than scalar data.
  // Check the entire intersecting page envelope, not just the requested bytes.
  let begin=target.address()&!4095;let end=((u64::from(target.address())+u64::from(size)+4095)&!4095).min(u64::from(target.base)+u64::from(target.size));
  if begin<target.base{return Err("CRT protection page owner extent");}
  self.ordinary_file_bytes(CrtPointer{address:begin,..target},u32::try_from(end-u64::from(begin)).map_err(|_|"CRT protection page extent")?)?;
  self.valid(output,4)?;
  let old=self.overlapping_tags(output.address(),4);
  if output.kind!=CrtRegionKind::Stack||self.unobserved_contexts.iter().any(|(p,_)|p.cap==output.cap)||!old.is_empty()&&(old.len()!=1||old[0].0!=output.address()||matches!(old[0].1,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)|CrtValue::Dispatcher(_))){return Err("CRT protection output role/authority");}
  self.memory.protect_data_with_old((target.cap,target.owner,target.address(),size),flags,(output.cap,output.owner,output.address())).map_err(|_|"CRT protection range/permission/output contract")?;
  // The complete successful API word write destroys old data authority. A
  // failed protection/output operation preserves both bytes and tags atomically.
  for(at,_)in old{self.tags.remove(&at);}for n in 0..4{self.partial.remove(&(output.address()+n));}Ok(())
 }
 /// Registration is a process-owned exchange, never exception dispatch authority.
 fn unhandled_filter_value(&self)->Result<CrtValue,&'static str>{
  if self.closed{return Err("CRT process filter lifetime");}self.memory.validate(self.anchor,self.file_view.owner).map_err(|_|"CRT process filter storage lifetime")?;
  match self.unhandled_filter{CrtUnhandledFilter::Unobserved=>Ok(CrtValue::Scalar{bits:0,known:0}),CrtUnhandledFilter::Default=>Ok(CrtValue::scalar(0)),CrtUnhandledFilter::Guest(image,p)=>{if self.process_image_code(image,p.address(),1)?!=p{return Err("CRT process filter code identity");}Ok(CrtValue::Pointer(p))}}
 }
 fn exchange_unhandled_filter(&mut self,init:CrtInitialization,target:Option<(CrtProcessImage,CrtPointer)>)->Result<CrtValue,&'static str>{
  self.initialization(init)?;let previous=self.unhandled_filter_value()?;
  let next=if let Some((image,p))=target{if p.kind!=CrtRegionKind::Module||self.process_image_code(image,p.address(),1)?!=p{return Err("CRT process filter target identity");}CrtUnhandledFilter::Guest(image,p)}else{CrtUnhandledFilter::Default};
  self.unhandled_filter=next;self.last_os_error=None;Ok(previous)
 }
 fn unhandled_filter_delivery(&self)->Result<(),&'static str>{self.unhandled_filter_value()?;Err("CRT unhandled exception delivery unbound")}
 fn process_image_code(&self,token:CrtProcessImage,address:u32,size:u32)->Result<CrtPointer,&'static str>{
  let p=self.process_image_pointer(token,address,size)?;self.memory.validate_executable(p.cap,p.owner,address,size).map_err(|_|"CRT process image code permission")?;Ok(p)
 }
 fn process_image(&self,token:CrtProcessImage)->Result<CrtPointer,&'static str>{
  if self.closed||token.anchor!=self.anchor||token.owner!=self.owner||self.main_image!=Some(token){return Err("CRT process image owner/lifetime");}
  for p in &self.main_image_regions{self.identity_range(*p,p.size)?;}self.identity_range(token.root,token.root.size)?;Ok(token.root)
 }
 /// Apply an independently established successful executable-module load.
 /// This records reference effects only; it does not attest DllMain/TLS effects.
 fn module_acquire_result(&mut self,init:CrtInitialization,identity:&str,handle:u32)->Result<(CrtModule,CrtModuleReference),&'static str>{
  self.initialization(init)?;
  if self.providers.get(&handle).is_some_and(|p|p.root.is_none()){return Err("CRT provider not published");}
  if self.closed||handle==0||handle==u32::MAX||identity.is_empty()||identity.len()>256||self.module_references.len()>=256{return Err("CRT module acquisition bounds");}
  let serial=self.serial.checked_add(1).ok_or("CRT module serial")?;
  let generation=if let Some(m)=self.modules.get(&handle){
   if !m.certain||m.identity!=identity{return Err("CRT module identity/effects uncertain");}m.generation
  }else{if self.modules.len()>=64{return Err("CRT module budget");}serial};
  let module=CrtModule{anchor:self.anchor,handle,generation};
  self.modules.entry(handle).or_insert_with(||CrtLoadedModule{identity:identity.into(),generation,certain:true});
  let reference=CrtModuleReference{module,serial};self.module_references.insert(serial,reference);self.serial=serial;Ok((module,reference))
 }
 fn module_identity(&self,module:CrtModule)->Result<(),&'static str>{
  let m=self.modules.get(&module.handle).ok_or("CRT unloaded module")?;
  if self.closed||module.anchor!=self.anchor||m.generation!=module.generation||!m.certain||!self.module_references.values().any(|r|r.module==module){return Err("CRT module owner/generation/lifetime");}Ok(())
 }
 /// The independently established release outcome consumes exactly one owned
 /// acquisition. An unclosed failure invalidates lifetime knowledge rather
 /// than guessing that no detach or reference effect occurred.
 fn module_release_result(&mut self,init:CrtInitialization,reference:CrtModuleReference,success:bool)->Result<(),&'static str>{
  self.initialization(init)?;self.module_identity(reference.module)?;
  if self.module_references.get(&reference.serial)!=Some(&reference){return Err("CRT module reference replay/owner");}
  if self.providers.values().any(|p|p.root==Some(reference)){return Err("CRT process provider root is not a load reference");}
  if !success{self.modules.get_mut(&reference.module.handle).unwrap().certain=false;return Err("CRT failed release effects unclosed");}
  self.module_references.remove(&reference.serial);
  if !self.module_references.values().any(|r|r.module==reference.module){self.modules.remove(&reference.module.handle);self.exports.retain(|_,e|e.function.module!=reference.module);}
  Ok(())
 }
 /// A named, separately justified function export. Variable and ordinal
 /// results, forwarded-owner assumptions, and host addresses are not calls.
 fn module_export_result(&mut self,init:CrtInitialization,module:CrtModule,symbol:&str,address:u32)->Result<CrtFunction,&'static str>{
  self.initialization(init)?;self.module_identity(module)?;
  if self.providers.contains_key(&module.handle){return Err("CRT native provider requires checked publication");}
  if symbol.is_empty()||symbol.len()>256||!symbol.is_ascii()||symbol.as_bytes().contains(&0)||address==0||address==u32::MAX||self.exports.len()>=256{return Err("CRT export bounds/kind");}
  let serial=self.serial.checked_add(1).ok_or("CRT export serial")?;
  let function=CrtFunction{module,address,serial};self.exports.insert(serial,CrtExport{function,symbol:symbol.into(),target:module,callable:true,api:None});self.serial=serial;Ok(function)
 }
 fn function_identity(&self,function:CrtFunction,symbol:Option<&str>)->Result<(),&'static str>{
  self.module_identity(function.module)?;let e=self.exports.get(&function.serial).ok_or("CRT unknown export")?;self.module_identity(e.target)?;
  if e.function!=function||symbol.is_some_and(|s|s!=e.symbol){return Err("CRT export owner/symbol");}if !e.callable{return Err("CRT native provider export implementation unbound");}Ok(())
 }
 /// Allocate the native registry's real export-index storage before exposing a
 /// module. No DLL code, TLS callback or externally supplied success is executed.
 fn provider_begin(&mut self,init:CrtInitialization,identity:&str,handle:u32,limit:usize)->Result<CrtProviderBuild,&'static str>{
  self.initialization(init)?;
  if identity.is_empty()||identity.len()>256||!identity.is_ascii()||identity.as_bytes().contains(&0)||handle==0||handle==u32::MAX||limit==0||limit>64||self.providers.len()>=64||self.modules.contains_key(&handle)||self.providers.contains_key(&handle)
   ||self.modules.values().any(|m|m.identity.eq_ignore_ascii_case(identity))||self.providers.values().any(|p|p.identity.eq_ignore_ascii_case(identity)){return Err("CRT provider identity/resource domain");}
  let serial=self.serial.checked_add(1).ok_or("CRT provider serial")?;
  let mut exports=Vec::new();exports.try_reserve_exact(limit).map_err(|_|"CRT provider export storage allocation")?;
  self.providers.insert(handle,CrtNativeProvider{serial,identity:identity.into(),root:None,exports,limit});self.serial=serial;
  Ok(CrtProviderBuild{anchor:self.anchor,thread:self.thread,serial,handle})
 }
 fn provider_build(&self,init:CrtInitialization,ticket:&CrtProviderBuild)->Result<(),&'static str>{
  self.initialization(init)?;
  if ticket.anchor!=self.anchor||ticket.thread!=self.thread||!self.providers.get(&ticket.handle).is_some_and(|p|p.serial==ticket.serial&&p.root.is_none()){return Err("CRT provider build owner/phase/lifetime");}Ok(())
 }
 fn provider_abort(&mut self,init:CrtInitialization,ticket:&CrtProviderBuild)->Result<(),&'static str>{self.provider_build(init,ticket)?;self.providers.remove(&ticket.handle);Ok(())}
 /// Publish only the constructed native namespace and its process root. This
 /// cannot certify Windows loader effects or make an export callable by itself.
 fn provider_publish(&mut self,init:CrtInitialization,ticket:&CrtProviderBuild)->Result<CrtModule,&'static str>{
  self.provider_build(init,ticket)?;
  if self.modules.len()>=64||self.module_references.len()>=256||self.modules.contains_key(&ticket.handle){return Err("CRT provider publication resource/identity");}
  let identity=self.providers.get(&ticket.handle).unwrap().identity.clone();
  if self.modules.values().any(|m|m.identity.eq_ignore_ascii_case(&identity)){return Err("CRT provider publication identity collision");}
  let serial=self.serial.checked_add(1).ok_or("CRT provider serial")?;
  let module=CrtModule{anchor:self.anchor,handle:ticket.handle,generation:serial};let root=CrtModuleReference{module,serial};
  self.modules.insert(module.handle,CrtLoadedModule{identity,generation:serial,certain:true});self.module_references.insert(serial,root);
  self.providers.get_mut(&ticket.handle).unwrap().root=Some(root);self.serial=serial;Ok(module)
 }
 fn provider_ready(&self,module:CrtModule)->Result<&CrtNativeProvider,&'static str>{
  self.module_identity(module)?;let p=self.providers.get(&module.handle).ok_or("CRT missing native provider")?;
  if !p.root.is_some_and(|r|r.module==module&&self.module_references.get(&r.serial)==Some(&r)){return Err("CRT native provider root lifetime");}Ok(p)
 }
 /// A target lease borrows a separately live native provider. It is not a
 /// Windows LoadLibrary reference, an executable host pointer or an API proof.
 fn provider_export(&mut self,init:CrtInitialization,module:CrtModule,target:CrtModule,symbol:&str,address:u32)->Result<CrtProviderExport,&'static str>{
  self.initialization(init)?;let provider=self.provider_ready(module)?;self.provider_ready(target)?;
  if provider.exports.len()>=provider.limit||self.exports.len()>=256||symbol.is_empty()||symbol.len()>256||!symbol.is_ascii()||symbol.as_bytes().contains(&0)||address==0||address==u32::MAX
   ||self.exports.values().any(|e|e.function.module==module&&e.symbol==symbol){return Err("CRT provider export bounds/duplicate");}
  // Cyclic provider dependencies have no supported destruction ordering.
  let mut pending=vec![target];let mut seen=std::collections::BTreeSet::new();
  while let Some(at)=pending.pop(){if module!=target&&at==module{return Err("CRT provider dependency cycle");}if seen.insert(at.handle){for e in self.exports.values().filter(|e|e.function.module==at&&e.target!=at){self.provider_ready(e.target)?;pending.push(e.target);}}}
  let serial=self.serial.checked_add(1).ok_or("CRT provider serial")?;let function=CrtFunction{module,address,serial};
  self.exports.insert(serial,CrtExport{function,symbol:symbol.into(),target,callable:false,api:None});self.providers.get_mut(&module.handle).unwrap().exports.push(serial);self.serial=serial;Ok(CrtProviderExport{record:function})
 }
 fn provider_target(&self,export:CrtProviderExport)->Result<CrtModule,&'static str>{
  let function=export.record;self.provider_ready(function.module)?;let e=self.exports.get(&function.serial).ok_or("CRT stale provider export")?;
  if e.function!=function||e.callable{return Err("CRT provider descriptor identity/kind");}self.provider_ready(e.target)?;Ok(e.target)
 }
 fn provider_destroy(&mut self,init:CrtInitialization,module:CrtModule)->Result<(),&'static str>{
  self.initialization(init)?;let p=self.provider_ready(module)?;let root=p.root.unwrap();
  if self.native_sync.values().any(|(f,_,_)|f.module==module||self.exports.get(&f.serial).is_some_and(|e|e.target==module))||self.module_references.values().any(|r|r.module==module&&*r!=root)||self.exports.values().any(|e|e.target==module&&e.function.module!=module){return Err("CRT provider still acquired/borrowed");}
  // All rejection checks precede teardown; unrelated earlier effects survive.
  self.exports.retain(|_,e|e.function.module!=module);self.providers.remove(&module.handle);self.module_references.remove(&root.serial);self.modules.remove(&module.handle);Ok(())
 }
 /// Complete a pending native replacement provider. This executes Rust
 /// initialization only; it is not a Windows DllMain or API-set certificate.
 /// Failed construction removes its own namespace, retaining unrelated effects
 /// and monotonic serials. Host OOM outside fallible reserves remains unclosed.
 fn provider_initialize_sync(&mut self,init:CrtInitialization,ticket:&CrtProviderBuild,address:u32)->Result<(CrtModule,CrtFunction),&'static str>{
  self.provider_build(init,ticket)?;
  let mut published=None;
  let result=(||{
   if address==0||address==u32::MAX||self.exports.len()>=256||self.serial.checked_add(2).is_none(){return Err("CRT native provider initialization bounds");}
   let module=self.provider_publish(init,ticket)?;published=Some(module);
   let descriptor=self.provider_export(init,module,module,"InitializeCriticalSectionEx",address)?;
   let function=self.bind_native_sync(init,descriptor)?;Ok((module,function))
  })();
  if result.is_err(){match published{Some(module)=>self.provider_destroy(init,module)?,None=>self.provider_abort(init,ticket)?,}}
  result
 }
 /// Real native reference bookkeeping, with no supplied load-success result.
 /// Only the already implemented synchronization operation is eligible.
 fn native_provider_acquire(&mut self,init:CrtInitialization,function:CrtFunction)->Result<CrtNativeProviderReference,&'static str>{
  self.initialization(init)?;self.native_api_identity(function)?;self.provider_ready(function.module)?;
  if self.module_references.len()>=256{return Err("CRT native provider reference budget");}
  let serial=self.serial.checked_add(1).ok_or("CRT native provider reference serial")?;
  let reference=CrtModuleReference{module:function.module,serial};self.module_references.insert(serial,reference);self.serial=serial;
  Ok(CrtNativeProviderReference{reference,function})
 }
 fn native_provider_release(&mut self,init:CrtInitialization,owned:CrtNativeProviderReference)->Result<(),&'static str>{
  self.initialization(init)?;self.native_api_identity(owned.function)?;let p=self.provider_ready(owned.reference.module)?;
  if owned.reference.module!=owned.function.module||p.root==Some(owned.reference)||self.module_references.get(&owned.reference.serial)!=Some(&owned.reference){return Err("CRT native provider reference owner/replay");}
  self.module_references.remove(&owned.reference.serial);Ok(())
 }
 /// Resolve only a unique already implemented native export; lookup creates no
 /// descriptor and grants no authority to an unimplemented or stale target.
 fn native_named_export(&self,init:CrtInitialization,module:CrtModule,name:&str)->Result<CrtFunction,&'static str>{
  self.initialization(init)?;self.provider_ready(module)?;
  if name.is_empty()||name.len()>255||!name.is_ascii()||name.as_bytes().contains(&0){return Err("CRT native named export encoding/bounds");}
  let mut matches=self.exports.values().filter(|e|e.function.module==module&&e.symbol==name);
  let e=matches.next().ok_or("CRT native named export unsupported")?;
  if matches.next().is_some(){return Err("CRT native named export ambiguous");}
  if self.provider_ready(module)?.exports.iter().filter(|id|**id==e.function.serial).count()!=1{return Err("CRT native named export publication incomplete");}
  self.function_identity(e.function,Some(name))?;
  if e.api.is_none(){return Err("CRT native named export implementation unbound");}
  self.provider_ready(e.target)?;Ok(e.function)
 }
 /// This issuer binds only the implemented, startup-exclusive global-lock API.
 fn bind_native_sync(&mut self,init:CrtInitialization,descriptor:CrtProviderExport)->Result<CrtFunction,&'static str>{
  self.initialization(init)?;self.provider_target(descriptor)?;let e=self.exports.get_mut(&descriptor.record.serial).unwrap();
  if e.symbol!="InitializeCriticalSectionEx"{return Err("CRT native synchronization symbol/ABI");}
  e.api=Some(CrtNativeApi::InitializeGlobalCriticalSectionEx);e.callable=true;Ok(descriptor.record)
 }
 fn bind_native_fls(&mut self,init:CrtInitialization,descriptor:CrtProviderExport)->Result<CrtFunction,&'static str>{
  self.initialization(init)?;self.provider_target(descriptor)?;let e=self.exports.get_mut(&descriptor.record.serial).unwrap();
  if e.symbol!="FlsAlloc"{return Err("CRT native FLS symbol/ABI");}e.api=Some(CrtNativeApi::FlsAlloc);e.callable=true;Ok(descriptor.record)
 }
 fn bind_native_fls_set(&mut self,init:CrtInitialization,d:CrtProviderExport)->Result<CrtFunction,&'static str>{self.initialization(init)?;self.provider_target(d)?;let e=self.exports.get_mut(&d.record.serial).unwrap();if e.symbol!="FlsSetValue"{return Err("CRT native FLS setter symbol/ABI");}e.api=Some(CrtNativeApi::FlsSetValue);e.callable=true;Ok(d.record)}
 fn bind_native_file_mode(&mut self,init:CrtInitialization,d:CrtProviderExport,mode:CrtFileApiMode)->Result<(CrtFunction,CrtProcessFileMode),&'static str>{
  self.initialization(init)?;self.provider_target(d)?;
  if self.file_mode.is_some()||self.exports.get(&d.record.serial).is_none_or(|e|e.symbol!="AreFileApisANSI"){return Err("CRT file mode publication state/symbol");}
  let serial=self.serial.checked_add(1).ok_or("CRT file mode serial")?;
  let token=CrtProcessFileMode{anchor:self.anchor,serial};
  let e=self.exports.get_mut(&d.record.serial).unwrap();e.api=Some(CrtNativeApi::AreFileApisAnsi);e.callable=true;
  self.file_mode=Some((token,mode));self.serial=serial;Ok((d.record,token))
 }
 fn file_mode(&self,token:CrtProcessFileMode)->Result<CrtFileApiMode,&'static str>{
  if self.closed||token.anchor!=self.anchor||self.file_mode.is_none_or(|(t,_)|t!=token)||self.memory.validate(self.anchor,guest_memory::Owner::Module(self.owner)).is_err(){return Err("CRT process file mode owner/lifetime");}Ok(self.file_mode.unwrap().1)
 }
 fn set_file_mode(&mut self,token:CrtProcessFileMode,mode:CrtFileApiMode)->Result<(),&'static str>{self.file_mode(token)?;self.file_mode.as_mut().unwrap().1=mode;Ok(())}
 fn file_mode_result(&mut self,token:CrtProcessFileMode)->Result<CrtValue,&'static str>{
  let truth=self.file_mode(token)?!=CrtFileApiMode::Oem;self.symbolic_bool(truth)
 }
 /// Preserve BOOL truth without choosing any unspecified representation bits.
 fn symbolic_bool(&mut self,truth:bool)->Result<CrtValue,&'static str>{
  if !truth{return Ok(CrtValue::scalar(0));}
  let serial=self.serial.checked_add(1).ok_or("CRT BOOL symbol serial")?;self.serial=serial;Ok(CrtValue::NonZero{anchor:self.anchor,serial})
 }
 /// One-call source acquisition. No query-to-copy authority is cached.
 fn utf8_source(&self,input:CrtPointer,count:i32)->Result<(Vec<u16>,guest_memory::ReadFact),&'static str>{
  if count!= -1&&!(1..=32767).contains(&count){return Err("native UTF8 input count outside bounded domain");}
  let bound=if count== -1{32767}else{count as u32};let mut units=Vec::new();let mut terminated=false;
  for n in 0..bound{let p=self.offset(input,i64::from(n)*2)?;let unit=self.load(p,16)?.known_scalar()? as u16;units.try_reserve(1).map_err(|_|"native UTF8 source resource")?;units.push(unit);if count== -1&&unit==0{terminated=true;break;}}
  if count== -1&&!terminated{return Err("native UTF8 unterminated input");}
  let fact=self.memory.prove_read(input.cap,input.owner,input.address(),units.len()as u32*2).map_err(|_|"native UTF8 source read provenance")?;Ok((units,fact))
 }
 fn utf8_required(&self,input:CrtPointer,count:i32)->Result<u32,&'static str>{
  let(units,_)=self.utf8_source(input,count)?;
  char::decode_utf16(units).try_fold(0u32,|total,c|total.checked_add(c.unwrap_or(char::REPLACEMENT_CHARACTER).len_utf8()as u32).ok_or("native UTF8 byte count overflow"))
 }
 /// The public Win32 error paths can write output before failure. Only the
 /// complete-fit flags0 domain is implemented here; failures are not simulated.
 fn utf8_write(&mut self,input:CrtPointer,count:i32,destination:CrtPointer,capacity:u32)->Result<u32,&'static str>{
  let(units,fact)=self.utf8_source(input,count)?;let input_bytes=units.len()as u32*2;
  let mut bytes=Vec::new();for c in char::decode_utf16(units){let c=c.unwrap_or(char::REPLACEMENT_CHARACTER);let mut text=[0;4];let encoded=c.encode_utf8(&mut text).as_bytes();bytes.try_reserve(encoded.len()).map_err(|_|"native UTF8 output resource")?;bytes.extend_from_slice(encoded);}
  let written=u32::try_from(bytes.len()).map_err(|_|"native UTF8 byte count overflow")?;
  if capacity==0||capacity>131072{return Err("native UTF8 output capacity domain");}
  if written>capacity{return Err("native UTF8 insufficient-capacity effects unbound");}
  self.valid(destination,capacity)?;self.ordinary_file_bytes(destination,capacity)?;
  if !matches!(destination.kind,CrtRegionKind::Stack|CrtRegionKind::Buffer|CrtRegionKind::Module)||self.unobserved_contexts.iter().any(|(q,_)|q.cap==destination.cap){return Err("native UTF8 output role");}
  if u64::from(input.address())<u64::from(destination.address())+u64::from(capacity)&&u64::from(destination.address())<u64::from(input.address())+u64::from(input_bytes){return Err("native UTF8 input/output alias");}
  self.memory.validate_writable(destination.cap,destination.owner,destination.address(),capacity).map_err(|_|"native UTF8 output permission")?;
  for(at,v)in self.overlapping_tags(destination.address(),written){if matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)|CrtValue::Dispatcher(_))||at<destination.address()||u64::from(at)+4>u64::from(destination.address())+u64::from(written){return Err("native UTF8 partial/control output unbound");}}
  self.memory.read_proven(fact,input.owner).map_err(|_|"native UTF8 source observation expired")?;
  let mut n=0usize;while n<bytes.len(){let p=self.offset(destination,n as i64)?;if self.tags.contains_key(&p.address()){let word=u32::from_le_bytes(bytes[n..n+4].try_into().unwrap());self.store(p,32,CrtValue::scalar(word))?;n+=4;}else{self.store(p,8,CrtValue::scalar(u32::from(bytes[n])))?;n+=1;}}
  Ok(written)
 }

 /// PE32 startup-only opaque initialization; no private byte pattern is asserted.
 fn initialize_slist_head(&mut self,init:CrtInitialization,p:CrtPointer)->Result<CrtSListHead,&'static str>{
  self.initialization(init)?;self.valid(p,8)?;
  if p.kind!=CrtRegionKind::Module||p.address()%8!=0||self.file_overlap(p,8){return Err("CRT SLIST module/alignment domain");}
  self.ordinary_non_slist_bytes(p,8)?;self.memory.validate_writable(p.cap,p.owner,p.address(),8).map_err(|_|"CRT SLIST write permission")?;
  if self.errno_cell.is_some_and(|q|q.cap==p.cap&&u64::from(p.address())<u64::from(q.address())+4&&u64::from(q.address())<u64::from(p.address())+8){return Err("CRT SLIST errno alias");}
  let header=self.subrange(p,8)?;let existing=(0..32).find(|i|self.slist_heads.get(i).is_some_and(|h|h.header==header));
  if self.slist_heads.values().any(|h|h.header.cap==p.cap&&h.header!=header&&u64::from(p.address())<u64::from(h.header.address())+8&&u64::from(h.header.address())<u64::from(p.address())+8){return Err("CRT overlapping SLIST headers");}
  let index=existing.or_else(||(0..32).find(|i|!self.slist_heads.contains_key(i))).ok_or("CRT SLIST capacity domain")?;
  let serial=self.serial.checked_add(1).ok_or("CRT SLIST generation")?;let old=self.overlapping_tags(p.address(),8);
  if old.iter().any(|(at,v)|*at<p.address()||u64::from(*at)+4>u64::from(p.address())+8||matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)|CrtValue::Dispatcher(_))){return Err("CRT SLIST partial/control alias");}
  // Atomic forgetting expires old read facts. Unknown private bytes cannot be
  // observed through guest loads, copies or writes while this role is live.
  self.memory.forget(p.address(),8).map_err(|_|"CRT SLIST effect range")?;
  for(at,_)in old{self.tags.remove(&at);}self.partial.retain(|at,_|*at<p.address()||u64::from(*at)>=u64::from(p.address())+8);
  let head=CrtSListHead{anchor:self.anchor,header,serial};self.serial=serial;self.slist_heads.insert(index,head);Ok(head)
 }
 fn slist_head(&self,h:CrtSListHead)->Result<(),&'static str>{
  if h.anchor!=self.anchor||!self.slist_heads.values().any(|q|*q==h){return Err("CRT stale/foreign SLIST state");}self.valid(h.header,8)
 }
 fn native_api_identity(&self,f:CrtFunction)->Result<(),&'static str>{
  self.function_identity(f,None)?;
  match self.exports.get(&f.serial).and_then(|e|e.api){Some(CrtNativeApi::InitializeGlobalCriticalSectionEx)=>self.native_sync_identity(f),Some(CrtNativeApi::FlsAlloc)=>self.function_identity(f,Some("FlsAlloc")),Some(CrtNativeApi::FlsSetValue)=>self.function_identity(f,Some("FlsSetValue")),Some(CrtNativeApi::AreFileApisAnsi)=>self.function_identity(f,Some("AreFileApisANSI")),None=>Err("CRT native API implementation unbound")}
 }
 fn native_sync_identity(&self,function:CrtFunction)->Result<(),&'static str>{
  self.function_identity(function,Some("InitializeCriticalSectionEx"))?;
  if self.exports.get(&function.serial).and_then(|e|e.api)!=Some(CrtNativeApi::InitializeGlobalCriticalSectionEx){return Err("CRT native synchronization implementation unbound");}Ok(())
 }
 /// Object and lease storage is fixed at runtime creation. This closes native
 /// bookkeeping allocation only, not Windows allocation-failure equivalence.
 fn native_sync_initialize(&mut self,init:CrtInitialization,function:CrtFunction,index:u32,p:CrtPointer,_spin:u32,flags:u32)->Result<u32,&'static str>{
  self.initialization(init)?;self.native_sync_identity(function)?;self.identity_range(p,24)?;
  self.memory.validate_writable(p.cap,p.owner,p.address,24).map_err(|_|"CRT synchronization writable range")?;
  if flags!=0||index>=32||p.kind!=CrtRegionKind::Module||p.address%4!=0||self.global_objects.contains_key(&index)||self.global_objects.values().any(|q|u64::from(p.address)<u64::from(q.address)+24&&u64::from(q.address)<u64::from(p.address)+24)||self.has_overlapping_tags(p.address,24){return Err("CRT synchronization flags/object domain");}
  self.ordinary_file_bytes(p,24)?;
  if self.native_sync.contains_key(&index){return Err("CRT synchronization tracking occupied");}
  self.construct_global_lock(init,index,p,1)?;self.native_sync.insert(index,(function,index,p));Ok(1)
 }
 fn native_sync_delete(&mut self,init:CrtInitialization,function:CrtFunction,index:u32,p:CrtPointer)->Result<(),&'static str>{
  self.initialization(init)?;self.native_sync_identity(function)?;self.identity_range(p,24)?;
  if self.native_sync.get(&index)!=Some(&(function,index,p)){return Err("CRT synchronization object owner/lifetime");}
  self.destroy_global_lock(init,index)?;self.native_sync.remove(&index);Ok(())
 }
 fn loader_value(&self,value:CrtValue)->Result<(),&'static str>{match value{
  CrtValue::Module(m)=>self.module_identity(m),CrtValue::Function(f)=>self.function_identity(f,None),
  CrtValue::Scalar{bits:0|u32::MAX,known:u32::MAX}=>Ok(()),_=>Err("CRT loader cache type/unknown")}}
 /// Serialized full-word XCHG in the explicit startup-exclusive domain.
 /// The runtime is not shared; no host callback runs between read and write.
 /// General concurrent guest publication needs a separate interleaving proof.
 fn bind_loader_cell(&mut self,init:CrtInitialization,p:CrtPointer,function:bool)->Result<(),&'static str>{
  self.initialization(init)?;if self.closed||p.kind!=CrtRegionKind::Module||p.address%4!=0||self.loader_cells.len()>=128||self.loader_cells.contains_key(&p.address){return Err("CRT loader cell role/alignment/budget");}
  let old=self.load(p,32)?;self.loader_cell_value(function,old)?;self.loader_cells.insert(p.address,(p,function));Ok(())
 }
 fn loader_cell_value(&self,function:bool,v:CrtValue)->Result<(),&'static str>{
  self.loader_value(v)?;if matches!(v,CrtValue::Module(_))&&function||matches!(v,CrtValue::Function(_))&&!function{return Err("CRT module/export cache kind");}Ok(())
 }
 fn exchange_module_word(&mut self,p:CrtPointer,value:CrtValue)->Result<CrtValue,&'static str>{
  if self.closed||self.initialization.is_none()||p.kind!=CrtRegionKind::Module||p.address%4!=0{return Err("CRT exchange exclusive module word");}
  let &(bound,function)=self.loader_cells.get(&p.address).ok_or("CRT unbound loader cache")?;
  if bound!=p{return Err("CRT loader cell lifetime/alias");}self.loader_cell_value(function,value)?;let old=self.load(p,32)?;self.loader_cell_value(function,old)?;
  self.store(p,32,value)?;Ok(old)
 }
 fn bind_fiber(&mut self,thread:u64)->Result<CrtFiber,&'static str>{
  if self.closed||thread!=self.thread||self.fiber.is_some(){return Err("CRT fiber context already bound/foreign");}
  let serial=self.serial.checked_add(1).ok_or("CRT fiber serial")?;let f=CrtFiber{anchor:self.anchor,thread,serial};self.serial=serial;self.fiber=Some(f);Ok(f)
 }
 fn check_fiber(&self,f:CrtFiber)->Result<(),&'static str>{if self.closed||self.fiber!=Some(f)||f.anchor!=self.anchor||f.thread!=self.thread{return Err("CRT fiber identity/lifetime");}Ok(())}
 /// Snapshot live allocation identities before entering the bound call.
 /// This is a checked component effect boundary, not proof of a host allocator.
 fn begin_heap_ptd_allocation(&self,f:CrtFiber,slot:CrtFlsSlot)->Result<CrtHeapPtdAllocation,&'static str>{
  self.check_fiber(f)?;self.fls_index(slot.allocation)?;
  if slot.fiber!=f||self.fls.get(&slot.index)!=Some(&(slot,CrtValue::scalar(u32::MAX))){return Err("CRT PTD allocation missing sentinel/slot");}
  Ok(CrtHeapPtdAllocation{anchor:self.anchor,slot,before:self.regions.iter().map(|r|r.pointer.cap).collect()})
 }
 /// Consume only after the protected allocation continuation has returned.
 /// Existing roots cannot gain a new role by copying their bytes.
 fn bind_heap_ptd_return(&mut self,ticket:CrtHeapPtdAllocation,p:CrtPointer)->Result<(),&'static str>{self.bind_heap_ptd_layout(ticket,p,CrtPtdLayout::Vcruntime)}
 fn bind_heap_ptd_layout(&mut self,ticket:CrtHeapPtdAllocation,p:CrtPointer,layout:CrtPtdLayout)->Result<(),&'static str>{
  let size=layout.size();
  if ticket.anchor!=self.anchor{return Err("CRT PTD allocation foreign ticket");}let slot=ticket.slot;let f=slot.fiber;let before=&ticket.before;
  self.check_fiber(f)?;self.valid(p,size)?;
  if slot.fiber!=f||self.fls.get(&slot.index).map(|x|x.0)!=Some(slot){return Err("CRT PTD allocation slot lifetime");}self.fls_index(slot.allocation)?;
  if self.fls.get(&slot.index).map(|x|x.1)!=Some(CrtValue::scalar(u32::MAX)){return Err("CRT PTD allocation missing sentinel");}
  if p.kind!=CrtRegionKind::Buffer||p.address!=p.base||p.size!=size||before.contains(&p.cap)||self.heap_ptds.iter().any(|v|v.pointer.cap==p.cap)
   ||!self.regions.iter().any(|r|r.pointer==p&&r.heap&&r.file_owner.is_none()){return Err("CRT PTD allocation fresh root/role");}
  for offset in (0..size).step_by(4){if self.load(self.offset(p,i64::from(offset))?,32)?!=CrtValue::scalar(0){return Err("CRT PTD allocation zero initialization");}}
  self.heap_ptds.push(CrtHeapPtdView{pointer:p,slot,layout});Ok(())
 }
 fn heap_ptd_view(&self,p:CrtPointer,slot:CrtFlsSlot)->Result<(),&'static str>{self.heap_ptd_layout_view(p,slot,CrtPtdLayout::Vcruntime)}
 fn heap_ptd_layout_view(&self,p:CrtPointer,slot:CrtFlsSlot,layout:CrtPtdLayout)->Result<(),&'static str>{
  self.check_fiber(slot.fiber)?;self.fls_index(slot.allocation)?;
  let view=self.heap_ptds.iter().find(|v|v.pointer==p&&v.slot==slot&&v.layout==layout).ok_or("CRT PTD view owner/slot/lifetime")?;
  self.valid(p,view.layout.size())?;if p.size!=view.layout.size(){return Err("CRT PTD view layout extent");}
  if self.fls.get(&slot.index).map(|x|x.0)!=Some(slot)||!self.heap_ptds.iter().any(|v|v.pointer==p&&v.slot==slot)
   ||!self.regions.iter().any(|r|r.pointer==p&&r.heap&&r.file_owner.is_none()){return Err("CRT PTD view owner/slot/lifetime");}Ok(())
 }
 fn fls_value_for(&self,slot:CrtFlsSlot,v:CrtValue)->Result<(),&'static str>{
  if matches!(v,CrtValue::Scalar{known:u32::MAX,..})&&self.fls_indices.get(&slot.index).is_some_and(|e|e.native&&e.id==slot.allocation){return Ok(());}
  if let CrtValue::Pointer(p)=v{if p.kind==CrtRegionKind::Buffer{if let Some(view)=self.heap_ptds.iter().find(|v|v.pointer.cap==p.cap){return self.heap_ptd_layout_view(p,slot,view.layout);}}}self.fls_value(v)
 }
 fn dispatcher_ptd(&self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,40)?;
  if p.kind==CrtRegionKind::ThreadData&&p.address==p.base&&self.regions.iter().any(|r|r.pointer==p){return Ok(());}
  let view=self.heap_ptds.iter().find(|v|v.pointer==p&&v.layout==CrtPtdLayout::Vcruntime).ok_or("C++ PTD root provenance")?;self.heap_ptd_view(p,view.slot)?;
  if self.fls.get(&view.slot.index).map(|x|x.1)!=Some(CrtValue::Pointer(p)){return Err("CRT PTD view not published");}Ok(())
 }
 fn fls_value(&self,v:CrtValue)->Result<(),&'static str>{match v{
  CrtValue::Pointer(p)=>{self.valid(p,20)?;if p.kind!=CrtRegionKind::ThreadData||p.address!=p.base||!self.regions.iter().any(|r|r.pointer==p){return Err("CRT FLS PTD root/extent");}},
  CrtValue::Scalar{bits:0|u32::MAX,known:u32::MAX}=>{},_=>return Err("CRT FLS unknown/forged PTD value")};Ok(())}
 /// Bind independently established initial FLS state, not execute FlsAlloc.
 fn bind_fls(&mut self,f:CrtFiber,index:u32,value:CrtValue)->Result<CrtFlsSlot,&'static str>{
  self.check_fiber(f)?;self.fls_value(value)?;
  if index==u32::MAX||self.fls_indices.len()>=64||self.fls_indices.contains_key(&index)||self.fls.contains_key(&index){return Err("CRT FLS index/budget/already bound");}
  let serial=self.serial.checked_add(2).ok_or("CRT FLS serial")?;
  let allocation=CrtFlsIndex{anchor:self.anchor,index,serial:serial-1};let slot=CrtFlsSlot{fiber:f,index,serial,allocation};
  self.fls_indices.insert(index,CrtProcessFls{id:allocation,callback:None,certain:true,input_binding:true,native:false});self.serial=serial;self.fls.insert(index,(slot,value));Ok(slot)
 }
 /// Actual bounded native allocation, not an observed/supplied index.
 /// Capacity/serial rejection is outside this native component domain; no
 /// Windows failure code or FLS_OUT_OF_INDEXES result is fabricated.
 fn native_fls_allocate(&mut self,init:CrtInitialization,callback:Option<(CrtProcessImage,CrtPointer)>)->Result<CrtFlsIndex,&'static str>{
  self.initialization(init)?;self.fls_callback(callback)?;
  let index=(0..64).find(|n|!self.fls_indices.contains_key(n)).ok_or("CRT native FLS index capacity")?;
  if self.fls_indices.len()>=64{return Err("CRT native FLS index capacity");}
  let serial=self.serial.checked_add(1).ok_or("CRT FLS serial")?;
  let id=CrtFlsIndex{anchor:self.anchor,index,serial};
  self.fls_indices.insert(index,CrtProcessFls{id,callback,certain:true,input_binding:false,native:true});self.serial=serial;self.last_os_error=None;Ok(id)
 }
 /// Native current-fiber read. A fresh native allocation has the documented
 /// initial zero value; supplied/uncertain allocations cannot issue that fact.
 /// Existing values, including unknown bits, are never reset by acquisition.
 fn native_fls_read(&mut self,init:CrtInitialization,f:CrtFiber,index:u32)->Result<CrtValue,&'static str>{
  self.initialization(init)?;self.check_fiber(f)?;
  let entry=*self.fls_indices.get(&index).ok_or("CRT native FLS read stale index")?;self.fls_index(entry.id)?;
  if !entry.native{return Err("CRT native FLS read supplied allocation");}
  let slot=if let Some(&(slot,_))=self.fls.get(&index){
   if slot.fiber!=f||slot.allocation!=entry.id{return Err("CRT native FLS read fiber/index identity");}slot
  }else{
   if self.fls.len()>=64{return Err("CRT native FLS value capacity");}
   let serial=self.serial.checked_add(1).ok_or("CRT FLS serial")?;let slot=CrtFlsSlot{fiber:f,index,serial,allocation:entry.id};
   self.fls.insert(index,(slot,CrtValue::scalar(0)));self.serial=serial;slot
  };self.fls_get(f,slot,index)
 }
 /// Fixed-storage publication for an actually allocated native index. Opaque
 /// scalar values carry bits only and confer no pointer/PTD authority.
 fn native_fls_set(&mut self,init:CrtInitialization,f:CrtFiber,index:u32,value:CrtValue)->Result<bool,&'static str>{
  self.initialization(init)?;self.check_fiber(f)?;
  if index==u32::MAX{self.last_os_error=Some(87);return Ok(false);}
  let entry=*self.fls_indices.get(&index).ok_or("CRT native FLS setter stale index")?;self.fls_index(entry.id)?;
  if !entry.native{return Err("CRT native FLS setter supplied allocation");}
  let existing=self.fls.get(&index).copied();
  let slot=match existing{Some((slot,_))=>{if slot.fiber!=f||slot.allocation!=entry.id{return Err("CRT native FLS setter fiber/index identity");}slot},None=>{
   if self.fls.len()>=64{return Err("CRT native FLS value capacity");}
   CrtFlsSlot{fiber:f,index,serial:self.serial.checked_add(1).ok_or("CRT FLS serial")?,allocation:entry.id}
  }};
  self.fls_value_for(slot,value)?;
  if existing.is_none(){self.serial=slot.serial;}
  self.fls.insert(index,(slot,value));self.errno_cell=None;self.errno=None;self.last_os_error=None;Ok(true)
 }
 /// Record a separately established allocation outcome, including its exact
 /// callback owner. This does not invoke FlsAlloc or assert loader effects.
 fn fls_allocation_result(&mut self,init:CrtInitialization,index:u32,callback:Option<(CrtProcessImage,CrtPointer)>)->Result<Option<CrtFlsIndex>,&'static str>{
  self.initialization(init)?;self.fls_callback(callback)?;
  if index==u32::MAX{return Ok(None);}
  if self.fls_indices.len()>=64||self.fls_indices.contains_key(&index){return Err("CRT FLS process index/budget/alias");}
  let serial=self.serial.checked_add(1).ok_or("CRT FLS serial")?;let id=CrtFlsIndex{anchor:self.anchor,index,serial};
  self.fls_indices.insert(index,CrtProcessFls{id,callback,certain:true,input_binding:false,native:false});self.serial=serial;Ok(Some(id))
 }
 fn fls_callback(&self,callback:Option<(CrtProcessImage,CrtPointer)>)->Result<(),&'static str>{
  if let Some((image,p))=callback{if self.process_image_code(image,p.address(),1)?!=p{return Err("CRT FLS callback image/alias");}}Ok(())
 }
 fn fls_index(&self,id:CrtFlsIndex)->Result<(),&'static str>{
  self.memory.validate(self.anchor,self.file_view.owner).map_err(|_|"CRT FLS process storage lifetime")?;
  let entry=self.fls_indices.get(&id.index).ok_or("CRT FLS process index retired")?;
  if self.closed||id.anchor!=self.anchor||entry.id!=id||!entry.certain{return Err("CRT FLS process index owner/lifetime");}self.fls_callback(entry.callback)
 }
 /// Only a fiber with no prior value lease can receive the independently
 /// established initial null value. Rebinding cannot reset a published value.
 fn bind_fls_fiber(&mut self,f:CrtFiber,id:CrtFlsIndex)->Result<CrtFlsSlot,&'static str>{
  self.check_fiber(f)?;self.fls_index(id)?;if self.fls.contains_key(&id.index){return Err("CRT FLS fiber value already bound");}
  let serial=self.serial.checked_add(1).ok_or("CRT FLS serial")?;let slot=CrtFlsSlot{fiber:f,index:id.index,serial,allocation:id};
  self.fls.insert(id.index,(slot,CrtValue::scalar(0)));self.serial=serial;Ok(slot)
 }
 /// Bounded stationary-fiber teardown: a null value has no callback work.
 /// Nonnull or unknown values cannot be discarded to manufacture cleanup.
 fn detach_empty_fls_fiber(&mut self,f:CrtFiber,slot:CrtFlsSlot)->Result<(),&'static str>{
  self.check_fiber(f)?;self.fls_index(slot.allocation)?;
  if slot.fiber!=f||self.fls.get(&slot.index)!=Some(&(slot,CrtValue::scalar(0))){return Err("CRT FLS fiber detach needs live null value");}
  self.fls.remove(&slot.index);self.heap_ptds.retain(|v|v.slot!=slot);self.errno_cell=None;self.errno=None;Ok(())
 }
 /// Free outcome is applicable only after all value/callback work is closed.
 /// On unclosed failure retain storage but revoke lifetime knowledge.
 fn fls_free_index_result(&mut self,init:CrtInitialization,id:CrtFlsIndex,success:bool)->Result<(),&'static str>{
  self.initialization(init)?;self.fls_index(id)?;
  if self.fls.contains_key(&id.index){return Err("CRT FLS free has live fiber/callback effects");}
  if !success{self.fls_indices.get_mut(&id.index).unwrap().certain=false;self.errno_cell=None;self.errno=None;return Err("CRT FLS free failure effects unclosed");}
  self.fls_indices.remove(&id.index);Ok(())
 }
 fn fls_get(&mut self,f:CrtFiber,slot:CrtFlsSlot,index:u32)->Result<CrtValue,&'static str>{
  self.check_fiber(f)?;let &(actual,value)=self.fls.get(&index).ok_or("CRT unbound FLS index")?;
  if slot!=actual||slot.fiber!=f||slot.index!=index{return Err("CRT FLS owner/reused index");}self.fls_index(slot.allocation)?;self.fls_value_for(slot,value)?;
  // FlsGetValue's public success contract does not promise a preserved or
  // zero LastError. The original getter saves/restores it around this call.
  self.last_os_error=None;Ok(value)
 }
 /// Apply an independently supplied setter outcome. Failure leaves value
 /// knowledge unknown; the public BOOL contract cannot certify atomicity.
 fn fls_set(&mut self,f:CrtFiber,slot:CrtFlsSlot,index:u32,value:CrtValue,success:bool,last_error:Option<u32>)->Result<bool,&'static str>{
  self.check_fiber(f)?;if slot.fiber!=f||slot.index!=index||self.fls.get(&index).map(|x|x.0)!=Some(slot){return Err("CRT FLS setter owner/index/lifetime");}self.fls_index(slot.allocation)?;self.fls_value_for(slot,value)?;
  self.fls.insert(index,(slot,if success{value}else{CrtValue::Scalar{bits:0,known:0}}));self.errno_cell=None;self.errno=None;self.last_os_error=last_error;Ok(success)
 }
 fn retire_fls(&mut self,f:CrtFiber,slot:CrtFlsSlot)->Result<(),&'static str>{
  self.check_fiber(f)?;if slot.fiber!=f||self.fls.get(&slot.index).map(|x|x.0)!=Some(slot){return Err("CRT stale FLS retirement");}self.fls_index(slot.allocation)?;if !self.fls_indices.get(&slot.index).is_some_and(|e|e.input_binding){return Err("CRT allocated FLS requires callback/free closure");}self.fls_indices.remove(&slot.index);self.fls.remove(&slot.index);self.heap_ptds.retain(|v|v.slot!=slot);self.errno_cell=None;self.errno=None;Ok(())
 }
 fn retire_fiber(&mut self,f:CrtFiber)->Result<(),&'static str>{self.check_fiber(f)?;if !self.fls.is_empty(){return Err("CRT live FLS slots/callback effects");}self.fiber=None;self.errno_cell=None;self.errno=None;Ok(())}
 /// Separate startup-exclusive storage authority, with no preconstructed lock.
 /// Ending it does not attest that original CRT initialization has completed.
 fn new_initializing(owner:u64,thread:u64,file_address:u32,byte_limit:usize)->Result<(Self,CrtInitialization),&'static str>{Self::new_initializing_array(owner,thread,file_address,1,byte_limit)}
 fn new_initializing_array(owner:u64,thread:u64,file_address:u32,file_count:u32,byte_limit:usize)->Result<(Self,CrtInitialization),&'static str>{
  let mut runtime=Self::file_array(owner,thread,file_address,file_count,byte_limit)?;runtime.lock_objects.clear();runtime.initialization=Some(1);
  let token=CrtInitialization{anchor:runtime.anchor,thread,serial:1};Ok((runtime,token))
 }
 fn initialization(&self,token:CrtInitialization)->Result<(),&'static str>{
  self.memory.validate(self.anchor,self.file_view.owner).map_err(|_|"CRT initialization storage lifetime")?;
  if self.closed||token.anchor!=self.anchor||token.thread!=self.thread||self.initialization!=Some(token.serial){return Err("CRT initialization owner/lifetime");}Ok(())
 }
 fn end_initialization(&mut self,token:CrtInitialization)->Result<(),&'static str>{self.initialization(token)?;if self.providers.values().any(|p|p.root.is_none()){return Err("CRT initialization has pending provider");}if !self.locks.is_empty()||!self.descriptor_locks.is_empty()||!self.record_locks.is_empty()||!self.global_locks.is_empty(){return Err("CRT initialization with live lock lease");}self.initialization=None;Ok(())}
 /// The receipt attests only this component's caller/thread lifecycle. It
 /// cannot assert process-wide Windows shutdown or unrelated thread quiescence.
 fn begin_shutdown(&mut self,receipt:CrtShutdownReceipt)->Result<CrtShutdown,&'static str>{
  if receipt.anchor!=self.anchor||receipt.thread!=self.thread||receipt.event==0||self.initialization.is_some()||self.shutdown.is_some()||self.closed||!self.locks.is_empty()||!self.descriptor_locks.is_empty()||!self.record_locks.is_empty()||!self.global_locks.is_empty(){return Err("CRT shutdown receipt/phase/active lease");}
  let serial=self.serial.checked_add(1).ok_or("CRT shutdown generation")?;let token=CrtShutdown{anchor:self.anchor,thread:self.thread,serial,event:receipt.event};self.serial=serial;self.shutdown=Some(token);Ok(token)
 }
 fn shutdown(&self,token:CrtShutdown)->Result<(),&'static str>{if self.closed||self.shutdown!=Some(token){return Err("CRT shutdown owner/lifetime");}Ok(())}
 fn destroy_lock_shutdown(&mut self,token:CrtShutdown,file:CrtPointer)->Result<(),&'static str>{self.shutdown(token)?;self.file_record(file)?;if self.locks.iter().any(|l|l.record==file.address)||!self.lock_objects.remove(&file.address){return Err("CRT shutdown lock still leased/missing");}Ok(())}
 fn free_shutdown(&mut self,token:CrtShutdown,p:CrtPointer)->Result<(),&'static str>{self.shutdown(token)?;self.free_allocation(p)}
 fn end_shutdown(&mut self,token:CrtShutdown)->Result<(),&'static str>{self.shutdown(token)?;if !self.locks.is_empty()||!self.descriptor_locks.is_empty()||!self.record_locks.is_empty()||!self.global_locks.is_empty()||!self.lock_objects.is_empty()||!self.record_objects.is_empty()||!self.global_objects.is_empty(){return Err("CRT shutdown remaining lock authority");}self.shutdown=None;self.closed=true;Ok(())}
 fn construct_lock(&mut self,token:CrtInitialization,file:CrtPointer)->Result<(),&'static str>{
  self.initialization(token)?;self.file_record(file)?;self.lock_objects.reserve()?;if !self.lock_objects.insert(file.address){return Err("CRT duplicate lock construction");}Ok(())
 }
 /// Bound InitializeCriticalSectionEx result, for the exclusive x86 FILE domain.
 /// The external result is an input effect, not a simulated successful OS call.
 fn construct_lock_result(&mut self,token:CrtInitialization,lock:CrtPointer,flags:u32,result:u32)->Result<bool,&'static str>{
  self.initialization(token)?;self.identity_range(lock,24)?;
  let file=self.offset(lock,-32)?;self.file_record(file)?;
  if flags!=0||self.lock_objects.contains(&file.address)||!self.overlapping_tags(lock.address,24).is_empty(){return Err("CRT lock construction flags/duplicate/typed alias");}
  self.memory.forget(lock.address,24).map_err(|_|"CRT opaque lock range")?;
  self.partial.retain(|&at,_|at<lock.address||at>=lock.address+24);self.last_os_error=None;
  if result!=0{self.construct_lock(token,file)?;}Ok(result!=0)
 }
 /// Native FILE critical section construction in the exclusive startup domain.
 /// Resources/authority reject before opaque-byte effects; no supplied API result.
 fn native_file_initialize(&mut self,init:CrtInitialization,function:CrtFunction,p:CrtPointer,spin:u32,flags:u32)->Result<bool,&'static str>{
  self.initialization(init)?;self.native_sync_identity(function)?;self.provider_ready(function.module)?;
  self.identity_range(p,24)?;let file=self.offset(p,-32)?;self.file_record(file)?;
  self.memory.validate_writable(p.cap,p.owner,p.address(),24).map_err(|_|"CRT FILE lock writable range")?;
  if spin!=4000||flags!=0||p.address()%4!=0||self.lock_objects.contains(&file.address())||self.has_overlapping_tags(p.address(),24){return Err("CRT native FILE lock domain/duplicate/alias");}
  self.ordinary_file_bytes(p,24)?;
  self.lock_objects.reserve()?;
  self.memory.forget(p.address(),24).map_err(|_|"CRT FILE lock opaque range")?;
  self.partial.retain(|&at,_|at<p.address()||at>=p.address()+24);self.lock_objects.insert(file.address());self.last_os_error=None;Ok(true)
 }
 /// Explicit successful initialization outcome for a distinct module lock.
 fn construct_global_lock(&mut self,token:CrtInitialization,index:u32,p:CrtPointer,result:u32)->Result<bool,&'static str>{
  self.initialization(token)?;self.identity_range(p,24)?;
  if index>=32||p.kind!=CrtRegionKind::Module||p.address%4!=0||self.global_objects.contains_key(&index)||self.global_objects.values().any(|q|u64::from(p.address)<u64::from(q.address)+24&&u64::from(q.address)<u64::from(p.address)+24)||self.has_overlapping_tags(p.address,24){return Err("CRT global lock role/index/alias");}
  let object=self.subrange(p,24)?;
  self.memory.forget(p.address,24).map_err(|_|"CRT global lock bytes")?;self.partial.retain(|&at,_|at<p.address||at>=p.address+24);self.last_os_error=None;
  if result!=0{self.global_objects.insert(index,object);}Ok(result!=0)
 }
 /// An integer produced by a certified helper does not itself grant memory
 /// authority. Bind it to the live module object for the exact table/index.
 fn check_global_address(&self,index:u32,table:u32,address:u32)->Result<u32,&'static str>{
  if index>=32||table==0||table%4!=0||table.checked_add(index*24)!=Some(address){return Err("CRT global index/address overflow");}
  let mut matches=(0..32).filter(|slot|self.global_objects.get(slot).is_some_and(|p|p.address==address&&p.kind==CrtRegionKind::Module));
  let slot=matches.next().ok_or(if self.global_objects.contains_key(&index){"CRT global table/object mismatch"}else{"CRT unconstructed indexed lock"})?;if matches.next().is_some(){return Err("CRT ambiguous indexed lock");}
  let p=*self.global_objects.get(&slot).unwrap();self.identity_range(p,24)?;self.memory.validate_writable(p.cap,p.owner,p.address,24).map_err(|_|"CRT global lock permission")?;Ok(slot)
 }
 fn lock_global(&mut self,thread:u64,index:u32)->Result<CrtGlobalLock,&'static str>{
  let p=*self.global_objects.get(&index).ok_or("CRT unconstructed global lock")?;self.identity_range(p,24)?;self.memory.validate_writable(p.cap,p.owner,p.address,24).map_err(|_|"CRT global lock permission")?;
  if self.closed||thread!=self.thread||self.global_locks.len()>=32{return Err("CRT global lock thread/budget");}
  let serial=self.serial.checked_add(1).ok_or("CRT global lock serial")?;
  let token=CrtGlobalLock{anchor:self.anchor,thread,serial,depth:self.global_locks.len(),index,storage:p};self.global_locks.push(token);self.serial=serial;Ok(token)
 }
 fn check_global(&self,token:CrtGlobalLock)->Result<(),&'static str>{
  if self.closed||token.anchor!=self.anchor||token.thread!=self.thread||self.global_locks.last()!=Some(&token)||self.global_objects.get(&token.index)!=Some(&token.storage){return Err("CRT stale/foreign/unordered global lock");}self.identity_range(token.storage,24)?;self.memory.validate_writable(token.storage.cap,token.storage.owner,token.storage.address,24).map_err(|_|"CRT global lock permission")
 }
 fn unlock_global(&mut self,token:CrtGlobalLock)->Result<(),&'static str>{self.check_global(token)?;self.global_locks.pop();Ok(())}
 fn destroy_global_lock(&mut self,token:CrtInitialization,index:u32)->Result<(),&'static str>{
  self.initialization(token)?;if self.global_locks.iter().any(|l|l.index==index){return Err("CRT live global lock destruction");}let p=*self.global_objects.get(&index).ok_or("CRT missing global lock")?;self.identity_range(p,24)?;self.global_objects.remove(&index);Ok(())
 }
 fn file_storage(&self,cap:guest_memory::Capability)->Option<CrtPointer>{std::iter::once(self.file_view).chain(self.regions.iter().map(|r|r.pointer).filter(|p|p.kind==CrtRegionKind::File)).find(|p|p.cap==cap)}
 fn file_overlap(&self,p:CrtPointer,size:u32)->bool{self.file_storage(p.cap).is_some_and(|f|u64::from(p.address)<u64::from(f.base)+u64::from(f.size)&&u64::from(f.base)<u64::from(p.address)+u64::from(size.max(1)))}
 fn ordinary_file_bytes(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  if self.slist_heads.values().any(|h|h.header.cap==p.cap&&u64::from(p.address)<u64::from(h.header.address())+8&&u64::from(h.header.address())<u64::from(p.address)+u64::from(size)){return Err("CRT opaque SLIST header bytes");}
  self.ordinary_non_slist_bytes(p,size)
 }
 fn ordinary_non_slist_bytes(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  if self.global_objects.values().any(|q|q.cap==p.cap&&u64::from(p.address)<u64::from(q.address)+24&&u64::from(q.address)<u64::from(p.address)+u64::from(size)){return Err("CRT opaque global lock bytes");}
  if self.record_objects.iter().any(|r|r.cap==p.cap&&u64::from(p.address)<u64::from(r.address)+24&&u64::from(r.address)<u64::from(p.address)+u64::from(size)){return Err("CRT opaque descriptor lock bytes");}
  if self.file_storage(p.cap).is_some()&&self.lock_objects.iter().any(|&at|u64::from(p.address)<u64::from(at)+56&&u64::from(at)+32<u64::from(p.address)+u64::from(size)){return Err("CRT opaque critical section bytes");}Ok(())
 }
 fn destroy_lock(&mut self,token:CrtInitialization,file:CrtPointer)->Result<(),&'static str>{
  self.initialization(token)?;self.file_record(file)?;if self.locks.iter().any(|l|l.record==file.address)||!self.lock_objects.remove(&file.address){return Err("CRT missing/live lock destruction");}Ok(())
 }
 fn file_record(&self,file:CrtPointer)->Result<(),&'static str>{
  let root=self.file_storage(file.cap).ok_or("CRT FILE owner")?;
  if file.kind!=CrtRegionKind::File||file.cap!=root.cap||file.owner!=root.owner||file.address<root.base||(file.address-root.base)%56!=0||file.address.checked_add(56).is_none_or(|end|u64::from(end)>u64::from(root.base)+u64::from(root.size)){return Err("CRT FILE record bounds");}
  self.identity_range(file,56)
 }

 fn file(&self)->CrtPointer{self.file_view}
 /// Copying already-issued pointer bits does not dereference the pointee or
 /// renew its lifetime. Retired roots remain only as bounded provenance, never
 /// as mappings. Foreign and fabricated tokens cannot enter typed storage.
 fn thread_head(&self,registry:u64,epoch:u64,head:[u64;3])->Result<CrtThreadHead,&'static str>{let token=CrtThreadHead{anchor:self.anchor,thread:self.thread,registry,epoch,head};self.thread_head_transport(token)?;Ok(token)}
 /// Arena/thread transport check only; the installation binding must also
 /// validate the actual live registry epoch and head identity.
 fn validate_thread_head(&self,head:CrtThreadHead)->Result<(),&'static str>{self.thread_head_transport(head)}
 fn thread_head_transport(&self,head:CrtThreadHead)->Result<(),&'static str>{if self.closed||head.anchor!=self.anchor||head.thread!=self.thread||head.registry==0||head.epoch==0{return Err("CRT foreign thread registration token");}Ok(())}
 /// Opaque callback identity only: no numeric Windows address, byte extent or
 /// contents are invented. The API effect proof remains a separate obligation.
 fn new_dispatcher(&mut self,epoch:u64,callback:u64)->Result<CrtDispatcherContext,&'static str>{
  if self.closed||epoch==0||callback==0||self.dispatchers.len()>=16{return Err("CRT dispatcher owner/budget");}
  let serial=self.generation.checked_add(1).ok_or("CRT dispatcher identity exhausted")?;
  let token=CrtDispatcherContext{anchor:self.anchor,thread:self.thread,epoch,callback,serial};
  self.generation=serial;self.dispatchers.insert(serial,token);Ok(token)
 }
 fn dispatcher(&self,token:CrtDispatcherContext)->Result<(),&'static str>{
  if self.closed||token.anchor!=self.anchor||token.thread!=self.thread||self.dispatchers.get(&token.serial)!=Some(&token){return Err("CRT dispatcher owner/lifetime");}Ok(())
 }
 fn end_dispatcher(&mut self,token:CrtDispatcherContext)->Result<(),&'static str>{self.dispatcher(token)?;self.dispatchers.remove(&token.serial);Ok(())}
 fn pointer_transport(&self,p:CrtPointer)->Result<(),&'static str>{
  let root=std::iter::once(self.file_view).chain(self.regions.iter().map(|r|r.pointer)).chain(self.retired.iter().copied()).chain(self.uncertain_allocations.iter().copied()).find(|r|r.cap==p.cap&&r.kind==p.kind).ok_or("CRT foreign/unissued pointer value")?;
  if p.owner!=root.owner||p.kind!=root.kind||p.base<root.base||u64::from(p.base)+u64::from(p.size)>u64::from(root.base)+u64::from(root.size)||p.address<p.base||u64::from(p.address)>u64::from(p.base)+u64::from(p.size){return Err("CRT pointer value provenance");}Ok(())
 }
 fn reserve_retirement(&mut self)->Result<(),&'static str>{if self.retired.len()>=4096{return Err("CRT retired provenance budget");}self.retired.try_reserve(1).map_err(|_|"CRT retired provenance storage")}
 fn identity_range(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  let root=if p.kind==CrtRegionKind::File{self.file_storage(p.cap).ok_or("CRT stale/foreign FILE")?}else{self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT stale/foreign pointer")?.pointer};
  if root.cap!=p.cap||root.owner!=p.owner||root.kind!=p.kind||p.base<root.base||u64::from(p.base)+u64::from(p.size)>u64::from(root.base)+u64::from(root.size)
   ||p.address<p.base||p.address.checked_add(size).is_none_or(|end|u64::from(end)>u64::from(p.base)+u64::from(p.size)){
   return Err("CRT pointer complete range/identity");
  }
  self.memory.validate(p.cap,p.owner).map_err(|_|"CRT pointer lifetime")?;
  if size!=0{self.memory.validate_range(p.cap,p.owner,p.address,size).map_err(|_|"CRT pointer mapped range")?;}
  Ok(())
 }
 fn valid(&self,p:CrtPointer,size:u32)->Result<(),&'static str>{
  self.identity_range(p,size)?;
  if self.closed{return Err("CRT retired stream lifecycle");}
  if self.file_overlap(p,size){let file=self.file_storage(p.cap).ok_or("CRT FILE identity")?;let base=file.base;if p.address<base||u64::from(p.address)+u64::from(size)>u64::from(base)+u64::from(file.size){return Err("CRT access crosses FILE view");}let record=base+(p.address-base)/56*56;if size!=0&&(size<=4||self.initialization.is_none()&&self.shutdown.is_none())&&(p.address-base)%56+size>56{return Err("CRT access crosses FILE records");}if self.initialization.is_none()&&self.shutdown.is_none()&&!self.locks.iter().any(|l|l.record==record){return Err("CRT unlocked FILE record access");}}
  if self.initialization.is_none()&&self.shutdown.is_none(){
   if p.kind==CrtRegionKind::Descriptor&&!self.record_locks.iter().any(|l|l.record.cap==p.cap&&p.address>=l.record.address&&u64::from(p.address)+u64::from(size)<=u64::from(l.record.address)+56){
    let owner=self.descriptors.iter().find(|d|d.live&&d.record.is_some_and(|r|r.cap==p.cap&&p.address>=r.address&&u64::from(p.address)+u64::from(size)<=u64::from(r.address)+56)).ok_or("CRT unbound descriptor record access")?;
    if !self.descriptor_locks.iter().any(|l|l.id==owner.id){return Err("CRT unlocked descriptor record access");}
   }
  }
  Ok(())
 }
 fn offset(&self,p:CrtPointer,delta:i64)->Result<CrtPointer,&'static str>{
  self.identity_range(p,0)?;let address=i64::from(p.address).checked_add(delta).and_then(|n|u32::try_from(n).ok()).ok_or("CRT pointer arithmetic overflow")?;
  let q=CrtPointer{address,..p};self.identity_range(q,0)?;Ok(q)
 }
 /// x86 address formation is not a memory access. Keep the original capability
 /// and complete subrange even for a temporary out-of-range effective address.
 /// Only the instruction address path uses this; loads/stores and transport
 /// still require the resulting complete range to belong to that capability.
 fn effective_address(&self,p:CrtPointer,address:u32)->Result<CrtPointer,&'static str>{
  self.identity_range(CrtPointer{address:p.base,..p},0)?;Ok(CrtPointer{address,..p})
 }
 fn subrange(&self,p:CrtPointer,size:u32)->Result<CrtPointer,&'static str>{
  if size==0{return Err("CRT empty subrange");}self.identity_range(p,size)?;Ok(CrtPointer{base:p.address,size,..p})
 }
 fn difference(&self,a:CrtPointer,b:CrtPointer)->Result<u32,&'static str>{
  self.identity_range(a,0)?;self.identity_range(b,0)?;if a.cap!=b.cap{return Err("CRT unrelated pointer subtraction");}Ok(a.address.wrapping_sub(b.address))
 }
 fn map_region(&mut self,base:u32,size:u32,kind:CrtRegionKind,initial:Option<&[u8]>)->Result<CrtPointer,&'static str>{
  if self.closed||matches!(kind,CrtRegionKind::Buffer|CrtRegionKind::ProcessData)||kind==CrtRegionKind::File&&(self.initialization.is_none()||base%4!=0||size%56!=0)||base==0||size==0||base.checked_add(size).is_none()
   ||initial.is_some_and(|bytes|bytes.len()!=size as usize){return Err("CRT mapped region contract");}
  let next=self.generation.checked_add(1).ok_or("CRT generation budget")?;
  let owner=match kind{CrtRegionKind::Stack|CrtRegionKind::Context|CrtRegionKind::ThreadData=>guest_memory::Owner::Stack(next),_=>guest_memory::Owner::Module(self.owner)};
  let cap=self.memory.map(base,size,owner,guest_memory::Permissions::READ_WRITE,false).map_err(|_|"CRT region bounds/alias/budget")?;
  if let Some(bytes)=initial {if self.memory.write(base,bytes).is_err(){self.memory.release(cap,owner).map_err(|_|"CRT failed mapping rollback")?;return Err("CRT region initialization");}}
  let p=CrtPointer{cap,owner,base,size,address:base,kind};self.regions.push(CrtRegion{pointer:p,heap:false,file_owner:None});self.generation=next;Ok(p)
 }
 fn resolve_absolute(&self,address:u32,kind:CrtRegionKind)->Result<CrtPointer,&'static str>{
  let p=std::iter::once(self.file_view).chain(self.regions.iter().map(|r|r.pointer)).find(|p|p.kind==kind&&address>=p.base&&u64::from(address)<u64::from(p.base)+u64::from(p.size)).ok_or("CRT undeclared absolute region/role")?;
  let q=CrtPointer{address,..p};self.identity_range(q,1)?;Ok(q)
 }
 fn lock(&mut self,thread:u64)->Result<CrtLock,&'static str>{self.lock_file(thread,self.file())}
 fn lock_file(&mut self,thread:u64,file:CrtPointer)->Result<CrtLock,&'static str>{
  self.file_record(file)?;
  if self.closed||thread!=self.thread||!self.lock_objects.contains(&file.address){return Err("CRT foreign thread/unconstructed lock");}
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
 fn has_overlapping_tags(&self,address:u32,size:u32)->bool{
  self.tags.keys().any(|&at|u64::from(at)<u64::from(address)+u64::from(size)&&u64::from(address)<u64::from(at)+4)
 }
 fn overlapping_tags(&self,address:u32,size:u32)->Vec<(u32,CrtValue)>{
  self.tags.iter().filter(|(at,_)|u64::from(**at)<u64::from(address)+u64::from(size)&&u64::from(address)<u64::from(**at)+4).map(|(&a,&v)|(a,v)).collect()
 }
 fn load(&self,p:CrtPointer,width:u8)->Result<CrtValue,&'static str>{
  if self.unobserved_contexts.iter().any(|(q,_)|q.cap==p.cap){return Err("unobserved context raw read requires acquisition proof");}
  self.load_unsealed(p,width)
 }
 /// Internal storage validation only. Original guest loads always use load().
 fn load_unsealed(&self,p:CrtPointer,width:u8)->Result<CrtValue,&'static str>{
  let size=match width{8=>1,16=>2,32=>4,_=>return Err("CRT load width")};self.valid(p,size)?;self.ordinary_file_bytes(p,size)?;
  self.memory.validate_readable(p.cap,p.owner,p.address,size).map_err(|_|"CRT read permission")?;
  // A checked scalar/typed load needs at most one matching tag. Inspect the
  // iterator directly so argument and protected-return reads cannot allocate.
  let mut tags=self.tags.iter().filter(|(at,_)|u64::from(**at)<u64::from(p.address)+u64::from(size)&&u64::from(p.address)<u64::from(**at)+4);
  if let Some((&at,&value))=tags.next(){if width!=32||at!=p.address||tags.next().is_some(){return Err("CRT partial typed-word read");}
   match value{CrtValue::Module(m)=>self.module_identity(m)?,CrtValue::Function(f)=>self.function_identity(f,None)?,CrtValue::Heap(h)=>self.heap_identity(h)?,CrtValue::Dispatcher(token)=>self.dispatcher(token)?,CrtValue::Pointer(q)=>self.pointer_transport(q)?,CrtValue::ProcessHandle(h)=>self.native_endpoint(h).map(|_|())?,CrtValue::Handle(h)=>{self.descriptor(h)?;},CrtValue::ThreadHead(head)=>self.thread_head_transport(head)?,_=>{}}
   return Ok(value);
  }
  let(mut bits,mut known)=(0u32,0u32);for i in 0..size{let a=p.address+i;
   let(byte,mask)=match self.memory.read(a,1){Ok(bytes)=>(bytes[0],255),Err(guest_memory::Fault::Uninitialized)=>self.partial.get(&a).copied().unwrap_or((0,0)),Err(_)=>return Err("CRT scalar read permission/range")};
   bits|=u32::from(byte&mask)<<(i*8);known|=u32::from(mask)<<(i*8);
  }
  Ok(CrtValue::Scalar{bits,known:if width==32{known}else{known|(!0u32<<width)}})
 }
 /// Preflight the complete scalar pair before either word changes. This
 /// bounded store cannot expose, overwrite or manufacture typed authority.
 fn validate_stack_pair(&self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,8)?;
  if p.kind!=CrtRegionKind::Stack||!self.overlapping_tags(p.address(),8).is_empty()||self.unobserved_contexts.iter().any(|(q,_)|q.cap==p.cap){return Err("CRT scalar pair role/typed alias");}
  self.memory.validate_writable(p.cap,p.owner,p.address(),8).map_err(|_|"CRT scalar pair permission")?;Ok(())
 }
 fn store_stack_pair(&mut self,p:CrtPointer,words:[CrtValue;2])->Result<(),&'static str>{
  self.validate_stack_pair(p)?;
  if !words.iter().all(|v|matches!(v,CrtValue::Scalar{..})){return Err("CRT scalar pair value type");}
  let high=self.offset(p,4)?;self.store(p,32,words[0])?;self.store(high,32,words[1])
 }
 fn store(&mut self,p:CrtPointer,width:u8,value:CrtValue)->Result<(),&'static str>{
  if self.unobserved_contexts.iter().any(|(q,_)|q.cap==p.cap){return Err("unobserved context write requires effect proof");}
  let size=match width{8=>1,16=>2,32=>4,_=>return Err("CRT store width")};self.valid(p,size)?;self.ordinary_file_bytes(p,size)?;
  if matches!(p.kind,CrtRegionKind::Input|CrtRegionKind::ProcessData){return Err("CRT immutable source write");}
  self.memory.validate_writable(p.cap,p.owner,p.address,size).map_err(|_|"CRT storage write")?;
  if let Some(cell)=self.errno_cell.filter(|q|q.cap==p.cap&&u64::from(p.address)<u64::from(q.address)+4&&u64::from(q.address)<u64::from(p.address)+u64::from(size)){
   if cell.kind==CrtRegionKind::Buffer{self.ucrt_errno_identity(cell)?;}
   if !matches!(value,CrtValue::Scalar{..}){return Err("CRT errno scalar field");}
  }
  let old=self.overlapping_tags(p.address,size);
  if old.iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_))){return Err("CRT protected saved/return overwrite");}
  if !old.is_empty()&&(width!=32||old.len()!=1||old[0].0!=p.address){return Err("CRT partial pointer/handle overwrite");}
  if self.file_overlap(p,size){
   let base=self.file_storage(p.cap).ok_or("CRT FILE identity")?.base;
   if (p.address-base)%56<8 {
    if width!=32||![0,4].contains(&((p.address-base)%56))||!matches!(value,CrtValue::Pointer(_)|CrtValue::Scalar{bits:0,known:u32::MAX}){return Err("CRT FILE pointer field type");}
   }
  }
  let bits=match value{
   CrtValue::NonZero{..}=>{if width!=32{return Err("CRT nonzero symbol store width");}0},
   CrtValue::Module(m)=>{if width!=32||!matches!(p.kind,CrtRegionKind::Stack|CrtRegionKind::Module){return Err("CRT module transport role/width");}self.module_identity(m)?;m.handle},
   CrtValue::Function(f)=>{if width!=32||!matches!(p.kind,CrtRegionKind::Stack|CrtRegionKind::Module){return Err("CRT export transport role/width");}self.function_identity(f,None)?;f.address},
   CrtValue::Heap(h)=>{if width!=32{return Err("CRT heap handle width");}self.heap_identity(h)?;0},
   CrtValue::Dispatcher(token)=>{if width!=32||p.kind!=CrtRegionKind::Stack{return Err("CRT dispatcher transport role");}self.dispatcher(token)?;0},
   CrtValue::Scalar{bits,..}=>bits,
   CrtValue::Pointer(q)=>{if width!=32{return Err("CRT pointer store width");}self.pointer_transport(q)?;q.address},
   CrtValue::ProcessHandle(h)=>{if width!=32{return Err("CRT process handle store width");}self.native_endpoint(h)?;h.handle},
   CrtValue::Handle(h)=>{if width!=32{return Err("CRT handle store width");}self.descriptor(h)?;h.handle},
   CrtValue::ThreadHead(head)=>{if width!=32||p.kind!=CrtRegionKind::Stack{return Err("CRT thread registration token storage role");}self.thread_head_transport(head)?;0},
   CrtValue::OpaqueSaved(r)=>{if width!=32||p.kind!=CrtRegionKind::Stack||r>7{return Err("CRT saved-register slot");}0},
   CrtValue::ProtectedReturn(id)=>{if width!=32||p.kind!=CrtRegionKind::Stack||id==0{return Err("CRT protected return slot");}0},
  };
  if self.file_overlap(p,size){if let CrtValue::Pointer(q)=value{
   let base=self.file_storage(p.cap).ok_or("CRT FILE identity")?.base;
   if (p.address-base)%56<8{self.claim_file_buffer(q,base+(p.address-base)/56*56)?;}
  }}
  // A symbolic nonzero has no backing bit pattern to write. Use one atomic
  // forget operation rather than writing a dummy zero followed by forgetting.
  if matches!(value,CrtValue::NonZero{..}){self.memory.forget(p.address,4).map_err(|_|"CRT nonzero scalar knowledge")?;}else{self.memory.write(p.address,&bits.to_le_bytes()[..size as usize]).map_err(|_|"CRT storage write")?;}
  for(at,_)in old{self.tags.remove(&at);}for i in 0..size{self.partial.remove(&(p.address+i));}
  match value{CrtValue::NonZero{..}=>{self.tags.insert(p.address,value);},CrtValue::Scalar{bits,known}=>{for i in 0..size{let mask=(known>>(8*i))as u8;if mask!=255{self.memory.forget(p.address+i,1).map_err(|_|"CRT scalar knowledge epoch")?;self.partial.insert(p.address+i,(((bits>>(8*i))as u8)&mask,mask));}}},_=>{self.tags.insert(p.address,value);}}
  if let Some(cell)=self.errno_cell{if cell.cap==p.cap&&u64::from(p.address)<u64::from(cell.address)+4&&u64::from(cell.address)<u64::from(p.address)+u64::from(size){self.errno=self.load(cell,32)?.known_scalar().ok().map(|n|n as i32);}}
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
  self.check_lock(lease)?;if p.address%4!=0||p.kind!=CrtRegionKind::File||p.address<lease.record||u64::from(p.address)+4>u64::from(lease.record)+56{return Err("CRT atomic FILE lease/operand identity");}
  let old=self.load(p,32)?.known_scalar()?;let next=if or{old|bits}else{old&bits};self.store(p,32,CrtValue::scalar(next))?;Ok(old)
 }
 fn alloc_buffer(&mut self,lease:CrtLock,size:u32,available:bool)->Result<Option<CrtPointer>,&'static str>{
  self.check_lock(lease)?;let result=self.allocate(size,false,available)?;
  if let Some(p)=result{self.claim_file_buffer(p,lease.record)?;}Ok(result)
 }
 /// Exclusive FILE-buffer ownership is narrower than general pointer transport.
 /// An unassigned original allocator result may be claimed on its first FILE
 /// cursor/base store. Copying a retired pointer never recreates ownership.
 fn claim_file_buffer(&mut self,p:CrtPointer,record:u32)->Result<(),&'static str>{
  self.pointer_transport(p)?;
  if let Some(region)=self.regions.iter_mut().find(|r|r.pointer.cap==p.cap&&r.heap){
   if region.pointer.kind!=CrtRegionKind::Buffer||region.file_owner.is_some_and(|owner|owner!=record)||self.heap_ptds.iter().any(|v|v.pointer.cap==p.cap){return Err("CRT cross-FILE buffer ownership");}
   region.file_owner=Some(record);
  }Ok(())
 }
 fn alloc_initialization(&mut self,token:CrtInitialization,size:u32,zeroed:bool,available:bool)->Result<Option<CrtPointer>,&'static str>{self.initialization(token)?;self.allocate(size,zeroed,available)}
 fn allocate(&mut self,size:u32,zeroed:bool,available:bool)->Result<Option<CrtPointer>,&'static str>{
  let heap=self.memory.process_heap();
  let address=self.memory.heap_alloc(heap,if zeroed{8}else{0},size,if available{guest_memory::Availability::Available}else{guest_memory::Availability::AllocationFailed}).map_err(|_|"CRT allocation contract/budget")?;
  let Some(base)=address else{return Ok(None)};
  let cap=self.memory.heap_capability(heap,base).map_err(|_|"CRT allocation identity")?;
  let p=CrtPointer{cap,owner:guest_memory::Owner::Heap(0),base,size,address:base,kind:CrtRegionKind::Buffer};self.regions.push(CrtRegion{pointer:p,heap:true,file_owner:None});Ok(Some(p))
 }
 /// Bind an observed process-heap outcome without inventing handle bits.
 fn process_heap_result(&mut self,init:CrtInitialization,available:bool,exceptions:Option<bool>)->Result<CrtValue,&'static str>{
  self.initialization(init)?;self.canonical_errno=true;self.last_os_error=None;if !available{return Ok(CrtValue::scalar(0));}
  let heap=CrtHeap{anchor:self.anchor,process:self.memory.process_heap(),exceptions};if self.heap.is_some_and(|h|h!=heap){return Err("CRT changed process heap contract");}self.heap=Some(heap);Ok(CrtValue::Heap(heap))
 }
 /// Acquire the one heap already owned by Space. This publishes a handle proof,
 /// not a new allocation arena, supplied OS result or exception-policy fact.
 fn native_process_heap(&mut self,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.initialization(init)?;
  if let Some(heap)=self.heap{self.heap_identity(heap)?;self.last_os_error=None;return Ok(CrtValue::Heap(heap));}
  let heap=CrtHeap{anchor:self.anchor,process:self.memory.process_heap(),exceptions:None};
  self.heap=Some(heap);self.last_os_error=None;Ok(CrtValue::Heap(heap))
 }
 fn heap_identity(&self,heap:CrtHeap)->Result<(),&'static str>{if self.closed||heap.anchor!=self.anchor||heap.process!=self.memory.process_heap()||self.heap!=Some(heap)||self.memory.validate(self.anchor,guest_memory::Owner::Module(self.owner)).is_err(){return Err("CRT heap owner/lifetime");}Ok(())}
 fn heap_alloc_result(&mut self,init:CrtInitialization,heap:CrtHeap,flags:u32,size:u32,descriptor:bool,available:bool)->Result<Option<CrtPointer>,&'static str>{
  self.initialization(init)?;self.heap_identity(heap)?;
  if heap.exceptions!=Some(false)||flags!=8||size==0{return Err("CRT unproved heap flags/exception/zero request");}
  let result=if descriptor{if size%56!=0{return Err("CRT descriptor allocation extent");}self.alloc_descriptor_block(init,size/56,available)}else{self.allocate(size,true,available)}?;if result.is_some(){self.last_os_error=None;}Ok(result)
 }
 /// Ordinary live heap calls do not borrow startup-exclusive authority. This
 /// admits only zeroed, nonzero Buffer allocation from the established heap.
 /// Descriptor construction and policy initialization remain startup-only.
 fn live_heap_alloc_result(&mut self,heap:CrtHeap,flags:u32,size:u32,available:bool)->Result<Option<CrtPointer>,&'static str>{
  self.heap_identity(heap)?;
  if heap.exceptions!=Some(false)||flags!=8||size==0{return Err("CRT live allocation flags/exception/zero request");}
  let result=self.allocate(size,true,available)?;if result.is_some(){self.last_os_error=None;}Ok(result)
 }
 /// Serialized startup-only module-word update under a live indexed lease.
 /// No callback/interleaving occurs between the checked read and write.
 fn module_word_pointer(&self,image:CrtProcessImage,value:CrtValue)->Result<CrtPointer,&'static str>{
  match value{CrtValue::Scalar{bits,known:u32::MAX}=>self.process_image_pointer(image,bits,4),CrtValue::Pointer(p)=>{if self.process_image_pointer(image,p.address(),4)?!=p{return Err("CRT module word alias");}Ok(p)},_=>Err("CRT module word address knowledge")}
 }
 /// Scalar atomic words during serialized initialization; no guest concurrency
 /// or host callback/interleaving is admitted. Heap words retain whole identity.
 fn initializing_scalar_pointer(&self,init:CrtInitialization,image:CrtProcessImage,value:CrtValue)->Result<CrtPointer,&'static str>{
  self.initialization(init)?;self.process_image(image)?;
  let p=match value{CrtValue::Scalar{..}=>self.module_word_pointer(image,value)?,CrtValue::Pointer(p)=>p,_=>return Err("CRT initializing scalar word address")};
  self.valid(p,4)?;if p.address%4!=0{return Err("CRT initializing scalar word alignment");}
  if p.kind==CrtRegionKind::Module{if self.process_image_pointer(image,p.address,4)?!=p{return Err("CRT initializing module word identity");}}
  else if p.kind!=CrtRegionKind::Buffer||p.address!=p.base||!self.regions.iter().any(|r|r.pointer==p&&r.heap&&r.file_owner.is_none()){return Err("CRT initializing whole buffer word");}
  Ok(p)
 }
 fn exchange_initializing_scalar(&mut self,init:CrtInitialization,image:CrtProcessImage,p:CrtPointer,value:u32,add:bool)->Result<u32,&'static str>{
  if self.initializing_scalar_pointer(init,image,CrtValue::Pointer(p))?!=p{return Err("CRT initializing scalar identity");}
  self.memory.validate_writable(p.cap,p.owner,p.address,4).map_err(|_|"CRT initializing scalar permission")?;
  let old=self.load(p,32)?.known_scalar()?;self.store(p,32,CrtValue::scalar(if add{old.wrapping_add(value)}else{value}))?;Ok(old)
 }
 fn increment_module_reference(&mut self,init:CrtInitialization,image:CrtProcessImage,lease:CrtGlobalLock,p:CrtPointer)->Result<u32,&'static str>{self.add_module_reference(init,image,lease,p,1)}
 /// Single guest-thread operation under the consumer's exclusive global lease;
 /// no callback or interleaving occurs between checked read and write.
 fn add_module_reference(&mut self,init:CrtInitialization,image:CrtProcessImage,lease:CrtGlobalLock,p:CrtPointer,addend:u32)->Result<u32,&'static str>{
  self.initialization(init)?;self.check_global(lease)?;
  if p.kind!=CrtRegionKind::Module||p.address%4!=0||self.process_image_pointer(image,p.address,4)?!=p{return Err("CRT module reference identity/alignment");}
  self.memory.validate_writable(p.cap,p.owner,p.address,4).map_err(|_|"CRT module reference permission")?;
  self.ordinary_file_bytes(p,4)?;let old=self.load(p,32)?.known_scalar()?;
  self.store(p,32,CrtValue::scalar(old.wrapping_add(addend)))?;Ok(old)
 }
 /// Execute a bounded successful allocation in the explicit native domain.
 /// Budget/host allocation failure is rejection, never guest NULL or a guessed
 /// exception policy. The existing process heap and allocation identity survive.
 fn native_heap_allocate(&mut self,init:CrtInitialization,heap:CrtHeap,flags:u32,size:u32)->Result<CrtPointer,&'static str>{
  self.initialization(init)?;self.heap_identity(heap)?;
  if !matches!(flags,0|8)||size==0{return Err("CRT native heap flags/size domain");}
  let p=self.allocate(size,flags==8,true)?.ok_or("CRT native heap allocation unavailable")?;self.last_os_error=None;Ok(p)
 }
 fn native_descriptor_allocate(&mut self,init:CrtInitialization,heap:CrtHeap,flags:u32,size:u32)->Result<CrtPointer,&'static str>{
  if flags!=8||size==0||size%56!=0||size/56>64{return Err("CRT native descriptor allocation extent");}
  let p=self.native_heap_allocate(init,heap,flags,size)?;let q=CrtPointer{kind:CrtRegionKind::Descriptor,..p};
  let r=self.regions.last_mut().ok_or("CRT native descriptor allocation identity")?;if r.pointer!=p||!r.heap||r.file_owner.is_some(){return Err("CRT native descriptor fresh allocation");}r.pointer=q;Ok(q)
 }
 fn native_record_initialize(&mut self,init:CrtInitialization,function:CrtFunction,p:CrtPointer,flags:u32)->Result<bool,&'static str>{
  self.initialization(init)?;self.native_sync_identity(function)?;self.provider_ready(function.module)?;self.descriptor_slot(p)?;
  if flags!=0||self.record_objects.len()>=8192{return Err("CRT native descriptor lock resource/flags");}
  self.record_objects.try_reserve(1).map_err(|_|"CRT native descriptor lock storage unavailable")?;
  self.construct_record_lock_result(init,p,flags,1)
 }
 /// Select the allocation role before any pointer escapes; no Buffer alias
 /// is relabelled or allowed to bypass record locks.
 fn alloc_descriptor_block(&mut self,token:CrtInitialization,count:u32,available:bool)->Result<Option<CrtPointer>,&'static str>{
  self.initialization(token)?;if count==0||count>64{return Err("CRT descriptor allocation count");}
  let Some(p)=self.allocate(count*56,true,available)? else{return Ok(None)};
  let q=CrtPointer{kind:CrtRegionKind::Descriptor,..p};
  self.regions.last_mut().ok_or("CRT allocation issuance")?.pointer=q;Ok(Some(q))
 }
 fn descriptor_slot(&self,p:CrtPointer)->Result<(),&'static str>{
  self.identity_range(p,56)?;
  let root=self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT descriptor slot identity")?.pointer;
  if p.kind!=CrtRegionKind::Descriptor||root.size%56!=0||(p.address-root.base)%56!=0{return Err("CRT descriptor slot alignment/role");}Ok(())
 }
 fn construct_record_lock_result(&mut self,token:CrtInitialization,p:CrtPointer,flags:u32,result:u32)->Result<bool,&'static str>{
  self.initialization(token)?;self.descriptor_slot(p)?;
  if flags!=0||self.record_objects.iter().any(|r|r.cap==p.cap&&r.address==p.address)||!self.overlapping_tags(p.address,24).is_empty(){return Err("CRT descriptor lock flags/duplicate/alias");}
  self.memory.forget(p.address,24).map_err(|_|"CRT descriptor lock range")?;
  self.partial.retain(|&at,_|at<p.address||at>=p.address+24);self.last_os_error=None;
  if result!=0{self.record_objects.push(self.subrange(p,56)?);}Ok(result!=0)
 }
 fn record_lock_live(&self,p:CrtPointer)->Result<(),&'static str>{
  self.descriptor_slot(p)?;
  if !self.record_objects.iter().any(|r|r.cap==p.cap&&r.address==p.address){return Err("CRT descriptor lock not constructed");}Ok(())
 }
 fn lock_record(&mut self,thread:u64,p:CrtPointer)->Result<CrtRecordLock,&'static str>{
  self.record_lock_live(p)?;if self.closed||thread!=self.thread||self.record_locks.len()>=32{return Err("CRT record lock thread/budget");}
  let serial=self.serial.checked_add(1).ok_or("CRT record lock generation")?;
  let lease=CrtRecordLock{anchor:self.anchor,thread,serial,depth:self.record_locks.len(),record:self.subrange(p,56)?};self.record_locks.push(lease);self.serial=serial;Ok(lease)
 }
 fn unlock_record(&mut self,lease:CrtRecordLock)->Result<(),&'static str>{
  if self.record_locks.last()!=Some(&lease){return Err("CRT stale/foreign/unordered record unlock");}self.record_locks.pop();Ok(())
 }
 fn destroy_record_lock(&mut self,token:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{
  self.initialization(token)?;self.record_lock_live(p)?;
  if self.record_locks.iter().any(|l|l.record.cap==p.cap&&l.record.address==p.address)||self.descriptors.iter().any(|d|d.record.is_some_and(|r|r.cap==p.cap&&r.address==p.address)&&(d.live||self.descriptor_locks.iter().any(|l|l.id==d.id))){return Err("CRT live descriptor record destruction");}
  self.record_objects.retain(|r|r.cap!=p.cap||r.address!=p.address);Ok(())
 }
 fn free_buffer(&mut self,lease:CrtLock,p:CrtPointer)->Result<(),&'static str>{self.check_lock(lease)?;
  if !self.regions.iter().any(|r|r.pointer.cap==p.cap&&r.heap&&r.file_owner==Some(lease.record)){return Err("CRT buffer free requires owning FILE");}
  self.free_allocation(p)}
 fn free_initialization(&mut self,token:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{self.initialization(token)?;self.free_allocation(p)}
 fn free_allocation(&mut self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,0)?;if !matches!(p.kind,CrtRegionKind::Buffer|CrtRegionKind::Descriptor)||p.address!=p.base{return Err("CRT allocation base required");}
  let index=self.regions.iter().position(|r|r.pointer.cap==p.cap&&r.heap).ok_or("CRT allocation ownership")?;let root=self.regions[index].pointer;
  if p.base!=root.base||(p.kind==CrtRegionKind::Descriptor&&p.size!=root.size)||self.record_objects.iter().any(|r|r.cap==p.cap)||self.record_locks.iter().any(|l|l.record.cap==p.cap)||self.descriptors.iter().any(|d|d.live&&d.record.is_some_and(|r|r.cap==p.cap)){return Err("CRT allocation incomplete/live record ownership");}self.reserve_retirement()?;
  self.memory.heap_free(self.memory.process_heap(),0,p.base).map_err(|_|"CRT allocation lifetime")?;self.regions.remove(index);self.retired.push(root);self.heap_ptds.retain(|v|v.pointer.cap!=root.cap);
  self.tags.retain(|&at,_|at<root.base||u64::from(at)>=u64::from(root.base)+u64::from(root.size));self.partial.retain(|&at,_|at<root.base||u64::from(at)>=u64::from(root.base)+u64::from(root.size));Ok(())
 }
 /// Actual release in the explicit native owned-heap domain. Bookkeeping
 /// capacity is reserved before Space releases storage; rejected requests are
 /// not fabricated Windows FALSE/LastError observations. The independent
 /// supplied-failure model and original errno route retain their stricter policy.
 fn native_heap_free(&mut self,init:CrtInitialization,heap:CrtHeap,flags:u32,p:CrtPointer)->Result<(CrtValue,CrtHeapFreeEffect),&'static str>{
  self.initialization(init)?;self.heap_identity(heap)?;self.valid(p,0)?;
  if flags!=0||p.kind!=CrtRegionKind::Buffer||p.address()!=p.base||!self.regions.iter().any(|r|r.pointer==p&&r.heap&&r.file_owner.is_none()){return Err("CRT native HeapFree whole owned buffer");}
  let serial=self.serial.checked_add(1).ok_or("CRT HeapFree serial")?;
  self.free_allocation(p)?;
  self.serial=serial;self.last_os_error=None;
  Ok((CrtValue::NonZero{anchor:self.anchor,serial},CrtHeapFreeEffect{anchor:self.anchor,thread:self.thread,serial,pointer:p,failed:false}))
 }
 /// Apply a supplied synchronous HeapFree outcome only to an owned whole
 /// Buffer. FALSE gives no documented unchanged-content/lifetime guarantee.
 /// Keep the underlying allocation charged and revoke every dereference fact.
 fn heap_free_preflight(&self,heap:CrtHeap,flags:u32,p:CrtPointer)->Result<usize,&'static str>{
  self.heap_identity(heap)?;self.valid(p,0)?;
  let index=self.regions.iter().position(|r|r.pointer==p&&r.heap&&r.file_owner.is_none()).ok_or("CRT HeapFree whole unowned buffer")?;
  if flags!=0||heap.exceptions!=Some(false)||p.kind!=CrtRegionKind::Buffer||p.address!=p.base{return Err("CRT HeapFree domain");}Ok(index)
 }
 fn heap_free_result(&mut self,heap:CrtHeap,flags:u32,p:CrtPointer,raw:u32,last_error:Option<u32>)->Result<CrtHeapFreeEffect,&'static str>{
  let index=self.heap_free_preflight(heap,flags,p)?;
  let serial=self.serial.checked_add(1).ok_or("CRT HeapFree serial")?;
  if raw==0{
   if self.uncertain_allocations.len()>=64{return Err("CRT uncertain heap budget");}
   self.uncertain_allocations.try_reserve(1).map_err(|_|"CRT uncertain heap storage")?;
   self.regions.remove(index);self.uncertain_allocations.push(p);self.heap_ptds.retain(|v|v.pointer.cap!=p.cap);
   if self.errno_cell.is_some_and(|q|q.cap==p.cap){self.errno_cell=None;self.errno=None;}
  }else{self.free_allocation(p)?;}
  self.serial=serial;self.last_os_error=if raw==0{last_error}else{None};
  Ok(CrtHeapFreeEffect{anchor:self.anchor,thread:self.thread,serial,pointer:p,failed:raw==0})
 }
 /// Called only after the original free body has returned through its checked
 /// CALL, including the actual errno store. A rejected later effect leaves the
 /// allocation uncertain but cannot issue normal-return authority.
 fn complete_heap_free(&mut self,effect:CrtHeapFreeEffect)->Result<(),&'static str>{
  if effect.anchor!=self.anchor||effect.thread!=self.thread||self.closed{return Err("CRT HeapFree foreign completion");}
  if effect.failed{
   if !self.uncertain_allocations.contains(&effect.pointer)||self.completed_failed_frees.iter().any(|(c,_)|*c==effect.pointer.cap){return Err("CRT HeapFree stale completion");}
   self.completed_failed_frees.push((effect.pointer.cap,effect.serial));
  }else if !self.retired.contains(&effect.pointer){return Err("CRT HeapFree retirement missing");}
  Ok(())
 }
 fn take_ptd_free_completion(&mut self,p:CrtPointer,after:u64)->Result<(),&'static str>{
  if self.retired.iter().any(|q|q.cap==p.cap)&&!self.uncertain_allocations.iter().any(|q|q.cap==p.cap){return Ok(());}
  if let Some(i)=self.completed_failed_frees.iter().position(|(cap,serial)|*cap==p.cap&&*serial>after){self.completed_failed_frees.remove(i);return Ok(());}
  Err("C++ PTD free effect missing")
 }
 fn retire_region(&mut self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,0)?;let index=self.regions.iter().position(|r|r.pointer.cap==p.cap).ok_or("CRT region identity")?;let root=self.regions[index].pointer;
  if !matches!(p.kind,CrtRegionKind::Stack|CrtRegionKind::Context|CrtRegionKind::ThreadData|CrtRegionKind::Input|CrtRegionKind::Result)||p.address!=root.base||p.base!=root.base||p.size!=root.size{return Err("CRT complete temporary region required");}
  if self.overlapping_tags(p.base,p.size).iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_))){return Err("CRT retirement before protected restoration");}
  self.reserve_retirement()?;self.memory.release(p.cap,p.owner).map_err(|_|"CRT region release")?;self.regions.remove(index);self.retired.push(root);if self.errno_cell.is_some_and(|p|p.cap==root.cap){self.errno=None;}self.tags.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));self.partial.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));Ok(())
 }
 /// Output effect for the explicitly selected native launch ABI, which has
 /// no Windows CRT inheritance block. This is not acquisition of Windows data.
 fn native_startup_info_output(&mut self,init:CrtInitialization,p:CrtPointer)->Result<(),&'static str>{
  self.initialization(init)?;self.valid(p,68)?;
  if p.kind!=CrtRegionKind::Stack||!self.overlapping_tags(p.address(),68).is_empty()||self.unobserved_contexts.iter().any(|(q,_)|q.cap==p.cap){return Err("startup info output role/protected alias");}
  self.memory.validate_writable(p.cap,p.owner,p.address(),68).map_err(|_|"startup info output permission")?;
  // Preflight covers every store. Unknown fields stay uninitialized even if
  // a previous call left known bytes in this storage.
  for offset in (0..68).step_by(4){self.store(self.offset(p,offset)?,32,CrtValue::Scalar{bits:0,known:0})?;}
  self.store(p,32,CrtValue::scalar(68))?;
  self.store(self.offset(p,50)?,16,CrtValue::scalar(0))?;
  self.store(self.offset(p,52)?,32,CrtValue::scalar(0))?;Ok(())
 }
 /// Canonical MSVC-style command line for an explicit UTF-8 native launch.
 /// argv[0] uses the distinct program-name grammar, not argument backslash rules.
 fn encode_native_command_line(args:&[String])->Result<(Vec<u8>,Vec<u8>),&'static str>{
  const MAX:usize=32766;
  if args.is_empty()||args.len()>32767||args[0].is_empty()||args[0].contains('"')||args.iter().any(|a|a.contains('\0')){return Err("native command-line argument domain");}
  fn put(s:&mut String,units:&mut usize,c:char)->Result<(),&'static str>{*units=units.checked_add(c.len_utf16()).filter(|n|*n<=32766).ok_or("native command-line UTF16 limit")?;s.push(c);Ok(())}
  let mut text=String::new();text.try_reserve_exact(4*(MAX+1)).map_err(|_|"native command-line encoding resource")?;let mut units=0;
  put(&mut text,&mut units,'"')?;for c in args[0].chars(){put(&mut text,&mut units,c)?;}put(&mut text,&mut units,'"')?;
  for argument in &args[1..]{
   put(&mut text,&mut units,' ')?;put(&mut text,&mut units,'"')?;let mut slashes=0usize;
   for c in argument.chars(){if c=='\\'{slashes=slashes.checked_add(1).filter(|n|*n<=MAX).ok_or("native command-line UTF16 limit")?;continue;}
    let count=if c=='"'{slashes*2+1}else{slashes};for _ in 0..count{put(&mut text,&mut units,'\\')?;}slashes=0;put(&mut text,&mut units,c)?;
   }
   for _ in 0..slashes*2{put(&mut text,&mut units,'\\')?;}put(&mut text,&mut units,'"')?;
  }
  let mut wide=Vec::new();wide.try_reserve_exact((units+1)*2).map_err(|_|"native command-line encoding resource")?;for unit in text.encode_utf16().chain(std::iter::once(0)){wide.extend_from_slice(&unit.to_le_bytes());}
  let mut narrow=text.into_bytes();narrow.push(0);Ok((narrow,wide))
 }
 /// Process-owned, immutable buffers. Failed pair publication releases only its
 /// private first mapping; no pointer or generation escapes on failure.
 /// Controlled launch input, never an implicit read of the host environment.
 /// Names are ASCII in this bounded profile; Unicode values are preserved.
 /// No entry contents appear in diagnostics. Hidden drive entries/collisions
 /// and non-ASCII name collation remain unsupported until separately proved.
 fn declare_environment(&mut self,init:CrtInitialization,profile:&str,base:u32,entries:&[(String,String)])->Result<(),&'static str>{
  self.initialization(init)?;if profile!="w2l-controlled-environment-v1"||self.environment.is_some()||base==0||base%4096!=0||entries.len()>256{return Err("CRT environment launch profile/extent");}
  let mut names=std::collections::BTreeSet::new();let mut ordered=Vec::new();
  ordered.try_reserve_exact(entries.len()).map_err(|_|"CRT environment metadata resource")?;
  let mut units=1usize;
  for(name,value)in entries{if name.is_empty()||!name.is_ascii()||name.contains(['=','\0'])||value.contains('\0')||!names.insert(name.to_ascii_uppercase()){return Err("CRT environment entry domain/collision");}
   units=units.checked_add(name.len()).and_then(|n|n.checked_add(value.encode_utf16().count()+2)).filter(|n|*n<=32767).ok_or("CRT environment supported size")?;ordered.push((name,value));}
  if entries.is_empty(){units=2;}ordered.sort_by_key(|(n,_)|n.to_ascii_uppercase());
  let mut words=Vec::new();words.try_reserve_exact(units*2).map_err(|_|"CRT environment encoding resource")?;
  for(name,value)in ordered{for u in name.encode_utf16().chain(std::iter::once(61)).chain(value.encode_utf16()).chain(std::iter::once(0)){words.extend_from_slice(&u.to_le_bytes());}}
  words.extend_from_slice(&0u16.to_le_bytes());if entries.is_empty(){words.extend_from_slice(&0u16.to_le_bytes());}
  self.environment=Some(Box::new(CrtEnvironment{anchor:self.anchor,owner:self.owner,pid:std::process::id(),words,next:base,blocks:Vec::new()}));Ok(())
 }
 fn environment_live(&self)->Result<(),&'static str>{let e=self.environment.as_ref().ok_or("CRT environment launch state unbound")?;if self.closed||e.anchor!=self.anchor||e.owner!=self.owner||e.pid!=std::process::id(){return Err("CRT environment process/lifetime");}self.memory.validate(self.anchor,guest_memory::Owner::Module(self.owner)).map_err(|_|"CRT environment storage lifetime")}
 fn environment_snapshot(&mut self,init:CrtInitialization)->Result<CrtPointer,&'static str>{
  self.initialization(init)?;self.environment_live()?;let e=self.environment.as_mut().unwrap();if e.blocks.len()>=16{return Err("CRT environment snapshot capacity unsupported");}
  let size=e.words.len()as u32;let base=e.next;let next=base.checked_add(size).and_then(|n|n.checked_add(4095)).map(|n|n&!4095).filter(|n|*n>base).ok_or("CRT environment address budget")?;
  e.blocks.try_reserve(1).map_err(|_|"CRT environment snapshot metadata resource")?;self.regions.try_reserve(1).map_err(|_|"CRT environment region metadata resource")?;
  let cap=self.memory.map_image(base,size,self.owner,guest_memory::Permissions::READ,&e.words).map_err(|_|"CRT environment snapshot mapping unsupported")?;
  let p=CrtPointer{cap,owner:guest_memory::Owner::Module(self.owner),base,address:base,size,kind:CrtRegionKind::ProcessData};e.blocks.push(p);e.next=next;self.regions.push(CrtRegion{pointer:p,heap:false,file_owner:None});self.last_os_error=None;Ok(p)
 }
 fn free_environment_snapshot(&mut self,init:CrtInitialization,p:CrtPointer)->Result<CrtValue,&'static str>{
  self.initialization(init)?;self.environment_live()?;let index=self.environment.as_ref().unwrap().blocks.iter().position(|q|*q==p).ok_or("CRT environment exact acquired root required")?;self.valid(p,p.size)?;
  let serial=self.serial.checked_add(1).ok_or("CRT environment BOOL identity budget")?;self.reserve_retirement()?;
  self.memory.release(p.cap,p.owner).map_err(|_|"CRT environment release unsupported")?;self.environment.as_mut().unwrap().blocks.remove(index);self.regions.retain(|r|r.pointer.cap!=p.cap);self.retired.push(p);self.tags.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));self.partial.retain(|&a,_|a<p.base||u64::from(a)>=u64::from(p.base)+u64::from(p.size));self.serial=serial;self.last_os_error=None;Ok(CrtValue::NonZero{anchor:self.anchor,serial})
 }
 fn publish_command_line(&mut self,init:CrtInitialization,base:u32,codepage:u32,args:&[String])->Result<CrtCommandLine,&'static str>{
  self.initialization(init)?;if self.command_line.is_some()||codepage!=65001||base==0||base%4096!=0{return Err("native command-line profile/base/publication");}
  let serial=self.serial.checked_add(1).ok_or("native command-line generation")?;let(narrow,wide)=Self::encode_native_command_line(args)?;
  let offset=u32::try_from(narrow.len()).map_err(|_|"native command-line size")?.checked_add(4095).map(|n|n&!4095).ok_or("native command-line address")?;let wide_base=base.checked_add(offset).ok_or("native command-line address")?;
  self.regions.try_reserve(2).map_err(|_|"native command-line region metadata resource")?;
  let a=self.memory.map_image(base,narrow.len()as u32,self.owner,guest_memory::Permissions::READ,&narrow).map_err(|_|"native command-line narrow mapping")?;
  let w=match self.memory.map_image(wide_base,wide.len()as u32,self.owner,guest_memory::Permissions::READ,&wide){Ok(w)=>w,Err(_)=>{self.memory.release(a,guest_memory::Owner::Module(self.owner)).map_err(|_|"native command-line mapping rollback")?;return Err("native command-line wide mapping");}};
  let make=|cap,address,size|CrtPointer{cap,owner:guest_memory::Owner::Module(self.owner),base:address,address,size,kind:CrtRegionKind::ProcessData};
  let token=CrtCommandLine{anchor:self.anchor,pid:std::process::id(),serial,codepage,narrow:make(a,base,narrow.len()as u32),wide:make(w,wide_base,wide.len()as u32)};
  for pointer in [token.narrow,token.wide]{self.regions.push(CrtRegion{pointer,heap:false,file_owner:None});}self.serial=serial;self.command_line=Some(token);Ok(token)
 }
 fn acquire_native_command_line(&mut self,init:CrtInitialization,base:u32,codepage:u32)->Result<CrtCommandLine,&'static str>{
  self.initialization(init)?;if codepage!=65001||self.command_line.is_some(){return Err("native command-line profile/base/publication");}
  #[cfg(target_os="linux")]{let mut args=Vec::new();for argument in std::env::args_os(){if args.len()>=32767{return Err("native command-line argument count");}let argument=argument.into_string().map_err(|_|"native command-line non-UTF8 argument")?;if argument.len()>131064{return Err("native command-line argument size");}args.try_reserve(1).map_err(|_|"native command-line argument resource")?;args.push(argument);}self.publish_command_line(init,base,codepage,&args)}
  #[cfg(not(target_os="linux"))]{let _=base;Err("native command-line acquisition unsupported host")}
 }
 fn command_line_pointer(&self,token:CrtCommandLine,wide:bool)->Result<CrtPointer,&'static str>{
  if self.closed||token.anchor!=self.anchor||token.pid!=std::process::id()||token.codepage!=65001||self.command_line!=Some(token){return Err("native command-line process/lifetime");}
  let p=if wide{token.wide}else{token.narrow};self.identity_range(p,p.size)?;self.memory.validate_immutable(p.cap,p.owner,p.address(),p.size).map_err(|_|"native command-line immutable lifetime")?;self.memory.read(p.address(),p.size).map_err(|_|"native command-line initialized bytes")?;Ok(p)
 }
 /// A declared process image-name snapshot. Supplied text is component input;
 /// only acquire_native_image_name can publish the actual native producer.
 fn publish_image_name(&mut self,init:CrtInitialization,image:CrtProcessImage,base:u32,text:&str,native:bool)->Result<CrtImageName,&'static str>{
  self.initialization(init)?;self.process_image(image)?;if self.image_name.is_some()||base==0||base%4096!=0||text.is_empty()||text.contains('\0')||text.encode_utf16().count()>32766{return Err("native image name profile/size/publication");}
  let serial=self.serial.checked_add(1).ok_or("native image name generation")?;let mut bytes=Vec::new();bytes.try_reserve_exact((text.encode_utf16().count()+1)*2).map_err(|_|"native image name encoding resource")?;for unit in text.encode_utf16().chain(std::iter::once(0)){bytes.extend_from_slice(&unit.to_le_bytes());}
  self.regions.try_reserve(1).map_err(|_|"native image name metadata resource")?;let cap=self.memory.map_image(base,bytes.len()as u32,self.owner,guest_memory::Permissions::READ,&bytes).map_err(|_|"native image name mapping")?;
  let wide=CrtPointer{cap,owner:guest_memory::Owner::Module(self.owner),base,address:base,size:bytes.len()as u32,kind:CrtRegionKind::ProcessData};
  let fact=match self.memory.prove_read(cap,wide.owner,base,wide.size){Ok(f)=>f,Err(_)=>{self.memory.release(cap,wide.owner).map_err(|_|"native image name mapping rollback")?;return Err("native image name read provenance");}};
  let value=CrtImageName{anchor:self.anchor,image,pid:std::process::id(),serial,wide,fact,native};self.regions.push(CrtRegion{pointer:wide,heap:false,file_owner:None});self.serial=serial;self.image_name=Some(value);Ok(value)
 }
 fn acquire_native_image_name(&mut self,init:CrtInitialization,image:CrtProcessImage,base:u32)->Result<CrtImageName,&'static str>{
  self.initialization(init)?;self.process_image(image)?;if self.image_name.is_some(){return Err("native image name already acquired");}
  #[cfg(target_os="linux")]{let path=std::env::current_exe().map_err(|_|"native image name acquisition failed")?;let text=path.to_str().ok_or("native image name non-UTF8 path")?;if !path.is_absolute(){return Err("native image name must be absolute");}self.publish_image_name(init,image,base,text,true)}
  #[cfg(not(target_os="linux"))]{let _=base;Err("native image name acquisition unsupported host")}
 }
 fn image_name_bytes(&self,name:CrtImageName)->Result<&[u8],&'static str>{
  if self.closed||name.anchor!=self.anchor||name.pid!=std::process::id()||self.image_name!=Some(name){return Err("native image name process/lifetime");}self.process_image(name.image)?;self.identity_range(name.wide,name.wide.size)?;self.memory.validate_immutable(name.wide.cap,name.wide.owner,name.wide.address(),name.wide.size).map_err(|_|"native image name immutable lifetime")?;self.memory.read_proven(name.fact,name.wide.owner).map_err(|_|"native image name observation expired")
 }
 /// Modern positive-count main-image contract only. Parameter/resource failures
 /// outside this domain reject rather than inventing a Windows error outcome.
 fn image_name_output(&mut self,name:CrtImageName,module:CrtValue,destination:CrtPointer,count:u32)->Result<u32,&'static str>{
  let bytes=self.image_name_bytes(name)?;let length=(bytes.len()/2-1)as u32;match module{CrtValue::Scalar{bits:0,known:u32::MAX}=>{},CrtValue::Pointer(p)if p==self.process_image(name.image)?=>{},_=>return Err("native image name module authority")};
  if count==0||count>32767{return Err("native image name count domain");}let extent=count.checked_mul(2).ok_or("native image name output size")?;self.valid(destination,extent)?;if !matches!(destination.kind,CrtRegionKind::Stack|CrtRegionKind::Buffer|CrtRegionKind::Module)||self.overlapping_tags(destination.address(),extent).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)|CrtValue::Dispatcher(_))){return Err("native image name output role/alias");}self.memory.validate_writable(destination.cap,destination.owner,destination.address(),extent).map_err(|_|"native image name output permission")?;
  let copied=length.min(count-1);let written=(copied+1)*2;
  // Complete data-word overwrites discard pointer/handle authority using the
  // existing 32-bit store. Partial symbolic-word overwrites remain unsupported.
  for(at,value)in self.overlapping_tags(destination.address(),written){if !matches!(value,CrtValue::Scalar{..})&&(at<destination.address()||u64::from(at)+4>u64::from(destination.address())+u64::from(written)||(at-destination.address())%2!=0){return Err("native image name partial typed output unbound");}}
  let mut i=0;while i<=copied{let p=self.offset(destination,i64::from(i)*2)?;let unit=if i==copied{CrtValue::scalar(0)}else{self.load(self.offset(name.wide,i64::from(i)*2)?,16)?};
   if self.tags.get(&p.address()).is_some_and(|v|!matches!(v,CrtValue::Scalar{..})){let next=if i+1==copied{0}else{self.load(self.offset(name.wide,i64::from(i+1)*2)?,16)?.known_scalar()?};self.store(p,32,CrtValue::scalar(unit.known_scalar()?|(next<<16)))?;i+=2;}else{self.store(p,16,unit)?;i+=1;}
  }
  let truncated=length>=count;self.last_os_error=if truncated{Some(122)}else{None};Ok(if truncated{count}else{length})
 }
 /// Native launch producer. Owned duplicates pin the actual host endpoints;
 /// virtual process handle values never equal borrowed host fd numbers by design.
 fn acquire_native_standards(&mut self,init:CrtInitialization)->Result<CrtNativeStandards,&'static str>{
  self.initialization(init)?;if self.native_standards.is_some(){return Err("native standard table already acquired");}
  #[cfg(target_os="linux")]{
   use std::os::fd::AsFd;
   let input=std::io::stdin().as_fd().try_clone_to_owned().map(std::fs::File::from).map_err(|_|"native stdin acquisition failed")?;
   let output=std::io::stdout().as_fd().try_clone_to_owned().map(std::fs::File::from).map_err(|_|"native stdout acquisition failed")?;
   let error=std::io::stderr().as_fd().try_clone_to_owned().map(std::fs::File::from).map_err(|_|"native stderr acquisition failed")?;
   self.publish_owned_standards(init,[input,output,error])
  }
  #[cfg(not(target_os="linux"))]{Err("native standard acquisition unsupported host")}
 }
 /// Takes real owned resources by value; no outcome/scalar can mint authority.
 fn publish_owned_standards(&mut self,init:CrtInitialization,files:[std::fs::File;3])->Result<CrtNativeStandards,&'static str>{
  self.initialization(init)?;if self.native_standards.is_some(){return Err("native standard table already acquired");}
  let serial=self.serial.checked_add(3).ok_or("native standard generation")?;
  self.native_endpoints.try_reserve(3).map_err(|_|"native standard resource budget")?;
  let mut handles=[0;3];let mut candidate=0x1000u32;
  for i in 0..3{while self.descriptors.iter().any(|d|d.id.handle==candidate)||self.native_endpoints.iter().any(|e|e.id.handle==candidate)||handles[..i].contains(&candidate){candidate=candidate.checked_add(4).ok_or("native handle value budget")?;}handles[i]=candidate;candidate=candidate.checked_add(4).ok_or("native handle value budget")?;}
  let set=CrtNativeStandards{anchor:self.anchor,serial,pid:std::process::id()};let mut entries=[CrtStandardEntry{value:CrtValue::scalar(0),last_error:None};3];
  for(i,file)in files.into_iter().enumerate(){let id=CrtProcessHandle{anchor:self.anchor,serial:self.serial+1+i as u64,handle:handles[i]};self.native_endpoints.push(CrtNativeEndpoint{id,file:Some(file),certain:true});entries[i].value=CrtValue::ProcessHandle(id);}
  self.serial=serial;self.native_standards=Some((set,entries));Ok(set)
 }
 fn native_standard_set(&self,set:CrtNativeStandards)->Result<(),&'static str>{
  if self.closed||set.anchor!=self.anchor||set.pid!=std::process::id()||self.native_standards.as_ref().is_none_or(|(id,_)|*id!=set){return Err("native standard process/lifetime");}Ok(())
 }
 fn native_endpoint(&self,h:CrtProcessHandle)->Result<&std::fs::File,&'static str>{
  if self.closed||h.anchor!=self.anchor||self.native_standards.as_ref().is_none_or(|(id,_)|id.pid!=std::process::id()){return Err("native endpoint process/lifetime");}
  let e=self.native_endpoints.iter().find(|e|e.id==h).ok_or("native endpoint identity")?;
  if !e.certain{return Err("native endpoint effects unknown");}e.file.as_ref().ok_or("native endpoint retired")
 }
 /// Copies the process table. It does not query/validate an OS handle or
 /// acquire another owned endpoint. Lost authority is returned as bits only.
 fn native_get_standard(&mut self,init:CrtInitialization,set:CrtNativeStandards,selector:u32)->Result<CrtValue,&'static str>{
  self.initialization(init)?;self.native_standard_set(set)?;let index=match selector{0xfffffff6=>0,0xfffffff5=>1,0xfffffff4=>2,_=>return Err("native standard selector unsupported")};
  let entry=self.native_standards.as_ref().unwrap().1[index];let value=match entry.value{CrtValue::ProcessHandle(h)if self.native_endpoint(h).is_err()=>CrtValue::scalar(h.handle),v=>v};
  if !matches!(value,CrtValue::ProcessHandle(_)|CrtValue::Scalar{known:u32::MAX,..}){return Err("native standard table value unknown");}
  self.last_os_error=entry.last_error;Ok(value)
 }
 fn native_file_type(&mut self,init:CrtInitialization,value:CrtValue)->Result<CrtValue,&'static str>{
  self.initialization(init)?;let CrtValue::ProcessHandle(h)=value else{return Err("native file type lacks owned endpoint");};
  let file=self.native_endpoint(h)?;
  #[cfg(target_os="linux")]{
   use std::os::unix::fs::FileTypeExt;
   let observation=file.metadata();self.last_os_error=None;let kind=observation.map_err(|_|"native file type query failed")?.file_type();
   let result=if kind.is_file()||kind.is_dir()||kind.is_block_device(){1}else if kind.is_char_device(){2}else if kind.is_fifo()||kind.is_socket(){3}else{return Err("native file type unsupported");};
   self.last_os_error=None;Ok(CrtValue::scalar(result))
  }
  #[cfg(not(target_os="linux"))]{let _=file;Err("native file type unsupported host")}
 }
 fn bind_descriptor(&mut self,number:u32,handle:u32)->Result<CrtDescriptorId,&'static str>{
  if self.locks.is_empty()&&self.initialization.is_none()||number>2047||handle==0||handle==u32::MAX||self.descriptors.iter().any(|d|d.live&&d.id.number==number){return Err("CRT descriptor binding/alias");}
  let generation=self.generation.checked_add(1).ok_or("CRT descriptor generation")?;
  // Equal process handle values share one lifetime, while descriptor numbers
  // retain separate lock/storage identities. A reused value gets a fresh epoch.
  let native=self.native_endpoints.iter().rev().find(|e|e.id.handle==handle).map(|e|e.id);if let Some(h)=native{self.native_endpoint(h)?;}let handle_generation=native.map(|h|h.serial).unwrap_or_else(||self.descriptors.iter().find(|d|d.live&&d.id.handle==handle).map_or(generation,|d|d.id.handle_generation));
  let id=CrtDescriptorId{anchor:self.anchor,generation,number,handle,handle_generation};self.descriptors.push(CrtDescriptor{id,live:true,record:None,record_initialized:false});self.generation=generation;Ok(id)
 }
 /// A descriptor lease is separate from FILE locking: low-I/O can be called
 /// without a FILE, and one FILE's lock cannot authorize another descriptor.
 fn descriptor_identity(&self,id:CrtDescriptorId)->Result<(),&'static str>{
  if self.closed||id.anchor!=self.anchor||!self.descriptors.iter().any(|d|d.live&&d.id==id){return Err("CRT descriptor owner/lifetime");}if let Some(e)=self.native_endpoints.iter().find(|e|e.id.handle==id.handle&&e.id.serial==id.handle_generation){self.native_endpoint(e.id)?;}Ok(())
 }
 fn descriptor(&self,id:CrtDescriptorId)->Result<(),&'static str>{
  self.descriptor_identity(id)?;if self.initialization.is_none()&&self.shutdown.is_none()&&!self.descriptor_locks.iter().any(|l|l.id==id){return Err("CRT exact descriptor lock required");}Ok(())
 }
 fn lock_descriptor(&mut self,thread:u64,id:CrtDescriptorId)->Result<CrtDescriptorLock,&'static str>{
  self.descriptor_identity(id)?;if let Some(p)=self.descriptors.iter().find(|d|d.id==id).and_then(|d|d.record){if self.regions.iter().any(|r|r.heap&&r.pointer.cap==p.cap){self.record_lock_live(p)?;}}if thread!=self.thread||self.descriptor_locks.len()>=32{return Err("CRT descriptor lock thread/budget");}
  let serial=self.serial.checked_add(1).ok_or("CRT descriptor lock generation")?;
  let lease=CrtDescriptorLock{anchor:self.anchor,thread,serial,depth:self.descriptor_locks.len(),id};self.descriptor_locks.push(lease);self.serial=serial;Ok(lease)
 }
 fn unlock_descriptor(&mut self,lease:CrtDescriptorLock)->Result<(),&'static str>{
  if self.descriptor_locks.last()!=Some(&lease){return Err("CRT descriptor stale/foreign/unordered unlock");}self.descriptor_locks.pop();Ok(())
 }
 /// Explicit declared-input storage binding only. This establishes neither
 /// initialized descriptor contents nor successful original CRT startup.
 fn claim_descriptor_record(&mut self,thread:u64,id:CrtDescriptorId,record:CrtPointer)->Result<CrtDescriptorLock,&'static str>{
  self.descriptor_identity(id)?;self.identity_range(record,56)?;
  if record.kind!=CrtRegionKind::Descriptor||record.address%4!=0||self.descriptors.iter().any(|d|d.record.is_some_and(|p|p.cap==record.cap&&u64::from(p.address)<u64::from(record.address)+56&&u64::from(record.address)<u64::from(p.address)+56))||self.descriptors.iter().any(|d|d.id==id&&d.record.is_some()){return Err("CRT descriptor record alias/role");}
  if self.regions.iter().any(|r|r.heap&&r.pointer.cap==record.cap){self.record_lock_live(record)?;}
  let lease=self.lock_descriptor(thread,id)?;
  self.descriptors.iter_mut().find(|d|d.id==id).ok_or("CRT descriptor identity")?.record=Some(record);Ok(lease)
 }
 fn bind_descriptor_record(&mut self,lease:CrtLock,id:CrtDescriptorId,record:CrtPointer)->Result<(),&'static str>{
  self.check_lock(lease)?;self.descriptor(id)?;self.valid(record,56)?;
  let item=self.descriptors.iter().find(|d|d.id==id).ok_or("CRT descriptor binding")?;
  if item.record!=Some(record)||item.record_initialized{return Err("CRT descriptor unclaimed/repeated record");}
  if self.load(self.offset(record,24)?,32)?!=CrtValue::Handle(id){return Err("CRT descriptor handle field identity");}
  self.load(self.offset(record,40)?,8)?.known_scalar()?;self.load(self.offset(record,41)?,8)?.known_scalar()?;
  self.descriptors.iter_mut().find(|d|d.id==id).ok_or("CRT descriptor binding")?.record_initialized=true;Ok(())
 }
 fn descriptor_record(&self,id:CrtDescriptorId)->Result<CrtPointer,&'static str>{
  self.descriptor(id)?;let record=self.descriptors.iter().find(|d|d.id==id&&d.record_initialized).and_then(|d|d.record).ok_or("CRT descriptor record unbound")?;self.valid(record,56)?;
  if self.load(self.offset(record,24)?,32)?!=CrtValue::Handle(id){return Err("CRT descriptor handle changed");}Ok(record)
 }
 fn require_narrow_descriptor(&self,id:CrtDescriptorId)->Result<CrtPointer,&'static str>{
  let record=self.descriptor_record(id)?;
  if self.load(self.offset(record,40)?,8)?.known_scalar()?!=0x81||self.load(self.offset(record,41)?,8)?.known_scalar()?!=0{return Err("CRT descriptor is not owned open nonappend narrow text");}Ok(record)
 }
 fn write_once(&mut self,id:CrtDescriptorId,source:CrtPointer,count:u32,backend:&mut impl CrtBackend)->Result<CrtWriteResult,&'static str>{
  if self.unobserved_contexts.iter().any(|(q,_)|q.cap==source.cap){return Err("unobserved context external observation unproved");}
  self.descriptor(id)?;if count>16384{return Err("CRT WriteFile source budget");}self.valid(source,count)?;self.ordinary_file_bytes(source,count)?;
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
  self.descriptor(id)?;let result=backend.close_once(id);self.last_os_error=None;
  // An unavailable observation can follow an external effect. Revoke every
  // cached alias rather than pretending the handle is still known live.
  if result!=Ok(false){for d in &mut self.descriptors{if d.id.handle==id.handle&&d.id.handle_generation==id.handle_generation{d.live=false;}}for e in &mut self.native_endpoints{if e.id.handle==id.handle&&e.id.serial==id.handle_generation{if result==Ok(true){e.file=None;}else{e.certain=false;}}}}result
 }
 /// Bind the actual accessor result, without initializing the selected cell.
 fn bind_errno_cell(&mut self,p:CrtPointer)->Result<CrtPointer,&'static str>{
  self.valid(p,4)?;let root=self.regions.iter().find(|r|r.pointer.cap==p.cap).ok_or("CRT errno owner")?.pointer;
  let role=match p.kind{CrtRegionKind::ThreadData=>root.kind==p.kind&&p.address-root.base==16,CrtRegionKind::Module=>root.kind==p.kind&&root.size==4&&p.address==root.base,_=>false};
  if !role||p.address%4!=0{return Err("CRT errno owner/field role");}self.record_errno_cell(p)
 }
 /// A checked UCRT field view preserves the original heap capability and layout.
 fn ucrt_errno_identity(&self,p:CrtPointer)->Result<(),&'static str>{
  self.valid(p,4)?;let root=self.regions.iter().find(|r|r.pointer.cap==p.cap&&r.heap&&r.file_owner.is_none()).ok_or("CRT UCRT errno allocation identity")?.pointer;
  if p.kind!=CrtRegionKind::Buffer||p.address!=root.base.checked_add(16).ok_or("CRT UCRT errno address")?{return Err("CRT UCRT errno field offset");}
  let view=self.heap_ptds.iter().find(|v|v.pointer==root&&v.layout==CrtPtdLayout::Ucrt).ok_or("CRT UCRT errno layout identity")?;
  self.heap_ptd_layout_view(root,view.slot,CrtPtdLayout::Ucrt)?;
  if self.fls.get(&view.slot.index)!=Some(&(view.slot,CrtValue::Pointer(root))){return Err("CRT UCRT errno current publication");}Ok(())
 }
 fn bind_ucrt_errno_cell(&mut self,p:CrtPointer)->Result<CrtPointer,&'static str>{self.ucrt_errno_identity(p)?;self.record_errno_cell(p)}
 fn bind_image_errno_cell(&mut self,image:CrtProcessImage,p:CrtPointer)->Result<CrtPointer,&'static str>{
  if p.kind!=CrtRegionKind::Module||self.process_image_pointer(image,p.address,4)?!=p{return Err("CRT errno canonical image field");}self.record_errno_cell(p)
 }
 fn record_errno_cell(&mut self,p:CrtPointer)->Result<CrtPointer,&'static str>{
  if p.address%4!=0{return Err("CRT errno owner/field role");}let p=self.subrange(p,4)?;let value=self.load(p,32)?;if !matches!(value,CrtValue::Scalar{..}){return Err("CRT errno initial scalar type");}
  self.canonical_errno=true;self.errno_cell=Some(p);self.errno=value.known_scalar().ok().map(|n|n as i32);Ok(p)
 }
 fn set_errors(&mut self,lease:CrtLock,errno:Option<i32>,doserrno:Option<u32>)->Result<(),&'static str>{self.check_lock(lease)?;if self.canonical_errno&&self.errno_cell.is_none(){return Err("CRT canonical errno cell not yet bound");}if let Some(p)=self.errno_cell{self.store(p,32,match errno{Some(n)=>CrtValue::scalar(n as u32),None=>CrtValue::Scalar{bits:0,known:0}})?;}self.errno=errno;self.doserrno=doserrno;Ok(())}
 fn initialize_c_locale(&mut self,lease:CrtLock)->Result<CrtLocale,&'static str>{self.check_lock(lease)?;if self.locale_live{return Err("CRT duplicate locale ownership");}self.locale_generation=self.locale_generation.checked_add(1).ok_or("CRT locale generation")?;self.locale_live=true;Ok(CrtLocale{anchor:self.anchor,thread:self.thread,generation:self.locale_generation})}
 fn check_locale(&self,thread:u64,locale:CrtLocale)->Result<(),&'static str>{if self.closed||locale.anchor!=self.anchor||locale.thread!=self.thread||thread!=self.thread||!self.locale_live||locale.generation!=self.locale_generation{return Err("CRT locale thread/lifetime");}Ok(())}
 fn retire_locale(&mut self,lease:CrtLock,locale:CrtLocale)->Result<(),&'static str>{self.check_lock(lease)?;self.check_locale(self.thread,locale)?;self.locale_live=false;Ok(())}
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
    fn opaque_dispatcher_transport_is_scoped_and_never_exposes_bytes() {
        native(
            r#"
let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();
let stack=rt.map_region(0x8000,128,CrtRegionKind::Stack,None).unwrap();
let token=rt.new_dispatcher(13,701).unwrap();let value=CrtValue::Dispatcher(token);
rt.store(stack,32,value).unwrap();rt.store(rt.offset(stack,4).unwrap(),32,value).unwrap();
assert_eq!(rt.load(stack,32).unwrap(),value);assert!(value.known_scalar().is_err());
assert!(rt.load(stack,8).is_err());assert!(rt.load(rt.offset(stack,1).unwrap(),32).is_err());
assert!(rt.store(stack,16,value).is_err());
let module=rt.map_region(0x9000,4,CrtRegionKind::Module,None).unwrap();assert!(rt.store(module,32,value).is_err());
let mut foreign=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();foreign.map_region(0x8000,128,CrtRegionKind::Stack,None).unwrap();let other=foreign.new_dispatcher(13,701).unwrap();
assert_eq!(other.serial,token.serial);assert_ne!(other.anchor,token.anchor);assert!(foreign.dispatcher(token).is_err());
assert!(rt.dispatcher(CrtDispatcherContext{thread:10,..token}).is_err());
assert!(rt.dispatcher(CrtDispatcherContext{epoch:14,..token}).is_err());
assert!(rt.dispatcher(CrtDispatcherContext{callback:702,..token}).is_err());
let file_lock=rt.lock(9).unwrap();let fd=rt.bind_descriptor(1,44).unwrap();let lease=rt.lock_descriptor(9,fd).unwrap();
struct Never;impl CrtBackend for Never{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("opaque token escaped to host");}}
assert!(rt.write_once(fd,stack,4,&mut Never).is_err());rt.unlock_descriptor(lease).unwrap();rt.unlock(file_lock).unwrap();
rt.end_dispatcher(token).unwrap();assert!(rt.load(stack,32).is_err());assert!(rt.load(rt.offset(stack,4).unwrap(),32).is_err());
assert!(rt.store(rt.offset(stack,8).unwrap(),32,value).is_err());assert!(rt.end_dispatcher(token).is_err());
let next=rt.new_dispatcher(13,701).unwrap();assert_ne!(next,token);assert!(rt.dispatcher(token).is_err());
rt.store(stack,32,CrtValue::Dispatcher(next)).unwrap();assert_eq!(rt.load(stack,32).unwrap(),CrtValue::Dispatcher(next));
for _ in 1..16{rt.new_dispatcher(13,702).unwrap();}assert!(rt.new_dispatcher(13,703).is_err());
"#,
        );
    }

    #[test]
    fn lock_result_preserves_fields_and_rejects_opaque_aliases() {
        native(
            r#"
for result in [0,1,7,u32::MAX]{
 let(mut r,init)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();let f=r.file();let p=r.offset(f,32).unwrap();
 r.store(r.offset(f,28).unwrap(),32,CrtValue::scalar(73)).unwrap();r.store(p,32,CrtValue::scalar(99)).unwrap();r.last_os_error=Some(9);
 assert_eq!(r.construct_lock_result(init,p,0,result).unwrap(),result!=0);assert_eq!(r.last_os_error,None);assert_eq!(r.load(r.offset(f,28).unwrap(),32).unwrap(),CrtValue::scalar(73));
 if result==0{assert!(r.lock(2).is_err());assert!(r.load(p,32).unwrap().known_scalar().is_err());}
 else{let l=r.lock(2).unwrap();assert!(r.load(p,8).is_err());assert!(r.store(r.offset(f,31).unwrap(),16,CrtValue::scalar(0)).is_err());assert!(r.store(p,32,CrtValue::scalar(0)).is_err());assert!(r.construct_lock_result(init,p,0,1).is_err());r.unlock(l).unwrap();r.destroy_lock(init,f).unwrap();assert!(!r.lock_objects.contains(&f.address()));}
}
let(mut r,init)=CrtStreamRuntime::new_initializing(1,2,0x5000,32768).unwrap();let f=r.file();let p=r.offset(f,32).unwrap();let(_,foreign)=CrtStreamRuntime::new_initializing(1,2,0x5000,32768).unwrap();
assert!(r.construct_lock_result(foreign,p,0,1).is_err());assert!(r.construct_lock_result(init,r.offset(p,4).unwrap(),0,1).is_err());assert!(r.construct_lock_result(init,r.subrange(p,20).unwrap(),0,1).is_err());assert!(r.construct_lock_result(init,p,1,1).is_err());
r.store(p,32,CrtValue::Pointer(f)).unwrap();assert!(r.construct_lock_result(init,p,0,1).is_err());assert_eq!(r.load(p,32).unwrap(),CrtValue::Pointer(f));assert!(r.lock_objects.is_empty());
"#,
        );
    }

    #[test]
    fn composed_heap_errors_cannot_fall_back_to_an_unbound_shadow_errno() {
        native(
            r#"
let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();rt.process_heap_result(init,true,Some(false)).unwrap();let ptd=rt.map_region(0x7000,20,CrtRegionKind::ThreadData,None).unwrap();let cell=rt.offset(ptd,16).unwrap();rt.store(cell,32,CrtValue::scalar(73)).unwrap();rt.construct_lock(init,rt.file()).unwrap();rt.end_initialization(init).unwrap();let lease=rt.lock(2).unwrap();assert!(rt.set_errors(lease,Some(22),Some(5)).is_err());assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(73));assert_eq!(rt.errno,None);assert_eq!(rt.doserrno,None);rt.bind_errno_cell(cell).unwrap();rt.set_errors(lease,Some(22),Some(5)).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(22));assert_eq!(rt.errno,Some(22));rt.unlock(lease).unwrap();
"#,
        );
    }

    #[test]
    fn opaque_heap_contracts_reject_cross_runtime_forged_and_unknown_policy() {
        native(
            r#"
let(mut a,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let(mut b,other)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();
assert!(a.process_heap_result(other,true,Some(false)).is_err());assert_eq!(a.process_heap_result(init,false,None).unwrap(),CrtValue::scalar(0));assert!(a.heap.is_none());
let CrtValue::Heap(heap)=a.process_heap_result(init,true,Some(false)).unwrap()else{panic!()};let CrtValue::Heap(foreign)=b.process_heap_result(other,true,Some(false)).unwrap()else{panic!()};assert!(a.heap_identity(foreign).is_err());assert!(a.process_heap_result(init,true,None).is_err());
let slot=a.map_region(0x7000,8,CrtRegionKind::Module,None).unwrap();a.store(slot,32,CrtValue::Heap(heap)).unwrap();assert_eq!(a.load(slot,32).unwrap(),CrtValue::Heap(heap));assert!(a.load(slot,8).is_err());assert!(a.store(slot,16,CrtValue::Heap(heap)).is_err());assert!(b.store(b.file(),32,CrtValue::Heap(heap)).is_err());
for flags in [0,4,9]{assert!(a.heap_alloc_result(init,heap,flags,56,true,true).is_err());}assert!(a.heap_alloc_result(init,heap,8,0,false,true).is_err());assert!(a.heap_alloc_result(init,heap,8,57,true,true).is_err());a.last_os_error=Some(77);assert!(a.heap_alloc_result(init,heap,8,56,true,false).unwrap().is_none());assert_eq!(a.last_os_error,Some(77));
let p=a.heap_alloc_result(init,heap,8,56,true,true).unwrap().unwrap();assert_eq!(a.last_os_error,None);assert_eq!(a.load(p,32).unwrap(),CrtValue::scalar(0));let(mut u,ut)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let CrtValue::Heap(unknown)=u.process_heap_result(ut,true,None).unwrap()else{panic!()};assert!(u.heap_alloc_result(ut,unknown,8,56,true,true).is_err());a.end_initialization(init).unwrap();assert!(a.heap_alloc_result(init,heap,8,56,true,true).is_err());
"#,
        );
    }

    #[test]
    fn global_lock_identity_cannot_be_substituted_by_file_or_record_leases() {
        native(
            r#"
let(mut a,init)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();let(mut b,other)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();
let p=a.map_region(0x8000,48,CrtRegionKind::Module,None).unwrap();let q=b.map_region(0x8000,48,CrtRegionKind::Module,None).unwrap();
assert!(a.construct_global_lock(other,7,p,1).is_err());assert!(a.construct_global_lock(init,32,p,1).is_err());assert!(!a.construct_global_lock(init,7,p,0).unwrap());assert!(a.lock_global(2,7).is_err());
a.construct_global_lock(init,7,p,1).unwrap();b.construct_global_lock(other,7,q,1).unwrap();assert!(a.construct_global_lock(init,8,a.offset(p,4).unwrap(),1).is_err());assert!(a.construct_global_lock(init,7,p,1).is_err());assert!(a.load(p,8).is_err());assert!(a.store(a.offset(p,23).unwrap(),16,CrtValue::scalar(0)).is_err());assert!(a.lock_global(3,7).is_err());
a.construct_global_lock(init,8,a.offset(p,24).unwrap(),1).unwrap();let x=a.lock_global(2,7).unwrap();let y=a.lock_global(2,8).unwrap();let foreign=b.lock_global(2,7).unwrap();assert!(a.unlock_global(foreign).is_err());assert!(a.unlock_global(x).is_err());assert!(a.destroy_global_lock(init,7).is_err());assert!(a.end_initialization(init).is_err());a.unlock_global(y).unwrap();a.unlock_global(x).unwrap();assert!(a.unlock_global(x).is_err());a.destroy_global_lock(init,7).unwrap();assert!(a.lock_global(2,7).is_err());a.construct_global_lock(init,7,p,1).unwrap();let next=a.lock_global(2,7).unwrap();assert!(a.check_global(x).is_err());assert_ne!(next.serial,x.serial);a.unlock_global(next).unwrap();
a.serial=u64::MAX;assert!(a.lock_global(2,7).is_err());assert!(a.global_locks.is_empty());a.destroy_global_lock(init,7).unwrap();a.destroy_global_lock(init,8).unwrap();a.end_initialization(init).unwrap();assert!(a.construct_global_lock(init,7,p,1).is_err());
"#,
        );
    }

    #[test]
    fn descriptor_allocations_and_locks_preserve_identity_before_handle_binding() {
        native(
            r#"
let(mut r,init)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();
let(mut foreign,other)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();
assert!(r.alloc_descriptor_block(other,2,true).is_err());for n in [0,65,u32::MAX]{assert!(r.alloc_descriptor_block(init,n,true).is_err());}
let before=r.regions.len();assert!(r.alloc_descriptor_block(init,2,false).unwrap().is_none());assert_eq!(r.regions.len(),before);
let block=r.alloc_descriptor_block(init,3,true).unwrap().unwrap();let second=r.offset(block,56).unwrap();let third=r.offset(block,112).unwrap();
assert!(r.claim_file_buffer(block,0x4000).is_err());assert!(r.valid(CrtPointer{kind:CrtRegionKind::Buffer,..block},4).is_err());assert!(r.free_initialization(init,r.subrange(block,56).unwrap()).is_err());assert!(r.lock_record(2,block).is_err());
for invalid in [r.offset(block,4).unwrap(),r.subrange(block,24).unwrap(),r.file()]{assert!(r.construct_record_lock_result(init,invalid,0,1).is_err());}
assert!(r.construct_record_lock_result(other,block,0,1).is_err());assert!(r.construct_record_lock_result(init,block,1,1).is_err());
r.store(block,32,CrtValue::Pointer(second)).unwrap();assert!(r.construct_record_lock_result(init,block,0,1).is_err());assert_eq!(r.load(block,32).unwrap(),CrtValue::Pointer(second));r.store(block,32,CrtValue::scalar(9)).unwrap();
assert!(!r.construct_record_lock_result(init,third,0,0).unwrap());assert!(r.lock_record(2,third).is_err());assert!(r.load(third,32).unwrap().known_scalar().is_err());
assert!(r.construct_record_lock_result(init,block,0,1).unwrap());assert!(r.construct_record_lock_result(init,second,0,7).unwrap());assert!(r.construct_record_lock_result(init,block,0,1).is_err());
assert!(r.load(block,8).is_err());assert!(r.store(r.offset(block,23).unwrap(),16,CrtValue::scalar(0)).is_err());assert!(r.construct_lock_result(init,r.offset(block,32).unwrap(),0,1).is_err());assert!(foreign.lock_record(2,block).is_err());assert!(r.lock_record(3,block).is_err());
let a=r.lock_record(2,block).unwrap();let b=r.lock_record(2,second).unwrap();assert!(r.unlock_record(a).is_err());assert!(r.destroy_record_lock(init,block).is_err());assert!(r.end_initialization(init).is_err());assert!(r.free_initialization(init,block).is_err());r.unlock_record(b).unwrap();r.unlock_record(a).unwrap();assert!(r.unlock_record(a).is_err());
let id=r.bind_descriptor(0,44).unwrap();let dl=r.claim_descriptor_record(2,id,block).unwrap();assert!(r.destroy_record_lock(init,block).is_err());r.unlock_descriptor(dl).unwrap();assert!(r.destroy_record_lock(init,block).is_err());
r.construct_lock(init,r.file()).unwrap();let fl=r.lock(2).unwrap();let dl=r.lock_descriptor(2,id).unwrap();r.store(r.offset(block,24).unwrap(),32,CrtValue::Handle(id)).unwrap();r.store(r.offset(block,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();r.store(r.offset(block,41).unwrap(),8,CrtValue::scalar(0)).unwrap();r.bind_descriptor_record(fl,id,block).unwrap();assert_eq!(r.require_narrow_descriptor(id).unwrap(),block);
struct Backend;impl CrtBackend for Backend{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("opaque lock escaped");}fn close_once(&mut self,_:CrtDescriptorId)->Result<bool,&'static str>{Ok(true)}}
assert!(r.write_once(id,block,1,&mut Backend).is_err());assert!(r.close_once(id,&mut Backend).unwrap());assert!(r.destroy_record_lock(init,block).is_err());r.unlock_descriptor(dl).unwrap();r.unlock(fl).unwrap();r.destroy_record_lock(init,block).unwrap();r.destroy_record_lock(init,second).unwrap();assert!(r.destroy_record_lock(init,second).is_err());r.free_initialization(init,block).unwrap();assert!(r.offset(block,0).is_err());assert!(r.lock_record(2,second).is_err());assert!(r.construct_record_lock_result(init,second,0,1).is_err());
let fresh=r.alloc_descriptor_block(init,2,true).unwrap().unwrap();assert_ne!(fresh.cap,block.cap);
// A record lease authorizes exactly its slot after exclusive initialization ends.
r.construct_record_lock_result(init,fresh,0,1).unwrap();r.end_initialization(init).unwrap();assert!(r.load(r.offset(fresh,24).unwrap(),32).is_err());let lease=r.lock_record(2,fresh).unwrap();assert_eq!(r.load(r.offset(fresh,24).unwrap(),32).unwrap(),CrtValue::scalar(0));assert!(r.load(r.offset(fresh,56+24).unwrap(),32).is_err());assert!(r.load(r.offset(fresh,54).unwrap(),32).is_err());r.unlock_record(lease).unwrap();assert!(r.load(r.offset(fresh,24).unwrap(),32).is_err());
"#,
        );
    }

    #[test]
    fn effective_addresses_never_expand_memory_or_transport_authority() {
        native(
            r#"
let(mut r,init)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();let p=r.alloc_descriptor_block(init,2,true).unwrap().unwrap();
let neighbour=r.map_region(p.address+112,64,CrtRegionKind::Result,Some(&[23;64])).unwrap();let beyond=r.effective_address(p,p.address+144).unwrap();
assert!(r.load(beyond,32).is_err());assert!(r.store(beyond,32,CrtValue::scalar(9)).is_err());assert!(r.pointer_transport(beyond).is_err());assert!(r.offset(p,144).is_err());assert!(r.free_initialization(init,beyond).is_err());
let back=r.effective_address(beyond,p.address+80).unwrap();assert_eq!(r.load(back,32).unwrap(),CrtValue::scalar(0));assert_eq!(r.load(neighbour,8).unwrap(),CrtValue::scalar(23));
let narrow=r.subrange(p,56).unwrap();let escaped=r.effective_address(narrow,p.address+80).unwrap();assert!(r.load(escaped,8).is_err());assert!(r.effective_address(CrtPointer{kind:CrtRegionKind::Buffer,..p},p.address).is_err());
r.free_initialization(init,p).unwrap();assert!(r.effective_address(beyond,p.address).is_err());assert!(r.load(back,32).is_err());
"#,
        );
    }

    #[test]
    fn locale_identity_rejects_another_runtime_with_equal_thread_and_generation() {
        native(
            r#"
let mut a=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let mut b=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();
let al=a.lock(9).unwrap();let bl=b.lock(9).unwrap();let first=a.initialize_c_locale(al).unwrap();let other=b.initialize_c_locale(bl).unwrap();
assert!(a.check_locale(9,other).is_err());assert!(b.check_locale(9,first).is_err());
assert_eq!(first.generation,other.generation);assert_ne!(first.anchor,other.anchor);assert!(a.retire_locale(al,other).is_err());a.check_locale(9,first).unwrap();b.check_locale(9,other).unwrap();
assert!(a.check_locale(10,first).is_err());let mut bad=first;bad.thread=10;assert!(a.check_locale(9,bad).is_err());
a.retire_locale(al,first).unwrap();assert!(a.check_locale(9,first).is_err());let next=a.initialize_c_locale(al).unwrap();assert!(next.generation>first.generation);assert!(a.check_locale(9,first).is_err());a.check_locale(9,next).unwrap();
let marker=a.map_region(0x5000,4,CrtRegionKind::Module,None).unwrap();assert!(a.load(marker,32).unwrap().known_scalar().is_err());a.check_locale(9,next).unwrap();assert!(a.load(marker,32).unwrap().known_scalar().is_err());
assert!(a.retire_locale(bl,next).is_err());a.check_locale(9,next).unwrap();a.retire_locale(al,next).unwrap();a.locale_generation=u64::MAX;assert!(a.initialize_c_locale(al).is_err());assert!(!a.locale_live);
a.unlock(al).unwrap();assert!(a.initialize_c_locale(al).is_err());b.unlock(bl).unwrap();
let shutdown=b.begin_shutdown(CrtShutdownReceipt{anchor:b.anchor,thread:9,event:19}).unwrap();b.destroy_lock_shutdown(shutdown,b.file()).unwrap();b.end_shutdown(shutdown).unwrap();assert!(b.check_locale(9,other).is_err());
"#,
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
let mut r=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let lease=r.lock(2).unwrap();let fd=r.bind_descriptor(1,44).unwrap();let endpoint_lease=r.lock_descriptor(2,fd).unwrap();let data=r.map_region(0x8000,4,CrtRegionKind::Input,Some(b"A\r\nZ")).unwrap();struct Failed;impl CrtBackend for Failed{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{Ok(CrtWriteResult{success:false,written:u32::MAX,last_error:Some(5)})}}
assert!(r.last_error().is_err());let failure=r.write_once(fd,data,4,&mut Failed).unwrap();assert!(!failure.success);assert_eq!(r.last_error().unwrap(),5);
let mut backend=B{calls:0,closed:false};let result=r.write_once(fd,data,4,&mut backend).unwrap();assert!(r.last_error().is_err());assert_eq!(result.written,2);assert_eq!(backend.calls,1);assert_eq!(r.errno,None);assert_eq!(r.doserrno,None);assert!(r.store(data,8,CrtValue::scalar(0)).is_err());
let unknown=r.alloc_buffer(lease,4,true).unwrap().unwrap();assert!(r.write_once(fd,unknown,4,&mut backend).is_err());assert_eq!(backend.calls,1);let record=r.map_region(0x9000,56,CrtRegionKind::Descriptor,None).unwrap();let descriptor_lease=r.claim_descriptor_record(2,fd,record).unwrap();let holder=r.offset(record,24).unwrap();r.store(holder,32,CrtValue::Handle(fd)).unwrap();r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();r.store(r.offset(record,41).unwrap(),8,CrtValue::scalar(0)).unwrap();r.bind_descriptor_record(lease,fd,record).unwrap();assert_eq!(r.require_narrow_descriptor(fd).unwrap(),record);r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0xa1)).unwrap();assert!(r.require_narrow_descriptor(fd).is_err());r.store(r.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();assert_eq!(r.load(holder,32).unwrap(),CrtValue::Handle(fd));assert!(r.write_once(fd,holder,4,&mut backend).is_err());
assert!(r.close_once(fd,&mut backend).unwrap());assert!(backend.closed);assert!(r.load(holder,32).is_err());assert!(r.write_once(fd,data,4,&mut backend).is_err());assert_eq!(backend.calls,1);r.unlock_descriptor(descriptor_lease).unwrap();r.unlock_descriptor(endpoint_lease).unwrap();r.unlock(lease).unwrap();
"#,
        );
    }
    #[test]
    fn distinct_record_leases_and_one_way_shutdown_do_not_reuse_initialization() {
        native(
            r#"
let(mut r,init)=CrtStreamRuntime::new_initializing_array(7,9,0x4000,2,32768).unwrap();let a=r.file();let b=r.offset(a,56).unwrap();
for f in [a,b]{r.construct_lock(init,f).unwrap();r.store(r.offset(f,12).unwrap(),32,CrtValue::scalar(0x42)).unwrap();}r.end_initialization(init).unwrap();
let la=r.lock_file(9,a).unwrap();let lb=r.lock_file(9,b).unwrap();assert!(r.atomic_or(lb,r.offset(a,12).unwrap(),16).is_err());assert_eq!(r.load(r.offset(a,12).unwrap(),32).unwrap().known_scalar().unwrap(),0x42);r.atomic_or(lb,r.offset(b,12).unwrap(),16).unwrap();r.unlock(lb).unwrap();
let da=r.bind_descriptor(0,33).unwrap();let db=r.bind_descriptor(1,44).unwrap();assert!(r.descriptor(da).is_err());let dla=r.lock_descriptor(9,da).unwrap();r.descriptor(da).unwrap();assert!(r.descriptor(db).is_err());let dlb=r.lock_descriptor(9,db).unwrap();assert!(r.unlock_descriptor(dla).is_err());r.unlock_descriptor(dlb).unwrap();r.unlock_descriptor(dla).unwrap();assert!(r.descriptor(da).is_err());
assert!(r.begin_shutdown(CrtShutdownReceipt{anchor:r.anchor,thread:9,event:11}).is_err());r.unlock(la).unwrap();
let(mut other,_)=CrtStreamRuntime::new_initializing(7,9,0x4000,32768).unwrap();assert!(r.begin_shutdown(CrtShutdownReceipt{anchor:other.anchor,thread:9,event:11}).is_err());
let shutdown=r.begin_shutdown(CrtShutdownReceipt{anchor:r.anchor,thread:9,event:11}).unwrap();assert!(r.construct_lock(init,a).is_err());assert!(r.end_initialization(init).is_err());assert!(r.end_shutdown(shutdown).is_err());
r.destroy_lock_shutdown(shutdown,a).unwrap();assert!(r.lock_file(9,a).is_err());r.destroy_lock_shutdown(shutdown,b).unwrap();r.end_shutdown(shutdown).unwrap();assert!(r.load(a,32).is_err());assert!(r.lock_descriptor(9,da).is_err());assert!(r.begin_shutdown(CrtShutdownReceipt{anchor:r.anchor,thread:9,event:11}).is_err());assert!(r.end_shutdown(shutdown).is_err());assert!(other.shutdown(shutdown).is_err());
"#,
        );
    }
    #[test]
    fn buffer_claim_and_release_require_the_same_file_record() {
        native(
            r#"
let (mut r,init)=CrtStreamRuntime::new_initializing_array(7,9,0x4000,2,32768).unwrap();
let a=r.file();let b=r.offset(a,56).unwrap();
r.construct_lock(init,a).unwrap();r.construct_lock(init,b).unwrap();
r.store(b,32,CrtValue::scalar(0)).unwrap();r.end_initialization(init).unwrap();
let la=r.lock_file(9,a).unwrap();let p=r.alloc_buffer(la,8,true).unwrap().unwrap();r.unlock(la).unwrap();
let lb=r.lock_file(9,b).unwrap();
assert!(r.store(b,32,CrtValue::Pointer(p)).is_err());assert_eq!(r.load(b,32).unwrap(),CrtValue::scalar(0));
assert!(r.free_buffer(lb,p).is_err());assert!(r.offset(p,0).is_ok());r.unlock(lb).unwrap();
let la=r.lock_file(9,a).unwrap();r.store(a,32,CrtValue::Pointer(p)).unwrap();r.free_buffer(la,p).unwrap();r.unlock(la).unwrap();
let lb=r.lock_file(9,b).unwrap();r.store(b,32,CrtValue::Pointer(p)).unwrap();assert!(r.offset(p,0).is_err());assert!(r.free_buffer(lb,p).is_err());
// An allocator result not yet assigned to a FILE is claimed by its first base store.
let q=r.allocate(8,false,true).unwrap().unwrap();r.store(r.offset(b,4).unwrap(),32,CrtValue::Pointer(q)).unwrap();r.unlock(lb).unwrap();
let la=r.lock_file(9,a).unwrap();assert!(r.store(a,32,CrtValue::Pointer(q)).is_err());assert!(r.free_buffer(la,q).is_err());r.unlock(la).unwrap();
let lb=r.lock_file(9,b).unwrap();r.free_buffer(lb,q).unwrap();r.unlock(lb).unwrap();
"#,
        );
    }
}
