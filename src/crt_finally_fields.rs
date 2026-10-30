//! Live scalar effects for original finally/dispatcher proof emission.
//! The enclosing component supplies a proved frame, exact code/table ranges and
//! scalar data bindings. This grants no handler selection or restoration token.
pub(crate) const EMITTED_TYPES: &str = r#"
struct CrtFinallyFields {
 anchor:guest_memory::Capability, identity:RegistryIdentity, binding:OwnedFrameBinding,
 id:RegistrationId, event:u64, ebp:u32, local:i32, cursor:i32,
 trace:CrtPointer, globals:Vec<CrtPointer>, immutable:Vec<(CrtPointer,Vec<u8>)>, failed:bool,
}
impl CrtFinallyFields {
 fn bind(rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage,
   local:i32,cursor:i32,trace:CrtPointer,globals:Vec<CrtPointer>,immutable:&[(u32,&[u8])])->RegistryResult<Self>{
  s.validate(rt,r,m)?;
  if local==cursor||local%4!=0||cursor%4!=0||!s.ordinary.contains(&local)||!s.ordinary.contains(&cursor)||globals.len()>64||immutable.is_empty()||immutable.len()>64{return Err("finally scalar field authority");}
  let mut occupied=std::collections::BTreeSet::new();
  for p in std::iter::once(&trace).chain(globals.iter()){
   if p.kind!=CrtRegionKind::Module||p.address()%4!=0||!occupied.insert(p.address())||p.address()==r.cookie_address{return Err("finally module scalar alias");}
   rt.valid(*p,4)?;rt.load(*p,32)?.known_scalar()?;
   for (at,bytes) in immutable{let end=u64::from(*at)+bytes.len()as u64;if u64::from(p.address())<end&&u64::from(*at)<u64::from(p.address())+4{return Err("finally scalar/code or metadata alias");}}
  }
  let mut bound=Vec::new();let mut total=0usize;
  for (at,bytes) in immutable{
   total=total.checked_add(bytes.len()).ok_or("finally immutable budget")?;
   if bytes.is_empty()||total>16384{return Err("finally immutable budget");}
   let p=rt.resolve_absolute(*at,CrtRegionKind::Module)?;rt.valid(p,u32::try_from(bytes.len()).map_err(|_|"finally immutable extent")?)?;
   bound.push((p,bytes.to_vec()));
  }
  let fields=Self{anchor:rt.anchor,identity:r.identity,binding:s.binding,id:s.id,event:m.event,ebp:s.image.ebp,local,cursor,trace,globals,immutable:bound,failed:false};
  fields.validate(rt,r,m,s)?;Ok(fields)
 }
 fn validate(&self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage)->RegistryResult<()>{
  if self.failed||self.anchor!=rt.anchor||self.identity!=r.identity||self.binding!=s.binding||self.id!=s.id||self.event!=m.event||self.ebp!=s.image.ebp{return Err("finally owner/lifetime/failed operation");}
  s.validate(rt,r,m)?;
  for offset in [self.local,self.cursor]{if !s.ordinary.contains(&offset){return Err("finally protected scalar role");}rt.load(self.frame_at(rt,s,offset)?,32)?.known_scalar()?;}
  for p in std::iter::once(&self.trace).chain(self.globals.iter()){rt.load(*p,32)?.known_scalar()?;}
  for(p,bytes)in &self.immutable{for(i,b)in bytes.iter().enumerate(){if rt.load(rt.offset(*p,i as i64)?,8)?.known_scalar()?!=u32::from(*b){return Err("finally original code/table changed");}}}Ok(())
 }
 fn frame_at(&self,rt:&CrtStreamRuntime,s:&CrtOwnedStorage,offset:i32)->RegistryResult<CrtPointer>{
  if !s.ordinary.contains(&offset){return Err("finally unowned frame field");}
  rt.offset(s.entry,i64::from(s.image.ebp)-i64::from(s.image.entry_sp)+i64::from(offset))
 }
 fn cell(&self,rt:&CrtStreamRuntime,s:&CrtOwnedStorage,index:usize)->RegistryResult<CrtPointer>{match index{0=>Ok(self.trace),1=>self.frame_at(rt,s,self.local),_=>Err("finally scalar cell index")}}
 fn read(&mut self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage,index:usize)->RegistryResult<u32>{
  let result=(||{self.validate(rt,r,m,s)?;rt.load(self.cell(rt,s,index)?,32)?.known_scalar()})();if result.is_err(){self.failed=true;}result
 }
 fn write(&mut self,rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage,index:usize,value:u32)->RegistryResult<()>{
  let result=(||{self.validate(rt,r,m,s)?;rt.store(self.cell(rt,s,index)?,32,CrtValue::scalar(value))})();if result.is_err(){self.failed=true;}result
 }
 fn read_cursor(&mut self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage)->RegistryResult<i32>{
  let result=(||{self.validate(rt,r,m,s)?;Ok(rt.load(self.frame_at(rt,s,self.cursor)?,32)?.known_scalar()? as i32)})();if result.is_err(){self.failed=true;}result
 }
 fn write_cursor(&mut self,rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage,value:i32)->RegistryResult<()>{
  let result=(||{self.validate(rt,r,m,s)?;rt.store(self.frame_at(rt,s,self.cursor)?,32,CrtValue::scalar(value as u32))})();if result.is_err(){self.failed=true;}result
 }
 fn write_global(&mut self,rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,s:&CrtOwnedStorage,index:usize,value:u32)->RegistryResult<()>{
  let result=(||{self.validate(rt,r,m,s)?;rt.store(*self.globals.get(index).ok_or("finally global index")?,32,CrtValue::scalar(value))})();if result.is_err(){self.failed=true;}result
 }
}
"#;
