//! Resident-module acquisition, with explicit process-environment premises.
pub(crate) const TYPES: &str = r#"
/// An explicit component environment: resident ordinary DLLs, without package,
/// SxS or .local redirection. This is not an issuer of startup/DllMain proof.
struct CrtResidentLoader {anchor:guest_memory::Capability,entries:std::collections::BTreeMap<String,CrtModule>}
impl CrtResidentLoader {
 fn name(name:&str)->Result<String,&'static str>{
  if name.is_empty()||name.len()>255||!name.is_ascii()||name.bytes().any(|b|!b.is_ascii_alphanumeric()&&!matches!(b,b'-'|b'_'|b'.'))||name.ends_with('.')||name.starts_with('.') {return Err("resident loader basename/encoding domain");}
  let mut name=name.to_ascii_lowercase();if name.starts_with("api-")||name.starts_with("ext-"){return Err("resident loader API-set mapping unbound");}
  if !name.contains('.') {name.push_str(".dll");}if !name.ends_with(".dll"){return Err("resident loader executable kind unbound");}Ok(name)
 }
 fn bind(rt:&CrtStreamRuntime,entries:&[(String,CrtModule)])->Result<Self,&'static str>{
  if entries.len()>64{return Err("resident loader module budget");}let mut table=std::collections::BTreeMap::new();
  for(name,module)in entries{rt.module_identity(*module)?;let name=Self::name(name)?;let identity=Self::name(&rt.modules.get(&module.handle).ok_or("CRT unloaded module")?.identity)?;
   if name!=identity||rt.modules.values().map(|m|Self::name(&m.identity)).collect::<Result<Vec<_>,_>>()?.iter().filter(|n|**n==name).count()!=1||table.insert(name,*module).is_some(){return Err("resident loader identity/ambiguous basename");}}
  Ok(Self{anchor:rt.anchor,entries:table})
 }
 fn load(&self,rt:&mut CrtStreamRuntime,init:CrtInitialization,name:&str,reserved:u32,flags:u32)->Result<CrtModule,&'static str>{
  rt.initialization(init)?;if self.anchor!=rt.anchor{return Err("resident loader process owner");}
  if reserved!=0||!matches!(flags,0|0x800){return Err("resident loader flags/reserved argument");}
  let name=Self::name(name)?;if rt.modules.values().map(|m|Self::name(&m.identity)).collect::<Result<Vec<_>,_>>()?.iter().filter(|n|**n==name).count()>1{return Err("resident loader identity/ambiguous basename");}let module=*self.entries.get(&name).ok_or("resident loader search/first-load effects unbound")?;rt.module_identity(module)?;
  let identity=rt.modules.get(&module.handle).ok_or("CRT unloaded module")?.identity.clone();
  let(acquired,_)=rt.module_acquire_result(init,&identity,module.handle)?;if acquired!=module{return Err("resident loader generation changed");}
  rt.last_os_error=None;Ok(acquired)
 }
 fn call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,iat:u32)->Result<CrtValue,&'static str>{
  cpu.validate_active(rt)?;if iat!=0x415074{return Err("resident loader export/release effects unbound");}
  let sp=CrtCpu::pointer(cpu.r[4])?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let mut text=Vec::new();let mut ended=false;
  for i in 0..260{let unit=rt.load(rt.offset(p,i*2)?,16)?.known_scalar()? as u16;if unit==0{ended=true;break;}text.push(unit);}
  if !ended{return Err("resident loader unterminated name");}let name=String::from_utf16(&text).map_err(|_|"resident loader UTF16")?;
  let reserved=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
  let module=self.load(rt,init,&name,reserved,flags)?;cpu.clobber(CrtValue::Module(module));cpu.finish_pop(rt,12)
 }
}
/// Explicit native replacement environment, not an inferred Windows loader state.
/// Mapping revision 1 is grounded in the x86 Windows 10.0.20348 observation.
/// Only this named domain is supported; no generic Windows version claim follows.
struct CrtNativePlatform {anchor:guest_memory::Capability,function:CrtFunction,fls:Option<CrtFunction>}
impl CrtNativePlatform {
 const PROFILE:&'static str="w2l-native-sync-20348-v1";
 const CONTRACT:&'static str="api-ms-win-core-synch-l1-2-0";
 fn prepare(rt:&mut CrtStreamRuntime,init:CrtInitialization,profile:&str,handle:u32,address:u32)->Result<Self,&'static str>{
  rt.initialization(init)?;if profile!=Self::PROFILE{return Err("native platform profile unsupported");}
  // Native bootstrap executes before guest entry. A failed bootstrap issues no
  // guest LoadLibrary result, fabricated LastError or DLL initialization receipt.
  let ticket=rt.provider_begin(init,"kernelbase.dll",handle,1)?;
  let(_,function)=rt.provider_initialize_sync(init,&ticket,address)?;
  Ok(Self{anchor:rt.anchor,function,fls:None})
 }
 /// Explicit optional native kernel32/FLS service, prepared before entry.
 fn enable_fls(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,handle:u32,address:u32)->Result<(),&'static str>{
  self.validate(rt,init)?;if self.fls.is_some(){return Err("native FLS provider already enabled");}
  let ticket=rt.provider_begin(init,"kernel32.dll",handle,1)?;let mut published=None;
  let result=(||{let m=rt.provider_publish(init,&ticket)?;published=Some(m);let d=rt.provider_export(init,m,m,"FlsAlloc",address)?;rt.bind_native_fls(init,d)})();
  match result{Ok(f)=>{self.fls=Some(f);Ok(())},Err(e)=>{if let Some(m)=published{rt.provider_destroy(init,m)?;}else{rt.provider_abort(init,&ticket)?;}Err(e)}}
 }
 fn fls_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,image:CrtProcessImage,f:CrtFunction)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if self.fls!=Some(f)||rt.native_named_export(init,f.module,"FlsAlloc")?!=f{return Err("native FLS callable target");}rt.native_api_identity(f)?;cpu.native_fls_alloc_call(rt,init,image)
 }
 fn validate(&self,rt:&CrtStreamRuntime,init:CrtInitialization)->Result<(),&'static str>{
  rt.initialization(init)?;if self.anchor!=rt.anchor{return Err("native platform process identity");}
  rt.native_sync_identity(self.function)?;rt.provider_ready(self.function.module)?;
  if !rt.modules.get(&self.function.module.handle).is_some_and(|m|m.identity=="kernelbase.dll")||rt.exports.get(&self.function.serial).is_none_or(|e|e.target!=self.function.module){return Err("native platform mapping identity");}Ok(())
 }
 fn load(&self,rt:&mut CrtStreamRuntime,init:CrtInitialization,name:&str,reserved:u32,flags:u32)->Result<CrtModule,&'static str>{
  self.validate(rt,init)?;
  if reserved!=0||flags!=0x800{return Err("native platform loader flags/reserved");}
  if !name.is_ascii(){return Err("native platform API-set encoding");}
  let bare=if name.len()>=4&&name[name.len()-4..].eq_ignore_ascii_case(".dll"){&name[..name.len()-4]}else{name};
  if bare.eq_ignore_ascii_case("kernel32")||bare.eq_ignore_ascii_case("api-ms-win-core-fibers-l1-1-1"){
   let f=self.fls.ok_or("native platform FLS provider not enabled")?;rt.native_api_identity(f)?;rt.provider_ready(f.module)?;
   let owned=rt.native_provider_acquire(init,f)?;rt.last_os_error=None;return Ok(owned.reference.module);
  }
  if !bare.eq_ignore_ascii_case(Self::CONTRACT){return Err("native platform API-set mapping unsupported");}
  // No host allocation here. Exhaustion rejects the component; it is never a
  // guest BOOL/null return. Whole-program admission must establish this budget.
  let owned=rt.native_provider_acquire(init,self.function)?;
  rt.last_os_error=None;Ok(owned.reference.module)
 }
 /// Execute the declared bounded native operation. Invalid state/resource
 /// domains reject; no internal error is fabricated as a Windows BOOL failure.
 fn sync_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,function:CrtFunction,index:u32)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if function!=self.function{return Err("native platform synchronization target");}
  if rt.native_named_export(init,function.module,"InitializeCriticalSectionEx")?!=function{return Err("native platform synchronization publication");}
  cpu.native_sync_call(rt,init,function,index)
 }
 fn call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,iat:u32)->Result<CrtValue,&'static str>{
  cpu.validate_active(rt)?;self.validate(rt,init)?;
  if iat==0x415070{
   if cpu.return_pop!=8||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=cpu.entry[i]){return Err("native platform stdcall frame");}
   let sp=CrtCpu::pointer(cpu.r[4])?;let CrtValue::Module(module)=rt.load(rt.offset(sp,4)?,32)? else{return Err("native platform export module authority");};
   if module!=self.function.module&&self.fls.is_none_or(|f|module!=f.module){return Err("native platform export source identity");}
   let p=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let mut bytes=[0u8;256];let mut len=None;
   for(i,b)in bytes.iter_mut().enumerate(){let unit=rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?;if unit==0{len=Some(i);break;}*b=unit as u8;}
   let len=len.ok_or("native platform export unterminated name")?;let name=std::str::from_utf8(&bytes[..len]).map_err(|_|"native platform export encoding")?;
   let f=rt.native_named_export(init,module,name)?;cpu.clobber(CrtValue::Function(f));return cpu.finish_pop(rt,8)
  }
  if iat!=0x415074{return Err("native platform release contract unbound");}
  if cpu.return_pop!=12||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=cpu.entry[i]){return Err("native platform stdcall frame");}
  let sp=CrtCpu::pointer(cpu.r[4])?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
  let mut bytes=[0u8;260];let mut len=None;
  for(i,b)in bytes.iter_mut().enumerate(){let unit=rt.load(rt.offset(p,(i*2)as i64)?,16)?.known_scalar()?;if unit==0{len=Some(i);break;}if unit>127{return Err("native platform API-set encoding");}*b=unit as u8;}
  let len=len.ok_or("native platform unterminated name")?;let name=std::str::from_utf8(&bytes[..len]).map_err(|_|"native platform API-set encoding")?;
  let reserved=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
  let module=self.load(rt,init,name,reserved,flags)?;cpu.clobber(CrtValue::Module(module));cpu.finish_pop(rt,12)
 }
}

"#;
#[test]
fn resident_load_acquires_real_reference_and_rejects_search_and_stale_authority() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let(m,root)=rt.module_acquire_result(init,"Independent-One.dll",0x700000).unwrap();let f=rt.module_export_result(init,m,"IndependentExport",0x701000).unwrap();
let loader=CrtResidentLoader::bind(&rt,&[("independent-one.DLL".into(),m)]).unwrap();
for flags in [0,0x800]{let count=rt.module_references.len();let loaded=loader.load(&mut rt,init,"INDEPENDENT-ONE",0,flags).unwrap();assert_eq!(loaded,m);assert_eq!(rt.module_references.len(),count+1);rt.function_identity(f,Some("IndependentExport")).unwrap();assert_eq!(rt.last_os_error,None);}
for(name,reserved,flags,error)in [("other.dll",0,0x800,"resident loader search/first-load effects unbound"),("api-ms-win-core-synch-l1-2-0.dll",0,0x800,"resident loader API-set mapping unbound"),("../independent-one.dll",0,0,"resident loader basename/encoding domain"),("independent-one.dll",1,0,"resident loader flags/reserved argument"),("independent-one.dll",0,8,"resident loader flags/reserved argument"),("independent-one.exe",0,0,"resident loader executable kind unbound")]{let count=rt.module_references.len();rt.last_os_error=Some(87);assert_eq!(loader.load(&mut rt,init,name,reserved,flags),Err(error));assert_eq!(rt.module_references.len(),count);assert_eq!(rt.last_os_error,Some(87));}
assert!(matches!(CrtResidentLoader::bind(&rt,&[("wrong.dll".into(),m)]),Err("resident loader identity/ambiguous basename")));
assert!(matches!(CrtResidentLoader::bind(&rt,&[("independent-one.dll".into(),m),("Independent-One".into(),m)]),Err("resident loader identity/ambiguous basename")));
let(duplicate,duplicate_ref)=rt.module_acquire_result(init,"INDEPENDENT-ONE.dll",0x720000).unwrap();assert!(matches!(CrtResidentLoader::bind(&rt,&[("independent-one.dll".into(),m)]),Err("resident loader identity/ambiguous basename")));assert_eq!(loader.load(&mut rt,init,"Independent-One.dll",0,0),Err("resident loader identity/ambiguous basename"));rt.module_release_result(init,duplicate_ref,true).unwrap();assert!(rt.module_identity(duplicate).is_err());
let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();assert_eq!(loader.load(&mut other,oi,"Independent-One.dll",0,0),Err("resident loader process owner"));
let refs:Vec<_>=rt.module_references.values().copied().collect();for r in refs{rt.module_release_result(init,r,true).unwrap();}assert_eq!(loader.load(&mut rt,init,"Independent-One.dll",0,0),Err("CRT unloaded module"));assert_eq!(rt.function_identity(f,None),Err("CRT unloaded module"));
let(new,_)=rt.module_acquire_result(init,"Independent-One.dll",root.module.handle).unwrap();assert_ne!(new,m);assert_eq!(loader.load(&mut rt,init,"Independent-One.dll",0,0),Err("CRT module owner/generation/lifetime"));
"#,
        "resident-loader",
    );
}

#[test]
fn declared_native_platform_rejects_unproved_profiles_and_preserves_lifetimes() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();
for profile in ["", "Windows7", "w2l-native-sync-20348-v2"]{let serial=r.serial;assert!(matches!(CrtNativePlatform::prepare(&mut r,i,profile,0x700000,0x701000),Err("native platform profile unsupported")));assert_eq!(r.serial,serial);assert!(r.providers.is_empty());}
assert!(matches!(CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0),Err("CRT native provider initialization bounds")));assert!(r.providers.is_empty());assert!(r.module_references.is_empty());
let p=CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let m=p.function.module;
assert!(CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x720000,0x721000).is_err());assert_eq!(r.module_references.len(),1);
for(name,reserved,flags,error)in [("api-ms-win-core-synch-l1-2-1",0,0x800,"native platform API-set mapping unsupported"),("kernelbase.dll",0,0x800,"native platform API-set mapping unsupported"),("api-ms-win-core-synch-l1-2-0",1,0x800,"native platform loader flags/reserved"),("api-ms-win-core-synch-l1-2-0",0,0,"native platform loader flags/reserved"),("é😊.dll",0,0x800,"native platform API-set encoding")]{r.last_os_error=Some(1114);let serial=r.serial;assert_eq!(p.load(&mut r,i,name,reserved,flags),Err(error));assert_eq!(r.serial,serial);assert_eq!(r.last_os_error,Some(1114));assert_eq!(r.module_references.len(),1);}
for name in ["api-ms-win-core-synch-l1-2-0", "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL"]{assert_eq!(p.load(&mut r,i,name,0,0x800),Ok(m));assert_eq!(r.last_os_error,None);}
assert_eq!(r.module_references.len(),3);assert!(r.provider_destroy(i,m).is_err());
let(mut other,oi)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();assert_eq!(p.load(&mut other,oi,CrtNativePlatform::CONTRACT,0,0x800),Err("native platform process identity"));
r.thread+=1;assert_eq!(p.load(&mut r,i,CrtNativePlatform::CONTRACT,0,0x800),Err("CRT initialization owner/lifetime"));r.thread-=1;
let refs:Vec<_>=r.module_references.values().copied().filter(|x|Some(*x)!=r.providers[&m.handle].root).collect();for reference in refs{r.native_provider_release(i,CrtNativeProviderReference{reference,function:p.function}).unwrap();}
r.provider_destroy(i,m).unwrap();assert_eq!(p.load(&mut r,i,CrtNativePlatform::CONTRACT,0,0x800),Err("CRT unloaded module"));
let new=CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();assert_ne!(new.function,p.function);assert_eq!(p.load(&mut r,i,CrtNativePlatform::CONTRACT,0,0x800),Err("CRT module owner/generation/lifetime"));new.validate(&r,i).unwrap();
"#,
        "native-platform-profile",
    );
}

#[test]
fn native_profile_sync_preserves_failure_state_and_checked_abi() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
for mode in 0..12 {
 let(mut r,i)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();
 let platform=CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();
 let mut function=platform.function;let mut index=3;
 let object=r.map_region(0x9000,48,CrtRegionKind::Module,Some(&[71;48])).unwrap();
 let p=r.subrange(object,24).unwrap();
 let sp=r.map_region(0xa000,64,CrtRegionKind::Stack,None).unwrap();
 r.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();
 r.store(r.offset(sp,4).unwrap(),32,CrtValue::Pointer(p)).unwrap();
 r.store(r.offset(sp,8).unwrap(),32,CrtValue::scalar(4000)).unwrap();
 r.store(r.offset(sp,12).unwrap(),32,CrtValue::scalar(0)).unwrap();
 let mut c=CrtCpu::new(sp,77).unwrap();c.return_pop=12;
 match mode {
  1=>{function.address+=4;},
  2=>{index=32;},
  3=>{r.store(r.offset(sp,12).unwrap(),32,CrtValue::scalar(1)).unwrap();},
  4=>{c.return_pop=8;},
  5=>{c.return_id=78;},
  6=>{c.r[3]=CrtValue::scalar(99);},
  7=>{r.provider_destroy(i,function.module).unwrap();},
  8=>{r.providers.get_mut(&function.module.handle).unwrap().exports.clear();},
  9=>{r.thread+=1;},
  10=>{r.native_sync_initialize(i,function,3,r.offset(object,24).unwrap(),0,0).unwrap();},
  11=>{r.store(p,32,CrtValue::Pointer(r.file())).unwrap();},
  _=>{}
 }
 r.last_os_error=Some(1114);let before=r.load(p,32).unwrap();let serial=r.serial;
 let result=platform.sync_call(&mut r,&mut c,i,function,index);
 if mode==0 {
  assert_eq!(result,Ok(CrtValue::scalar(1)));assert!(c.returned);
  assert_eq!(CrtCpu::pointer(c.r[4]).unwrap().address(),0xa010);assert_eq!(r.last_os_error,None);
  assert!(platform.sync_call(&mut r,&mut c,i,function,index).is_err());
  let first=r.lock_global(23,3).unwrap();let second=r.lock_global(23,3).unwrap();
  assert!(r.native_sync_delete(i,function,3,p).is_err());
  r.unlock_global(second).unwrap();r.unlock_global(first).unwrap();
  r.native_sync_delete(i,function,3,p).unwrap();assert!(r.native_sync_delete(i,function,3,p).is_err());
  assert_eq!(r.native_sync_initialize(i,function,3,p,0,0),Ok(1));
 } else {
  assert_eq!(result,Err(match mode{1=>"native platform synchronization target",2|3|10|11=>"CRT synchronization flags/object domain",4|6=>"CRT synchronization stdcall frame",5=>"CRT active caller lifetime/return authority",7=>"CRT unloaded module",8=>"CRT native named export publication incomplete",9=>"CRT initialization owner/lifetime",_=>unreachable!()}),"mode {mode}");assert!(!c.returned);
  assert_eq!(c.r[4],CrtValue::Pointer(sp));assert_eq!(r.load(sp,32).unwrap(),CrtValue::ProtectedReturn(77));
  assert_eq!(r.load(p,32).unwrap(),before,"mode {mode}: effect before rejection");
  assert_eq!(r.last_os_error,Some(1114));assert_eq!(r.serial,serial);
  if mode==10{assert_eq!(r.global_objects.values().count(),1);assert_eq!(r.global_objects.get(&3).unwrap().address(),0x9018);}
  else{assert!(r.global_objects.is_empty());assert!(r.native_sync.is_empty());}
 }
}
"#,
        "native-profile-sync-boundary",
    );
}

#[test]
fn explicit_fls_provider_rolls_back_and_rejects_stale_or_unpublished_targets() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
let mut p=CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();
assert!(p.enable_fls(&mut r,i,0x720000,0).is_err());assert!(p.fls.is_none());assert_eq!(r.providers.len(),1);assert_eq!(r.module_references.len(),1);assert_eq!(r.exports.len(),1);
p.enable_fls(&mut r,i,0x720000,0x721000).unwrap();let f=p.fls.unwrap();assert!(p.enable_fls(&mut r,i,0x740000,0x741000).is_err());assert_eq!(r.providers.len(),2);
for name in ["kernel32","KERNEL32.DLL","api-ms-win-core-fibers-l1-1-1"]{assert_eq!(p.load(&mut r,i,name,0,0x800),Ok(f.module));}
assert_eq!(r.native_named_export(i,f.module,"FlsAlloc"),Ok(f));assert_eq!(r.native_named_export(i,f.module,"flsAlloc"),Err("CRT native named export unsupported"));
assert!(r.native_named_export(i,p.function.module,"FlsAlloc").is_err());assert!(r.provider_destroy(i,f.module).is_err());
let refs:Vec<_>=r.module_references.values().copied().filter(|x|x.module==f.module&&Some(*x)!=r.providers[&f.module.handle].root).collect();
for reference in refs{r.native_provider_release(i,CrtNativeProviderReference{reference,function:f}).unwrap();}
let ids=r.providers[&f.module.handle].exports.clone();r.providers.get_mut(&f.module.handle).unwrap().exports.clear();assert_eq!(r.native_named_export(i,f.module,"FlsAlloc"),Err("CRT native named export publication incomplete"));r.providers.get_mut(&f.module.handle).unwrap().exports=ids;
r.provider_destroy(i,f.module).unwrap();assert!(r.native_api_identity(f).is_err());assert_eq!(p.load(&mut r,i,"kernel32",0,0x800),Err("CRT unloaded module"));assert_eq!(r.fls_indices.len(),0);
"#,
        "explicit-fls-provider",
    );
}
