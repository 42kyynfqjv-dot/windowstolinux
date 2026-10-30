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
