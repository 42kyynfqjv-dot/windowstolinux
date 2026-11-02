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
struct CrtNativePlatform {file_mode:Option<(CrtFunction,CrtProcessFileMode)>,code_pages:bool,anchor:guest_memory::Capability,function:CrtFunction,fls:Option<CrtFunction>,fls_set:Option<CrtFunction>,second_fiber:bool,startup_metadata:bool,standards:Option<CrtNativeStandards>,command_line:Option<CrtCommandLine>,image_name:Option<CrtImageName>}
impl CrtNativePlatform {
 const PROFILE:&'static str="w2l-native-sync-20348-v1";
 const CONTRACT:&'static str="api-ms-win-core-synch-l1-2-0";
 const SECOND_FIBER_PROFILE:&'static str="w2l-native-second-fiber-20348-2398cc6a-v1";
 fn enable_second_fiber(&mut self,rt:&CrtStreamRuntime,init:CrtInitialization,profile:&str)->Result<(),&'static str>{self.validate(rt,init)?;if profile!=Self::SECOND_FIBER_PROFILE||self.second_fiber{return Err("second fiber profile unsupported/already enabled");}self.second_fiber=true;Ok(())}
 /// Native launch ABI v1 has no Windows CRT serialized inheritance block.
 /// Other STARTUPINFO fields are deliberately unknown, not guessed host values.
 const STARTUP_PROFILE:&'static str="w2l-native-startup-metadata-v1";
 fn enable_startup_metadata(&mut self,rt:&CrtStreamRuntime,init:CrtInitialization,profile:&str)->Result<(),&'static str>{
  self.validate(rt,init)?;if profile!=Self::STARTUP_PROFILE||!self.second_fiber||self.startup_metadata{return Err("native startup metadata profile unsupported/already enabled");}self.startup_metadata=true;Ok(())
 }
 fn startup_info_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if !self.startup_metadata{return Err("startup GetStartupInfoW effects unbound at 0x408543");}
  cpu.validate_active(rt)?;
  if cpu.return_pop!=4||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("startup info ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,8)?;
  rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),8).map_err(|_|"startup info call stack permission")?;
  let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
  rt.native_startup_info_output(init,p)?;
  cpu.clobber(CrtValue::Scalar{bits:0,known:0});cpu.finish_pop(rt,4)
 }
 fn acquire_standard_handles(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization)->Result<(),&'static str>{
  self.validate(rt,init)?;if !self.startup_metadata||self.standards.is_some(){return Err("native standard launch profile unbound/already acquired");}self.standards=Some(rt.acquire_native_standards(init)?);Ok(())
 }
 fn standard_handle_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,file_type:bool)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;let set=self.standards.ok_or("startup native standard handles unbound")?;rt.native_standard_set(set)?;cpu.validate_active(rt)?;
  if cpu.return_pop!=4||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native standard API ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,8)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),8).map_err(|_|"native standard API stack permission")?;let value=rt.load(rt.offset(sp,4)?,32)?;
  let result=if file_type{rt.native_file_type(init,value)?}else{rt.native_get_standard(init,set,value.known_scalar()?)?};cpu.clobber(result);cpu.finish_pop(rt,4)
 }
 fn environment_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,free:bool)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;cpu.validate_active(rt)?;let pop=if free{4}else{0};
  if cpu.return_pop!=pop||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("CRT environment API ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),u32::from(pop)+4).map_err(|_|"CRT environment API stack permission")?;
  let result=if free{let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;rt.free_environment_snapshot(init,p)?}else{CrtValue::Pointer(rt.environment_snapshot(init)?)};
  cpu.clobber(result);cpu.finish_pop(rt,pop)
 }
 fn acquire_command_line(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,base:u32,codepage:u32)->Result<(),&'static str>{
  self.validate(rt,init)?;if !self.startup_metadata||self.command_line.is_some(){return Err("native command-line launch profile unbound/already acquired");}self.command_line=Some(rt.acquire_native_command_line(init,base,codepage)?);Ok(())
 }
 const IMAGE_NAME_PROFILE:&'static str="w2l-native-main-image-name-modern-v1";
 /// Snapshot the actual Linux executable name before guest entry. This does
 /// not claim the spelling of a Windows source path or XP truncation behavior.
 fn acquire_image_name(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,image:CrtProcessImage,base:u32,profile:&str)->Result<(),&'static str>{
  self.validate(rt,init)?;if profile!=Self::IMAGE_NAME_PROFILE||!self.startup_metadata||self.image_name.is_some(){return Err("native image name launch profile unbound/already acquired");}self.image_name=Some(rt.acquire_native_image_name(init,image,base)?);Ok(())
 }
 fn image_name_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;cpu.validate_active(rt)?;if cpu.return_pop!=12||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native image name API ABI");}let name=self.image_name.ok_or("startup native image name unbound")?;if !name.native{return Err("native image name actual acquisition unbound");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,16)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),16).map_err(|_|"native image name API stack permission")?;let module=rt.load(rt.offset(sp,4)?,32)?;let destination=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let count=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let extent=count.checked_mul(2).ok_or("native image name output size")?;
  if destination.cap==sp.cap&&u64::from(destination.address())<u64::from(sp.address())+16&&u64::from(sp.address())<u64::from(destination.address())+u64::from(extent){return Err("native image name API argument alias");}
  let value=rt.image_name_output(name,module,destination,count)?;cpu.clobber(CrtValue::scalar(value));cpu.finish_pop(rt,12)
 }
 fn command_line_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,wide:bool)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native command-line API ABI");}let sp=CrtCpu::pointer(cpu.r[4])?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),4).map_err(|_|"native command-line API return permission")?;
  let token=self.command_line.ok_or("startup native command line unbound")?;let p=rt.command_line_pointer(token,wide)?;rt.last_os_error=None;cpu.clobber(CrtValue::Pointer(p));cpu.finish(rt)
 }
 /// ACP is the declared process encoding, never the host's inferred Windows ACP.
 /// The same live token backs both command-line encodings and this API result.
 fn ansi_code_page_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;cpu.validate_active(rt)?;
  if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native code-page API ABI");}
  let token=self.command_line.ok_or("native ANSI process profile unbound")?;
  rt.command_line_pointer(token,false)?;rt.command_line_pointer(token,true)?;
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),4).map_err(|_|"native code-page return permission")?;
  rt.last_os_error=None;cpu.clobber(CrtValue::scalar(token.codepage));cpu.finish(rt)
 }
 /// Installed-code-page results are a separate versioned OS contract, not ACP.
 const CODE_PAGE_PROFILE:&'static str="w2l-native-installed-codepages-20348-raw-v1";
 fn enable_code_pages(&mut self,rt:&CrtStreamRuntime,init:CrtInitialization,profile:&str)->Result<(),&'static str>{
  self.validate(rt,init)?;if self.code_pages||profile!=Self::CODE_PAGE_PROFILE{return Err("native installed code-page profile unsupported/already enabled");}self.code_pages=true;Ok(())
 }
 fn valid_code_page_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if !self.code_pages{return Err("native installed code-page profile unbound");}cpu.validate_active(rt)?;
  if cpu.return_pop!=4||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native installed code-page ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,8)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),8).map_err(|_|"native installed code-page stack permission")?;
  let page=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;
  let result=match page{65001=>1,u32::MAX=>0,_=>return Err("native installed code-page query outside measured profile")};
  // The profile binds raw BOOL; LastError is not promised by the public contract.
  rt.last_os_error=None;cpu.clobber(CrtValue::scalar(result));cpu.finish_pop(rt,4)
 }
 fn prepare(rt:&mut CrtStreamRuntime,init:CrtInitialization,profile:&str,handle:u32,address:u32)->Result<Self,&'static str>{
  rt.initialization(init)?;if profile!=Self::PROFILE{return Err("native platform profile unsupported");}
  // Native bootstrap executes before guest entry. A failed bootstrap issues no
  // guest LoadLibrary result, fabricated LastError or DLL initialization receipt.
  let ticket=rt.provider_begin(init,"kernelbase.dll",handle,1)?;
  let(_,function)=rt.provider_initialize_sync(init,&ticket,address)?;
  Ok(Self{file_mode:None,code_pages:false,anchor:rt.anchor,function,fls:None,fls_set:None,second_fiber:false,startup_metadata:false,standards:None,command_line:None,image_name:None})
 }
 /// Explicit optional native kernel32/FLS service, prepared before entry.
 fn enable_fls(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,handle:u32,address:u32)->Result<(),&'static str>{
  self.validate(rt,init)?;if self.fls.is_some(){return Err("native FLS provider already enabled");}
  let setter_address=address.checked_add(4).filter(|n|*n!=u32::MAX).ok_or("native FLS setter address")?;let ticket=rt.provider_begin(init,"kernel32.dll",handle,3)?;let mut published=None;
  let result=(||{let m=rt.provider_publish(init,&ticket)?;published=Some(m);let d=rt.provider_export(init,m,m,"FlsAlloc",address)?;let alloc=rt.bind_native_fls(init,d)?;let d=rt.provider_export(init,m,m,"FlsSetValue",setter_address)?;let setter=rt.bind_native_fls_set(init,d)?;if let Some(f)=rt.fiber{rt.check_fiber(f)?;}else{rt.bind_fiber(rt.thread)?;}Ok((alloc,setter))})();
  match result{Ok((f,setter))=>{self.fls=Some(f);self.fls_set=Some(setter);Ok(())},Err(e)=>{if let Some(m)=published{rt.provider_destroy(init,m)?;}else{rt.provider_abort(init,&ticket)?;}Err(e)}}
 }
 /// PE32 opaque SLIST startup initialization; no raw header bytes are claimed.
 fn slist_head_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,image:CrtProcessImage)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;rt.process_image(image)?;cpu.validate_active(rt)?;
  if cpu.return_pop!=4||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("CRT SLIST API ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,8)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),8).map_err(|_|"CRT SLIST return stack permission")?;
  let value=rt.load(rt.offset(sp,4)?,32)?;let p=match value{CrtValue::Pointer(p)=>p,CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(image,bits,8)?,_=>return Err("CRT SLIST pointer knowledge")};
  rt.initialize_slist_head(init,p)?;rt.last_os_error=None;cpu.clobber(CrtValue::Scalar{bits:0,known:0});cpu.finish_pop(rt,4)
 }
 /// Modern UTF-8 query or complete-fit write. Strict and insufficient-capacity
 /// failure effects remain unbound; original Windows may write before failure.
 fn wide_conversion_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,image:Option<CrtProcessImage>)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;cpu.validate_active(rt)?;
  if cpu.return_pop!=32||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native UTF8 query ABI");}
  let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,36)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),36).map_err(|_|"native UTF8 query stack permission")?;
  let page=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;
  let input=CrtCpu::pointer(rt.load(rt.offset(sp,12)?,32)?)?;let count=rt.load(rt.offset(sp,16)?,32)?.known_scalar()? as i32;
  let capacity=rt.load(rt.offset(sp,24)?,32)?.known_scalar()?;
  if flags!=0{return Err("native UTF8 flags outside supported query domain");}
  if rt.load(rt.offset(sp,28)?,32)?!=CrtValue::scalar(0)||rt.load(rt.offset(sp,32)?,32)?!=CrtValue::scalar(0){return Err("native UTF8 default-character outputs unbound");}
  if page==0{let token=self.command_line.ok_or("native UTF8 ACP profile unbound")?;rt.command_line_pointer(token,false)?;rt.command_line_pointer(token,true)?;if token.codepage!=65001{return Err("native UTF8 ACP encoding mismatch");}}
  else if page!=65001{return Err("native UTF8 code-page alias unbound");}
  // cbMultiByte=0 ignores lpMultiByteStr, including a non-NULL value. It must
  // not read, initialize or issue authority for that unused output address.
  for n in 0..8{if matches!(rt.load(rt.offset(sp,4+i64::from(n)*4)?,32)?,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)){return Err("native UTF8 query protected argument");}}
  let result=if capacity==0{rt.utf8_required(input,count)?}else{
   let value=rt.load(rt.offset(sp,20)?,32)?;let destination=match value{CrtValue::Pointer(p)=>p,CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(image.ok_or("native UTF8 output pointer authority")?,bits,capacity)?,_=>return Err("native UTF8 output pointer authority")};
   if u64::from(destination.address())<u64::from(sp.address())+36&&u64::from(sp.address())<u64::from(destination.address())+u64::from(capacity){return Err("native UTF8 call-frame output alias");}
   rt.utf8_write(input,count,destination,capacity)?
  };rt.last_os_error=None;cpu.clobber(CrtValue::scalar(result));cpu.finish_pop(rt,32)
 }
 const FILE_MODE_PROFILE:&'static str="w2l-native-process-file-mode-v1";
 /// Explicit pre-entry native policy; not acquired Windows loader/process state.
 fn enable_file_mode(&mut self,rt:&mut CrtStreamRuntime,init:CrtInitialization,profile:&str,mode:CrtFileApiMode)->Result<(),&'static str>{
  self.validate(rt,init)?;if profile!=Self::FILE_MODE_PROFILE||self.file_mode.is_some()||rt.file_mode.is_some(){return Err("native file mode profile/state");}
  let f=self.fls.ok_or("native file mode kernel32 provider unbound")?;rt.native_api_identity(f)?;rt.provider_ready(f.module)?;
  if !rt.modules.get(&f.module.handle).is_some_and(|m|m.identity=="kernel32.dll"){return Err("native file mode provider identity");}
  let address=f.address.checked_add(8).filter(|n|*n!=u32::MAX).ok_or("native file mode callable address")?;
  if rt.serial.checked_add(2).is_none(){return Err("native file mode serial");}
  let descriptor=rt.provider_export(init,f.module,f.module,"AreFileApisANSI",address)?;
  self.file_mode=Some(rt.bind_native_file_mode(init,descriptor,mode)?);Ok(())
 }
 fn file_mode_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,function:CrtFunction)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;let(f,token)=self.file_mode.ok_or("native file mode launch policy unbound")?;
  if function!=f||rt.native_named_export(init,f.module,"AreFileApisANSI")?!=f{return Err("native file mode callable identity");}rt.native_api_identity(f)?;rt.provider_ready(f.module)?;rt.file_mode(token)?;
  cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("native file mode ABI");}let sp=CrtCpu::pointer(cpu.r[4])?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),4).map_err(|_|"native file mode return permission")?;
  let result=rt.file_mode_result(token)?;rt.last_os_error=None;cpu.clobber(result);cpu.finish(rt)
 }
 fn fls_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,image:CrtProcessImage,f:CrtFunction)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if self.fls!=Some(f)||rt.native_named_export(init,f.module,"FlsAlloc")?!=f{return Err("native FLS callable target");}rt.native_api_identity(f)?;cpu.native_fls_alloc_call(rt,init,image)
 }
 /// Static named-import adapter only. This does not publish a dynamic export
 /// descriptor or grant GetProcAddress authority for FlsGetValue.
 fn fls_get_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;let f=self.fls.ok_or("native FLS getter provider not enabled")?;rt.native_api_identity(f)?;rt.provider_ready(f.module)?;
  if !rt.modules.get(&f.module.handle).is_some_and(|m|m.identity=="kernel32.dll"){return Err("native FLS getter provider identity");}
  let fiber=rt.fiber.ok_or("native FLS current fiber unbound")?;cpu.native_fls_get_call(rt,init,fiber)
 }
 fn fls_set_call(&self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,f:CrtFunction)->Result<CrtValue,&'static str>{
  self.validate(rt,init)?;if self.fls_set!=Some(f)||rt.native_named_export(init,f.module,"FlsSetValue")?!=f{return Err("native FLS setter callable target");}rt.native_api_identity(f)?;let fiber=rt.fiber.ok_or("native FLS current fiber unbound")?;rt.check_fiber(fiber)?;cpu.native_fls_set_call(rt,init,fiber)
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
  if self.second_fiber&&(bare.eq_ignore_ascii_case("api-ms-win-core-fibers-l1-1-2")||bare.eq_ignore_ascii_case("kernelbase")){let owned=rt.native_provider_acquire(init,self.function)?;rt.last_os_error=None;return Ok(owned.reference.module);}
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
   if self.second_fiber&&module==self.function.module&&name=="FlsGetValue2"{
    rt.provider_ready(module)?;
    if rt.exports.values().any(|e|e.function.module==module&&e.symbol==name){return Err("second fiber profile contradicts export state");}
    rt.last_os_error=Some(127);cpu.clobber(CrtValue::scalar(0));return cpu.finish_pop(rt,8);
   }
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
fn opaque_slist_api_preflights_abi_lifetimes_and_preserves_void_return() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
for mode in 0..11{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x400000,&[0;512]).unwrap();let platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let header=rt.map_region(0x20000,64,CrtRegionKind::Module,Some(&[0xa5;64])).unwrap();let stack=rt.map_region(0xa000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,384).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(900)).unwrap();let mut c=CrtCpu::new(sp,900).unwrap();c.push(&mut rt,if mode==4{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::Pointer(header)}).unwrap();rt.last_os_error=Some(71);
 if mode==5{rt.memory.release(image.root.cap,image.root.owner).unwrap();}if mode==6{rt.end_initialization(init).unwrap();}if mode==7{rt.thread+=1;}if mode==8{rt.provider_destroy(init,platform.function.module).unwrap();}if mode==9{rt.memory.release(header.cap,header.owner).unwrap();}
 let result=c.call_activation(&mut rt,0x430000,4,|rt,c|{if mode==1{c.return_pop=0;}if mode==2{c.r[3]=CrtValue::scalar(3);}if mode==3{c.return_id+=1;}if mode==10{rt.store(rt.offset(CrtCpu::pointer(c.r[4])?,-8)?,32,CrtValue::ProtectedReturn(c.return_id))?;}platform.slist_head_call(rt,c,init,image)});
 if mode==0{assert_eq!(result,Ok(CrtValue::Scalar{bits:0,known:0}));assert_eq!(c.r[4],CrtValue::Pointer(sp));assert!(!c.returned);assert_eq!(rt.last_os_error,None);let h=*rt.slist_heads.values().next().unwrap();rt.slist_head(h).unwrap();assert_eq!(rt.load(header,32),Err("CRT opaque SLIST header bytes"));}
 else{assert!(result.is_err(),"SLIST ABI/lifetime mode {mode} must reject");assert!(rt.slist_heads.is_empty());assert_eq!(rt.last_os_error,Some(71));if mode!=9{assert_eq!(rt.memory.read(header.address(),8).unwrap(),&[0xa5;8]);}}
}
"#,
        "slist-api-preflight",
    );
}

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

#[test]
fn startup_metadata_profile_preserves_void_abi_and_failure_ordering() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
for mode in 0..10{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,32768).unwrap();
 let mut platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();
 assert!(platform.enable_startup_metadata(&rt,init,CrtNativePlatform::STARTUP_PROFILE).is_err());
 platform.enable_second_fiber(&rt,init,CrtNativePlatform::SECOND_FIBER_PROFILE).unwrap();
 assert!(platform.enable_startup_metadata(&rt,init,"unrecognized-launch").is_err());
 if mode!=1{platform.enable_startup_metadata(&rt,init,CrtNativePlatform::STARTUP_PROFILE).unwrap();assert!(platform.enable_startup_metadata(&rt,init,CrtNativePlatform::STARTUP_PROFILE).is_err());}
 let stack=rt.map_region(0xa000,512,CrtRegionKind::Stack,Some(&[0x55;512])).unwrap();let out=rt.offset(stack,64).unwrap();let sp=rt.offset(stack,384).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(700)).unwrap();let mut c=CrtCpu::new(sp,700).unwrap();
 let argument=if mode==5{rt.offset(sp,-8).unwrap()}else{out};c.push(&mut rt,CrtValue::Pointer(argument)).unwrap();let before=rt.memory.read(out.address(),68).unwrap().to_vec();
 if mode==6{rt.end_initialization(init).unwrap();}if mode==7{rt.provider_destroy(init,platform.function.module).unwrap();}if mode==8{rt.thread+=1;}
 let result=c.call_activation(&mut rt,0x430000,4,|rt,c|{
  if mode==2{c.r[3]=CrtValue::scalar(123);}if mode==3{c.return_pop=0;}if mode==4{c.return_id+=1;}
  platform.startup_info_call(rt,c,init)
 });
 if mode==0||mode==9{
  assert_eq!(result,Ok(CrtValue::Scalar{bits:0,known:0}));assert_eq!(c.r[4],CrtValue::Pointer(sp));assert!(!c.returned);assert!(c.r[0].known_scalar().is_err());assert_eq!(rt.load(out,32).unwrap(),CrtValue::scalar(68));assert_eq!(rt.load(rt.offset(out,50).unwrap(),16).unwrap(),CrtValue::scalar(0));assert_eq!(rt.memory.read(out.address()-4,4).unwrap(),&[0x55;4]);assert_eq!(rt.memory.read(out.address()+68,4).unwrap(),&[0x55;4]);
 }else{assert!(result.is_err(),"bad call mode {mode} must reject");assert_eq!(rt.memory.read(out.address(),68).unwrap(),before,"failed preflight must preserve metadata output");}
}
"#,
        "startup-metadata-native-profile-abi",
    );
}

#[test]
fn installed_code_page_catalog_is_distinct_from_acp_and_rejects_unmeasured_queries() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        TYPES,
        r#"
#[inline(never)] fn foreign_anchor()->guest_memory::Capability{
 let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();other.anchor
}
#[inline(never)] fn query(mode:u32,foreign:guest_memory::Capability){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let mut p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();
 assert!(p.command_line.is_none());assert!(!p.code_pages);assert!(p.enable_code_pages(&rt,init,"unmeasured-profile").is_err());assert!(!p.code_pages);
 if mode!=3{p.enable_code_pages(&rt,init,CrtNativePlatform::CODE_PAGE_PROFILE).unwrap();assert!(p.enable_code_pages(&rt,init,CrtNativePlatform::CODE_PAGE_PROFILE).is_err());}
 let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();c.return_pop=4;
 let page=if mode==1{u32::MAX}else if mode==2{1252}else{65001};rt.store(rt.offset(sp,4).unwrap(),32,if mode==4{CrtValue::Scalar{bits:page,known:0}}else if mode==12{CrtValue::Pointer(stack)}else{CrtValue::scalar(page)}).unwrap();
 if mode==5{assert_ne!(foreign,rt.anchor);p.anchor=foreign;}if mode==6{rt.provider_destroy(init,p.function.module).unwrap();}if mode==7{rt.end_initialization(init).unwrap();}if mode==8{c.return_pop=0;}if mode==9{c.r[3]=CrtValue::scalar(12);}if mode==10{c.return_id+=1;}if mode==11{rt.memory.release(stack.cap,stack.owner).unwrap();}if mode==13{rt.bind_fiber(rt.thread).unwrap();}if mode==14{rt.thread+=1;}
 rt.last_os_error=Some(71);let before=c.r;let generation=rt.generation;let result=p.valid_code_page_call(&mut rt,&mut c,init);
 if matches!(mode,0|1|13){assert_eq!(result,Ok(CrtValue::scalar(u32::from(mode!=1))));assert!(c.returned);assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(sp,8).unwrap()));for r in [3,5,6,7]{assert_eq!(c.r[r],before[r]);}assert_eq!(rt.last_os_error,None);assert!(c.r[1].known_scalar().is_err());assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(None,None,None,None));assert!(p.valid_code_page_call(&mut rt,&mut c,init).is_err());}
 else{let expected=match mode{2=>"native installed code-page query outside measured profile",3=>"native installed code-page profile unbound",4|12=>"CRT scalar knowledge/type",5=>"native platform process identity",6=>"CRT unloaded module",7|14=>"CRT initialization owner/lifetime",8|9=>"native installed code-page ABI",10=>"CRT active caller lifetime/return authority",11=>"CRT pointer lifetime",_=>unreachable!()};assert_eq!(result,Err(expected),"catalog mode {mode}");assert!(!c.returned);assert_eq!(c.r,before);assert_eq!(rt.last_os_error,Some(71));assert_eq!(rt.generation,generation);}
}
let foreign=foreign_anchor();for mode in 0..15{query(mode,foreign);}
"#,
        "installed-code-page-catalog",
    );
}

#[test]
fn native_file_locks_preserve_distinct_records_and_preflight_rejection() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        TYPES,
        r#"
for mode in 0..11{
 let(mut rt,init)=CrtStreamRuntime::new_initializing_array(17,23,0x8000,3,65536).unwrap();let platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let file=rt.file();let lock=rt.offset(file,32).unwrap();rt.store(lock,32,CrtValue::scalar(77)).unwrap();let mut pointer=lock;let mut function=platform.function;
 match mode{1=>pointer=rt.offset(lock,4).unwrap(),2=>{rt.store(lock,32,CrtValue::Pointer(file)).unwrap();},3=>rt.end_initialization(init).unwrap(),4=>rt.thread+=1,5=>rt.provider_destroy(init,function.module).unwrap(),6=>{rt.native_file_initialize(init,function,lock,4000,0).unwrap();},7=>{pointer=rt.offset(file,56+32).unwrap();rt.native_file_initialize(init,function,lock,4000,0).unwrap();},8=>{let p=rt.map_region(0x9000,24,CrtRegionKind::Module,Some(&[0;24])).unwrap();pointer=p;},_=>{}}
 let result=rt.native_file_initialize(init,function,pointer,if mode==9{0}else{4000},if mode==7||mode==10{1}else{0});
 if mode==0{assert_eq!(result,Ok(true));assert!(rt.lock_objects.contains(&file.address()));assert_eq!(rt.load(lock,32),Err("CRT opaque critical section bytes"));let lease=rt.lock_file(23,file).unwrap();assert!(rt.destroy_lock(init,file).is_err());rt.unlock(lease).unwrap();rt.destroy_lock(init,file).unwrap();assert!(!rt.lock_objects.contains(&file.address()));assert_eq!(rt.native_file_initialize(init,function,lock,4000,0),Ok(true));}
 else{assert!(result.is_err(),"FILE negative{mode}");assert_eq!(rt.lock_objects.iter().count(),usize::from(mode==6||mode==7));if mode==7{let second=rt.offset(file,56).unwrap();assert!(!rt.lock_objects.contains(&second.address()));assert!(rt.lock_file(23,file).is_ok());}if !matches!(mode,2|6|7){assert_eq!(rt.memory.read(lock.address(),4).unwrap(),&77u32.to_le_bytes());}}
}
"#,
        "native-FILE-locks",
    );
}

#[test]
fn native_file_constructor_reservation_is_fallible_and_preallocated_effects_need_no_allocation() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
struct Reject;static DENY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);static ATTEMPTS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Reject{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){ATTEMPTS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::ptr::null_mut()}else{std::alloc::System.alloc(l)}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){ATTEMPTS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::ptr::null_mut()}else{std::alloc::System.realloc(p,l,n)}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){std::alloc::System.dealloc(p,l)}
}
#[global_allocator]static ALLOC:Reject=Reject;
let(mut rt,init)=CrtStreamRuntime::new_initializing_array(17,23,0x8000,3,65536).unwrap();let platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let pointers=std::array::from_fn::<_,3,_>(|i|rt.offset(rt.file(),i as i64*56+32).unwrap());
DENY.store(true,std::sync::atomic::Ordering::SeqCst);let failure=CrtFileLockSet::first(0x9000);let results=pointers.map(|p|rt.native_file_initialize(init,platform.function,p,4000,0));DENY.store(false,std::sync::atomic::Ordering::SeqCst);
assert!(matches!(failure,Err("CRT FILE lock bookkeeping resource")));assert_eq!(ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst),1);assert_eq!(results,[Ok(true);3]);assert_eq!(rt.lock_objects.len(),3);for p in pointers{assert_eq!(rt.load(p,8),Err("CRT opaque critical section bytes"));}
"#,
        "FILE-lock-resource",
    );
}
