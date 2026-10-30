//! Byte-bound original lock-table loop, rollback and tail import.
use crate::crt_stream_ir::Target;
pub(crate) const LOCKS:&str="8bff5657bf50d1410033f66a0068a00f000057e8d3c2ffff85c07418ff05b8d2410083c61883c71881fe6801000072dbb001eb0a6a00e81d0000005932c05f5ec3";
pub(crate) const CLEAN:&str="8bff568b35b8d2410085f674206bc618578db838d1410057ff1554504100ff0db8d2410083ef1883ee0175eb5fb0015ec3";
pub(crate) const THUNK: &str = "8bff558bec5dff25ac504100";
pub(crate) fn source() -> Result<String, String> {
    let mut out = String::from(
        r#"
fn startup_lock_api(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,inputs:&CrtEntropyInputs,iat:u32)->Result<CrtValue,&'static str>{
 inputs.validate(rt)?;c.validate_active(rt)?;
 let symbol=if iat==0x4150ac{"InitializeCriticalSectionEx"}else if iat==0x415054{"DeleteCriticalSection"}else{return Err("startup lock import unsupported");};
 rt.process_image_import(inputs.image,iat,"kernel32.dll",symbol)?;
 let f={let mut functions=rt.exports.values().filter(|e|e.api==Some(CrtNativeApi::InitializeGlobalCriticalSectionEx)&&e.callable).map(|e|e.function);let f=functions.next().ok_or("startup lock callable provider missing")?;if functions.next().is_some(){return Err("startup lock callable provider ambiguous");}f};rt.native_sync_identity(f)?;
 let sp=CrtCpu::pointer(c.r[4])?;let pop=if iat==0x4150ac{12}else{4};
 if c.return_pop!=pop||c.r[4]!=c.entry[4]||[3,5,6,7].iter().any(|&i|c.r[i]!=c.entry[i]){return Err("startup lock API frame");}rt.offset(sp,4+i64::from(pop))?;
 let p=match rt.load(rt.offset(sp,4)?,32)?{CrtValue::Pointer(p)=>{if rt.process_image_pointer(inputs.image,p.address(),24)?!=p{return Err("startup lock canonical alias");}p},CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(inputs.image,bits,24)?,_=>return Err("startup lock address authority")};
 rt.memory.validate_writable(p.cap,p.owner,p.address(),24).map_err(|_|"startup lock object permission")?;
 if iat==0x4150ac{
  let spin=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
  let index=(0..32).find(|i|!rt.global_objects.contains_key(i)&&!rt.native_sync.contains_key(i)).ok_or("startup lock object capacity")?;
  let ok=rt.native_sync_initialize(inputs.init,f,index,p,spin,flags)?;c.clobber(CrtValue::scalar(ok));
 }else{
  let index=(0..32).find(|i|rt.native_sync.get(i)==Some(&(f,*i,p))).ok_or("startup lock delete identity")?;
  rt.native_sync_delete(inputs.init,f,index,p)?;c.clobber(CrtValue::Scalar{bits:0,known:0});
 }c.finish_pop(rt,pop)
}
"#,
    );
    for (name, origin, hex) in [
        ("startup_lock_loop", 0x40bd8e, LOCKS),
        ("startup_lock_cleanup", 0x40bde6, CLEAN),
    ] {
        let bytes = crate::crt_startup_table::raw(hex);
        let g = crate::crt_startup_table::graph(&bytes, origin)?;
        let roles = std::collections::BTreeMap::from([
            (0x41d150, "CrtRegionKind::Module".into()),
            (0x41d138, "CrtRegionKind::Module".into()),
            (0x41d2b8, "CrtRegionKind::Module".into()),
        ]);
        let initial = if name == "startup_lock_loop" {
            "if rt.load(count,32)?.known_scalar()?!=0{return Err(\"startup lock initial count\");}"
        } else {
            ""
        };
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                Ok(match t{
   Target::Direct(0x408079)=>format!("cpu.call_activation(rt,{next},12,|rt,c|startup_lock_thunk(rt,c,inputs,effect))?;"),
   Target::Direct(0x40bde6)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_lock_cleanup(rt,c,inputs,effect))?;"),
   Target::Import(0x415054)=>format!("rt.process_image_import(inputs.image,0x415054,\"kernel32.dll\",\"DeleteCriticalSection\")?;cpu.call_activation(rt,{next},4,|rt,c|effect(rt,c,inputs,0x415054))?;"),
   _=>return Err("startup lock loop call target".into())})
            },
            &roles,
            2048,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let code=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(code.address(),{}).map_err(|_|\"startup locks code read\")?!=&{bytes:?}{{return Err(\"startup locks code changed\");}}let count=rt.process_image_pointer(inputs.image,0x41d2b8,4)?;if rt.load(count,32)?.known_scalar()?>15{{return Err(\"startup lock count bound\");}}{initial}{body}}}",bytes.len(),bytes.len()));
    }
    let bytes = crate::crt_startup_table::raw(THUNK);
    let g = crate::crt_startup_table::graph(&bytes[..6], 0x408079)?;
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |_, _| Err("unexpected thunk call".into()),
        &Default::default(),
        16,
        |_, _| Err("unexpected thunk thread".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x40807f),
    )?;
    out.push_str(&format!("fn startup_lock_thunk(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x408079,12)?;if rt.memory.read(p.address(),12).map_err(|_|\"startup thunk read\")?!=&{bytes:?}{{return Err(\"startup lock thunk changed\");}}let _=(||->Result<CrtValue,&'static str>{{ {body} }})()?;rt.process_image_import(inputs.image,0x4150ac,\"kernel32.dll\",\"InitializeCriticalSectionEx\")?;effect(rt,cpu,inputs,0x4150ac)}}"));
    Ok(out)
}
#[test]
fn original_lock_graphs_decode() {
    source().unwrap();
}
