//! Original initializer/rollback loop with owned immutable tables and callbacks.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const LOOP:&str="8bff558bec5356578b7d083b7d0c74518bf78b1e85db740e8bcbff1528514100ffd384c0740883c6083b750c75e43b750c742e3bf7742683c6fc837efc0074138b1e85db740d6a008bcbff1528514100ffd35983ee088d46043bc775dd32c0eb02b0015f5e5b5dc3";
pub(crate) const WRAPPER: &str = "683860410068b85f4100e8c45200005959c3";
pub(crate) const FIRST: &str = "c70534d1410078c14100b001c3";
pub(crate) const TABLE:&str="587540000000000087754000000000001381400067814000d51b4000d51b40008ebd4000e6bd4000f0c8400010c9400000000000b575400007a440003da4400097864000f786400093704000d51b40002ab440000000000000000000d51b400000000000d575400000000000be754000d51b40007f75400065754000d51b4000";
pub(crate) fn raw(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) fn graph(bytes: &[u8], origin: u32) -> Result<Graph, String> {
    let mut d =
        iced_x86::Decoder::with_ip(32, bytes, u64::from(origin), iced_x86::DecoderOptions::NONE);
    let mut nodes = std::collections::BTreeMap::new();
    while d.can_decode() {
        let i = d.decode();
        let at = (i.ip32() - origin) as usize;
        nodes.insert(
            i.ip32(),
            Graph::decode_instruction(&bytes[at..at + i.len()], i.ip32())?,
        );
    }
    Ok(Graph {
        origin,
        end: origin + bytes.len() as u32,
        nodes,
    })
}
pub(crate) fn source() -> Result<String, String> {
    let bytes = raw(LOOP);
    let g = graph(&bytes, 0x40c926)?;
    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &g,
        |pc, t| {
            if t != Target::Import(0x415128) {
                return Err("initializer table call form".into());
            }
            let cleanup = pc == 0x40c970;
            Ok(format!("certificate.validate(rt,image)?;let index=certificate.cursor(rt,cpu,{cleanup})?;let address=CrtCpu::number(cpu.r[3])?;if CrtCpu::number(cpu.r[1])?!=address{{return Err(\"initializer guard register target\");}}if {cleanup}{{if failed.is_none()||!completed[index]||cleaned[index]||(index+1..certificate.len).any(|j|completed[j]&&!cleaned[j]&&certificate.pairs[j].1!=0){{return Err(\"initializer cleanup order/lifetime\");}}}}else if failed.is_some()||completed[index]||(0..index).any(|j|certificate.pairs[j].0!=0&&!completed[j]){{return Err(\"initializer execution order\");}}let target=rt.process_image_code(image,address,1)?;let guard=rt.process_image_code(image,0x401bf9,3)?;if rt.load(rt.process_image_pointer(image,0x415128,4)?,32)?.known_scalar()?!=0x401bf9||rt.memory.read(guard.address(),3).map_err(|_|\"initializer guard read\")?!=[0xc2,0,0]{{return Err(\"initializer guard identity\");}}cpu.call_activation(rt,{},0,startup_original_guard)?;guarded=Some((index,{cleanup},target));",pc+g.nodes[&pc].length))
        },
        &std::collections::BTreeMap::new(),
        4096,
        |_, _| Err("initializer thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("initializer return cleanup".into());
            }
            Ok(Some("certificate.validate(rt,image)?;let al=cpu.get(0,8,0)?.known_scalar()?;if let Some(_)=failed{if al!=0||(0..certificate.len).any(|j|completed[j]&&!cleaned[j]&&certificate.pairs[j].1!=0){return Err(\"initializer incomplete rollback\");}}else if al!=1||(0..certificate.len).any(|j|certificate.pairs[j].0!=0&&!completed[j]){return Err(\"initializer incomplete initialization\");}return cpu.finish(rt);".into()))
        },
        None,
        |_, _, _| Ok(None),
        |pc, _| {
            let cleanup = pc == 0x40c976;
            Ok(format!("certificate.validate(rt,image)?;let index=certificate.cursor(rt,cpu,{cleanup})?;let address=CrtCpu::number(target)?;let Some((bound_index,bound_cleanup,bound_target))=guarded.take()else{{return Err(\"initializer missing/replayed guard\");}};if bound_index!=index||bound_cleanup!={cleanup}||bound_target!=rt.process_image_code(image,address,1)?{{return Err(\"initializer callback target changed\");}}cpu.call_activation(rt,{},0,|rt,c|callback(rt,c,index,{cleanup},bound_target))?;certificate.validate(rt,image)?;if {cleanup}{{cleaned[index]=true;}}else if cpu.get(0,8,0)?.known_scalar()?==0{{failed=Some(index);}}else{{completed[index]=true;}}",pc+g.nodes[&pc].length))
        },
    )?;
    let literals=format!("fn crate_table_bytes()->Vec<u8>{{vec!{:?}}}fn crate_first_bytes()->Vec<u8>{{vec!{:?}}}fn crate_loop_bytes()->Vec<u8>{{vec!{:?}}}",raw(TABLE),raw(FIRST),bytes);
    let mut out = format!(
        r#"
struct CrtInitializerTable{{begin:CrtPointer,len:usize,pairs:[(u32,u32);16]}}
impl CrtInitializerTable{{
 fn bind(rt:&CrtStreamRuntime,image:CrtProcessImage,begin:u32,end:u32)->Result<Self,&'static str>{{
  let size=end.checked_sub(begin).filter(|n|*n<=128&&*n%8==0).ok_or("initializer table extent")?;if begin%4!=0{{return Err("initializer table alignment");}}
  let p=rt.process_image_pointer(image,begin,size.max(1))?;if rt.memory.validate_immutable(p.cap,p.owner,p.address(),size.max(1)).is_err(){{return Err("initializer table must be immutable");}}
  let mut pairs=[(0,0);16];for(i,pair)in pairs.iter_mut().take((size/8)as usize).enumerate(){{*pair=(rt.load(rt.offset(p,(i*8)as i64)?,32)?.known_scalar()?,rt.load(rt.offset(p,(i*8+4)as i64)?,32)?.known_scalar()?);}}
  Ok(Self{{begin:p,len:(size/8)as usize,pairs}})
 }}
 fn validate(&self,rt:&CrtStreamRuntime,image:CrtProcessImage)->Result<(),&'static str>{{
  if rt.process_image_pointer(image,self.begin.address(),(self.len as u32*8).max(1))?!=self.begin{{return Err("initializer table owner changed");}}
  if rt.memory.validate_immutable(self.begin.cap,self.begin.owner,self.begin.address(),(self.len as u32*8).max(1)).is_err(){{return Err("initializer table permission changed");}}
  let code=rt.process_image_code(image,0x40c926,{length})?;if rt.memory.read(code.address(),{length}).map_err(|_|"initializer loop code read")?!=&{bytes:?}{{return Err("initializer loop code changed");}}
  for(i,pair)in self.pairs[..self.len].iter().enumerate(){{if (rt.load(rt.offset(self.begin,(i*8)as i64)?,32)?.known_scalar()?,rt.load(rt.offset(self.begin,(i*8+4)as i64)?,32)?.known_scalar()?)!=*pair{{return Err("initializer table changed");}}}}Ok(())
 }}
 fn cursor(&self,rt:&CrtStreamRuntime,c:&CrtCpu,cleanup:bool)->Result<usize,&'static str>{{
  let p=CrtCpu::pointer(c.r[6])?;rt.identity_range(p,4)?;
  if p.cap!=self.begin.cap||p.owner!=self.begin.owner{{return Err("initializer cursor owner");}}
  let delta=p.address().checked_sub(self.begin.address()).and_then(|d|d.checked_sub(if cleanup{{4}}else{{0}})).ok_or("initializer cursor range")?;
  if delta%8!=0||(delta/8)as usize>=self.len{{return Err("initializer cursor extent");}}let index=(delta/8)as usize;
  let expected=if cleanup{{self.pairs[index].1}}else{{self.pairs[index].0}};
  if expected==0||CrtCpu::number(c.r[3])?!=expected{{return Err("initializer table/target identity");}}Ok(index)
 }}
}}
fn startup_table_loop(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,image:CrtProcessImage,callback:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,usize,bool,CrtPointer)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{
 cpu.validate_active(rt)?;let sp=CrtCpu::pointer(cpu.r[4])?;let begin=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let end=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let certificate=CrtInitializerTable::bind(rt,image,begin,end)?;certificate.validate(rt,image)?;rt.store(rt.offset(sp,4)?,32,CrtValue::Pointer(certificate.begin))?;
 let mut completed=[false;16];let mut cleaned=[false;16];let mut failed:Option<usize>=None;let mut guarded:Option<(usize,bool,CrtPointer)>=None;{body}
}}
"#,
        length = bytes.len()
    );
    for(name,origin,code)in [("startup_table_entry",0x407653,WRAPPER),("startup_table_first",0x407558,FIRST),
 ("startup_table_second",0x407587,"8bff568b3500c0410056e8f604000056e86454000056e85456000056e8b8f0ffff56e829faffff83c414b0015ec3"),
 ("startup_init_store_a",0x407a8c,"8bff558bec8b4508a3a0ce41005dc3"),("startup_init_store_b",0x40ca00,"8bff558bec8b4508a3ccd241005dc3"),
 ("startup_init_store_c",0x40cbf6,"8bff558bec8b4508a3d0d24100a3d4d24100a3d8d24100a3dcd241005dc3"),
 ("startup_init_store_d",0x406660,"8bff558bec8b4508a33ccd41005dc3"),("startup_init_store_e",0x406fd7,"8bff558bec8b4508a35cce41005dc3"),
 ("startup_table_heap_clear",0x40c910,"8325c8d2410000b001c3"),("startup_table_noop",0x401bd5,"b001c3"),("startup_table_third",0x408113,"8bff558bec518d45fc506a0268800000006800e04100ff15b050410085c00f95c0c9c3")]{
  let bytes=raw(code);let g=Graph::decode(&bytes,origin)?;
  let roles=std::collections::BTreeMap::from_iter([0x41d134,0x41c000,0x41cea0,0x41d2cc,0x41d2d0,0x41d2d4,0x41d2d8,0x41d2dc,0x41cd3c,0x41ce5c,0x41e000,0x41d2c8].map(|a|(a,"CrtRegionKind::Module".into())));
  let body=crate::crt_stream_emit::emit_body(&g,|pc,t|{let next=pc+g.nodes[&pc].length;if t==Target::Direct(0x40c926){return Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_table_loop(rt,c,inputs.image,callback))?;"));}else if t==Target::Import(0x4150b0){return Ok(format!("rt.process_image_import(inputs.image,0x4150b0,\"kernel32.dll\",\"VirtualProtect\")?;cpu.call_activation(rt,{next},16,|rt,c|c.virtual_protect_call(rt,inputs.image))?;"));}let callee=match t{Target::Direct(0x407a8c)=>"startup_init_store_a",Target::Direct(0x40ca00)=>"startup_init_store_b",Target::Direct(0x40cbf6)=>"startup_init_store_c",Target::Direct(0x406660)=>"startup_init_store_d",Target::Direct(0x406fd7)=>"startup_init_store_e",_=>return Err("initializer callback call binding".into())};Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|{callee}(rt,c,inputs))?;"))},&roles,512)?;
  let params=if name=="startup_table_entry"{",callback:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,usize,bool,CrtPointer)->Result<CrtValue,&'static str>"}else{""};
  out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs{params})->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"initializer helper code read\")?!=&{bytes:?}{{return Err(\"initializer helper code changed\");}}{body}}}",bytes.len(),bytes.len()));
 }
    let table = raw(TABLE);
    out.push_str(&format!("fn startup_original_table(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{let p=rt.process_image_pointer(inputs.image,0x415fb8,128)?;if rt.memory.read(p.address(),128).map_err(|_|\"initializer table read\")?!=&{table:?}{{return Err(\"original initializer table changed\");}}startup_table_entry(rt,cpu,inputs,&mut |rt,c,index,cleanup,target|{{if !cleanup{{match(index,target.address()){{(0,0x407558)=>startup_table_first(rt,c,inputs),(1,0x407587)=>startup_table_second(rt,c,inputs),(2,0x408113)=>startup_table_third(rt,c,inputs),(3,0x401bd5)=>startup_table_noop(rt,c,inputs),(4,0x40bd8e)=>startup_lock_loop(rt,c,inputs,&mut startup_lock_api),(5,0x40c8f0)=>startup_heap_original(rt,c,inputs,&mut startup_heap_api),(7,0x40a407)=>startup_fiber_init_registered(rt,c,inputs,platform,epoch.as_deref_mut(),&mut startup_fiber_api),_=>Err(\"original initializer callback effect unbound\")}}}}else{{match(index,target.address()){{(5,0x40c910)=>startup_table_heap_clear(rt,c,inputs),_=>Err(\"original initializer cleanup effect unbound\")}}}}}})}}"));
    out.push_str(&format!(
        "fn crate_second_b_bytes()->Vec<u8>{{vec!{:?}}}",
        raw("8bff558bec8b4508a3ccd241005dc3")
    ));
    out.push_str(&crate::crt_startup_locks::source()?);
    out.push_str(&crate::crt_startup_heap::source()?);
    out.push_str(&crate::crt_startup_fiber::source()?);
    out.push_str(&literals);
    Ok(out)
}
#[test]
fn original_initializer_loop_decodes_owned_calls_and_rollbacks() {
    source().unwrap();
}
