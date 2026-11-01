//! Original mode and argument-configuration prefix. No synthesized argv.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const MODE: &str = "33c040c3";
pub(crate) const WRAPPER: &str = "8bff558bec5de9f7fcffff";
pub(crate) const CONFIGURE: &str = "8bff558bec83ec0c578b7d0885ff750733c0e9230100005683ff02741b83ff017416e8d01500006a165e8930e8481400008bc6e90101000053e8164d00006804010000bb40cd410033f65356e8e6460000891d64ce410083c40c8b1d74ce410085db7405803b007505bb40cd41008d45f48975fc508d45fc8975f450565653e8b90000006a01ff75f4ff75fce81e0200008bf083c42085f6750ce8581500006a0c5e8930eb2f8d45f4508d45fc508b45fc8d0486505653e88100000083c41483ff01751c8b45fc4889356cce4100a368ce410033f66a00e89e1500008bc6eb578d45f833db5056895df8e8404500008bf8595985ff740aff75f8e87b150000eb2a8b55f88bcb8bc2391a74088d400441391875f853890d68ce4100895df889156cce4100e8511500008bfb5956895df8e8451500008bc7595b5e5fc9c3";
pub(crate) const IMAGE_NAME: &str = "8bff558bec81ec2c020000a100c0410033c58945fc8b45088d8df0fdffff68050100005150ff158450410085c07511ff154450410050e829ceffff5933c0eb558b4d0c8b451083a5e4fdffff00898dd4fdffff8985d8fdffff898ddcfdffff8985e0fdffffc685e8fdffff00e80bfdffff508d85effdffff508d85d4fdffff508d85f0fdffff50e877feffff8b85e4fdffff83c4108b4dfc33cde8a066ffffc9c3";
pub(crate) const LOCALE: &str = "8bff558bec83ec106a008d4df0e823ffffff8b45f4bae9fd0000395008740ce813d4ffff33d285c0750142807dfc00740a8b4df083a150030000fd8bc2c9c3";
pub(crate) const FILE_ANSI: &str = "8bff56e8cefdffff8bf085f6740c8bceff1528514100ffd65ec333c0405ec3";
pub(crate) const FILE_RESOLVE: &str =
    "a100e0410083f8ff750333c0c385c0751868f466410068f066410068f466410050e88500000083c410c3";
pub(crate) const CONVERT: &str = "8bff558bec568b750885f6750f8b4d0ce8d400000033c0e9a30000005333db66391e75258b750c395e0c75116a018bcee88d00000085c00f85810000008b4608881833c0895e10eb75535353536aff5653ff7514e85c0b000083c42085c07516ff154450410050e8f5ceffff59e84bcfffff8b00eb48578b7d0c3b470c760c508bcfe83b00000085c07532ff770c8b4d10ff770856ff7514e8b8fdffff85c07516ff154450410050e8b4ceffff59e80acfffff8b00eb064889471033c05f5b5e5dc3";
pub(crate) const CONVERT_WRITE: &str =
    "8bff558bec33c05050ff7514ff75106affff750c50ff7508e8430d000083c4205dc21000";
pub(crate) const WIDE_API: &str = "8bff558bec518b550853565781fae8fd0000740c81fae9fd0000740432dbeb02b301ff750c52e845ffffff33ff84db59598b4d248bf10f45f78365fc008b7d2084db0f457dfc740785c974038321005657ff751cff7518ff7514ff75105052ff15e05041005f5e5bc9c3";
pub(crate) const WIDE_FLAGS: &str = "8bff558bec8b4508b9acde00003bc1773d7479b933c400003bc1771d746e83e82a74692d02c40000746283e801745d83e801745883e803eb472d35c40000744c2d6312000074452d12080000eb2db9b1de00003bc1771374332dadde0000742c83e801742783e801eb112db2de0000741b83e80174162d351f0000740f83e801740a8b450c257fffffff5dc333c05dc3";
fn guard(at: u32, bytes: &[u8]) -> String {
    format!("let p=rt.process_image_code(inputs.image,{at},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"argv code read\")?!=&{bytes:?}{{return Err(\"argv original code changed\");}}",bytes.len(),bytes.len())
}
pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let mut out = String::new();
    let bytes = raw(MODE);
    let body = crate::crt_stream_emit::emit_body(
        &Graph::decode(&bytes, 0x401bbf)?,
        |_, _| Err("argv mode call".into()),
        &Default::default(),
        16,
    )?;
    out.push_str(&format!("fn argv_mode_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x401bbf,&bytes)));
    let bytes = raw(WRAPPER);
    let g = crate::crt_startup_table::graph(&bytes, 0x4069d4)?;
    // Tail transfer executes the same live activation, not a synthesized return.
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |_, _| Err("argv wrapper call".into()),
        &Default::default(),
        32,
        |_, _| Err("argv wrapper thread".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x4066d6),
    )?;
    let terminal = format!("if pc=={}{{return Ok(cpu.r[0]);}}", 0x4066d6);
    if !body.contains(&terminal) {
        return Err("argv tail cut missing".into());
    }
    let body = body.replace(
        &terminal,
        "if pc==0x4066d6{return argv_configure_original(rt,cpu,inputs,platform,epoch);}",
    );
    out.push_str(&format!("fn argv_configure_wrapper(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x4069d4,&bytes)));
    let bytes = raw(CONFIGURE);
    let mut g = crate::crt_startup_table::graph(&bytes[..(0x406727 - 0x4066d6)], 0x4066d6)?;
    g.nodes
        .extend(Graph::decode(&bytes[(0x40680f - 0x4066d6)..], 0x40680f)?.nodes);
    g.nodes.insert(
        0x406727,
        Node {
            length: 6,
            op: Op::Reject("argv post-image-name parsing unbound at 0x406727"),
            successors: vec![],
        },
    );
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x40b42a)=>format!("let p=platform.ok_or(\"argv locale platform unbound\")?;let e=epoch.as_deref_mut().ok_or(\"argv locale registry unbound\")?;cpu.call_activation(rt,{next},0,|rt,c|locale_startup_original(rt,c,inputs,p,e))?;"),
  Target::Direct(0x40ae0d)=>format!("let p=platform.ok_or(\"argv image-name platform unbound\")?;cpu.call_activation(rt,{next},0,|rt,c|argv_image_name_original(rt,c,inputs,p))?;"),
  Target::Direct(0x407ccd)=>"return Err(\"argv invalid-mode errno acquisition unbound\");".into(),
  Target::Direct(0x407b4f)=>"return Err(\"argv invalid-parameter effect unbound\");".into(),
  _=>return Err(format!("argv configuration target {t:?}"))})
        },
        &Default::default(),
        256,
    )?;
    out.push_str(&format!("fn argv_configure_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x4066d6,&bytes)));
    let bytes = raw(IMAGE_NAME);
    let mut g = crate::crt_startup_table::graph(&bytes[..(0x40ae99 - 0x40ae0d)], 0x40ae0d)?;
    for (pc, reason) in [
        (
            0x40ae99,
            "argv post-conversion result/epilog unbound at 0x40ae99",
        ),
        (
            0x40aea2,
            "argv failed image-name epilog unbound at 0x40aea2",
        ),
    ] {
        g.nodes.insert(
            pc,
            Node {
                length: 1,
                op: Op::Reject(reason),
                successors: vec![],
            },
        );
    }
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x40ab89)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_locale_original(rt,c,inputs,platform))?;"),
  Target::Direct(0x40ad10)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_convert_original(rt,c,inputs,platform))?;"),
  Target::Import(0x415084)=>format!("rt.process_image_import(inputs.image,0x415084,\"kernel32.dll\",\"GetModuleFileNameW\")?;cpu.call_activation(rt,{next},12,|rt,c|platform.image_name_call(rt,c,inputs.init))?;"),
  Target::Import(0x415044)=>"return Err(\"argv GetLastError failure acquisition unbound\");".into(),
  Target::Direct(0x407c71)=>"return Err(\"argv image-name error mapping unbound\");".into(),
  _=>return Err(format!("argv image-name target {t:?}"))})
        },
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        128,
    )?;
    out.push_str(&format!("fn argv_image_name_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x40ae0d,&bytes)));
    out.push_str(&locale_source()?);
    out.push_str(&conversion_source()?);
    Ok(out)
}
#[test]
fn original_mode_and_argv_prefix_keep_external_effects_unbound() {
    source().expect("actual mode/configuration and checked API prefix must lower");
}
#[test]
fn image_name_contract_preserves_units_truncation_ownership_and_unknown_tail() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 let mut cases=0;
 for text in ["/tmp/app.exe","C:\\建物\\😀 long.exe","/x/\u{0301}é"]{let units:Vec<_>=text.encode_utf16().collect();for count in 1..=(units.len()+3)as u32{for module_pointer in [false,true]{
  let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();let name=rt.publish_image_name(init,image,0x600000,text,false).unwrap();let storage=rt.map_region(0x20000,256,CrtRegionKind::Stack,None).unwrap();let output=rt.offset(storage,16).unwrap();rt.last_os_error=Some(73);if module_pointer{rt.thread+=1;}
  let got=rt.image_name_output(name,if module_pointer{CrtValue::Pointer(rt.process_image(image).unwrap())}else{CrtValue::scalar(0)},output,count).expect("valid main image contract");let copied=units.len().min(count as usize-1);assert_eq!(got,if units.len()>=count as usize{count}else{units.len()as u32});assert_eq!(rt.last_os_error,if units.len()>=count as usize{Some(122)}else{None});
  for n in 0..128{let p=rt.offset(storage,n*2).unwrap();if n>=8&&(n-8)as usize<=copied{let expected=if(n-8)as usize==copied{0}else{u32::from(units[(n-8)as usize])};assert_eq!(rt.load(p,16).unwrap(),CrtValue::scalar(expected));}else{assert!(rt.load(p,16).unwrap().known_scalar().is_err());assert_eq!(rt.memory.read(p.address(),2),Err(guest_memory::Fault::Uninitialized));}}assert_eq!(rt.image_name_bytes(name).unwrap().len(),(units.len()+1)*2);cases+=1;
 }}}
 assert_eq!(cases,86);
 for mode in 0..17{
  let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();let mut name=rt.publish_image_name(init,image,0x600000,"/test/é😀.exe",false).unwrap();let storage=rt.map_region(0x20000,512,CrtRegionKind::Stack,None).unwrap();let mut output=rt.offset(storage,32).unwrap();let mut module=CrtValue::scalar(0);let mut count=64;
  match mode{0=>count=0,1=>count=32768,2=>module=CrtValue::scalar(0x500000),3=>module=CrtValue::Scalar{bits:0,known:0},4=>{rt.memory.release(image.root.cap,image.root.owner).unwrap();},5=>{rt.memory.release(name.wide.cap,name.wide.owner).unwrap();},6=>{name.pid=name.pid.wrapping_add(1);},7=>{name.serial+=1;},8=>{output=name.wide;},9=>{output=rt.map_region(0x30000,128,CrtRegionKind::Module,None).unwrap();rt.memory.protect_data_with_old((output.cap,output.owner,output.address(),128),2,(storage.cap,storage.owner,storage.address())).unwrap();},10=>{output=rt.offset(storage,500).unwrap();},11=>{rt.closed=true;},12=>{let p=name.wide;rt.memory.protect_data_with_old((p.cap,p.owner,p.address(),p.size),4,(storage.cap,storage.owner,storage.address())).unwrap();rt.memory.write(p.address(),&[47,0]).unwrap();rt.memory.protect_data_with_old((p.cap,p.owner,p.address(),p.size),2,(storage.cap,storage.owner,storage.address())).unwrap();},13=>{name.wide.address+=2;},14=>{let p=rt.offset(storage,32).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(101)).unwrap();},15=>{let(other,oi)=CrtStreamRuntime::new_initializing(7,9,0x9000,65536).unwrap();let _=oi;let p=other.file_view;module=CrtValue::Pointer(p);},16=>{name.native=true;},_=>unreachable!()}
  rt.last_os_error=Some(73);let tags=rt.tags.clone();let result=rt.image_name_output(name,module,output,count);assert!(result.is_err(),"negative image-name mode {mode}");assert_eq!(rt.last_os_error,Some(73));assert_eq!(rt.tags,tags);assert_eq!(rt.memory.read(storage.address()+40,16),Err(guest_memory::Fault::Uninitialized));
 }
 for mode in 0..5{
  let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();if mode==0{rt.map_region(0x600000,4,CrtRegionKind::Stack,Some(&[5;4])).unwrap();}let serial=rt.serial;let regions=rt.regions.len();let text=match mode{1=>"",2=>"/a\0b",_=>"/path"};let base=if mode==3{0x600001}else{0x600000};if mode==4{rt.end_initialization(init).unwrap();}assert!(rt.publish_image_name(init,image,base,text,false).is_err());assert_eq!(rt.serial,serial);assert_eq!(rt.regions.len(),regions);assert!(rt.image_name.is_none());
 }
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();let name=rt.publish_image_name(init,image,0x600000,"/fixed",false).unwrap();rt.end_initialization(init).unwrap();assert!(rt.image_name_bytes(name).is_ok());assert!(rt.free_allocation(name.wide).is_err());assert!(rt.retire_region(name.wide).is_err());let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();assert!(other.image_name_bytes(name).is_err());
 "#,
        "image-name-contract",
    );
}
#[test]
fn native_image_name_is_actual_process_acquisition_not_supplied_text() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,262144).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();let got=rt.acquire_native_image_name(init,image,0x600000);
 #[cfg(target_os="linux")]{let name=got.expect("actual Linux native image acquisition");assert!(name.native);let path=std::env::current_exe().unwrap();let text=path.to_str().unwrap();let expected:Vec<_>=text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();assert_eq!(rt.image_name_bytes(name).unwrap(),expected);assert!(rt.acquire_native_image_name(init,image,0x700000).is_err());rt.end_initialization(init).unwrap();assert_eq!(rt.image_name_bytes(name).unwrap(),expected);}
 #[cfg(not(target_os="linux"))]{assert_eq!(got,Err("native image name acquisition unsupported host"));assert!(rt.image_name.is_none());}
 "#,
        "image-name-native",
    );
}
#[cfg(windows)]
#[test]
fn original_windows_image_name_api_matches_modern_component_contract() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 #[link(name="kernel32")]extern "system"{fn GetModuleFileNameW(module:usize,out:*mut u16,count:u32)->u32;fn SetLastError(value:u32);fn GetLastError()->u32;}
 use std::io::Write;
 let mut trace=std::env::var_os("W2L_EH4_EVIDENCE").map(|dir|std::fs::File::create(std::path::PathBuf::from(dir).join("original-windows-image-name.jsonl")).unwrap());
 let mut baseline=vec![0u16;32767];let length=unsafe{GetModuleFileNameW(0,baseline.as_mut_ptr(),32767)};assert!(length>0&&length<32767);let text=String::from_utf16(&baseline[..length as usize]).unwrap();let counts=[1,2,length,length+1,length+2,261];if let Some(out)=trace.as_mut(){writeln!(out,"{{\"kind\":\"original Windows GetModuleFileNameW API component; no PE translation\",\"arch\":{:?},\"baseline_utf16\":{:?}}}",std::env::consts::ARCH,&baseline[..length as usize]).unwrap();out.flush().unwrap();}
 for count in counts{let mut original=vec![0x5a5au16;count as usize+3];unsafe{SetLastError(73);}let result=unsafe{GetModuleFileNameW(0,original.as_mut_ptr(),count)};let last=unsafe{GetLastError()};if let Some(out)=trace.as_mut(){writeln!(out,"{{\"count\":{count},\"result\":{result},\"last_error\":{last},\"units\":{original:?}}}").unwrap();out.flush().unwrap();}let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,1048576).unwrap();let image=rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();let name=rt.publish_image_name(init,image,0x600000,&text,false).unwrap();let bytes:Vec<_>=vec![0x5a5au16;count as usize+3].into_iter().flat_map(u16::to_le_bytes).collect();let output=rt.map_region(0x20000,bytes.len()as u32,CrtRegionKind::Stack,Some(&bytes)).unwrap();let actual=rt.image_name_output(name,CrtValue::scalar(0),output,count).unwrap();assert_eq!(actual,result);for(n,&value)in original.iter().enumerate(){assert_eq!(rt.load(rt.offset(output,n as i64*2).unwrap(),16).unwrap(),CrtValue::scalar(u32::from(value)));}if count<=length{assert_eq!(last,122);assert_eq!(rt.last_os_error,Some(last));}}
 println!("six original Windows GetModuleFileNameW component observations; not PE translations");
 "#,
        "image-name-windows-api",
    );
}

fn locale_source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let mut out = String::new();
    let bytes = raw(LOCALE);
    let g = Graph::decode(&bytes, 0x40ab89)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x40aabe)=>format!("cpu.call_activation(rt,{next},4,|rt,c|locale_view_original(rt,c,inputs,platform))?;"),
  Target::Direct(0x407fc0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_file_ansi_original(rt,c,inputs,platform))?;"),
  _=>return Err("argv locale call target".into())})
        },
        &Default::default(),
        128,
        |_, _| Err("argv locale thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40aba3 {
                "let p=rt.module_word_pointer(inputs.image,cpu.r[0])?;rt.valid(p,12)?;cpu.r[0]=CrtValue::Pointer(p);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn argv_locale_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x40ab89,&bytes)));
    let bytes = raw(FILE_RESOLVE);
    let g = Graph::decode(&bytes, 0x407d96)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            if t != Target::Direct(0x407e41) {
                return Err("argv file resolver call target".into());
            }
            Ok(format!("cpu.call_activation(rt,{},0,|rt,c|startup_fiber_resolve(rt,c,inputs,Some(platform),&mut |rt,c,i,p,iat|startup_fiber_api(rt,c,i,p,iat)))?;",pc+g.nodes[&pc].length))
        },
        &BTreeMap::from([(0x41e000, "CrtRegionKind::Module".into())]),
        256,
        |_, _| Err("argv resolver thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x407d96 {
                "let cell=rt.process_image_pointer(inputs.image,0x41e000,4)?;startup_loader_cell(rt,inputs,cell,true)?;if rt.load(cell,32)?==CrtValue::scalar(u32::MAX){return Err(\"argv file API absence provenance unbound\");}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn argv_file_resolve_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x407d96,&bytes)));
    let bytes = raw(FILE_ANSI);
    let g = crate::crt_startup_table::graph(&bytes, 0x407fc0)?;
    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x407d96)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_file_resolve_original(rt,c,inputs,platform))?;"),
  Target::Import(0x415128)=>format!("let cell=rt.process_image_pointer(inputs.image,0x415128,4)?;if rt.load(cell,32)?.known_scalar()?!=0x401bf9{{return Err(\"argv file mode guard target\");}}let code=rt.process_image_code(inputs.image,0x401bf9,3)?;if rt.memory.read(code.address(),3).map_err(|_|\"argv file mode guard read\")?!=[0xc2,0,0]{{return Err(\"argv file mode guard code\");}}let CrtValue::Function(f)=cpu.r[1]else{{return Err(\"argv file mode guard provenance\");}};if cpu.r[6]!=CrtValue::Function(f)||platform.file_mode.is_none_or(|(expected,_)|expected!=f)||rt.native_named_export(inputs.init,f.module,\"AreFileApisANSI\")?!=f{{return Err(\"argv file mode guard mismatch\");}}cpu.call_activation(rt,{next},0,startup_original_guard)?;guarded=Some(f);"),
  _=>return Err("argv file API direct target".into())})
        },
        &Default::default(),
        128,
        |_, _| Err("argv file API thread".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |pc, _| {
            Ok(format!("let CrtValue::Function(f)=target else{{return Err(\"argv file mode callable provenance\");}};if guarded.take()!=Some(f){{return Err(\"argv file mode guard replay/target\");}}cpu.call_activation(rt,{},0,|rt,c|platform.file_mode_call(rt,c,inputs.init,f))?;",pc+g.nodes[&pc].length))
        },
    )?;
    out.push_str(&format!("fn argv_file_ansi_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let mut guarded=None;{}{body}}}",guard(0x407fc0,&bytes)));
    Ok(out)
}

#[cfg(windows)]
#[test]
fn original_windows_file_mode_and_utf8_conversion_observations() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 use std::io::Write;
 #[link(name="kernel32")]extern "system"{
 fn AreFileApisANSI()->i32;fn SetFileApisToANSI();fn SetFileApisToOEM();fn GetACP()->u32;fn GetOEMCP()->u32;
 fn GetModuleHandleW(name:*const u16)->usize;fn GetProcAddress(module:usize,name:*const u8)->usize;fn GetModuleHandleExW(flags:u32,address:*const u16,module:*mut usize)->i32;fn GetModuleFileNameW(module:usize,out:*mut u16,count:u32)->u32;
 fn SetLastError(value:u32);fn GetLastError()->u32;fn WideCharToMultiByte(cp:u32,flags:u32,input:*const u16,count:i32,out:*mut u8,capacity:i32,default:*const u8,used:*mut i32)->i32;
 }
 let initial=unsafe{AreFileApisANSI()};unsafe{SetFileApisToOEM()};let oem=unsafe{AreFileApisANSI()};unsafe{SetFileApisToANSI()};let ansi=unsafe{AreFileApisANSI()};unsafe{if initial==0{SetFileApisToOEM()}else{SetFileApisToANSI()}};let restored=unsafe{AreFileApisANSI()};assert_eq!(oem,0);assert_ne!(ansi,0);assert_eq!(restored!=0,initial!=0);
 let library:Vec<u16>="kernel32.dll".encode_utf16().chain(std::iter::once(0)).collect();let module=unsafe{GetModuleHandleW(library.as_ptr())};assert_ne!(module,0);let address=unsafe{GetProcAddress(module,b"AreFileApisANSI\0".as_ptr())};assert_ne!(address,0);let query:unsafe extern "system" fn()->i32=unsafe{std::mem::transmute(address)};assert_eq!(unsafe{query()}!=0,restored!=0);
 let mut owner=0;assert_ne!(unsafe{GetModuleHandleExW(6,address as *const u16,&mut owner)},0);let mut owner_name=vec![0u16;1024];let n=unsafe{GetModuleFileNameW(owner,owner_name.as_mut_ptr(),1024)};assert!(n>0&&n<1024);owner_name.truncate(n as usize);
 let mut trace=std::env::var_os("W2L_EH4_EVIDENCE").map(|dir|std::fs::File::create(std::path::PathBuf::from(dir).join("original-windows-narrow-conversion.jsonl")).unwrap());
 if let Some(out)=trace.as_mut(){writeln!(out,"{{\"kind\":\"original Windows file-mode and UTF8 API observations; no PE translation\",\"arch\":{:?},\"initial_ansi_raw\":{initial},\"oem_raw\":{oem},\"ansi_raw\":{ansi},\"restored_raw\":{restored},\"acp\":{},\"oemcp\":{},\"export_owner_utf16\":{owner_name:?}}}",std::env::consts::ARCH,unsafe{GetACP()},unsafe{GetOEMCP()}).unwrap();out.flush().unwrap();}
 let cases:&[(&str,&[u16],i32,u32,i32,i32,Option<u32>,Option<&[u8]>,bool)]=&[
("ascii-query",&[65, 0],-1,0,0,2,None,Some(&[65, 0]),false),
("unicode-query",&[233, 55357, 56832, 0],-1,0,0,7,None,Some(&[195, 169, 240, 159, 152, 128, 0]),false),
("unicode-write",&[233, 55357, 56832, 0],-1,0,7,7,None,Some(&[195, 169, 240, 159, 152, 128, 0]),false),
("positive-embedded-nul",&[65, 0, 66],3,0,3,3,None,Some(&[65, 0, 66]),false),
("valid-strict",&[233, 55357, 56832, 0],-1,128,7,7,None,Some(&[195, 169, 240, 159, 152, 128, 0]),false),
("high-replacement",&[55296, 0],-1,0,4,4,None,Some(&[239, 191, 189, 0]),false),
("low-replacement",&[56320, 0],-1,0,4,4,None,Some(&[239, 191, 189, 0]),false),
("high-strict",&[55296, 0],-1,128,8,0,Some(1113),None,false),
("low-strict",&[56320, 0],-1,128,8,0,Some(1113),None,false),
("insufficient",&[233, 55357, 56832, 0],4,0,2,0,Some(122),None,false),
("zero-input",&[65, 0],0,0,8,0,Some(87),None,false),
("invalid-flags",&[65, 0],-1,16,8,0,Some(1004),None,false),
("positive-split-pair",&[233, 55357, 56832, 0],2,0,8,5,None,Some(&[195, 169, 239, 191, 189]),false),
("minus-one-first-nul",&[65, 0, 66, 0],-1,0,8,2,None,Some(&[65, 0]),false),
("query-nonnull-output",&[65, 0],-1,0,0,2,None,Some(&[65, 0]),true)];
 let mut observed=Vec::new();
 for &(label,units,count,flags,capacity,expected,error,payload,query_nonnull)in cases{let mut bytes=vec![0x5au8;capacity as usize+4];let target=if capacity==0&&!query_nonnull{std::ptr::null_mut()}else{bytes.as_mut_ptr()};unsafe{SetLastError(73);}let result=unsafe{WideCharToMultiByte(65001,flags,units.as_ptr(),count,target,capacity,std::ptr::null(),std::ptr::null_mut())};let last=unsafe{GetLastError()};
  if let Some(out)=trace.as_mut(){writeln!(out,"{{\"label\":{label:?},\"utf16\":{units:?},\"input_count\":{count},\"flags\":{flags},\"capacity\":{capacity},\"query_nonnull\":{query_nonnull},\"result\":{result},\"last_error\":{last},\"bytes\":{bytes:?}}}").unwrap();out.flush().unwrap();}
  eprintln!("UTF8 original observation: label={label} flags={flags} capacity={capacity} result={result} last_error={last} bytes={bytes:?}");
  observed.push((label,flags,capacity,expected,error,payload,result,last,bytes));
 }
 // Collect all rows before checking conformance, so one mismatch cannot erase
 // later observations. Unsupported flags remain observation-only: the first
 // Windows run contradicted the documentation-derived invalid-flags oracle.
 for(label,flags,capacity,expected,error,payload,result,last,bytes)in observed{
  assert_eq!(&bytes[capacity as usize..],&[0x5a;4],"{label}: guard beyond API capacity");
  if matches!(flags,0|128){assert_eq!(result,expected,"{label}");if let Some(error)=error{assert_eq!(last,error,"{label}");}if capacity>0&&result>0{let payload=payload.unwrap();assert_eq!(&bytes[..payload.len()],payload,"{label}");assert!(bytes[payload.len()..].iter().all(|b|*b==0x5a),"{label}: exact output bytes");}}
  if capacity==0{assert_eq!(bytes,vec![0x5a;4]);}
 }
 "#,
        "windows-narrow-conversion",
    );
}

#[test]
fn process_file_mode_and_nonzero_bool_preserve_unknown_bits_and_lifetimes() {
    crate::crt_stream_callees_tests::native(
        crate::crt_resident_loader::TYPES,
        r#"
 let(mut rt,init)=CrtStreamRuntime::new_initializing(17,23,0x8000,131072).unwrap();let mut p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();p.enable_fls(&mut rt,init,0x720000,0x721000).unwrap();assert!(rt.native_named_export(init,p.fls.unwrap().module,"AreFileApisANSI").is_err());
 let serial=rt.serial;assert_eq!(p.enable_file_mode(&mut rt,init,"Windows7",CrtFileApiMode::Ansi),Err("native file mode profile/state"));assert_eq!(rt.serial,serial);assert!(rt.file_mode.is_none());
 p.enable_file_mode(&mut rt,init,CrtNativePlatform::FILE_MODE_PROFILE,CrtFileApiMode::Ansi).unwrap();let(f,t)=p.file_mode.unwrap();assert_eq!(rt.native_named_export(init,f.module,"AreFileApisANSI"),Ok(f));let a=rt.file_mode_result(t).unwrap();let b=rt.file_mode_result(t).unwrap();assert_ne!(a,b);assert!(a.known_scalar().is_err());assert_eq!(CrtCpu::bits(a),Ok((0,0)));assert!(CrtCpu::number(a).is_err());assert!(CrtCpu::pointer(a).is_err());
 let stack=rt.map_region(0x20000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,256).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(73)).unwrap();let mut c=CrtCpu::new(sp,73).unwrap();c.binary(&rt,8,a,a,32).unwrap();assert_eq!((c.flags.cf,c.flags.of,c.flags.zf,c.flags.sf),(Some(false),Some(false),Some(false),None));
 for bits in [1,2,256,0x80000000,u32::MAX]{assert_ne!(bits&bits,0);assert_eq!(c.flags.zf,Some(bits==0));}c.binary(&rt,8,a,b,32).unwrap();assert_eq!(c.flags.zf,None,"different TRUE results may have disjoint set bits");c.r[0]=a;assert!(c.get(0,8,0).unwrap().known_scalar().is_err());c.set(0,8,0,CrtValue::scalar(0)).unwrap();assert!(c.r[0].known_scalar().is_err());c.binary(&rt,8,c.r[0],c.r[0],32).unwrap();assert_eq!(c.flags.zf,None,"partial write cannot retain a nonzero fact");
 let data=rt.offset(stack,32).unwrap();rt.store(data,32,a).unwrap();assert_eq!(rt.load(data,32),Ok(a));assert!(rt.load(data,8).is_err());assert_eq!(rt.memory.read(data.address(),4),Err(guest_memory::Fault::Uninitialized));assert!(rt.store(data,8,CrtValue::scalar(0)).is_err());rt.store(data,32,CrtValue::scalar(0)).unwrap();assert_eq!(rt.load(data,32),Ok(CrtValue::scalar(0)));
 rt.thread+=1;assert_eq!(rt.file_mode(t),Ok(CrtFileApiMode::Ansi));rt.set_file_mode(t,CrtFileApiMode::Oem).unwrap();assert_eq!(rt.file_mode_result(t),Ok(CrtValue::scalar(0)));rt.thread-=1;assert_eq!(rt.file_mode(t),Ok(CrtFileApiMode::Oem));rt.set_file_mode(t,CrtFileApiMode::Ansi).unwrap();assert_ne!(rt.file_mode_result(t).unwrap(),a);
 let(other,_)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();assert_eq!(other.file_mode(t),Err("CRT process file mode owner/lifetime"));let forged=CrtProcessFileMode{serial:t.serial+1,..t};assert!(rt.file_mode(forged).is_err());
 let saved3=c.r[3];c.r[3]=CrtValue::scalar(91);rt.last_os_error=Some(73);let before=rt.serial;assert_eq!(p.file_mode_call(&mut rt,&mut c,init,f),Err("native file mode ABI"));assert_eq!(rt.serial,before);assert_eq!(rt.last_os_error,Some(73));assert!(!c.returned);c.r[3]=saved3;
 let result=p.file_mode_call(&mut rt,&mut c,init,f).expect("actual bound native mode call");assert!(matches!(result,CrtValue::NonZero{..}));assert!(c.returned);assert_eq!(rt.last_os_error,None);assert_eq!(p.file_mode_call(&mut rt,&mut c,init,f),Err("CRT active caller lifetime/return authority"));
 rt.provider_destroy(init,f.module).unwrap();assert!(rt.native_api_identity(f).is_err());assert_eq!(rt.file_mode(t),Ok(CrtFileApiMode::Ansi),"module unload is not a process mode reset");rt.closed=true;assert_eq!(rt.file_mode(t),Err("CRT process file mode owner/lifetime"));
 "#,
        "file-mode-bool",
    );
}

fn conversion_source() -> Result<String, String> {
    let mut out = String::new();
    for (name, at, hex) in [
        ("argv_convert_original", 0x40ad10, CONVERT),
        ("argv_convert_write_original", 0x40ab65, CONVERT_WRITE),
        ("argv_wide_original", 0x40b8c5, WIDE_API),
        ("argv_wide_flags_original", 0x40b835, WIDE_FLAGS),
    ] {
        let bytes = crate::crt_ptd::raw(hex);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |pc, target| {
                let next = pc + g.nodes[&pc].length;
                Ok(match target{
   Target::Direct(0x40b8c5)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_wide_original(rt,c,inputs,platform))?;"),
   Target::Direct(0x40b835)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_wide_flags_original(rt,c,inputs,platform))?;"),
   Target::Direct(0x40ab65)=>format!("cpu.call_activation(rt,{next},16,|rt,c|argv_convert_write_original(rt,c,inputs,platform))?;"),
   Target::Import(0x4150e0)=>format!("rt.process_image_import(inputs.image,0x4150e0,\"kernel32.dll\",\"WideCharToMultiByte\")?;cpu.call_activation(rt,{next},32,|rt,c|platform.wide_query_call(rt,c,inputs.init))?;"),
   Target::Direct(0x40add2)=>"return Err(\"argv conversion capacity/ownership growth unbound\");".into(),
   Target::Direct(0x40adf9)=>"return Err(\"argv conversion reset/free unbound\");".into(),
   Target::Import(0x415044)|Target::Direct(0x407c71)|Target::Direct(0x407ccd)=>"return Err(\"argv conversion error/errno effects unbound\");".into(),
   _=>return Err(format!("argv conversion call {target:?}"))
  })
            },
            &Default::default(),
            512,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(at,&bytes)));
    }
    Ok(out)
}

#[test]
fn utf8_queries_preserve_byte_counts_alias_domains_unknowns_and_output_memory() {
    crate::crt_stream_callees_tests::native(
        crate::crt_resident_loader::TYPES,
        r#"
 let vectors:&[(&[u16],i32,u32)]=&[(&[65,0],-1,2),(&[233,55357,56832,0],-1,7),(&[65,0,66],3,3),(&[55296,0],-1,4),(&[56320,0],-1,4),(&[233,55357,56832,0],2,5),(&[65,0,66,0],-1,2)];
 for &(units,count,expected)in vectors{let(mut rt,_)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();let source=rt.map_region(0x20000,64,CrtRegionKind::Stack,None).unwrap();for(n,&v)in units.iter().enumerate(){rt.store(rt.offset(source,n as i64*2).unwrap(),16,CrtValue::scalar(u32::from(v))).unwrap();}assert_eq!(rt.utf8_required(source,count),Ok(expected));let tail=rt.offset(source,units.len()as i64*2).unwrap();assert_eq!(rt.memory.read(tail.address(),2),Err(guest_memory::Fault::Uninitialized));}
 for mode in 0..12{let(mut rt,init)=CrtStreamRuntime::new_initializing(17,23,0x8000,131072).unwrap();let mut p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let source=rt.map_region(0x20000,64,CrtRegionKind::Stack,None).unwrap();for(n,v)in [233,55357,56832,0].into_iter().enumerate(){rt.store(rt.offset(source,n as i64*2).unwrap(),16,CrtValue::scalar(v)).unwrap();}let stack=rt.map_region(0x30000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,400).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(900+mode)).unwrap();let mut c=CrtCpu::new(sp,900+mode).unwrap();let mut args=[CrtValue::scalar(65001),CrtValue::scalar(0),CrtValue::Pointer(source),CrtValue::scalar(u32::MAX),CrtValue::scalar(0xdeadbeef),CrtValue::scalar(0),CrtValue::scalar(0),CrtValue::scalar(0)];
  if matches!(mode,1|10|11){args[0]=CrtValue::scalar(0);if mode!=10{let token=rt.publish_command_line(init,0x50000,65001,&["modeled".into()]).unwrap();p.command_line=Some(token);if mode==11{rt.memory.release(token.wide.cap,token.wide.owner).unwrap();}}}
  match mode{2=>args[1]=CrtValue::scalar(16),3=>args[0]=CrtValue::scalar(1),4=>args[5]=CrtValue::scalar(8),5=>args[6]=CrtValue::scalar(1),6=>args[3]=CrtValue::scalar(0),7=>{rt.store(source,16,CrtValue::Scalar{bits:0,known:0}).unwrap();},8=>{rt.memory.release(source.cap,source.owner).unwrap();},9=>args[1]=CrtValue::scalar(128),_=>{}}
  for v in args.into_iter().rev(){c.push(&mut rt,v).unwrap();}rt.last_os_error=Some(73);let got=c.call_activation(&mut rt,0x430000,32,|rt,c|p.wide_query_call(rt,c,init));
  if mode<=1{assert_eq!(got,Ok(CrtValue::scalar(7)));assert_eq!(c.r[4],CrtValue::Pointer(sp));assert_eq!(rt.last_os_error,None);c.finish(&mut rt).unwrap();assert!(c.returned);}
  else{assert!(got.is_err(),"query negative {mode} accepted");assert!(!c.returned);assert_eq!(rt.last_os_error,Some(73));if mode==2||mode==9{assert_eq!(got,Err("native UTF8 flags outside supported query domain"));}if mode==3{assert_eq!(got,Err("native UTF8 code-page alias unbound"));}if mode==4{assert_eq!(got,Err("native UTF8 conversion write effects unbound"));}if mode==5{assert_eq!(got,Err("native UTF8 default-character outputs unbound"));}if mode==6{assert_eq!(got,Err("native UTF8 input count outside bounded domain"));}if mode==10{assert_eq!(got,Err("native UTF8 ACP profile unbound"));}}
  assert_eq!(rt.memory.read(stack.address(),64),Err(guest_memory::Fault::Uninitialized),"query must not initialize ignored output memory");
 }
 "#,
        "utf8-query",
    );
}
