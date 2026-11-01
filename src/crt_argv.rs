//! Original mode and argument-configuration prefix. No synthesized argv.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const MODE: &str = "33c040c3";
pub(crate) const WRAPPER: &str = "8bff558bec5de9f7fcffff";
pub(crate) const CONFIGURE: &str = "8bff558bec83ec0c578b7d0885ff750733c0e9230100005683ff02741b83ff017416e8d01500006a165e8930e8481400008bc6e90101000053e8164d00006804010000bb40cd410033f65356e8e6460000891d64ce410083c40c8b1d74ce410085db7405803b007505bb40cd41008d45f48975fc508d45fc8975f450565653e8b90000006a01ff75f4ff75fce81e0200008bf083c42085f6750ce8581500006a0c5e8930eb2f8d45f4508d45fc508b45fc8d0486505653e88100000083c41483ff01751c8b45fc4889356cce4100a368ce410033f66a00e89e1500008bc6eb578d45f833db5056895df8e8404500008bf8595985ff740aff75f8e87b150000eb2a8b55f88bcb8bc2391a74088d400441391875f853890d68ce4100895df889156cce4100e8511500008bfb5956895df8e8451500008bc7595b5e5fc9c3";
pub(crate) const IMAGE_NAME: &str = "8bff558bec81ec2c020000a100c0410033c58945fc8b45088d8df0fdffff68050100005150ff158450410085c07511ff154450410050e829ceffff5933c0eb558b4d0c8b451083a5e4fdffff00898dd4fdffff8985d8fdffff898ddcfdffff8985e0fdffffc685e8fdffff00e80bfdffff508d85effdffff508d85d4fdffff508d85f0fdffff50e877feffff8b85e4fdffff83c4108b4dfc33cde8a066ffffc9c3";
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
    let mut g = crate::crt_startup_table::graph(&bytes[..(0x40ae79 - 0x40ae0d)], 0x40ae0d)?;
    for (pc, reason) in [
        (
            0x40ae79,
            "argv original narrow-conversion locale unbound at 0x40ae79",
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
  Target::Import(0x415084)=>format!("rt.process_image_import(inputs.image,0x415084,\"kernel32.dll\",\"GetModuleFileNameW\")?;cpu.call_activation(rt,{next},12,|rt,c|platform.image_name_call(rt,c,inputs.init))?;"),
  Target::Import(0x415044)=>"return Err(\"argv GetLastError failure acquisition unbound\");".into(),
  Target::Direct(0x407c71)=>"return Err(\"argv image-name error mapping unbound\");".into(),
  _=>return Err(format!("argv image-name target {t:?}"))})
        },
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        128,
    )?;
    out.push_str(&format!("fn argv_image_name_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x40ae0d,&bytes)));
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
