//! Independent private-adapter checks, including one retained original local
//! unwind body. These are native component executions, not PE translations.
use std::path::PathBuf;
use std::sync::OnceLock;

const CASES: &str = r#"
fn fixture()->(ThreadRegistry,FrameImage<RegistryHead>,RegistrationId,OwnedFrameBinding){
 let owner=23;let mut registry=ThreadRegistry::new(owner,0x1000,0x10000,&[(0x400000,0x420000)],0x41c000).unwrap();
 let entry_sp=0xe000;let ebp=entry_sp-4;let cookie=0x12345678;let previous=registry.head().unwrap();
 let words=std::collections::BTreeMap::from([
  (-128,FrameWord::Unknown),(-36,FrameWord::Scalar(5)),
  (-20,FrameWord::Borrowed(previous)),(-16,FrameWord::Scalar(0x4021c0)),
  (-12,FrameWord::EncodedScope{scope:0x41b000,cookie,bits:0x41b000^cookie}),
  (-8,FrameWord::Scalar(1)),(-4,FrameWord::Saved(5,None)),(0,FrameWord::Return),
 ]);
 let image=FrameImage{words,entry_sp,ebp,esp:entry_sp-128,record:ebp-16,scope_va:0x41b000,handler_va:0x4021c0,try_level:1};
 let binding=OwnedFrameBinding{owner,frame:FrameId{owner,generation:7},index:0};
 let id=registry.install_frame(binding,&image).unwrap();registry.contain(id).unwrap();(registry,image,id,binding)
}
fn entry()->LocalEntry{LocalEntry{entry_sp:0xd000,handler:0x4027b0,cookie_address:0x41c000,cookie:0x12345678,target_level:-2}}
fn rows()->[LocalScope;2]{[LocalScope{parent:-2,filter:0,handler:0x401200},LocalScope{parent:0,filter:0,handler:0x401100}]}
fn notifications(){
 let(_,_,_,binding)=fixture();let addresses=[0x41c074,0x41c078,0x41c07c];
 let mut n=NotificationState::new(23,addresses).unwrap();
 let values=[BridgeValue::Scalar(0x101),BridgeValue::Capability(DispatchCapability::Code{owner:23,frame:0,address:0x401100}),BridgeValue::Capability(DispatchCapability::Frame{owner:23,index:0,binding})];
 for(i,value)in values.iter().enumerate(){n.store(addresses[i],value).unwrap();}
 n.require(23,0,binding,0x401100,0x101).unwrap();
 assert_eq!(n.writes,addresses.into_iter().zip(values.clone()).collect::<Vec<_>>());
 let before=n.words.clone();let count=n.writes.len();
 for(address,value)in [
  (addresses[0],BridgeValue::Scalar(2)),
  (addresses[1],BridgeValue::Scalar(0x401100)),
  (addresses[1],BridgeValue::Capability(DispatchCapability::Code{owner:24,frame:0,address:0x401100})),
  (addresses[2],BridgeValue::Capability(DispatchCapability::Frame{owner:24,index:0,binding})),
  (addresses[2]+4,BridgeValue::Unknown),
 ]{assert!(n.store(address,&value).is_err());assert_eq!(n.words,before);assert_eq!(n.writes.len(),count);}
 assert!(n.require(23,0,binding,0x401104,0x101).is_err());assert!(n.require(23,1,binding,0x401100,0x101).is_err());
 let mut stale=binding;stale.frame.generation+=1;assert!(n.require(23,0,stale,0x401100,0x101).is_err());
 assert!(NotificationState::new(23,[addresses[0];3]).is_err());assert!(NotificationState::new(23,[1,4,8]).is_err());
 let mut packet=unknown_packet();packet[4]=BridgeValue::PrivateStack(-4);assert_eq!(call_return(packet.clone(),4).unwrap()[4],BridgeValue::PrivateStack(0));
 packet[4]=BridgeValue::Scalar(0);assert!(call_return(packet,4).is_err());
}
fn selected_bridge(){
 let(_,_,_,binding)=fixture();
 let notification=std::cell::RefCell::new(NotificationState::new(23,[0x41c078,0x41c074,0x41c07c]).unwrap());
 execute_selected_bridge(0,0x40135c,binding,&notification,23).unwrap();
 let state=notification.borrow();state.require(23,0,binding,0x40135c,1).unwrap();
 assert_eq!(state.writes.iter().map(|(a,_)|*a).collect::<Vec<_>>(),[0x41c078,0x41c074,0x41c07c]);
}
fn original_body(){
 let(mut registry,mut image,id,binding)=fixture();let head=registry.head().unwrap();let events=std::cell::RefCell::new(Vec::new());let rows=rows();
 registry.execute_handler(id,&mut image,|registry,image|registry.execute_local(id,image,entry(),|record,image|{
  let mut adapter=OriginalLocal{record,image,owner:23,frame:0,binding,ordinary:&[-32],scope_address:0x41b000,rows:&rows,pending:None,written:false,notified:false,
   finally:|handler,level,image:&mut FrameImage<RegistryHead>|{assert_eq!(image.try_level,if level==1{0}else{-2});events.borrow_mut().push(format!("finally:{handler:x}:{level}"));let mut m=FrameMemory::new(image,23,&[-32])?;let n=m.read_u32(-32)?;m.write_u32(-32,n*10+if level==1{3}else{7})},
   notification:|handler,reason|{assert_eq!(reason,0x101);events.borrow_mut().push(format!("notify:{handler:x}"));Ok(())}};
  assert_eq!(original_local(&mut adapter,-2,0)?,None);Ok(())
 })).unwrap();
 assert_eq!(*events.borrow(),["notify:401100","finally:401100:1","notify:401200","finally:401200:0"]);
 assert_eq!(FrameMemory::new(&mut image,23,&[-32]).unwrap().read_u32(-32).unwrap(),537);
 assert_eq!(image.try_level,-2);assert_eq!(registry.head().unwrap(),head);assert!(registry.temporary.is_empty());assert_eq!(registry.target_ready().unwrap(),id);
}
fn invalid_order(){
 for mode in 0..7 {
  let(mut registry,mut image,id,binding)=fixture();let rows=rows();let invoked=std::cell::Cell::new(false);
  let result=registry.execute_handler(id,&mut image,|registry,image|registry.execute_local(id,image,entry(),|record,image|{
   let mut a=OriginalLocal{record,image,owner:23,frame:0,binding,ordinary:&[-32],scope_address:0x41b000,rows:&rows,pending:None,written:false,notified:false,
    finally:|_,_,_:&mut FrameImage<RegistryHead>|{invoked.set(true);Ok(())},notification:|_,_|Ok(())};
   a.install_temporary(40,0x4027b0)?;a.decode_scope()?;
   match mode {
    0=>a.write_try_level(0),
    1=>a.scope_row(0).map(|_|()),
    2=>{a.scope_row(1)?;a.notify(0x401100,0x101)},
    3=>{a.scope_row(1)?;a.write_try_level(-2)},
    4=>{a.scope_row(1)?;a.write_try_level(0)?;a.invoke_finally(0x401100,1)},
    5=>{a.scope_row(1)?;a.write_try_level(0)?;a.notify(0x401100,0x101)?;a.invoke_finally(0x401104,1)},
    _=>{a.scope_row(1)?;a.write_try_level(0)?;a.notify(0x401100,0x101)?;a.invoke_finally(0x401100,0)},
   }
  }));assert!(result.is_err());assert!(!invoked.get());assert_eq!(image.try_level,if mode>=4{0}else{1});assert_eq!(registry.temporary.len(),1);assert!(!registry.temporary[0].restored);
 }
}
fn binding_failures(){
 for mode in 0..4 {
  let(mut registry,mut image,id,binding)=fixture();let rows=rows();
  let result=registry.execute_handler(id,&mut image,|registry,image|registry.execute_local(id,image,entry(),|record,image|{
   let mut bad=binding;if mode==0{bad.frame.generation+=1;}if mode==1{bad.owner=24;}
   let mut a=OriginalLocal{record,image,owner:23,frame:0,binding:bad,ordinary:&[-32],scope_address:if mode==2{0x41b004}else{0x41b000},rows:&rows,pending:None,written:false,notified:false,
    finally:|_,_,_:&mut FrameImage<RegistryHead>|Err("must not execute"),notification:|_,_|Err("must not execute")};
   a.install_temporary(40,0x4027b0)?;
   if mode==3{a.image.words.insert(-12,FrameWord::Bytes([Some(0);4]));}
   a.decode_scope()
  }));assert!(result.is_err());assert_eq!(image.try_level,1);assert!(registry.temporary[0].installed&&!registry.temporary[0].restored);
 }
}
fn failure_effects(){
 for fail_notify in [true,false]{
  let(mut registry,mut image,id,binding)=fixture();let rows=rows();let notifications=std::cell::Cell::new(0);let invoked=std::cell::Cell::new(false);
  let result=registry.execute_handler(id,&mut image,|registry,image|registry.execute_local(id,image,entry(),|record,image|{
   let mut a=OriginalLocal{record,image,owner:23,frame:0,binding,ordinary:&[-32],scope_address:0x41b000,rows:&rows,pending:None,written:false,notified:false,
    finally:|_,_,image:&mut FrameImage<RegistryHead>|{invoked.set(true);FrameMemory::new(image,23,&[-32])?.write_u32(-32,99)?;Err("finally fault")},
    notification:|_,_|{notifications.set(notifications.get()+1);if fail_notify{Err("notification fault")}else{Ok(())}}};
   original_local(&mut a,-2,0)
  }));assert_eq!(result.unwrap_err(),if fail_notify{"notification fault"}else{"finally fault"});
  assert_eq!(notifications.get(),1);assert_eq!(invoked.get(),!fail_notify);assert_eq!(image.try_level,0);
  assert_eq!(FrameMemory::new(&mut image,23,&[-32]).unwrap().read_u32(-32).unwrap(),if fail_notify{5}else{99});
  assert_eq!(registry.head,RegistryHead::Owned(registry.temporary[0].id));assert!(registry.frames[0].live);assert!(registry.frames[0].completion.is_none());assert!(registry.target_ready().is_err());
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"notifications"=>notifications(),"selected"=>selected_bridge(),"original"=>original_body(),"order"=>invalid_order(),"binding"=>binding_failures(),"failures"=>failure_effects(),_=>panic!("unknown test")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        // Retained authored PE SHA-256 55a2435e8800b54f81c20b55373b56206
        // c24bdeeeadc9580bb39b80bf5e04ce5, RVA 2710..27b0. This literal
        // tests actual original instructions; expected traces above are authored
        // separately, including a different table and initial scalar value.
        let hex="5356578b5424108b4424148b4c2418555250515168b027400064ff3500000000a100c0410033c489442408648925000000008b4424308b58088b4c242c33198b700c83fefe0f84460000008b54243483fafe74083bf20f86350000008d34768d5cb3108b0b89480c837b04000f85c0ffffff68010100008b4308e8a1020000b9010000008b4308e8b4020000e9a1ffffff648f050000000083c4185f5e5bc3cc";
        let bytes: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        let proof = super::super::local_unwind::prove(
            &bytes,
            0x402710,
            super::super::local_unwind::Kind::Body,
            &super::super::local_unwind::Bindings {
                body: 0x402710,
                nested_handler: 0x4027b0,
                cookie: 0x41c000,
                notify: 0x402a30,
                invoke: 0x402a50,
                check_cookie: 0x401990,
            },
        )
        .unwrap();
        let mut source = String::from("#![allow(dead_code,unused_assignments)]\n");
        source.push_str(&include_str!("linker/unwind_runtime.rs").replace("//!", "//"));
        source.push_str(super::super::frame_proof::EMITTED_TYPES);
        source.push_str(super::super::frame_memory::EMITTED_TYPES);
        source.push_str(super::super::thread_registry::EMITTED_TYPES);
        source.push_str(super::super::local_unwind::EMITTED_TYPES);
        source.push_str(super::super::unwind_bridges::EMITTED_TYPES);
        source.push_str(super::EMITTED_TYPES);
        let parse_hex = |hex: &str| {
            (0..hex.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let notification = super::super::unwind_bridges::prove_notification(
            &parse_hex("5351bb70c041008b4c240c894b08894304896b0c55515058595d595bc20400"),
            0x402a30,
            super::super::unwind_bridges::NotificationBinding {
                action_word: 0x41c078,
                target_word: 0x41c074,
                frame_word: 0x41c07c,
            },
        )
        .unwrap();
        let selected = super::super::unwind_bridges::prove_selected(
            &parse_hex("8bea8bf18bc16a01e80302000033c033db33c933d233ffffe6"),
            0x402820,
            0x402a30,
            &notification,
        )
        .unwrap();
        source.push_str(&format!("fn original_notification(registers:&DispatchPacket,argument:&BridgeValue<DispatchCapability>,mut store:impl FnMut(u32,&BridgeValue<DispatchCapability>)->Result<(),&'static str>)->Result<BridgeExit<DispatchCapability>,&'static str>{{type T=DispatchCapability;{}}}\n",notification.body()));
        source.push_str(&format!("fn original_selected_bridge(registers:&DispatchPacket,mut invoke:impl FnMut(BridgeCall,&BridgeValue<DispatchCapability>,&DispatchPacket,&[BridgeValue<DispatchCapability>],Option<u32>)->Result<BridgeReply<DispatchCapability>,&'static str>)->Result<BridgeExit<DispatchCapability>,&'static str>{{type T=DispatchCapability;{}}}\n",selected.body()));
        // Compile the production adapter template itself, not a second copy of
        // its stack-rebasing logic. Full Bundle composition is tested elsewhere.
        let adapter = include_str!("dispatch_support.rs")
            .split_once("fn execute_selected_bridge(")
            .unwrap()
            .1
            .split_once("fn execute_original_finally(")
            .unwrap()
            .0;
        source.push_str("fn execute_selected_bridge(");
        source.push_str(
            &adapter
                .replace("{notification_va}", "0x402a30")
                .replace("{{", "{")
                .replace("}}", "}"),
        );
        source.push_str(&format!("fn original_local(effects:&mut impl LocalUnwindEffects,target_level:i32,exception_flags:u32)->Result<Option<i32>,&'static str>{{{}}}\n",proof.source));
        source.push_str(CASES);
        let dir = std::env::temp_dir()
            .join(format!("w2l-dispatch-execution-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("main.rs");
        std::fs::write(&path, source).unwrap();
        let binary = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        let output = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(path)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        binary
    });
    let output = std::process::Command::new(binary)
        .arg(case)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn typed_notification_words_preserve_original_values_and_reject_aliases() {
    run("notifications");
}
#[test]
fn original_local_body_uses_live_registry_and_frame_memory() {
    run("original");
}
#[test]
fn original_selected_notification_rebases_callee_stack_to_caller() {
    run("selected");
}
#[test]
fn parent_notification_and_finally_order_cannot_be_skipped() {
    run("order");
}
#[test]
fn exact_private_frame_binding_and_encoded_scope_are_required() {
    run("binding");
}
#[test]
fn notification_and_finally_failures_preserve_preceding_original_effects() {
    run("failures");
}
