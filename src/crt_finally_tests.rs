//! Component assembly from unchanged authored PE bytes. Entry CPU, initial
//! trace and private callback scratch are explicit component inputs.
use std::collections::{BTreeMap, BTreeSet};
fn bytes(name: &str, hex: &str) -> Vec<u8> {
    if let Ok(root) = std::env::var("W2L_EH4_CODE") {
        return std::fs::read(std::path::Path::new(&root).join(name)).unwrap();
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) fn emit() -> String {
    let prolog=bytes("Inner-prolog.bin","558bec6afe68d0b14100681022400064a1000000005083ec10535657a100c041003145f833c5508d45f064a300000000");
    let init = bytes(
        "inner-scalar-init.bin",
        "c745e464000000c745e000000000c745fc00000000c745fc01000000",
    );
    let complete = [prolog, init].concat();
    let frame = crate::frame_proof::prove_frame(
        &complete,
        0x4010c0,
        0x41c000,
        &BTreeSet::from([0x41b1d0]),
        &BTreeSet::from([0x402210]),
    )
    .unwrap();
    assert_eq!(
        frame.scalar_words(),
        &BTreeMap::from([(-32, 0), (-28, 100)])
    );
    assert_eq!(frame.try_level(), 1);
    let main=bytes("main-prolog.bin","558bec6afe6818b24100681022400064a1000000005081c404fdffffa100c041003145f833c58945e4535657508d45f064a300000000");
    let main = crate::frame_proof::prove_frame(
        &main,
        0x401280,
        0x41c000,
        &BTreeSet::from([0x41b218]),
        &BTreeSet::from([0x402210]),
    )
    .unwrap();
    assert!(!main.ordinary_words().contains(&-28)); // Main's guard is not Inner's local.
    let table = bytes(
        "finally-dispatch-table.bin",
        "0100000000104000ffffffff20104000ffffffff40104000",
    );
    let rows = table
        .chunks_exact(8)
        .map(|r| {
            (
                i32::from_le_bytes(r[..4].try_into().unwrap()),
                u32::from_le_bytes(r[4..].try_into().unwrap()),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(rows, [(1, 0x401000), (-1, 0x401020), (-1, 0x401040)]);
    let dispatch=bytes("finally-dispatch.bin","83ec08538b5c2410578b3b83ff027744a148c94100568b74241c8944240c8b06894424108d44240c508b04fd84514100ffd08b44241083c404a348c941008b44241089068b04fd805141005e5f89035b83c408c36a5bff1504504100cc");
    let scope = bytes(
        "Inner-scope-table.bin",
        "feffffff00000000d0ffffff00000000feffffff000000007f11400000000000000000006e114000",
    );
    let mut out = String::from(crate::funclet::LIVE_EFFECTS);
    out.push_str(crate::crt_finally_fields::EMITTED_TYPES);
    out.push_str(&format!("fn older_entry_cut(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:RegistryHead)->RegistryResult<FrameImage<RegistryHead>>{{{}}}",frame.initializer_body()));
    out.push_str(&crate::crt_owned_frame::emit_initializer(
        &frame,
        "initialize_inner_scalars_owned",
    ));
    let guard=bytes("original-guard-validator.bin","558bec568b7508578b7d0c8b0683f8fe740d8b4e0403cf330c38e85df3ffff8b46088b4e0c03cf330c385f5e5de94af3ffff");
    let security = bytes(
        "original-security-check.bin",
        "3b0d00c041007501c3e97c020000",
    );
    let proof = crate::handler_guard::prove_guard(
        &guard,
        0x4021d0,
        &security,
        0x40154c,
        0x41c000,
        [-2, 0, -48, 0],
        &frame,
    )
    .unwrap();
    out.push_str(&proof.owned_call("original_inner_guard_call"));
    let mut regions = vec![
        (0x4010c0, complete),
        (0x401060, dispatch.clone()),
        (0x415180, table),
        (0x41b1d0, scope),
        (0x4021d0, guard),
        (0x40154c, security),
    ];
    let globals = BTreeMap::from([(0x41c94c, 0usize), (0x41c958, 1)]);
    for (name, at, hex) in [
        (
            "inner-finally-1",
            0x40116e,
            "8d45e4508d45e050e8e5feffff83c408c3",
        ),
        (
            "inner-finally-0",
            0x40117f,
            "8d45e4508d45e050e8d4feffff83c4088b45e4a34cc941008b45e0a358c94100c3",
        ),
    ] {
        let code = bytes(&format!("{name}.bin"), hex);
        let p = crate::funclet::prove_funclet(&code, at, 0x401060, frame.scalar_words(), &globals)
            .unwrap();
        assert_eq!((p.local_offset, p.cursor_offset), (-28, -32));
        assert!(
            crate::funclet::prove_funclet(&code, at, 0x401060, main.scalar_words(), &globals)
                .is_err()
        );
        out.push_str(&format!("fn live_funclet_{at}(effects:&mut impl LiveFinallyEffects<Error=&'static str>)->RegistryResult<()>{{{}}}",p.live_source));
        regions.push((at, code));
    }
    for entry in 0..3 {
        let p = crate::dispatch::prove_dispatch(
            &dispatch,
            0x401060,
            0x415180,
            &rows,
            0x41c948,
            &BTreeMap::from([(0x401000, 0), (0x401020, 1), (0x401040, 2)]),
            entry,
        )
        .unwrap();
        out.push_str(&format!("fn live_dispatch_{entry}(effects:&mut impl LiveFinallyEffects<Error=&'static str>)->RegistryResult<()>{{{}}}",p.live_source));
    }
    out.push_str("fn finally_original_regions()->Vec<(u32,&'static[u8])>{vec![");
    for (at, code) in regions {
        out.push_str(&format!("({at},&{code:?}),"));
    }
    out.push_str("]}");
    for (name, at, hex) in [
        ("handler_saved_entry", 0x402210, "558bec83ec1c538b5d085657"),
        ("handler_disposition_init", 0x402222, "c745f401000000"),
        ("handler_original_epilog", 0x4022e0, "8b45f45f5e5b8be55dc3"),
    ] {
        let code = bytes(&format!("{name}.bin"), hex);
        let graph = if name == "handler_original_epilog" {
            crate::crt_stream_ir::Graph::decode(&code, at)
        } else {
            crate::crt_stream_ir::Graph::decode_linear_fragment(&code, at)
        }
        .unwrap();
        let body = if name != "handler_original_epilog" {
            crate::crt_stream_emit::emit_linear_fragment(&graph, &Default::default()).unwrap()
        } else {
            crate::crt_stream_emit::emit_body(
                &graph,
                |_, _| Err("handler boundary has no imports".into()),
                &Default::default(),
                32,
            )
            .unwrap()
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{let p=rt.resolve_absolute({at},CrtRegionKind::Module)?;for(i,b)in {code:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err(\"handler boundary bytes changed\");}}}}{body}}}fn map_{name}(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region({at},{},CrtRegionKind::Module,Some(&{code:?}))?;Ok(())}}",code.len()));
    }
    out.push_str(BACKEND);
    out
}
const BACKEND: &str = r#"
struct FinallyBackend<'a,'r>{rt:&'a mut CrtStreamRuntime,record:&'a mut LocalRecord<'r>,machine:&'a Machine,storage:&'a mut CrtOwnedStorage,fields:CrtFinallyFields,fault:usize}
impl FinallyBackend<'_,'_>{
 fn validate(&mut self)->RegistryResult<()>{self.record.validate_binding(self.storage.binding,&self.storage.image)?;self.fields.validate(self.rt,self.record.registry,self.machine,self.storage)}
}
impl LiveFinallyEffects for FinallyBackend<'_,'_>{
 type Error=&'static str;
 fn require_cursor(&mut self,n:i32)->RegistryResult<()>{if self.read_cursor()?!=n{self.fields.failed=true;return Err("finally live cursor path");}Ok(())}
 fn read_cursor(&mut self)->RegistryResult<i32>{self.validate()?;self.fields.read_cursor(self.rt,self.record.registry,self.machine,self.storage)}
 fn write_cursor(&mut self,n:i32)->RegistryResult<()>{self.validate()?;self.fields.write_cursor(self.rt,self.record.registry,self.machine,self.storage,n)}
 fn read_cell(&mut self,i:usize)->RegistryResult<u32>{self.validate()?;self.fields.read(self.rt,self.record.registry,self.machine,self.storage,i)}
 fn write_cell(&mut self,i:usize,v:u32)->RegistryResult<()>{self.validate()?;if self.fault==4&&i==1{return Err("independent failure after trace store");}self.fields.write(self.rt,self.record.registry,self.machine,self.storage,i,v)}
 fn write_global(&mut self,i:usize,v:u32)->RegistryResult<()>{self.validate()?;if self.fault==5&&i==1{return Err("independent failure after first global store");}self.fields.write_global(self.rt,self.record.registry,self.machine,self.storage,i,v)}
 fn dispatch(&mut self)->RegistryResult<()>{self.validate()?;match self.read_cursor()?{0=>live_dispatch_0(self),1=>live_dispatch_1(self),2=>live_dispatch_2(self),_=>Err("unproved dispatcher cursor")}}
 fn cleanup(&mut self,action:usize,private:&mut[u32;2])->RegistryResult<()>{
  self.validate()?;
  // Independent component ABI cut: checked private pair, disjoint from the
  // parent fields, temporary registration, protected returns and call scratch.
  let pair=self.rt.resolve_absolute(0x9600,CrtRegionKind::Stack)?;
  let sp=self.rt.resolve_absolute(0x9500,CrtRegionKind::Stack)?;
  for (p,n) in [(pair,8),(self.rt.offset(sp,-8)?,12)]{
   self.rt.valid(p,n)?;let high=u64::from(p.address())+u64::from(n);
   if high>u64::from(self.storage.image.esp)||self.record.registry.temporary.iter().any(|t|u64::from(p.address())<t.high&&u64::from(t.low)<high)||!self.rt.overlapping_tags(p.address(),n).is_empty(){return Err("finally private scratch alias");}
  }
  self.rt.store(pair,32,CrtValue::scalar(private[0]))?;self.rt.store(self.rt.offset(pair,4)?,32,CrtValue::scalar(private[1]))?;
  self.rt.store(sp,32,CrtValue::ProtectedReturn(945))?;let mut cpu=CrtCpu::new(sp,945)?;cpu.push(self.rt,CrtValue::Pointer(pair))?;
  cpu.call_activation(self.rt,0x40109c,0,|rt,child|match action{0=>original_cleanup_4198400(rt,child),1=>original_cleanup_4198432(rt,child),2=>original_cleanup_4198464(rt,child),_=>Err("unbound original cleanup")})?;
  if self.fault==6{return Err("independent failure after private cleanup writes");}
  cpu.discard(self.rt,4)?;self.rt.consume_stack(sp,CrtValue::ProtectedReturn(945))?;
  for(i,v)in private.iter_mut().enumerate(){let p=self.rt.offset(pair,i as i64*4)?;let value=self.rt.load(p,32)?;*v=value.known_scalar()?;self.rt.consume_stack(p,value)?;}
  Ok(())
 }
}
fn map_finally_original(rt:&mut CrtStreamRuntime)->RegistryResult<()>{
 for(at,b)in finally_original_regions(){rt.map_region(at,b.len()as u32,CrtRegionKind::Module,Some(b))?;}
 for at in [0x41c948,0x41c94c,0x41c958]{rt.map_region(at,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;}Ok(())
}
fn original_finally_effects(rt:&mut CrtStreamRuntime,record:&mut LocalRecord<'_>,m:&Machine,s:&mut CrtOwnedStorage,target:u32,fault:usize)->RegistryResult<()>{
 record.validate_binding(s.binding,&s.image)?;require_original_notification(rt,s,target,0x101)?;
 if s.image.scope_va!=0x41b1d0{return Err("finally parent proof mismatch");}
 let trace=rt.resolve_absolute(0x41c948,CrtRegionKind::Module)?;
 let mut globals=[0x41c94c,0x41c958].into_iter().map(|at|rt.resolve_absolute(at,CrtRegionKind::Module)).collect::<RegistryResult<Vec<_>>>()?;
 let mut trace=trace;let mut local=-28;let mut cursor=-32;
 if fault==13{globals[1]=globals[0];}
 if fault==14{trace=rt.resolve_absolute(0x401060,CrtRegionKind::Module)?;}
 if fault==15{trace=rt.resolve_absolute(0x41b1d0,CrtRegionKind::Module)?;}
 if fault==16{cursor=local;}
 if fault==17{local=-48;}
 if fault==18{trace=rt.resolve_absolute(0x41c000,CrtRegionKind::Module)?;}
 if fault==19{let mut foreign=CrtStreamRuntime::new(rt.owner,rt.thread,0x8000,65536)?;trace=foreign.map_region(0x41c948,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;}
 let fields=CrtFinallyFields::bind(rt,record.registry,m,s,local,cursor,trace,globals,&finally_original_regions())?;
 let mut effects=FinallyBackend{rt,record,machine:m,storage:s,fields,fault};
 let result=match target{0x40116e=>live_funclet_4198766(&mut effects),0x40117f=>live_funclet_4198783(&mut effects),_=>Err("unbound original finally")};
 if result.is_err(){effects.fields.failed=true;assert!(effects.read_cursor().is_err());}result
}
"#;

pub(crate) const CASES: &str = r#"
fn live_finally_cases(){
 for mode in 0..38{
  let mut m=Machine::new_dispatch_known((0..if mode>=31{2}else{1}).map(|_|FrameSpec{scopes:vec![]}).collect(),0,[None;10],Some(0)).unwrap();let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);
  let older=if mode>=31{let b=m.owned_binding(0).unwrap();let image=older_entry_cut(0xe800,0x12345678,[None;8],r.head().unwrap()).unwrap();Some(r.install_frame(b,&image).unwrap())}else{None};
  let sp=rt.resolve_absolute(0xe000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(71)).unwrap();let c=CrtCpu::new(sp,71).unwrap();let binding=m.owned_binding(if mode>=31{1}else{0}).unwrap();
  let mut storage=initialize_inner_scalars_owned(&mut rt,&mut r,&m,binding,&c).unwrap();m.issue_owned_event(binding).unwrap();r.contain(older.unwrap_or(storage.id)).unwrap();let id=storage.id;
  map_handler_saved_entry(&mut rt).unwrap();map_handler_disposition_init(&mut rt).unwrap();map_handler_original_epilog(&mut rt).unwrap();map_finally_original(&mut rt).unwrap();map_original_cleanups(&mut rt).unwrap();map_original_notification(&mut rt).unwrap();
  let nested=original_nested_handler_bytes();rt.map_region(0x4027b0,nested.len()as u32,CrtRegionKind::Module,Some(&nested)).unwrap();
  let trace=rt.resolve_absolute(0x41c948,CrtRegionKind::Module).unwrap();let local=rt.resolve_absolute(storage.image.ebp-28,CrtRegionKind::Stack).unwrap();let cursor=rt.resolve_absolute(storage.image.ebp-32,CrtRegionKind::Stack).unwrap();
  let seed=if mode==1{u32::MAX}else{5};rt.store(trace,32,CrtValue::scalar(seed)).unwrap();
  if mode==2{rt.store(rt.resolve_absolute(0x40117f,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
  if mode==3{rt.store(rt.resolve_absolute(0x415180,CrtRegionKind::Module).unwrap(),32,CrtValue::scalar(2)).unwrap();}
  if mode==7{rt.store(local,32,CrtValue::Pointer(trace)).unwrap();}
  if mode==8{rt.store(cursor,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
  if mode==9{rt.store(rt.resolve_absolute(0x9600,CrtRegionKind::Stack).unwrap(),32,CrtValue::ProtectedReturn(999)).unwrap();}
  if mode==10{rt.store(rt.resolve_absolute(storage.image.ebp-48,CrtRegionKind::Stack).unwrap(),32,CrtValue::scalar(0)).unwrap();}
  if mode==11{rt.store(rt.resolve_absolute(0x401020,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
  let rows=[LocalScope{parent:-2,filter:0,handler:0x40117f},LocalScope{parent:0,filter:0,handler:0x40116e}];
  let result=r.execute_handler(id,&mut storage,|r,s|{
   let sp=rt.resolve_absolute(0x9800,CrtRegionKind::Stack)?;rt.store(sp,32,CrtValue::ProtectedReturn(946))?;
   let mut cpu=CrtCpu::new(sp,946)?;let exception=rt.map_region(0x7000,80,CrtRegionKind::Context,Some(&[0;80]))?;rt.store(rt.offset(sp,4)?,32,CrtValue::Pointer(exception))?;
   handler_saved_entry(&mut rt,&mut cpu)?;handler_disposition_init(&mut rt,&mut cpu)?;assert_eq!(cpu.steps,8);assert!(!cpu.returned);cpu.validate_active(&rt)?;
   r.execute_local(id,s,LocalEntry{entry_sp:0xc000,handler:0x4027b0,cookie_address:0x41c000,cookie:0x12345678,target_level:-2},|record,s|{
   let mut effects=CrtOwnedLocalEffects{rt:&mut rt,record,machine:&m,storage:s,rows:&rows,temporary:None,pending:None,written:false,notified:false,
    notification:|target,reason,rt:&mut CrtStreamRuntime,s:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>|{cpu.validate_active(rt)?;fixture_notify_invoke(rt,s,record,target,reason,0)},
    finally:|target,_,rt:&mut CrtStreamRuntime,s:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>|{
     cpu.validate_active(rt)?;
     if mode==12{let old=s.event;s.event+=1;let result=original_finally_effects(rt,record,&m,s,target,0);s.event=old;return result;}
     original_finally_effects(rt,record,&m,s,target,if mode>=20{0}else{mode})?;
     if mode==36{rt.consume_stack(sp,CrtValue::ProtectedReturn(946))?;}
     if mode==37{rt.store(rt.resolve_absolute(0x9900,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(946))?;}
     Ok(())
    }};owned_original_local(&mut effects,-2,0).map(|_|())
  }).and_then(|_|{
   if mode==20{let at=rt.resolve_absolute(s.image.ebp-48,CrtRegionKind::Stack)?;rt.store(at,32,CrtValue::scalar(0))?;}
   if mode==21{rt.store(rt.resolve_absolute(0x40154c,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
   cpu.validate_active(&rt)?;
   if mode==22{rt.store(rt.resolve_absolute(0x9900,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(946))?;}
   if mode==23{rt.consume_stack(sp,CrtValue::ProtectedReturn(946))?;}
   for(at,b)in finally_original_regions(){let at=rt.resolve_absolute(at,CrtRegionKind::Module)?;for(i,expected)in b.iter().enumerate(){if rt.load(rt.offset(at,i as i64)?,8)?.known_scalar()?!=u32::from(*expected){return Err("postcleanup original code changed");}}}
   let mut view=CrtOwnedFrameView{rt:&mut rt,registry:r,machine:&m,storage:s,search_storage:None,search:false,active:946,depth:0,calls:0,failed:false};
   if mode>=24{view.call(&mut cpu,0x40226e,|view,child|{
    if mode==25{let alias=view.rt.resolve_absolute(0x9900,CrtRegionKind::Stack)?;view.rt.store(alias,32,CrtValue::ProtectedReturn(child.return_id))?;}
    original_inner_guard_call(view,child,0x40226e)?;child.finish(view.rt)
   })?;}
   original_inner_guard_call(&mut view,&mut cpu,0x40226e)?;
   // Guard completion restores its own call stack, leaving the actual handler
   // saves live for the original epilog. No supplied packet replaces POPs.
   let bp=CrtCpu::pointer(cpu.r[5])?;
   if mode==26{rt.store(rt.offset(bp,-36)?,32,CrtValue::scalar(0))?;}
   if mode==27{rt.store(rt.resolve_absolute(0x4022e0,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
   if mode==28{rt.store(rt.offset(bp,-12)?,32,CrtValue::Scalar{bits:0,known:0})?;}
   if mode==29{rt.store(rt.offset(bp,-12)?,32,CrtValue::scalar(2))?;}
   if mode==30{rt.store(rt.resolve_absolute(0x9900,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(946))?;}
   if rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{return Err("handler epilog return alias");}
   let disposition=handler_original_epilog(&mut rt,&mut cpu)?.known_scalar()?;
   if disposition>1{return Err("unsupported handler disposition");}
   assert!(cpu.returned);assert_eq!(disposition,1);assert_eq!(cpu.r[4],CrtValue::Pointer(rt.offset(sp,4)?));assert_eq!(cpu.r[5],cpu.entry[5]);Ok(CrtHandlerExit{anchor:rt.anchor,id:s.id,event:m.event,disposition,completion_generation:r.generation.checked_add(1).ok_or("handler completion generation overflow")?})
  })});
  let read=|rt:&CrtStreamRuntime,p|rt.load(p,32).unwrap().known_scalar().unwrap();
  if mode<=1||mode==24||(31..=35).contains(&mode){let(mut exit,completion)=result.unwrap();if mode>=31{
    if mode==32{exit.event+=1;}if mode==33{exit.disposition=0;}if mode==34{m.current=0;}if mode==35{exit.completion_generation-=1;}
    let retired=storage.retire_completed(&mut rt,&mut r,&mut m,completion,exit);
    if mode==31{retired.unwrap();assert_eq!(r.target_ready().unwrap(),older.unwrap());assert!(!m.frames[1].live);assert!(rt.load(sp,32).unwrap().known_scalar().is_err());assert!(storage.validate_storage(&rt,&r,&m).is_err());let mut expired=c;assert!(expired.finish(&mut rt).is_err());}else{assert!(retired.is_err());assert!(m.frames[1].live);assert!(r.frames[1].linked);assert!(r.available().is_err());}
    continue;
   }else{assert!(r.retire_frame(completion,&storage.image).is_err());}let expected=if mode==1{0xffffff12}else{1298};assert_eq!(read(&rt,trace),expected);assert_eq!(read(&rt,local),118);assert_eq!(read(&rt,cursor),u32::MAX);assert_eq!(read(&rt,rt.resolve_absolute(0x41c94c,CrtRegionKind::Module).unwrap()),118);assert_eq!(read(&rt,rt.resolve_absolute(0x41c958,CrtRegionKind::Module).unwrap()),u32::MAX);assert_eq!(storage.image.try_level,-2);assert!(r.temporary.is_empty());}
  else{assert!(result.is_err(),"finally case {mode}");assert!(r.available().is_err());assert!(r.frames.last().unwrap().completion.is_none());
   if mode>=36{assert_eq!(read(&rt,trace),81);assert_eq!(read(&rt,local),107);assert_eq!(read(&rt,cursor),1);assert!(r.frames.last().unwrap().live);}else if mode>=20{assert_eq!(read(&rt,trace),1298);assert_eq!(read(&rt,local),118);assert_eq!(storage.image.try_level,-2);assert!(r.temporary.is_empty());}
   if mode==4{assert_eq!(read(&rt,trace),81);assert_eq!(read(&rt,local),100);assert_eq!(read(&rt,cursor),0);}
   if mode==5{assert_eq!(read(&rt,trace),1298);assert_eq!(read(&rt,local),118);assert_eq!(read(&rt,cursor),u32::MAX);assert_eq!(read(&rt,rt.resolve_absolute(0x41c94c,CrtRegionKind::Module).unwrap()),118);assert_eq!(read(&rt,rt.resolve_absolute(0x41c958,CrtRegionKind::Module).unwrap()),0);}
   if mode==6{assert_eq!(read(&rt,trace),5);assert_eq!(read(&rt,local),100);assert_eq!(read(&rt,rt.resolve_absolute(0x9600,CrtRegionKind::Stack).unwrap()),81);}
   if mode==11{assert_eq!(read(&rt,trace),81);assert_eq!(read(&rt,local),107);assert_eq!(read(&rt,cursor),1);}
  }
  assert_eq!(m.phase,Phase::Cleanup);assert!(m.restore_owned(0x40135c,|_,_|panic!("finally is not restoration")).is_err());
 }
}
"#;
