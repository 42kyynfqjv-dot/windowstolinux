//! Original helper/epilog instructions with a live registry and shared storage.
//! Body effects and the completed-event fixture are explicit component inputs.
use super::{EpilogProof, PrologProof, Region};
use std::path::PathBuf;
use std::sync::OnceLock;

fn epilog_bytes() -> Vec<u8> {
    // Unchanged authored PE [0x404696,0x4046a8), independent of proof output.
    vec![
        0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0, 0, 0, 0, 0x59, 0x5f, 0x5e, 0x5b, 0xc9, 0xc2, 0x0c, 0,
    ]
}
// Literal original-byte regions; expected effects below are authored directly.
fn file_scope(p: &PrologProof) -> super::file_scope::FileScopeProof {
    let region = |name: &str, literal: &str| match std::env::var("W2L_EH4_CODE") {
        Ok(path) => std::fs::read(std::path::Path::new(&path).join(name)).unwrap(),
        Err(_) => bytes_hex(literal),
    };
    let wrapper = region("file-wrapper.bin", "8365e4008b4508ff30e8beffffff598365fc008b4d0ce8370c00008bf08975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00");
    let lock = region("file-lock.bin", "8bff558bec8b450883c02050ff154c5041005dc3");
    let unlock = region(
        "file-unlock.bin",
        "8bff558bec8b450883c02050ff15505041005dc3",
    );
    let cleanup = region("file-cleanup.bin", "8b4510ff30e893ffffff59c3");
    super::file_scope::FileScopeProof::prove(
        super::file_scope::Input {
            wrapper: Region {
                bytes: &wrapper,
                origin: 0x404668,
            },
            lock: Region {
                bytes: &lock,
                origin: 0x404634,
            },
            unlock: Region {
                bytes: &unlock,
                origin: 0x404648,
            },
            cleanup: Region {
                bytes: &cleanup,
                origin: 0x4046ab,
            },
            enter_iat: 0x41504c,
            leave_iat: 0x415050,
            driver: 0x4052ba,
        },
        p,
    )
    .unwrap()
}
fn bytes_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn prolog() -> PrologProof {
    PrologProof::prove(
        Region {
            bytes: &super::tests::bytes(),
            origin: 0x401e60,
        },
        12,
        0x41b400,
        0x41c000,
        0x402210,
    )
    .unwrap()
}
fn emitted_literal(source: &str) -> &str {
    source
        .split_once("r#\"")
        .unwrap()
        .1
        .split_once("\"#;")
        .unwrap()
        .0
}
const CASES: &str = r#"
fn runtime(r:&ThreadRegistry)->CrtStreamRuntime{
 let mut rt=CrtStreamRuntime::new(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();
 rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
 rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt
}
fn cpu(rt:&mut CrtStreamRuntime,entry:u32,id:u64)->CrtCpu{
 let p=rt.resolve_absolute(entry,CrtRegionKind::Stack).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(id)).unwrap();
 for i in 1..=3{rt.store(rt.offset(p,i*4).unwrap(),32,CrtValue::scalar(i as u32*17)).unwrap();}
 let mut c=CrtCpu::new(p,id).unwrap();c.return_pop=12;c.r[3]=CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000};
 c.r[6]=CrtValue::scalar(0x76543210);c.entry=c.r;c
}
fn start(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,e:&mut NormalCallEpoch<'_>,b:&mut CrtNormalBinding,helper:u64)->RegistryResult<()>{
 c.push(rt,CrtValue::scalar(12))?;c.push(rt,CrtValue::scalar(0x41b400))?;c.push(rt,CrtValue::ProtectedReturn(helper))?;
 helper_run(rt,c,helper,b.token,|rt,c,record,head|b.install(rt,c,e,record,head))
}
fn nested_actual(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let previous=r.head;
 let before=m.owned_context;
 r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut outer=cpu(&mut rt,0xe000,71);let mut a=CrtNormalBinding::bind(&rt,&outer,e,epilog_run_layout())?;
  start(&mut rt,&mut outer,e,&mut a,99)?;let outer_id=a.id.unwrap();
  assert_eq!(e.head()?,RegistryHead::Normal(outer_id));
  // Independent body writes: scope becomes active and a local receives 93.
  rt.store(a.at(&rt,-8)?,32,CrtValue::scalar(0))?;rt.store(a.at(&rt,-32)?,32,CrtValue::scalar(93))?;
  let mut inner=cpu(&mut rt,0xd000,72);let mut b=CrtNormalBinding::bind(&rt,&inner,e,epilog_run_layout())?;
  assert_eq!(b.token.head,[3,e.generation,outer_id.generation]);start(&mut rt,&mut inner,e,&mut b,100)?;
  inner.r[0]=CrtValue::scalar(17);assert_eq!(epilog_run(&mut rt,&mut inner,e,&mut b)?,CrtValue::scalar(17));
  assert_eq!(inner.r[4],CrtValue::Pointer(rt.resolve_absolute(0xd010,CrtRegionKind::Stack)?));
  assert_eq!(e.head()?,RegistryHead::Normal(outer_id));assert!(b.authority(&rt,e).is_err());
  assert_eq!(rt.load(a.at(&rt,-32)?,32)?.known_scalar()?,93);
  rt.store(a.at(&rt,-8)?,32,CrtValue::scalar((-2i32)as u32))?;
  outer.r[0]=CrtValue::scalar(93);assert_eq!(epilog_run(&mut rt,&mut outer,e,&mut a)?,CrtValue::scalar(93));
  assert_eq!(outer.r[3],CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000});
  assert_eq!(outer.r[5],CrtValue::OpaqueSaved(5));assert_eq!(outer.r[6],CrtValue::scalar(0x76543210));
  assert_eq!(outer.r[4],CrtValue::Pointer(rt.resolve_absolute(0xe010,CrtRegionKind::Stack)?));
  assert_eq!(e.head()?,previous);
  assert!(!rt.tags.values().any(|v|matches!(v,CrtValue::ProtectedReturn(71|72|99|100)|CrtValue::ThreadHead(_))));
  // Retired storage cannot supply initialized values to a stale stack alias.
  assert_eq!(rt.load(a.at(&rt,-32)?,32)?,CrtValue::Scalar{bits:0,known:0});Ok(())
 }).unwrap();assert_eq!(m.owned_context,before);assert_eq!(r.head,previous);assert!(r.normal_epoch.is_none());
}
fn mutations(){
 for mode in 0..15{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;
   start(&mut rt,&mut c,e,&mut b,99)?;
   match mode{
    0=>rt.store(b.at(&rt,-36)?,32,CrtValue::Scalar{bits:0xabcd0000,known:0xffff00ff})?,
    1=>rt.store(b.at(&rt,-48)?,32,CrtValue::scalar(0))?,
    2=>rt.store(b.at(&rt,-12)?,32,CrtValue::scalar(0))?,
    3=>rt.store(b.at(&rt,-8)?,32,CrtValue::scalar(0))?,
    4=>{b.token.epoch+=1;},5=>{b.token.head[0]=0;},
    6=>{c.r[4]=CrtValue::Pointer(b.at(&rt,-44)?);},
    7=>{let foreign=runtime(e.registry);return epilog_run(&mut {foreign},&mut c,e,&mut b).map(|_|());},
    8=>{rt.store(rt.resolve_absolute(0x41c000,CrtRegionKind::Module)?,32,CrtValue::scalar(0))?;},
    9=>{c.return_id+=1;},10=>{e.registry.head=b.previous;},
    11=>{c.entry[3]=CrtValue::scalar(0xabcd0000);},
    12=>rt.store(b.at(&rt,-32)?,32,CrtValue::ProtectedReturn(456))?,
    13=>{c.r[0]=CrtValue::Pointer(b.at(&rt,-32)?);},
    _=>{let external=rt.map_region(0x7000,4,CrtRegionKind::Result,None)?;rt.store(external,32,CrtValue::Pointer(b.at(&rt,-32)?))?;},
   }
   epilog_run(&mut rt,&mut c,e,&mut b).map(|_|())
  });assert!(result.is_err(),"mutation {mode}");assert!(r.available().is_err());
  // Failure does not falsely complete the selected event or retire its frame.
  assert!(r.frames[0].linked&&r.frames[0].live);
 }
}
fn consumed_mutation(){
 for mode in 0..3{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   b.load_previous(&rt,&mut c,e,1)?;b.unlink(&rt,&c,e,1)?;
   b.pop(&mut rt,&mut c,e,-48,1)?;
   if mode==0{rt.store(b.at(&rt,-48)?,32,CrtValue::scalar(0))?;}else if mode==1{c.r[1]=CrtValue::scalar(0);}else{c.r[4]=CrtValue::Pointer(b.at(&rt,-40)?);}
   b.pop(&mut rt,&mut c,e,-44,7)
  }).is_err());assert!(r.normal_epoch.as_ref().unwrap().frames[0].unlinked);
 }
}
fn body_failure(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut address=None;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
  let p=b.at(&rt,-32)?;rt.store(p,32,CrtValue::scalar(93))?;address=Some(p);Err::<(),_>("unresolved body exception")
 });assert_eq!(result,Err("unresolved body exception"));assert_eq!(rt.load(address.unwrap(),32).unwrap().known_scalar().unwrap(),93);
 assert!(r.normal_epoch.as_ref().unwrap().frames[0].installed);assert!(!r.normal_epoch.as_ref().unwrap().frames[0].unlinked);
}
fn wrong_certificate(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
 assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);c.return_pop=0;
  let mut layout=epilog_run_layout();layout.pop=0;
  let mut b=CrtNormalBinding::bind(&rt,&c,e,layout)?;start(&mut rt,&mut c,e,&mut b,99)?;
  let sp=c.r[4];let head=e.head()?;
  let result=epilog_run(&mut rt,&mut c,e,&mut b);
  assert_eq!(result,Err("EH4 epilog certificate/binding disagreement"));assert_eq!(c.r[4],sp);
  assert_eq!(e.registry.head,head);assert!(!c.returned);result.map(|_|())
 }).is_err());
}
fn observed(){
 let file=std::env::var("W2L_EH4_VECTORS").expect("original observation vectors required");
 assert!(std::fs::metadata(&file).unwrap().len()<65536);
 let text=std::fs::read_to_string(file).unwrap();let lines:Vec<_>=text.lines().collect();assert_eq!(lines.len(),5);
 for line in lines{
  let v:Vec<u32>=line.split_whitespace().map(|s|s.parse().unwrap()).collect();assert_eq!(v.len(),10);
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  rt.store(rt.resolve_absolute(0x41c000,CrtRegionKind::Module).unwrap(),32,CrtValue::scalar(v[0])).unwrap();
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);
   for (i,reg) in [3,5,6,7].into_iter().enumerate(){c.r[reg]=CrtValue::scalar(v[i+1]);}c.entry=c.r;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   assert_eq!(CrtCpu::pointer(c.r[4])?.address(),0xe000-48);assert_eq!(CrtCpu::pointer(c.r[5])?.address(),0xe000-4);
   // Explicit unproved body boundary: observed EAX/flags are inputs here,
   // never substituted for execution of the full formatter body.
   c.r[0]=CrtValue::scalar(v[5]);c.flags=CrtFlags{cf:Some(v[6]&1!=0),zf:Some(v[6]&64!=0),sf:Some(v[6]&128!=0),of:Some(v[6]&2048!=0)};
   let result=epilog_run(&mut rt,&mut c,e,&mut b)?.known_scalar()?;
   let flags=u32::from(c.flags.cf.unwrap())|u32::from(c.flags.zf.unwrap())*64|u32::from(c.flags.sf.unwrap())*128|u32::from(c.flags.of.unwrap())*2048;
   let delta=CrtCpu::pointer(c.r[4])?.address()-0xe000;
   assert_eq!([result,flags,delta],[v[7],v[8],v[9]]);
   for (i,reg) in [3,5,6,7].into_iter().enumerate(){assert_eq!(c.r[reg].known_scalar()?,v[i+1]);}
   println!("{} {} {} {} {} {} {}",result,flags,delta,v[1],v[2],v[3],v[4]);Ok(())
  }).unwrap();
 }
}

fn file_setup(rt:&mut CrtStreamRuntime,c:&mut CrtCpu)->RegistryResult<CrtPointer>{
 let holders=rt.map_region(0x7000,16,CrtRegionKind::Context,None)?;
 rt.store(holders,32,CrtValue::Pointer(rt.file()))?;
 rt.store(rt.offset(holders,4)?,32,CrtValue::Pointer(rt.file()))?;
 rt.store(rt.offset(holders,8)?,32,CrtValue::scalar(0xfeed))?;
 let sp=CrtCpu::pointer(c.r[4])?;
 for(i,arg)in [CrtValue::Pointer(holders),CrtValue::Pointer(rt.offset(holders,8)?),CrtValue::Pointer(rt.offset(holders,4)?)].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4)?,32,arg)?;}
 Ok(holders)
}
fn file_scope_normal(){
 for expected in [0,1,93,0x80000000,u32::MAX]{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let previous=r.head;
  let outer=rt.lock(rt.thread).unwrap(); // Recursive acquisition must release only its own level.
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let holders=file_setup(&mut rt,&mut c)?;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,file_run_epilog_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let mut calls=0;
   let value=file_run(&mut rt,&mut c,e,&mut b,|rt,child,lease|{
    calls+=1;rt.check_lock(lease)?;assert_eq!(rt.locks.len(),2);
    assert_eq!(child.r[1],CrtValue::Pointer(rt.offset(holders,8)?));
    let bp=CrtCpu::pointer(child.r[5])?;
    assert_eq!(rt.load(rt.offset(bp,-4)?,32)?.known_scalar()?,0);
    assert_eq!(rt.load(rt.offset(bp,-28)?,32)?.known_scalar()?,0);
    // A real nested native activation must return through its own token
    // without consuming the FILE wrapper or driver continuation.
    let driver_return=child.return_id;
    child.call_activation(rt,0x1234,0,|rt,nested|{
     assert_ne!(nested.return_id,driver_return);rt.check_lock(lease)?;
     rt.store(rt.offset(holders,12)?,32,CrtValue::scalar(expected^0x55))?;
     nested.clobber(CrtValue::scalar(expected));nested.finish(rt)
    })?;
    assert_eq!(child.return_id,driver_return);child.finish(rt)
   })?;
   assert_eq!(value,CrtValue::scalar(expected));assert_eq!(calls,1);
   assert_eq!(rt.load(rt.offset(holders,12)?,32)?.known_scalar()?,expected^0x55);
   assert_eq!(rt.locks,vec![outer]);assert_eq!(e.head()?,previous);
   assert_eq!(c.r[4],CrtValue::Pointer(rt.resolve_absolute(0xe010,CrtRegionKind::Stack)?));
   // Void external unlock does not grant knowledge of volatile flags/registers.
   assert!(c.flags.zf.is_none());assert_eq!(c.r[6],c.entry[6]);Ok(())
  }).unwrap();rt.unlock(outer).unwrap();
 }
}
fn file_scope_failure(){
 for mode in 0..8{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut reached=None;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let holders=file_setup(&mut rt,&mut c)?;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,file_run_epilog_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   if mode==0{rt.store(rt.offset(holders,4)?,32,CrtValue::scalar(0))?;}
   if mode==1{rt.lock_objects.clear();}
   file_run(&mut rt,&mut c,e,&mut b,|rt,child,lease|{
    let bp=CrtCpu::pointer(child.r[5])?;let marker=rt.offset(holders,12)?;
    rt.store(marker,32,CrtValue::scalar(123))?;reached=Some(marker);
    match mode{
     2=>return Err("unclosed formatter exception/termination"),
     3=>{rt.store(rt.offset(bp,-4)?,32,CrtValue::scalar((-2i32)as u32))?;},
     4=>{rt.unlock(lease)?;},
     5=>{child.r[0]=CrtValue::scalar(7);return Ok(child.r[0]);}, // no protected RET
     6=>{rt.lock_file(rt.thread,rt.file())?;}, // extra live recursive acquisition
     7=>{rt.store(rt.offset(holders,4)?,32,CrtValue::Pointer(rt.offset(rt.file(),4)?))?;},
     _=>panic!("preflight did not reject"),
    }
    child.r[0]=CrtValue::scalar(7);child.finish(rt)
   }).map(|_|())
  });assert!(result.is_err(),"mode {mode}");assert!(r.available().is_err());
  let f=&r.normal_epoch.as_ref().unwrap().frames[0];assert!(f.installed&&!f.unlinked);
  if let Some(p)=reached{assert_eq!(rt.load(p,32).unwrap().known_scalar().unwrap(),123);}
  if mode==2||mode==3||mode==5{assert_eq!(rt.locks.len(),1);}
  if mode==6||mode==7{
   assert_eq!(rt.locks.len(),if mode==6{2}else{1});
   let level=rt.resolve_absolute(0xdff8,CrtRegionKind::Stack).unwrap();
   // An extra body lock fails before the scope reset; a changed cleanup
   // argument fails inside original cleanup after the reset. Neither retires it.
   assert_eq!(rt.load(level,32).unwrap().known_scalar().unwrap(),if mode==6{0}else{(-2i32)as u32});
   let saved=rt.resolve_absolute(0xdfdc,CrtRegionKind::Stack).unwrap();
   assert_eq!(rt.load(saved,32).unwrap(),CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000});
  }
  if mode==2{let level=rt.resolve_absolute(0xdff8,CrtRegionKind::Stack).unwrap();assert_eq!(rt.load(level,32).unwrap().known_scalar().unwrap(),0);}
 }
}

fn bytes_for_native_filter()->Vec<u8>{vec![0x8b,0x55,0xec,0x8b,0x02,0x8b,0x08,0x89,0x4d,0xe4,0x8b,0x55,0xe4,0x33,0xc0,0x81,0xfa,0x42,0x00,0x42,0xe0,0x0f,0x94,0xc0,0xc3]}
fn owned_loop_cases(){
 for case in 0..34{
  let original=case>=13;let mode=if case>=23{case-10}else if original{case-13}else{case};
  let mut m=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);
  let sp=rt.resolve_absolute(0xe000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(71)).unwrap();let c=CrtCpu::new(sp,71).unwrap();let binding=m.owned_binding(0).unwrap();let mut storage=initialize_main_owned(&mut rt,&mut r,&m,binding,&c).unwrap();activate_main_owned(&mut rt,&r,&m,&mut storage).unwrap();storage.scope_store(&mut rt,&r,&m,0,if mode==18{2}else{1}).unwrap();
  m.issue_owned_event(binding).unwrap();r.contain(storage.id).unwrap();let id=storage.id;let word=rt.resolve_absolute(storage.image.record+12,CrtRegionKind::Stack).unwrap();let marker=rt.resolve_absolute(storage.image.ebp-780,CrtRegionKind::Stack).unwrap();rt.store(marker,32,CrtValue::scalar(5)).unwrap();rt.store(rt.offset(marker,4).unwrap(),32,CrtValue::scalar(0)).unwrap();
  let nested_bytes=original_nested_handler_bytes();rt.map_region(0x4027b0,nested_bytes.len()as u32,CrtRegionKind::Module,Some(&nested_bytes)).unwrap();
  map_original_cleanups(&mut rt).unwrap();map_original_notification(&mut rt).unwrap();
  if mode==20{let p=rt.resolve_absolute(0x402a30,CrtRegionKind::Module).unwrap();rt.store(p,8,CrtValue::scalar(0x90)).unwrap();}
  if mode==16{let p=rt.resolve_absolute(0xbfd8,CrtRegionKind::Stack).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(999)).unwrap();}
  if mode==17{let p=rt.resolve_absolute(0x401020,CrtRegionKind::Module).unwrap();rt.store(p,8,CrtValue::scalar(0x90)).unwrap();}
  // Independently specified conformance table; the original PE is untouched.
  let mut rows=vec![LocalScope{parent:-2,filter:0,handler:if original{0x401000}else{0x401200}},LocalScope{parent:0,filter:if mode==9{0x401400}else{0},handler:if mode==10{0x700000}else if original{0x401020}else{0x401100}}];
  if mode==18{rows.push(LocalScope{parent:1,filter:0,handler:0x401040});}
  let table=rt.map_region(storage.image.scope_va,16+rows.len()as u32*12,CrtRegionKind::Module,None).unwrap();for(i,row)in rows.iter().enumerate(){for(j,v)in [row.parent as u32,row.filter,row.handler].into_iter().enumerate(){rt.store(rt.offset(table,16+(i*12+j*4)as i64).unwrap(),32,CrtValue::scalar(v)).unwrap();}}
  for (at,add) in [(0x401100,3u8),(0x401200,7u8)]{let bytes=[0x8b,0x02,0x6b,0xc0,10,0x83,0xc0,add,0x89,0x02,0xc3];let p=rt.map_region(at,bytes.len()as u32,CrtRegionKind::Module,Some(&bytes)).unwrap();if mode==12&&add==3{rt.store(p,8,CrtValue::scalar(0x90)).unwrap();}}
  if mode==1{rt.store(rt.offset(table,28).unwrap(),32,CrtValue::scalar(1)).unwrap();}
  if mode==11{rt.store(word,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
  let entry=LocalEntry{entry_sp:0xc000,handler:0x4027b0,cookie_address:0x41c000,cookie:0x12345678,target_level:-2};let events=std::cell::RefCell::new(Vec::new());
  let result=r.execute_handler(id,&mut storage,|r,storage|r.execute_local(id,storage,entry,|record,storage|{
   let mut effects=CrtOwnedLocalEffects{rt:&mut rt,record,machine:&m,storage,rows:&rows,native_stack:false,native_notification:None,native_finally_bridge:None,native_finally_body:None,installation_seen:false,temporary:None,pending:None,written:false,notified:false,
    notification:|handler,reason,rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>|{if original{fixture_notify_invoke(rt,storage,record,handler,reason,mode)?;}events.borrow_mut().push(format!("N{handler:x}:{reason:x}"));if mode==2{Err("independent notification failure")}else{Ok(())}},
    finally:|handler,level,rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>,_|{
     assert_eq!(rt.load(word,32)?.known_scalar()? as i32,if level==2{1}else if level==1{0}else{-2});events.borrow_mut().push(format!("F{handler:x}:{level}"));
     if mode==19{let p=rt.resolve_absolute(0x41c074,CrtRegionKind::Module)?;rt.store(p,32,CrtValue::scalar(handler))?;}
     if original{original_cleanup_invoke(rt,storage,record,handler,marker)?;}else{owned_callback_invoke(rt,storage,record,handler,marker)?;}
     if mode==3{return Err("independent cleanup failure");}
     if mode==4{rt.store(rt.offset(table,16)?,32,CrtValue::scalar(0))?;}
     if mode==5{rt.store(word,32,CrtValue::scalar(7))?;}
     if mode==6{let guard=rt.resolve_absolute(storage.image.ebp-796,CrtRegionKind::Stack)?;rt.store(guard,32,CrtValue::scalar(0))?;}
     if mode==13{let p=rt.resolve_absolute(record.address()?+8,CrtRegionKind::Stack)?;rt.store(p,32,CrtValue::scalar(0))?;}
     if mode==14{let p=rt.resolve_absolute(record.address()?+4,CrtRegionKind::Stack)?;rt.store(p,32,CrtValue::scalar(0x4027b0))?;}
     if mode==7||mode==8||mode==15{
      record.registry.execute_local(id,storage,LocalEntry{entry_sp:0xb000,..entry},|nested,storage|{
       let mut inner=CrtOwnedLocalEffects{rt,record:nested,machine:&m,storage,rows:&rows,native_stack:false,native_notification:None,native_finally_bridge:None,native_finally_body:None,installation_seen:false,temporary:None,pending:None,written:false,notified:false,
        notification:|_,_,_:&mut CrtStreamRuntime,_:&mut CrtOwnedStorage,_:&mut LocalRecord<'_>|Err("nested notification should not run"),finally:|_,_,_:&mut CrtStreamRuntime,_:&mut CrtOwnedStorage,_:&mut LocalRecord<'_>,_|Err("nested callback should not run")};
       // Same live cursor is already the parent's level. No duplicate cleanup.
       owned_original_local(&mut inner,if level==2{1}else if level==1{0}else{-2},0)?;
       if mode==8{return Err("independent nested failure");}Ok(())
      })?;
      if mode==15{let retired=rt.resolve_absolute(0xafd8,CrtRegionKind::Stack)?;assert!(rt.load(retired,32)?.known_scalar().is_err());}
     }Ok(())
    }};
   owned_original_local(&mut effects,-2,0).map(|_|())
  }));
  if mode==0||mode==7||mode==9||mode==15||mode==18{result.unwrap();assert_eq!(storage.image.try_level,-2);assert_eq!(rt.load(word,32).unwrap(),CrtValue::scalar((-2i32)as u32));assert!(r.temporary.is_empty());assert_eq!(r.head().unwrap(),RegistryHead::Owned(id));assert_eq!(rt.load(marker,32).unwrap().known_scalar().unwrap(),if mode==18{21281}else if original{if mode==9{81}else{1313}}else if mode==9{57}else{537});
   assert_eq!(*events.borrow(),if mode==18{vec!["N401040:101","F401040:2","N401020:101","F401020:1","N401000:101","F401000:0"]}else if original{if mode==9{vec!["N401000:101","F401000:0"]}else{vec!["N401020:101","F401020:1","N401000:101","F401000:0"]}}else if mode==9{vec!["N401200:101","F401200:0"]}else{vec!["N401100:101","F401100:1","N401200:101","F401200:0"]});
  }else{assert!(result.is_err(),"loop mode {mode}");assert!(r.available().is_err());assert!(r.frames[0].completion.is_none());assert!(!r.temporary.is_empty());if mode==1||mode==10||mode==11||mode==16{assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(5));}else{assert_eq!(storage.image.try_level,0);assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(if mode==2||mode==12||mode==17||mode>=19{5}else if original{82}else{53}));}}
  if original{
   let action=rt.resolve_absolute(0x41c078,CrtRegionKind::Module).unwrap();
   if mode==1||mode==16||mode>=20{assert!(rt.load(action,32).unwrap().known_scalar().is_err());}
   else{assert_eq!(rt.load(action,32).unwrap(),CrtValue::scalar(0x101));let target=rt.resolve_absolute(0x41c074,CrtRegionKind::Module).unwrap();
    if mode==19{assert_eq!(rt.load(target,32).unwrap(),CrtValue::scalar(0x401020));}else{assert!(matches!(rt.load(target,32).unwrap(),CrtValue::Pointer(_)));}
   }
  }
  assert_eq!(m.phase,Phase::Cleanup);assert_eq!(m.owned_context,Some([None;10]));assert!(m.restore_owned(0x40135c,|_,_|panic!("loop is not restoration")).is_err());
 }
}

fn owned_local_cases(){
 for mode in 0..10{
  let mut m=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();
  let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);
  let sp=rt.resolve_absolute(0xe000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(71)).unwrap();let mut c=CrtCpu::new(sp,71).unwrap();
  let binding=m.owned_binding(0).unwrap();let mut storage=initialize_main_owned(&mut rt,&mut r,&m,binding,&c).unwrap();activate_main_owned(&mut rt,&r,&m,&mut storage).unwrap();m.issue_owned_event(binding).unwrap();r.contain(storage.id).unwrap();
  let id=storage.id;let base=rt.resolve_absolute(storage.image.record,CrtRegionKind::Stack).unwrap();let word=rt.offset(base,12).unwrap();c.r[0]=CrtValue::Pointer(base);c.r[1]=CrtValue::scalar((-2i32)as u32);
  let entry=LocalEntry{entry_sp:0xc000,handler:0x4027b0,cookie_address:0x41c000,cookie:0x12345678,target_level:-2};
  if mode==2{c.r[0]=CrtValue::scalar(base.address());}
  if mode==3{let p=rt.resolve_absolute(storage.image.ebp-796,CrtRegionKind::Stack).unwrap();rt.store(p,32,CrtValue::scalar(0)).unwrap();}
  if mode==4{rt.store(word,32,CrtValue::scalar(1)).unwrap();}
  let before=m.owned_context;
  let result=r.execute_handler(id,&mut storage,|r,storage|r.execute_local(id,storage,entry,|local,storage|{
   if mode!=1{local.install_head(40,entry.handler)?;}
   if mode==5{local.restore_previous_head()?;}
   if mode==9{
    return local.registry.execute_local(id,storage,LocalEntry{entry_sp:0xb000,..entry},|nested,storage|{
     nested.install_head(40,entry.handler)?;original_local_level_store(&mut rt,nested,&m,storage,&c)?;assert_eq!(rt.load(word,32)?,CrtValue::scalar((-2i32)as u32));nested.restore_previous_head()
    }).and_then(|_|local.restore_previous_head());
   }
   let mut foreign=runtime(local.registry);let memory=if mode==8{&mut foreign}else{&mut rt};
   original_local_level_store(memory,local,&m,storage,&c)?;
   assert_eq!(rt.load(word,32)?,CrtValue::scalar((-2i32)as u32));assert_eq!(storage.image.try_level,-2);
   if mode==6{return Err("independent failure after live cleanup store");}
   if mode==7{original_local_level_store(&mut rt,local,&m,storage,&c)?;}
   local.restore_previous_head()
  }));
  if mode==0||mode==9{assert!(result.is_ok());storage.validate_storage(&rt,&r,&m).unwrap();assert_eq!(r.head().unwrap(),RegistryHead::Owned(id));}
  else{assert!(result.is_err(),"local mode {mode}");assert!(r.available().is_err());}
  let expected=if mode==0||mode==6||mode==7||mode==9{(-2i32)as u32}else if mode==4{1}else{0};assert_eq!(rt.load(word,32).unwrap(),CrtValue::scalar(expected));
  assert_eq!(m.owned_context,before);assert_eq!(m.phase,Phase::Cleanup);assert!(m.restore_owned(0x40135c,|_,_|panic!("local write is not restoration")).is_err());
 }
}

fn owned_main_cases(){
 for mode in 0..172{
  let mut m=Machine::new_dispatch_known((0..if mode>=75{2}else{1}).map(|_|FrameSpec{scopes:vec![]}).collect(),0,[None;10],Some(0)).unwrap();
  let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);
  let entry=rt.resolve_absolute(if mode==23||mode==32||mode==41||mode==76{0xe800}else{0xe000},CrtRegionKind::Stack).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(71)).unwrap();let cpu=CrtCpu::new(entry,71).unwrap();
  let binding=m.owned_binding(0).unwrap();
  if mode==75{
   let tags=rt.tags.clone();let wrong=m.owned_binding(1).unwrap();
   assert_eq!(initialize_inner_owned(&mut rt,&mut r,&m,wrong,&cpu).err(),Some("owned initializer frame order"));
   assert!(r.frames.is_empty());assert_eq!(rt.tags,tags);
  }
  let mut storage=if mode==1{initialize_inner_owned(&mut rt,&mut r,&m,binding,&cpu)}else{initialize_main_owned(&mut rt,&mut r,&m,binding,&cpu)}.unwrap();
  let level=rt.resolve_absolute(storage.image.record+12,CrtRegionKind::Stack).unwrap();
  if mode==13{rt.store(level,32,CrtValue::scalar(7)).unwrap();assert!(activate_main_owned(&mut rt,&r,&m,&mut storage).is_err());assert_eq!(rt.load(level,32).unwrap(),CrtValue::scalar(7));continue;}
  let activated=activate_main_owned(&mut rt,&r,&m,&mut storage);
  if mode==1{assert!(activated.is_err());}else{activated.unwrap();assert_eq!(rt.load(level,32).unwrap(),CrtValue::scalar(0));assert!(activate_main_owned(&mut rt,&r,&m,&mut storage).is_err());}
  let mut delivery_target=if mode>=75{
   let b=m.owned_binding(1).unwrap();let sp=rt.resolve_absolute(if mode==76{0xd800}else{0xd000},CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(72)).unwrap();let c=CrtCpu::new(sp,72).unwrap();
   assert!(m.issue_owned_event(binding).is_err());
   let mut target=initialize_inner_scalars_owned(&mut rt,&mut r,&m,b,&c).unwrap();if mode==122{target.scope_store(&mut rt,&r,&m,1,0).unwrap();}Some(target)
  }else{None};
  m.issue_owned_event(m.owned_binding(if mode>=75{1}else{0}).unwrap()).unwrap();r.contain(storage.id).unwrap();
  if mode==75{
   let target=delivery_target.as_ref().unwrap();let selected=r.selected.as_ref().unwrap().target;
   r.selected.as_mut().unwrap().target=target.id;
   assert_eq!(target.validate_search(&rt,&r,&m),Err("owned selected search authority"));
   r.selected.as_mut().unwrap().target=selected;
  }
  if mode==0{assert!(activate_main_owned(&mut rt,&r,&m,&mut storage).is_err());}

  let record=rt.map_region(0x50000,80,CrtRegionKind::Context,None).unwrap();let context=rt.map_region(0x51000,716,CrtRegionKind::Context,None).unwrap();let pair=rt.map_region(0x52000,8,CrtRegionKind::Context,None).unwrap();
  rt.store(record,32,CrtValue::scalar(0xe0424242)).unwrap();rt.store(pair,32,CrtValue::Pointer(record)).unwrap();rt.store(rt.offset(pair,4).unwrap(),32,CrtValue::Pointer(context)).unwrap();
  let bp=rt.resolve_absolute(storage.image.ebp,CrtRegionKind::Stack).unwrap();
  if mode>=24{storage.bind_captured(&rt,&r,&m,record,context,0xe0424242).unwrap();assert!(rt.load(rt.offset(bp,-20).unwrap(),32).unwrap().known_scalar().is_err());}
  else{rt.store(rt.offset(bp,-20).unwrap(),32,CrtValue::Pointer(pair)).unwrap();storage.bind_input(&rt,&r,&m,pair,record,context,0xe0424242).unwrap();}
  if mode==2||mode==3{let guard=rt.offset(bp,if mode==2{-28}else{-796}).unwrap();rt.store(guard,32,CrtValue::scalar(0)).unwrap();}
  if mode==4{storage.binding.frame.generation+=1;}
  if mode==5{r.frames[0].live=false;}
  if mode==6{rt.store(rt.offset(pair,4).unwrap(),32,CrtValue::scalar(0)).unwrap();}
  if mode==8{rt.store(rt.resolve_absolute(0x41c000,CrtRegionKind::Module).unwrap(),32,CrtValue::scalar(0)).unwrap();}
  if mode==10{m.phase=Phase::Done;}
  if mode==11{let p=rt.offset(bp,-776).unwrap();rt.store(p,32,CrtValue::OpaqueSaved(3)).unwrap();}
  let mut foreign=runtime(&r);
  let runtime=if mode==9{&mut foreign}else{&mut rt};
  let bridge_sp=if mode==12{entry}else{runtime.resolve_absolute(if mode==23||mode==32||mode==41||mode==76{0xb000}else{0xc000},CrtRegionKind::Stack).unwrap()};let return_id=if mode==12{71}else{200};if mode!=12{runtime.store(bridge_sp,32,CrtValue::ProtectedReturn(return_id)).unwrap();}
  let mut c=CrtCpu::new(bridge_sp,return_id).unwrap();let target_code=original_main_filter_bytes();let target=runtime.map_region(0x401333,target_code.len()as u32,CrtRegionKind::Module,Some(&target_code)).unwrap();
  c.r[1]=CrtValue::Pointer(target);c.r[2]=CrtValue::Pointer(bp);
  let mut view=CrtOwnedFrameView{rt:runtime,registry:&mut r,machine:&mut m,storage:&mut storage,search_storage:None,search:true,active:c.return_id,depth:0,calls:0,failed:false};
  if mode>=14{
   let (record,context)=if mode==19{
    let other_record=view.rt.map_region(0x53000,80,CrtRegionKind::Context,None).unwrap();let other_context=view.rt.map_region(0x54000,716,CrtRegionKind::Context,None).unwrap();
    view.rt.store(other_record,32,CrtValue::scalar(0xe0424242)).unwrap();(other_record,other_context)
   }else{(record,context)};
   for(offset,value)in [(4,0),(8,0),(16,0)]{view.rt.store(view.rt.offset(record,offset).unwrap(),32,CrtValue::scalar(value)).unwrap();}
   if mode!=15{view.rt.store(view.rt.offset(context,0xc4).unwrap(),32,CrtValue::scalar(0x9500)).unwrap();}
   let establisher=view.rt.resolve_absolute(view.storage.image.record,CrtRegionKind::Stack).unwrap();
   for(i,value)in [CrtValue::Pointer(record),if mode==16{CrtValue::Pointer(bp)}else{CrtValue::Pointer(establisher)},if mode==17{CrtValue::scalar(context.address())}else{CrtValue::Pointer(context)},CrtValue::scalar(0)].into_iter().enumerate(){view.rt.store(view.rt.offset(bridge_sp,4+i as i64*4).unwrap(),32,value).unwrap();}
   if mode==20{view.rt.store(view.rt.offset(record,4).unwrap(),32,CrtValue::scalar(0x10)).unwrap();}
   if mode==21{view.rt.store(view.rt.offset(bridge_sp,-8).unwrap(),32,CrtValue::ProtectedReturn(999)).unwrap();}
   if mode>=24{c.entry=c.r;}
   let before=c.r;
   let input=CrtOwnedPrefixInput::bind(&view,&c,record,context,owned_prefix_handler(),owned_prefix_temporary());
   if mode==15||mode==16||mode==17||mode==19||mode==20||mode==21{assert!(input.is_err(),"owned prefix mode {mode}");assert_eq!(c.r,before);continue;}
   let input=input.unwrap();assert_ne!(input.captured_esp,bridge_sp.address());
   if mode==18{view.rt.store(view.rt.offset(context,0xc4).unwrap(),32,CrtValue::scalar(0x9600)).unwrap();assert!(input.validate(&view,&c).is_err());assert_eq!(c.r,before);continue;}
   if mode==22{view.rt.store(view.rt.offset(bp,-796).unwrap(),32,CrtValue::scalar(0)).unwrap();assert!(input.validate(&view,&c).is_err());assert_eq!(c.r,before);continue;}
   if mode>=24{
    let raw=original_main_table();
    let table=view.rt.map_region(0x41b218,raw.len()as u32,CrtRegionKind::Module,Some(&raw)).unwrap();
    let feature=view.rt.map_region(0x41ccb8,4,CrtRegionKind::Module,if mode==25{None}else{Some(&[0,0,0,0])}).unwrap();
    let _=feature;
    view.rt.map_region(0x415128,4,CrtRegionKind::Module,if mode==27{None}else{Some(&[0,0,0,0])}).unwrap();
    if mode==26{view.rt.store(table,32,CrtValue::scalar((-2i32)as u32)).unwrap();}
    let result=owned_prefix_helpers::execute(&mut view,&mut c,&input);
    let hbp=view.rt.offset(bridge_sp,-4).unwrap();
    if mode==25||mode==26||mode==27{
     assert!(result.is_err(),"owned helper failure mode {mode}");assert!(view.failed);
     assert_eq!(view.rt.load(view.rt.offset(hbp,-12).unwrap(),32).unwrap(),CrtValue::scalar(1));
     assert_eq!(c.r[4],CrtValue::Pointer(view.rt.offset(hbp,if mode==25{-44}else if mode==26{-52}else{-56}).unwrap()));
     assert!(view.storage.input.unwrap().0.is_none());continue;
    }
    result.unwrap();input.validate(&view,&c).unwrap();assert_eq!(view.calls,3);
    let actual_pair=view.rt.offset(hbp,-28).unwrap();
    assert_eq!(view.storage.input.unwrap().0,Some(actual_pair));assert_eq!(view.rt.load(view.rt.offset(bp,-20).unwrap(),32).unwrap(),CrtValue::Pointer(actual_pair));
    assert_ne!(actual_pair,pair);assert_eq!(view.rt.load(actual_pair,32).unwrap(),CrtValue::Pointer(record));
    assert_eq!(c.r[4],CrtValue::Pointer(view.rt.offset(hbp,-40).unwrap()));assert_eq!(c.r[7],CrtValue::scalar(0));
    if mode==28{view.rt.store(view.rt.offset(actual_pair,4).unwrap(),32,CrtValue::scalar(context.address())).unwrap();assert!(view.validate().is_err());continue;}
    if mode==29{view.rt.consume_stack(bridge_sp,CrtValue::ProtectedReturn(return_id)).unwrap();assert!(view.validate().is_err());continue;}
    if mode==30{assert!(input.installed(&mut view,&c).is_err());continue;}
    if mode==31{view.rt.store(view.rt.offset(bp,-28).unwrap(),32,CrtValue::scalar(0)).unwrap();assert!(view.validate().is_err());continue;}
    if mode>=33{
     let code=view.rt.map_region(0x402272,original_handler_body().len()as u32,CrtRegionKind::Module,Some(&original_handler_body())).unwrap();
     if mode==34{view.rt.store(code,8,CrtValue::scalar(0x90)).unwrap();}
     if mode==35{view.rt.store(view.rt.offset(table,20).unwrap(),32,CrtValue::scalar(0x401334)).unwrap();}
     if mode==36{view.rt.store(target,8,CrtValue::scalar(0x90)).unwrap();}
     if mode==37{let p=view.rt.offset(bp,-4).unwrap();view.rt.store(p,32,CrtValue::scalar(1)).unwrap();}
     if mode==38{view.rt.consume_stack(bridge_sp,CrtValue::ProtectedReturn(return_id)).unwrap();}
     if mode==39{view.rt.store(view.rt.offset(hbp,-8).unwrap(),32,CrtValue::scalar(table.address())).unwrap();}
     if mode==40{c.r[6]=CrtValue::Pointer(hbp);}
     let snapshot=c.r;let saved=view.machine.owned_context;
     let result=owned_search_to_global_call(&mut view,&mut c,&input);
     if (34..=40).contains(&mode){
      assert!(result.is_err(),"owned search mode {mode}");assert!(view.failed);
      if mode!=36{assert_eq!(c.r,snapshot);}else{assert_eq!(view.rt.load(view.rt.offset(hbp,-20).unwrap(),32).unwrap(),CrtValue::Pointer(view.rt.offset(table,16).unwrap()));}
      assert!(view.rt.load(view.rt.offset(bp,-776).unwrap(),32).unwrap().known_scalar().is_err());continue;
     }
     result.unwrap();input.validate(&view,&c).unwrap();
     assert_eq!(c.r[1],CrtValue::Pointer(view.rt.offset(bp,-16).unwrap()));assert_eq!(c.r[2],CrtValue::Pointer(record));
     assert_eq!(c.r[3],CrtValue::scalar((-2i32)as u32));assert_eq!(c.r[7],CrtValue::scalar(0));assert_eq!(c.r[4],CrtValue::Pointer(view.rt.offset(hbp,-40).unwrap()));
     assert_eq!(view.calls,5);assert_eq!(view.storage.image.try_level,0);assert_eq!(view.machine.owned_context,saved);assert_eq!(view.machine.phase,Phase::Cleanup);
     for offset in [-776,-780]{assert_eq!(view.read(offset).unwrap(),CrtValue::scalar(0xe0424242));}
     if (51..=65).contains(&mode)||mode>=70{
      let captured_before=CrtOwnedUnwind::context_words(view.rt,context).unwrap();
      let delivery=view.rt.map_region(0x55000,716,CrtRegionKind::Context,None).unwrap();
      if mode!=55{view.rt.store(view.rt.offset(delivery,0xc4).unwrap(),32,CrtValue::scalar(0x9600)).unwrap();}
      let nested_context=view.rt.map_region(0x56000,716,CrtRegionKind::Context,None).unwrap();view.rt.store(view.rt.offset(nested_context,0xc4).unwrap(),32,CrtValue::scalar(0x9700)).unwrap();
      let before_wrapper=c.r;let mut reached=0;let mut marker=None;let mut retirement=None;
      let result=view.call(&mut c,0x402337,|f,wrapper|original_global_delivery_cut(f,wrapper,&input,|f,wrapper,session|{
       // Explicit independently supplied unwind delivery input. This is not
       // an implementation of RtlUnwind's writes or Windows context capture.
       assert!(input.validate_prefix_source(f).is_err());
       f.rt.store(f.rt.offset(record,4)?,32,CrtValue::scalar(2))?;
       if mode>=75{
        let target=delivery_target.as_mut().unwrap();
        let source_guard=f.rt.resolve_absolute(f.storage.image.ebp-28,CrtRegionKind::Stack)?;
        let guard_before=f.rt.load(source_guard,32)?;let source_pair=f.storage.input;
        let target_local=f.rt.resolve_absolute(target.image.ebp-28,CrtRegionKind::Stack)?;
        let target_guard=f.rt.resolve_absolute(target.image.ebp-48,CrtRegionKind::Stack)?;
        assert_ne!(target.image.entry_sp-target.image.esp,f.storage.image.entry_sp-f.storage.image.esp);
        if mode>=90{map_finally_original(f.rt)?;}else{let table=original_inner_table();f.rt.map_region(target.image.scope_va,table.len()as u32,CrtRegionKind::Module,Some(&table))?;}
        let sp=f.rt.resolve_absolute(0xa000,CrtRegionKind::Stack)?;
        f.rt.store(sp,32,CrtValue::ProtectedReturn(701))?;
        let owner=f.rt.resolve_absolute(if mode==78{f.storage.image.record}else{target.image.record},CrtRegionKind::Stack)?;
        for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(owner),CrtValue::Pointer(delivery),CrtValue::scalar(0)].into_iter().enumerate(){f.rt.store(f.rt.offset(sp,4+i as i64*4)?,32,v)?;}
        let mut child=CrtCpu::new(sp,701)?;
        let opaque=if mode>=141{
         let t=f.rt.new_dispatcher(if mode==142{session.epoch+1}else{session.epoch},if mode==143{702}else{701})?;
         f.rt.store(f.rt.offset(sp,16)?,32,CrtValue::Dispatcher(t))?;
         if mode==144{f.rt.end_dispatcher(t)?;}
         Some(t)
        }else{None};

        if mode==79{f.rt.store(source_guard,32,CrtValue::scalar(0))?;}
        if mode==80{f.rt.store(target_guard,32,CrtValue::scalar(0))?;}
        if mode==82{target.binding.frame.generation+=1;}
        if mode==87{f.rt.store(f.rt.resolve_absolute(0xb800,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(72))?;}
        if mode>=90{
         map_local_wrapper(f.rt)?;map_local_body(f.rt)?;map_finally_bridge(f.rt)?;if mode==105{let at=f.rt.resolve_absolute(target.image.scope_va+28,CrtRegionKind::Module)?;f.rt.store(at,32,CrtValue::scalar(1))?;}if mode==100{f.rt.store(f.rt.resolve_absolute(0x402710,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}if mode==97{f.rt.store(f.rt.resolve_absolute(0x4022bd,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}if mode==98{f.rt.store(f.rt.resolve_absolute(0x402860,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}map_original_cleanups(f.rt)?;map_original_notification(f.rt)?;
         let nested=original_nested_handler_bytes();f.rt.map_region(0x4027b0,nested.len()as u32,CrtRegionKind::Module,Some(&nested))?;
         f.rt.store(f.rt.resolve_absolute(0x41c948,CrtRegionKind::Module)?,32,CrtValue::scalar(5))?;
         if mode==149{f.rt.store(f.rt.resolve_absolute(0x4022bd,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
         if mode==119||mode==122||mode==123{let p=f.rt.resolve_absolute(target.image.ebp-32,CrtRegionKind::Stack)?;f.rt.store(p,32,if mode==123{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if mode==122{2}else{3})})?;}
         if mode==120{f.rt.store(f.rt.resolve_absolute(0x401000,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
         if mode==121{f.rt.store(f.rt.resolve_absolute(0x415184,CrtRegionKind::Module)?,32,CrtValue::scalar(0x401020))?;}
         if mode==110{f.rt.store(f.rt.resolve_absolute(0x402a30,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
         if mode==114{f.rt.store(f.rt.resolve_absolute(0x402a50,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
         if mode==115{f.rt.store(f.rt.resolve_absolute(target.image.scope_va+36,CrtRegionKind::Module)?,32,CrtValue::scalar(0x40116f))?;}
         if mode==116{f.rt.store(f.rt.resolve_absolute(0x40116e,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
         let result=f.with_handler_target(target,|source,target|{
          session.with_target_delivery(source,target,&mut child,delivery,|session,t,child,token|{
           reached+=1;assert_eq!(owned_delivery_prefix_helpers::execute(session,t,child,token)?,0x4022bd);
           original_unwind_caller(t,child,session,token,mode-90,source_guard)?;
           if mode>=141{
            let opaque=opaque.ok_or("test missing opaque input")?;
            assert_eq!(token.dispatcher,CrtValue::Dispatcher(opaque));
            if mode==145{t.rt.store(t.rt.offset(sp,16)?,32,CrtValue::scalar(0))?;}
            if mode==146{
             let nsp=t.rt.resolve_absolute(0x9800,CrtRegionKind::Stack)?;let mut nested=delivery_cpu(t,nsp,702,record,nested_context)?;
             t.rt.store(t.rt.offset(nsp,16)?,32,CrtValue::Dispatcher(opaque))?;
             return session.with_delivery(t,&mut nested,nested_context,|_,_,_,_|panic!("borrowed parent dispatcher accepted"));
            }
            if mode==147{
             assert!(CrtCpu::number(token.dispatcher).is_err());assert!(CrtCpu::pointer(token.dispatcher).is_err());
             assert!(t.rt.load(t.rt.offset(sp,16)?,8).is_err());
            }
            if mode==148{return Err("independent failure after cleanup effects");}
            if mode==150{
             let mut fault=CrtCpu::new(sp,701)?;
             assert_eq!(original_collided_dispatcher_write(t.rt,&mut fault),Err("CRT protected control bits"));
             return Err("collided dispatcher effect requires writable contract");
            }
           }
           session.validate_delivery(t,child,token)
          })?;
          let disposition=handler_original_epilog(source.rt,&mut child)?.known_scalar()?;
          if disposition!=1||!child.returned{return Err("connected original handler return");}
          Ok(CrtHandlerExit{anchor:source.rt.anchor,id:target.id,event:source.machine.event,disposition,completion_generation:source.registry.generation.checked_add(1).ok_or("handler completion generation overflow")?})
         });
         if let Some(t)=opaque{if ![142,143].contains(&mode){assert!(f.rt.dispatcher(t).is_err(),"dispatcher lease survived callback");}}
         let(exit,completion)=result?;
         if mode>=124{
          target.retire_completed(f.rt,f.registry,f.machine,completion,exit)?;
          let cut=session.resume_cut(f,wrapper,if mode==125{0x402856}else{0x402855})?;
          if mode==127{assert!(session.resume_cut(f,wrapper,0x402855).is_err());}
          if mode==126{f.rt.store(f.rt.offset(session.wrapper_entry,-8)?,32,CrtValue::scalar(1))?;}
          if mode==128{wrapper.return_id+=1;}
          if mode==129{f.rt.consume_stack(session.wrapper_entry,CrtValue::ProtectedReturn(session.wrapper_id))?;}
          if mode==130{f.machine.current=1;}
          if mode==131{f.rt.store(f.rt.offset(context,0xb8)?,32,CrtValue::scalar(7))?;}
          return Ok(Some(cut));
         }
         retirement=Some((exit,completion));return Ok(None);
        }
        let result=session.with_target_delivery(f,target,&mut child,delivery,|session,t,child,token|{
         reached+=1;assert_eq!(token.target,t.storage.id);assert_ne!(token.target,input.id);
         let branch=owned_delivery_prefix_helpers::execute(session,t,child,token)?;assert_eq!(branch,0x4022bd);
         assert_eq!(child.r[6],CrtValue::Pointer(t.owner_frame()?));assert_eq!(child.r[7],CrtValue::scalar(1));
         assert_eq!(t.read(-28)?,CrtValue::scalar(100));assert!(t.storage.input.is_none());assert!(t.storage.unwind_epoch.is_none());
         // Original prefix operates on target; suspended source pair/guard stay live.
         assert_eq!(t.rt.load(source_guard,32)?,guard_before);session.validate_delivery(t,child,token)?;
         if mode==81{t.rt.consume_stack(bridge_sp,CrtValue::ProtectedReturn(return_id))?;}
         if mode==83{t.rt.store(t.rt.offset(context,0xb8)?,32,CrtValue::scalar(7))?;}
         if mode==84{t.rt.store(t.rt.offset(delivery,0xb8)?,32,CrtValue::scalar(8))?;}
         if mode==88{t.rt.store(t.rt.offset(actual_pair,4)?,32,CrtValue::Pointer(delivery))?;}
         if mode==89{let mut forged=CrtUnwindDelivery{epoch:token.epoch,serial:token.serial,target:input.id,context:token.context,dispatcher:token.dispatcher,entry:token.entry,callback:token.callback,captured_esp:token.captured_esp,snapshot:token.snapshot.clone()};return session.validate_delivery(t,child,&mut forged);}
         if mode==85{t.write_u32(-28,0xface)?;marker=Some(target_local);return Err("independent target failure after write");}
         if mode==77||mode==86{
          let nsp=t.rt.resolve_absolute(if mode==86{0x9fc0}else{0x9800},CrtRegionKind::Stack)?;let mut nested=delivery_cpu(t,nsp,702,record,nested_context)?;
          session.with_delivery(t,&mut nested,nested_context,|session,t,nested,note|{reached+=1;assert_eq!(owned_delivery_prefix_helpers::execute(session,t,nested,note)?,0x4022bd);session.validate_delivery(t,nested,note)})?;
         }Ok(())
        });
        if mode==75||mode==76||mode==77{result?;assert_eq!(f.storage.input,source_pair);assert_eq!(f.rt.load(source_guard,32)?,guard_before);assert_eq!(CrtOwnedUnwind::context_words(f.rt,context)?,captured_before);assert!(session.check_cleanup_boundary(f,wrapper,0x402855).is_err());return Ok(None);}
        assert!(result.is_err(),"cross-frame case {mode}");return result.map(|_|None);
       }
       let context_arg=if mode==53{context}else if mode==54{record}else{delivery};
       let sp=f.rt.resolve_absolute(0xa000,CrtRegionKind::Stack)?;
       let mut child=delivery_cpu(f,sp,701,record,context_arg)?;
       if mode==56{f.rt.store(f.rt.offset(sp,12)?,32,CrtValue::scalar(context_arg.address()))?;}
       session.with_delivery(f,&mut child,context_arg,|session,f,child,token|{
        assert!(session.check_cleanup_boundary(f,wrapper,0x402855).is_err());
        reached+=1;assert_eq!(token.captured_esp,0x9600);assert_ne!(token.context,input.context);assert_ne!(token.captured_esp,CrtCpu::pointer(child.r[4])?.address());
        let branch=owned_delivery_prefix_helpers::execute(session,f,child,token)?;assert_eq!(branch,0x4022bd);session.validate_delivery(f,child,token)?;
        assert_eq!(child.r[5],CrtValue::Pointer(f.rt.offset(sp,-4)?));assert_eq!(child.r[4],CrtValue::Pointer(f.rt.offset(sp,-44)?));assert_eq!(f.storage.input.unwrap().0,Some(actual_pair));assert_eq!(f.storage.input.unwrap().2,context);
        if mode==57{f.rt.store(f.rt.offset(context,0xb8)?,32,CrtValue::scalar(7))?;}
        if mode==58{f.rt.store(f.rt.offset(delivery,0xb8)?,32,CrtValue::scalar(8))?;}
        if mode==59{f.rt.store(f.rt.offset(record,4)?,32,CrtValue::scalar(0))?;}
        if mode==61{f.rt.retire_region(delivery)?;}
        if mode==62{f.rt.consume_stack(bridge_sp,CrtValue::ProtectedReturn(return_id))?;}
        if mode==63{let p=f.rt.offset(bp,-780)?;f.rt.store(p,32,CrtValue::scalar(0xface))?;marker=Some(p);return Err("independent delivery failure");}
        if mode==70{f.rt.store(f.rt.offset(sp,12)?,32,CrtValue::Pointer(context))?;}
        if mode==65{f.rt.consume_stack(sp,CrtValue::ProtectedReturn(701))?;}
        if mode==52||mode==60||mode==64||mode==74{
         let nested=if mode==64{delivery}else{nested_context};let nsp=f.rt.resolve_absolute(if mode==74{0x9fc0}else{0x9800},CrtRegionKind::Stack)?;
         let mut ncpu=delivery_cpu(f,nsp,702,record,nested)?;
         session.with_delivery(f,&mut ncpu,nested,|session,f,ncpu,note|{
          if mode==60{return session.validate_delivery(f,child,token);}
          reached+=1;assert_eq!(note.captured_esp,0x9700);owned_handler_prolog(f,ncpu)?;session.validate_delivery(f,ncpu,note)
         })?;
         session.validate_delivery(f,child,token)?;
        }
        Ok(())
       })?;
       if mode==71{
        // Windows may reuse one unwind CONTEXT for sequential callbacks.
        // A new scoped lease is required; active aliasing still rejects.
        let next=f.rt.resolve_absolute(0x9800,CrtRegionKind::Stack)?;let mut sibling=delivery_cpu(f,next,703,record,delivery)?;
        session.with_delivery(f,&mut sibling,delivery,|session,f,sibling,token|{reached+=1;assert_eq!(token.serial,2);owned_handler_prolog(f,sibling)?;session.validate_delivery(f,sibling,token)})?;
       }
       assert!(session.active.is_empty());assert_eq!(session.used.len(),if mode==52||mode==71{2}else{1});
       if mode==72{f.rt.store(f.rt.offset(session.api_sp,4)?,32,CrtValue::scalar(0x402856))?;}
       if mode==73{wrapper.return_id+=1;}
       session.check_cleanup_boundary(f,wrapper,0x402855)?;

       assert_eq!(CrtOwnedUnwind::context_words(f.rt,context)?,captured_before);
       Ok(None)
      }));
      if (142..=146).contains(&mode)||mode==148||mode==149||mode==150{
       assert!(result.is_err(),"opaque dispatcher negative {mode}");if mode==149{assert_eq!(result,Err("unwind caller code changed"));}assert!(view.failed);
       assert!(view.storage.resume_ticket.is_none());assert_eq!(view.machine.owned_context,saved);
       let expected=if [145,146,148,150].contains(&mode){1298}else{5};
       assert_eq!(view.rt.load(view.rt.resolve_absolute(0x41c948,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(expected),"opaque mode {mode} result {result:?}");continue;
      }
      if mode>=124{
       if mode==124||mode==127||mode>=132{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert!(!view.failed);assert!(view.storage.resume_ticket.is_none());for reg in [3,5,6,7]{assert_eq!(c.r[reg],before_wrapper[reg]);}assert!(c.flags.zf.is_none());assert!(c.r[1].known_scalar().is_err());assert!(input.validate_prefix_source(&view).is_err());}
       else{assert!(result.is_err());assert!(view.failed);assert_ne!(result.unwrap_err(),"RtlUnwind requires owned continuation and effect contract");}
       if mode>=132{
        if mode==133{view.rt.store(view.rt.resolve_absolute(0x402337,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
        if mode==134{let id=view.storage.post_unwind.unwrap().1;view.rt.store(view.rt.resolve_absolute(0xa600,CrtRegionKind::Stack).unwrap(),32,CrtValue::ProtectedReturn(id)).unwrap();}
        if mode==135{view.rt.consume_stack(bridge_sp,CrtValue::ProtectedReturn(return_id)).unwrap();}
        if mode==136{view.rt.store(view.rt.offset(table,24).unwrap(),32,CrtValue::scalar(0x40135d)).unwrap();}
        if mode==137{c.r[7]=CrtValue::scalar(1);}
        if mode==138{view.rt.store(view.rt.offset(hbp,-16).unwrap(),32,CrtValue::Pointer(view.rt.resolve_absolute(delivery_target.as_ref().unwrap().image.ebp,CrtRegionKind::Stack).unwrap())).unwrap();}
        if mode==140{let fake=view.rt.map_region(0x70000,12,CrtRegionKind::Context,Some(&[0,0,0,0,0,0,0,0,0x5c,0x13,0x40,0])).unwrap();view.rt.store(view.rt.offset(hbp,-20).unwrap(),32,CrtValue::Pointer(fake)).unwrap();}
        let post=CrtOwnedPostUnwind::bind(&mut view,&c,&input,0);
        if [134,135,137,138,140].contains(&mode){assert!(post.is_err());assert_eq!(view.storage.image.try_level,0);continue;}
        let mut post=post.unwrap();
        let transferred=owned_post_global_caller(&mut view,&mut c,&mut post);
        if mode==132||mode==139||mode==141||mode==147||mode>=151{assert_eq!(transferred.unwrap(),CrtValue::scalar(0x40135c));assert_eq!(view.storage.image.try_level,-2);assert!(view.storage.post_authority.is_none());assert!(post.validate(&view,&c).is_err());if mode==139{assert!(owned_post_global_caller(&mut view,&mut c,&mut post).is_err());assert_eq!(view.storage.image.try_level,-2);}assert!(!c.returned);assert_eq!(view.machine.phase,Phase::Cleanup);
         if mode>=151{
          map_selected_regions(view.rt).unwrap();
          map_landing_context(view.rt).unwrap();
          if mode==152{view.rt.store(view.rt.resolve_absolute(0x402820,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
          if mode==153{view.rt.store(view.rt.resolve_absolute(0x402a30,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
          if mode==154{c.r[2]=CrtValue::Pointer(view.rt.resolve_absolute(delivery_target.as_ref().unwrap().image.ebp,CrtRegionKind::Stack).unwrap());}
          if mode==155{view.storage.selected_cut=None;}
          if mode==157{c.r[4]=CrtValue::Pointer(view.rt.offset(CrtCpu::pointer(c.r[4]).unwrap(),-4).unwrap());}
          let before=c.r;let jump=owned_selected_bridge(&mut view,&mut c);
          if mode==151||mode==156||mode>=158{
           let jump=jump.unwrap();assert_eq!(jump.landing.address(),0x40135c);assert_eq!(jump.owner,view.owner_frame().unwrap());assert!(jump.ticket>0);
           assert_eq!(view.rt.load(jump.slot,32).unwrap(),CrtValue::ProtectedReturn(jump.id));
           for reg in [0,1,2,3,7]{assert_eq!(c.r[reg],CrtValue::scalar(0));}assert_eq!(c.r[6],CrtValue::scalar(0x40135c));assert_eq!(c.r[5],CrtValue::Pointer(jump.owner));
           require_original_notification(view.rt,view.storage,0x40135c,1).unwrap();
           if mode==156{assert!(owned_selected_bridge(&mut view,&mut c).is_err());}
           if mode>=158{
            let slot=jump.slot;let old_entry=CrtCpu::pointer(c.entry[4]).unwrap();let saved_sp=view.rt.offset(jump.owner,-24).unwrap();let before=c.r;
            if mode==159{view.rt.store(saved_sp,32,CrtValue::scalar(view.storage.image.esp)).unwrap();}
            if mode==160{view.rt.store(view.rt.resolve_absolute(0x40135c,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
            if mode==161{view.rt.store(view.rt.offset(slot,-4).unwrap(),32,CrtValue::ProtectedReturn(jump.id)).unwrap();}
            if mode==162{view.rt.store(view.rt.offset(old_entry,24).unwrap(),32,CrtValue::ProtectedReturn(99999)).unwrap();}
            if mode==163{view.storage.selected_jump=None;}
            if mode==165{let p=view.rt.map_region(0x70000,4,CrtRegionKind::Result,None).unwrap();view.rt.store(p,32,CrtValue::Pointer(slot)).unwrap();}
            if mode==166{let p=view.rt.offset(jump.owner,-96).unwrap();view.rt.store(p,32,CrtValue::Pointer(slot)).unwrap();}
            if mode==167{let p=view.rt.map_region(0x7000,4,CrtRegionKind::Result,None).unwrap();view.rt.store(p,32,CrtValue::Pointer(slot)).unwrap();}
            if mode==164{let p=view.rt.offset(old_entry,-4).unwrap();let v=view.rt.load(p,32).unwrap();view.rt.consume_stack(p,v).unwrap();view.rt.store(p,32,CrtValue::scalar(123)).unwrap();}
            let pivot=owned_landing_pivot(&mut view,&mut c,jump);
            if mode==158||mode>=168{let mut ready=pivot.unwrap();assert_eq!(c.r[4],CrtValue::Pointer(view.rt.resolve_absolute(view.storage.image.esp,CrtRegionKind::Stack).unwrap()));assert!(view.storage.pair_return.is_none());assert!(view.rt.load(slot,32).unwrap().known_scalar().is_err());assert!(view.rt.load(old_entry,32).unwrap().known_scalar().is_err());assert!(!c.returned);
             assert!(!view.rt.tags.values().any(|v|matches!(v,CrtValue::Pointer(p) if p.cap==slot.cap&&p.address()>=slot.address()&&p.address()<view.storage.image.esp)));
             if mode==168{ready.event+=1;}
             if mode==169{view.rt.store(view.rt.resolve_absolute(0x40135f,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
             if mode==170{let p=view.rt.offset(ready.owner,-560).unwrap();view.rt.store(p,32,CrtValue::Pointer(slot)).unwrap();}
             if mode==171{c.r[4]=CrtValue::scalar(ready.sp.address());}
             let guard=view.rt.offset(ready.owner,-28).unwrap();let guard_before=view.rt.load(guard,32).unwrap();
             let untouched=view.rt.offset(ready.owner,-744).unwrap();let untouched_before=view.rt.load(untouched,32).unwrap();
             c.flags=CrtFlags{cf:Some(true),zf:None,sf:Some(false),of:Some(true)};
             let before=c.r;let prepared=owned_landing_context(&mut view,&mut c,ready);
             assert_eq!(view.rt.load(guard,32).unwrap(),guard_before);assert_eq!(view.rt.load(untouched,32).unwrap(),untouched_before);
             assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),None,Some(false),Some(true)));
             if mode==158{let prepared=prepared.unwrap();assert!(view.storage.selected_jump.is_none());assert_eq!(view.rt.load(view.rt.offset(prepared.ready.owner,-752).unwrap(),32).unwrap(),CrtValue::scalar(1));assert_eq!(view.rt.load(view.rt.offset(prepared.context,176).unwrap(),32).unwrap(),CrtValue::scalar(77));assert_eq!(view.rt.load(view.rt.offset(prepared.context,196).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.ready.sp));assert_eq!(view.rt.load(view.rt.offset(prepared.context,180).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.ready.owner));assert_eq!(view.rt.load(view.rt.offset(prepared.context,184).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.target));assert_eq!(view.machine.phase,Phase::Cleanup);assert!(c.validate_active(view.rt).is_err());
              assert!(untouched_before.known_scalar().is_err());
              let replay=CrtLandingReady{anchor:prepared.ready.anchor,event:prepared.ready.event,source:prepared.ready.source,owner:prepared.ready.owner,sp:prepared.ready.sp,id:prepared.ready.id};
              assert!(owned_landing_context(&mut view,&mut c,replay).is_err());}
             else{assert!(prepared.is_err(),"context mode {mode}");assert_eq!(c.r,before);}
            }
            else{assert!(pivot.is_err(),"landing mode {mode}");assert_eq!(c.r,before);assert!(view.storage.pair_return.is_some());}
           }
          }else{assert!(jump.is_err());if mode!=153{assert_eq!(c.r,before);}}
         }
        }
        else{assert!(transferred.is_err());assert_eq!(view.storage.image.try_level,0);}
       }
       assert_eq!(view.registry.target_ready().unwrap(),view.storage.id);assert!(!view.machine.frames[1].live);assert_eq!(view.rt.load(view.rt.resolve_absolute(0x41c948,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(1298));assert_eq!(view.machine.owned_context,saved);continue;
      }
      if mode>=90{
       assert!(result.is_err());assert!(view.failed);
       if mode==90||mode==93||mode==122{
        assert_eq!(result.unwrap_err(),"RtlUnwind requires owned continuation and effect contract");
        let memory=&mut *view.rt;
        assert_eq!(memory.load(memory.resolve_absolute(0x41c948,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(if mode==122{83}else{1298}));
        assert_eq!(memory.load(memory.resolve_absolute(delivery_target.as_ref().unwrap().image.ebp-28,CrtRegionKind::Stack).unwrap(),32).unwrap(),CrtValue::scalar(if mode==122{113}else{118}));
        let(mut exit,completion)=retirement.take().unwrap();if mode==93{exit.completion_generation-=1;}
        drop(view);let target=delivery_target.as_mut().unwrap();let retired=target.retire_completed(&mut rt,&mut r,&mut m,completion,exit);
        if mode==90||mode==122{retired.unwrap();assert_eq!(r.target_ready().unwrap(),storage.id);assert!(!m.frames[1].live);assert!(target.validate_storage(&rt,&r,&m).is_err());storage.validate_storage(&rt,&r,&m).unwrap();}
        else{assert!(retired.is_err());assert!(m.frames[1].live);assert!(r.available().is_err());}
       }else{
        assert!(retirement.is_none());assert!(view.registry.available().is_err());assert!(view.registry.frames[1].completion.is_none());assert!(view.machine.frames[1].live);
        let expected=if mode==97||mode==98||mode==100||mode==104||(105..=107).contains(&mode)||(110..=117).contains(&mode)||mode>=119{5}else if mode==91||(94..=96).contains(&mode)||mode==101||mode==102||mode==108||mode==109||mode==118{81}else{1298};assert_eq!(view.rt.load(view.rt.resolve_absolute(0x41c948,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(expected));
       }continue;
      }
      if mode>=75{
       let error=*result.as_ref().unwrap_err();assert!(view.failed);
       if mode==75||mode==76||mode==77{assert_eq!(error,"RtlUnwind requires owned continuation and effect contract");assert_eq!(reached,if mode==77{2}else{1});}
       else{assert_ne!(error,"RtlUnwind requires owned continuation and effect contract");}
       if [78,79,80,82,87].contains(&mode){assert_eq!(reached,0);}
       if mode==86{assert_eq!(error,"unwind delivery callback stack");assert_eq!(reached,1);}
       if mode==85{assert_eq!(error,"independent target failure after write");assert_eq!(view.rt.load(marker.unwrap(),32).unwrap(),CrtValue::scalar(0xface));}
       assert_eq!(view.machine.owned_context,saved);assert_eq!(view.machine.phase,Phase::Cleanup);continue;
      }
      if mode==70||mode==72||mode==73||mode==74{assert_ne!(result.as_ref().unwrap_err(),&"RtlUnwind requires owned continuation and effect contract");}
      assert!(result.is_err());assert!(view.failed);assert!(view.storage.unwind_epoch.is_some());
      if mode==51||mode==52||mode==71{assert_eq!(result.unwrap_err(),"RtlUnwind requires owned continuation and effect contract");assert_eq!(reached,if mode==52||mode==71{2}else{1});}
      if (53..=56).contains(&mode){assert_eq!(reached,0);}if mode==74{assert_eq!(reached,1);assert_eq!(result.as_ref().unwrap_err(),&"unwind delivery callback stack");}
      if let Some(p)=marker{assert_eq!(view.rt.load(p,32).unwrap(),CrtValue::scalar(0xface));}
      if mode==57{assert_eq!(view.rt.load(view.rt.offset(context,0xb8).unwrap(),32).unwrap(),CrtValue::scalar(7));}
      if mode==58{assert_eq!(view.rt.load(view.rt.offset(delivery,0xb8).unwrap(),32).unwrap(),CrtValue::scalar(8));}
      assert_eq!(view.machine.owned_context,saved);assert_eq!(view.machine.phase,Phase::Cleanup);continue;
     }
     if (66..=69).contains(&mode){
      // Explicit API continuation input, distinct from an executed API. The
      // original prolog, argument pushes, POPs and RET still execute natively.
      let old=c.r;let result=view.call(&mut c,0x402337,|f,wrapper|original_global_tail_cut(f,wrapper,&input,(mode-66)as u32));
      if mode==66{assert_eq!(result.unwrap(),CrtValue::scalar(0));for reg in [3,5,6,7]{assert_eq!(c.r[reg],old[reg]);}assert!(c.flags.zf.is_none());for reg in [1,2]{assert!(c.r[reg].known_scalar().is_err());}}
      else{assert!(result.is_err());assert!(view.failed);}
      assert_eq!(view.machine.owned_context,saved);assert_eq!(view.machine.phase,Phase::Cleanup);continue;
     }
     if mode==50{view.rt.store(view.rt.offset(record,4).unwrap(),32,CrtValue::scalar(2)).unwrap();assert!(input.validate(&view,&c).is_err());assert_eq!(view.rt.load(view.rt.offset(record,4).unwrap(),32).unwrap(),CrtValue::scalar(2));assert_eq!(view.machine.owned_context,saved);continue;}
     if mode==42{
      let sp=CrtCpu::pointer(c.r[4]).unwrap();let old=c.r;let result=view.call(&mut c,0x402337,|f,child|original_global_to_api(f,child,&input));
      assert_eq!(result.unwrap_err(),"RtlUnwind requires owned continuation and effect contract");assert!(view.failed);
      assert_eq!(c.r[4],CrtValue::Pointer(view.rt.offset(sp,-36).unwrap()));let transient=view.rt.load(view.rt.offset(sp,-4).unwrap(),32).unwrap();assert!(matches!(transient,CrtValue::ProtectedReturn(id) if id!=return_id)); // transient CALL remains live on failure
      assert_eq!(view.storage.image.try_level,0);assert_eq!(view.machine.owned_context,saved);assert_eq!(c.r[3],old[3]);continue;
     }
     if (43..=49).contains(&mode){
      // Separate original MOV fragment entry; no claim that RtlUnwind returned.
      let mut fragment=CrtCpu::new(bridge_sp,return_id).unwrap();fragment.r[0]=CrtValue::Pointer(view.rt.offset(bp,-16).unwrap());fragment.r[3]=CrtValue::scalar((-2i32)as u32);
      if mode==44{fragment.r[0]=CrtValue::scalar(view.storage.image.record);}
      if mode==45{fragment.r[0]=CrtValue::Pointer(hbp);}
      if mode==46{fragment.r[3]=CrtValue::Scalar{bits:0,known:0};}
      if mode==47{fragment.r[3]=CrtValue::scalar(1);}
      let result=if mode==49{fragment.r[1]=fragment.r[0];fragment.r[2]=fragment.r[3];owned_permuted_scope_store(&mut view,&fragment)}else{owned_selected_scope_store(&mut view,&fragment)};
      if (44..=47).contains(&mode){assert!(result.is_err());assert_eq!(view.storage.image.try_level,0);assert_eq!(view.rt.load(view.rt.offset(bp,-4).unwrap(),32).unwrap(),CrtValue::scalar(0));continue;}
      result.unwrap();assert_eq!(view.storage.image.try_level,-2);assert_eq!(view.rt.load(view.rt.offset(bp,-4).unwrap(),32).unwrap(),CrtValue::scalar((-2i32)as u32));
      if mode==48{assert!(owned_selected_scope_store(&mut view,&fragment).is_err());}
      assert_eq!(view.machine.phase,Phase::Cleanup);assert_eq!(view.machine.owned_context,saved);
      drop(view);assert!(m.restore_owned(0x40135c,|_,_|panic!("scope store cannot authorize restoration")).is_err());assert_eq!(m.owned_context,saved);continue;
     }
     drop(view);
     assert!(m.restore_owned(0x40135c,|_,_|panic!("search cannot authorize restoration")).is_err());assert_eq!(m.owned_context,saved);
     continue;
    }
    // Target-selection/caller-setup is still an explicit cut, not original table dispatch.
    c.r[1]=CrtValue::Pointer(target);c.r[2]=CrtValue::Pointer(bp);
    let value=view.call(&mut c,0x402400,|f,child|owned_filter_bridge(f,child,target,&target_code,|g,k|{owned_main_filter(g,k)?;k.finish(g.rt)})).unwrap();
    assert_eq!(value,CrtValue::scalar(1));for offset in [-776,-780]{assert_eq!(view.read(offset).unwrap(),CrtValue::scalar(0xe0424242));}
    input.validate(&view,&c).unwrap();assert_eq!(view.rt.load(bridge_sp,32).unwrap(),CrtValue::ProtectedReturn(return_id));continue;
   }
   owned_handler_prolog(&mut view,&mut c).unwrap();input.validate(&view,&c).unwrap();
   assert_eq!(c.r[5],CrtValue::Pointer(view.rt.offset(bridge_sp,-4).unwrap()));assert_eq!(c.r[4],CrtValue::Pointer(view.rt.offset(bridge_sp,-32).unwrap()));
   assert_eq!(view.rt.load(view.rt.offset(bridge_sp,-4).unwrap(),32).unwrap(),before[5]);continue;
  }
  if mode==7{let before=view.rt.load(view.rt.offset(bp,-796).unwrap(),32).unwrap();assert!(view.write_u32(-796,0).is_err());assert_eq!(view.rt.load(view.rt.offset(bp,-796).unwrap(),32).unwrap(),before);continue;}
  let result=owned_filter_bridge(&mut view,&mut c,target,&target_code,|f,k|{assert_eq!(k.r[5],CrtValue::Pointer(bp));owned_main_filter(f,k)?;k.finish(f.rt)});
  if mode==0{
   assert_eq!(result.unwrap(),CrtValue::scalar(1));
   for offset in [-776,-780]{assert_eq!(view.rt.load(view.rt.offset(bp,offset).unwrap(),32).unwrap().known_scalar().unwrap(),0xe0424242);}
   assert!(matches!(view.storage.image.words.get(&-780),Some(FrameWord::Unknown))); // cache has no write authority
   assert_eq!(view.machine.phase,Phase::Cleanup);assert_eq!(view.rt.load(entry,32).unwrap(),CrtValue::ProtectedReturn(71));
  }else{assert!(result.is_err(),"owned mode {mode}");}
 }
}

fn duplicate_notify_return(rt:&mut CrtStreamRuntime,s:&mut CrtOwnedStorage,r:&mut LocalRecord<'_>,cpu:&mut CrtCpu,target:u32,reason:u32)->RegistryResult<CrtValue>{
 rt.store(rt.resolve_absolute(0xa400,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(cpu.return_id))?;original_notify_child(rt,s,r,cpu,target,reason)
}
fn delivery_cpu(frame:&mut CrtOwnedFrameView<'_>,sp:CrtPointer,id:u64,record:CrtPointer,context:CrtPointer)->RegistryResult<CrtCpu>{
 frame.rt.store(sp,32,CrtValue::ProtectedReturn(id))?;let owner=frame.rt.resolve_absolute(frame.storage.image.record,CrtRegionKind::Stack)?;
 for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(owner),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){frame.rt.store(frame.rt.offset(sp,4+i as i64*4)?,32,v)?;}
 CrtCpu::new(sp,id)
}

fn path_edges(){
 let(m,r,_,_)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let sp=rt.resolve_absolute(0xc000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(901)).unwrap();
 for value in [Some(0),Some(1),None]{let mut c=CrtCpu::new(sp,901).unwrap();c.r[0]=value.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{bits:0,known:0});let before=c.r;
  let result=native_path_edge(&mut rt,&mut c);if value==Some(0){result.unwrap();}else{assert!(result.is_err());}assert_eq!(c.r,before);assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(901));}
 let mut c=CrtCpu::new(sp,901).unwrap();let original=c.r[3];
 let failure=c.call_activation(&mut rt,0x402855,0,|rt,k|{k.r[3]=CrtValue::scalar(0);k.r[0]=CrtValue::scalar(0);k.finish(rt)});
 assert_eq!(failure.unwrap_err(),"CRT callee saved restoration");assert_ne!(c.r[3],original);
 let _=m;
}
fn live_dispatch(){
 for mode in 0..37 {
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let outer=m.owned_context;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;let saved=c.r;
   let record=rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;let context=rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
   for(offset,value)in [(0,event.code),(4,0),(8,0),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
   rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9500))?;
   let objects=CrtNormalObjects::bind(&event,&rt,e,record,context)?;
   let mut d=cpu(&mut rt,0xc000,200);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
   for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,v)?;}
   let file=rt.file();let mut lease=None;
   if mode==18||mode==19{
    lease=Some(rt.lock(rt.thread)?);let holder=rt.map_region(0x52000,4,CrtRegionKind::Result,None)?;
    rt.store(holder,32,if mode==19{CrtValue::scalar(0)}else{CrtValue::Pointer(file)})?;
    rt.store(b.at(&rt,12)?,32,CrtValue::Pointer(holder))?;
   }
   rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;
   if mode==20{event.generation+=1;}
   if mode==21{event.frame.generation+=1;}
   if mode==22{rt.memory.release(context.cap,context.owner).map_err(|_|"test release")?;}
   let result=event.execute_context_checked_live_handler(&objects,&mut rt,&c,e,&b,&mut d,0x401900,|view,h|{
    assert!(!(20..=22).contains(&mode),"invalid event/object reached callback");
    if mode>=30{
     let feature=view.rt.map_region(0x41ccb8,4,CrtRegionKind::Module,Some(&1u32.to_le_bytes()))?;
     let entry=h.r[4];let before=h.entry;
     if mode==31{view.rt.store(feature,32,CrtValue::Scalar{bits:0,known:0})?;}
     if mode!=31{view.rt.map_region(0x41b400,16,CrtRegionKind::Module,Some(&original_scope_header().into_iter().flat_map(i32::to_le_bytes).collect::<Vec<_>>()))?;}
     if mode==32{let table_word=view.rt.resolve_absolute(0x41b408,CrtRegionKind::Module)?;view.rt.store(table_word,32,CrtValue::scalar(0))?;}
     if mode==33{let selector=view.rt.resolve_absolute(0x415128,CrtRegionKind::Module)?;view.rt.store(selector,32,CrtValue::Scalar{bits:0,known:0})?;}
     let front=if mode!=31{original_prefix_caller(view,h,&objects)}else{original_prefix_front(view,h,&objects)};
     if mode==30||mode>=34{front?;}else{assert!(front.is_err());}

     let bp=CrtCpu::pointer(h.r[5])?;
     assert_eq!(h.r[4],CrtValue::Pointer(view.rt.offset(bp,match mode{30|34..=36=>-40,31=>-44,32=>-52,_=>-56})?));
     if mode==31{assert_eq!(view.rt.load(CrtCpu::pointer(h.r[4])?,32)?.known_scalar()?,0xe0420042);}
     if mode==30||mode>=34{
      let pair=CrtHandlerPair::from_installed(view,h,&objects)?;assert_eq!(pair.read(view,h)?,(record,context));
      let expected=bytes_for_native_filter();
      let target=view.rt.map_region(0x413333,expected.len()as u32,CrtRegionKind::Module,Some(&expected))?;
      let before=[h.r[3],h.r[5],h.r[6],h.r[7]];
      h.r[1]=CrtValue::Pointer(target);h.r[2]=CrtValue::Pointer(b.at(view.rt,b.layout.bp)?);
      if mode==34{h.r[1]=CrtValue::scalar(target.address());}
      if mode==35{view.rt.store(target,8,CrtValue::scalar(0x90))?;}
      let filter=pair.call_filter(view,h,0x402300,|f,k,_,_|original_filter_bridge(f,k,target,&expected,|f,k|{
       assert_eq!(k.r[5],CrtValue::Pointer(b.at(f.rt,b.layout.bp)?));for r in [0,2,3,6,7]{assert_eq!(k.r[r],CrtValue::scalar(0));}
       if mode==36{f.write_u32(-28,95)?;return Err("independent actual bridge callee failure");}
       decoded_filter(f,k)?;k.finish(f.rt)
      }));
      if mode>=34{assert!(filter.is_err());assert_eq!(view.rt.load(marker,32)?.known_scalar()?,if mode==36{95}else{91});return Err("rejected original filter bridge binding/callback");}
      let filter=filter?;assert_eq!(filter,CrtValue::scalar(1));assert_eq!([h.r[3],h.r[5],h.r[6],h.r[7]],before);view.write_u32(-28,91)?;
      assert_eq!(view.rt.load(view.rt.offset(bp,-8)?,32)?,CrtValue::Pointer(view.rt.resolve_absolute(0x41b400,CrtRegionKind::Module)?));
      assert_eq!(view.rt.load(view.rt.offset(bp,-16)?,32)?,CrtValue::Pointer(b.at(view.rt,b.layout.bp)?));
      assert_eq!(h.r[6],CrtValue::Pointer(b.at(view.rt,b.layout.bp)?));assert_eq!(h.r[7].known_scalar()?,0);
      assert!(view.rt.load(view.rt.offset(bp,-44)?,32)?.known_scalar().is_err());
     }
     assert_eq!(view.rt.load(view.rt.offset(bp,-32)?,32)?,before[3]);
     assert_eq!(view.rt.load(view.rt.offset(bp,-36)?,32)?,before[6]);
     assert_eq!(view.rt.load(view.rt.offset(bp,-40)?,32)?,before[7]);
     assert_eq!(view.rt.load(view.rt.offset(bp,-12)?,32)?.known_scalar()?,1);
     assert_eq!(view.rt.load(view.rt.offset(bp,-1)?,8)?.known_scalar()?,0);
     assert_eq!(view.rt.load(record,32)?.known_scalar()?,0xe0420042);assert_ne!(h.r[4],entry);
     if mode!=31{assert_eq!(view.rt.load(feature,32)?.known_scalar()?,1);}else{assert!(view.rt.load(feature,32)?.known_scalar().is_err());}
     return Err("prefix front reached deferred guard/context caller boundary");
    }
    if mode==0||mode>=27 {
     // Original PUSH EBP; MOV EBP,ESP; SUB ESP,28 effects. The full
     // original handler prefix and its helper calls remain a separate gate.
     original_handler_prolog(view,h)?;
     let mut pair=CrtHandlerPair::bind(view,h,&objects)?;let old_bx=h.r[3];
     let feature=view.rt.map_region(0x41ccb8,4,CrtRegionKind::Module,None)?;
     let before=h.r;assert!(original_normalizer_call(view,h,&objects,0x40222e).is_err());assert_eq!(h.r,before);
     for value in [0,1,u32::MAX]{
      view.rt.store(feature,32,CrtValue::scalar(value))?;
      assert_eq!(original_normalizer_call(view,h,&objects,0x40222e)?,CrtValue::scalar(0xe0420042));
      assert!(h.r[1].known_scalar().is_err());assert!(h.r[2].known_scalar().is_err());assert_eq!(h.flags.zf,None);
     }
     let table=view.rt.map_region(0x41b400,16,CrtRegionKind::Module,Some(&original_scope_header().into_iter().flat_map(i32::to_le_bytes).collect::<Vec<_>>()))?;
     original_guard_call(view,h,0x402249)?;
     let table_word=view.rt.offset(table,8)?;let before=h.r;view.rt.store(table_word,32,CrtValue::scalar((-40i32)as u32))?;
     assert!(original_guard_call(view,h,0x402249).is_err());assert_eq!(h.r,before);view.rt.store(table_word,32,CrtValue::scalar((-44i32)as u32))?;
     view.rt.store(table_word,32,CrtValue::Scalar{bits:0,known:0})?;assert!(original_guard_call(view,h,0x402249).is_err());view.rt.store(table_word,32,CrtValue::scalar((-44i32)as u32))?;
     let guard_word=b.at(view.rt,b.layout.guard)?;let guard_value=view.rt.load(guard_word,32)?;view.rt.store(guard_word,32,CrtValue::scalar(0))?;
     assert!(original_guard_call(view,h,0x402249).is_err());view.rt.store(guard_word,32,guard_value)?;
     original_guard_call(view,h,0x402249)?;
     h.r[0]=CrtValue::Pointer(record);h.r[3]=CrtValue::Pointer(b.at(view.rt,b.layout.record)?);
     live_install(&mut pair,view,h)?;let(actual_record,actual_context)=pair.read(view,h)?;
     assert_eq!(view.rt.load(actual_record,32)?.known_scalar()?,0xe0420042);
     assert_eq!(view.rt.load(view.rt.offset(actual_context,0xc4)?,32)?.known_scalar()?,0x9500);
     let filter=pair.call_filter(view,h,0x402300,|borrowed,k,r,c|{
      assert_eq!(borrowed.rt.load(r,32)?.known_scalar()?,0xe0420042);
      assert_eq!(borrowed.rt.load(borrowed.rt.offset(c,0xc4)?,32)?.known_scalar()?,0x9500);
      if mode>=27{
       borrowed.write_u32(-28,95)?;
       if mode==27{borrowed.write_u32(-20,0)?;}
       if mode==28{borrowed.rt.store(borrowed.rt.offset(pair.low,4)?,32,CrtValue::scalar(0))?;}
       if mode==29{borrowed.rt.store(r,32,CrtValue::scalar(0))?;let result=decoded_filter(borrowed,k);assert_eq!(result,Err("live filter event proof boundary"));return result;}
      }
      assert!(pair.read(borrowed,k).is_err()); // child cannot impersonate owner
      if mode==0{assert_eq!(decoded_filter(borrowed,k)?,CrtValue::scalar(1));assert_eq!(borrowed.read_u32(-28)?,0xe0420042);borrowed.write_u32(-28,91)?;}
      else{k.r[0]=CrtValue::scalar(1);}k.finish(borrowed.rt)
     })?;assert_eq!(filter,CrtValue::scalar(1));pair.read(view,h)?;
     if mode==0{
      let rejected=pair.call_filter(view,h,0x402310,|borrowed,k,_,_|{assert_eq!(decoded_false_filter(borrowed,k)?,CrtValue::scalar(0));k.finish(borrowed.rt)})?;
      assert_eq!(rejected,CrtValue::scalar(0));assert_eq!(view.read_u32(-28)?,0xe0420042);view.write_u32(-28,91)?;
     }
     assert!(live_install(&mut pair,view,h).is_err());
     let original_sp=h.r[4];let foreign=runtime(view.epoch.registry);h.r[4]=CrtValue::Pointer(foreign.resolve_absolute(pair.low.address(),CrtRegionKind::Stack)?);
     assert!(pair.read(view,h).is_err(),"foreign stack address accepted");h.r[4]=original_sp;
     let prior=h.return_id;h.return_id+=1;assert!(pair.read(view,h).is_err());h.return_id=prior;
     view.write_u32(-20,0)?;assert!(pair.read(view,h).is_err());view.write(-20,CrtValue::Pointer(pair.low))?;
     h.r[3]=old_bx;h.leave(view.rt)?;assert!(pair.read(view,h).is_err());
     let returned_bp=h.r[5];h.r[5]=CrtValue::Pointer(pair.bp);assert!(pair.read(view,h).is_err());h.r[5]=returned_bp;
    }
    assert_eq!(view.read_u32(-28)?,91);view.write_u32(-28,92)?;
    // A typed alias observes immediate bytes, before callback completion.
    assert_eq!(view.rt.load(marker,32)?.known_scalar()?,92);
    if mode==23{
     assert!(view.call(h,0x401910,|child,_|{child.write_u32(-28,95)?;Err("nested failure cannot be swallowed")}).is_err());
     return Ok(CrtValue::scalar(0));
    }
    if mode==24{h.return_id+=1;return view.call(h,0x401910,|_,_|panic!("foreign activation accepted"));}
    if mode==25{let foreign=runtime(view.epoch.registry);let p=foreign.resolve_absolute(marker.address(),CrtRegionKind::Stack)?;return view.write(-28,CrtValue::Pointer(p)).map(|_|CrtValue::scalar(0));}
    if mode==1{return view.write_u32(-16,0).map(|_|CrtValue::scalar(0));} // predecessor
    if mode==2{return view.write_u32(-32,0).map(|_|CrtValue::scalar(0));} // saved EBX
    if mode==3{return view.write_u32(-27,0).map(|_|CrtValue::scalar(0));} // partial word
    if mode==4{return view.write_u32(i32::MAX,0).map(|_|CrtValue::scalar(0));}
    if mode==5{view.write(-28,CrtValue::Scalar{bits:0x42,known:255})?;return view.read_u32(-28).map(CrtValue::scalar);}
    if mode==6{view.rt.store(b.at(view.rt,b.layout.level)?,32,CrtValue::scalar(7))?;return view.validate().map(|_|CrtValue::scalar(0));}
    if mode==7{view.state.calls=4096;assert!(view.call(h,0x401910,|_,_|panic!("budget bypass")).is_err());h.r[0]=CrtValue::scalar(0);return h.finish(view.rt);}
    if mode==8{view.state.depth=32;return view.call(h,0x401910,|_,_|panic!("depth bypass"));}
    if mode==9{view.write_stack(-20,-28)?;assert_eq!(view.read(-20)?,CrtValue::Pointer(marker));return view.write_u32(-24,0).map(|_|CrtValue::scalar(0));} // saved ESP
    if mode==10{h.r[4]=view.interrupted.r[4];return view.call(h,0x401910,|_,_|panic!("alias bypass"));}
    if mode==11{return view.call(h,0x600000,|_,_|panic!("module bypass"));}
    h.r[0]=CrtValue::Pointer(b.at(view.rt,b.layout.record)?);let ebx=h.r[3];h.r[3]=CrtValue::scalar((-2i32)as u32);
    if mode==12{h.r[0]=CrtValue::Pointer(marker);}
    if mode==26{h.r[0]=CrtValue::scalar(b.at(view.rt,b.layout.record)?.address());}
    if mode==13{h.r[3]=CrtValue::Scalar{bits:0,known:255};}
    original_scope_store(view,h)?;h.r[3]=ebx;
    assert_eq!(view.rt.load(b.at(view.rt,b.layout.level)?,32)?.known_scalar()?,(-2i32)as u32);
    assert_eq!(view.event.dispatch_source(view.rt,view.interrupted,view.epoch,view.binding)?.try_level,-2);
    if mode==14{return view.store_try_level(0,1).map(|_|CrtValue::scalar(0));}
    view.call(h,0x401910,|child,n|{
     assert_eq!(child.state.depth,2);assert_eq!(child.read_u32(-28)?,92);
     n.r[1]=CrtValue::Pointer(b.at(child.rt,b.layout.record)?);n.r[2]=CrtValue::scalar(1);
     permuted_scope_store(child,n)?;child.write_u32(-28,93)?;
     // A deeper cleanup/helper sees both preceding original stores.
     child.call(n,0x401920,|deep,k|{
      assert_eq!(deep.state.depth,3);assert_eq!(deep.read_u32(-28)?,93);
      deep.store_try_level(1,-2)?;deep.write_u32(-28,94)?;
      if mode==15{return Err("independent nested cleanup failure");}
      k.r[0]=CrtValue::scalar(1);k.finish(deep.rt)
     })?;
     n.r[0]=CrtValue::scalar(1);n.finish(child.rt)
    })?;
    assert_eq!(view.state.depth,1);assert_eq!(view.read_u32(-28)?,94);
    if mode==18||mode==19{
     let original_bp=h.r[5];h.r[5]=CrtValue::Pointer(b.at(view.rt,b.layout.bp)?);
     view.call(h,0x404694,|cleanup,k|file_run_cleanup(cleanup.rt,k,file,&mut lease))?;
     h.r[5]=original_bp;assert!(lease.is_none());
    }
    if mode==16{view.rt.store(b.at(view.rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?;}
    h.r[0]=CrtValue::scalar(1);h.finish(view.rt)
   });
   assert_eq!(c.r,saved);
   if mode==0||mode==17||mode==18{
    let receipt=result?;
    assert_eq!(rt.load(marker,32)?.known_scalar()?,94);assert_eq!(receipt.level,-2);
    if mode==17{rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;assert!(event.take_handler_result(receipt,&rt,&c,e,&b).is_err());}
    else {assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b)?,1);assert!(e.state().is_err());}
   }else if (20..=22).contains(&mode){
    assert!(result.is_err());assert_eq!(event.delivery,CrtNormalDelivery::Pending);assert_eq!(rt.load(marker,32)?.known_scalar()?,91);
   }else{
    assert!(result.is_err(),"mode {mode}");assert_eq!(event.delivery,CrtNormalDelivery::Failed);
    if mode!=5{assert_eq!(rt.load(marker,32)?.known_scalar()?,if mode==36{95}else if mode>=30{91}else if mode==23||mode>=27{95}else if mode==15||mode==16||mode==19{94}else{92});}
   }
   if mode==19{rt.check_lock(lease.unwrap())?;}if mode==18{assert!(rt.locks.is_empty());}
   Err::<(),_>("live handler effects still require containment/restoration proof")
  });
  assert!(result.is_err());assert_eq!(m.owned_context,outer);
 }
}

fn pending_normal_exception(){
 for flags in [0u32,1]{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let original=m.owned_context;
  assert_eq!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let lease=rt.lock(rt.thread)?;rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,flags,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   if flags==0{c.flags=CrtFlags::unknown();}
   let call_flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
   let registers=c.r;let before=CrtCpu::pointer(c.r[4])?;
   let pending=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   pending.validate_pending(&rt,e)?;
   let source=pending.dispatch_source(&rt,&c,e,&b)?;
   assert_eq!(source.try_level,0);assert_eq!(source.record,b.at(&rt,b.layout.record)?.address());
   assert_eq!(source.words.get(&-32),None); // ordinary writes are not promoted to protected metadata
   let flags_before=c.flags;c.flags.cf=Some(!c.flags.cf.unwrap_or(false));
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());c.flags=flags_before;
   let reg=c.r[0];c.r[0]=CrtValue::scalar(123);assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());c.r[0]=reg;
   let cookie=rt.resolve_absolute(b.layout.cookie_address,CrtRegionKind::Module)?;
   let value=rt.load(cookie,32)?;rt.store(cookie,32,CrtValue::scalar(0))?;
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(cookie,32,value)?;
   let scope=b.at(&rt,b.layout.scope_slot)?;let value=rt.load(scope,32)?;
   rt.store(scope,32,CrtValue::scalar(0))?;assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(scope,32,value)?;
   let saved=b.at(&rt,-36)?;let value=rt.load(saved,32)?;
   rt.store(saved,32,CrtValue::scalar(123))?;assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(saved,32,value)?;
   let issued_return=rt.offset(before,-4)?;let value=rt.tags.remove(&issued_return.address()).unwrap();
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.tags.insert(issued_return.address(),value);
   let frame=e.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap();frame.next=1;
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());e.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap().next=0;
   pending.dispatch_source(&rt,&c,e,&b)?;
   let foreign=runtime(e.registry);assert!(pending.validate_pending(&foreign,e).is_err());
   let issued_sp=c.r[4];assert!(CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site()).is_err());assert_eq!(c.r[4],issued_sp);
   assert_eq!(pending.call_registers,registers);assert_eq!(pending.code,0xe0420042);assert_eq!(pending.noncontinuable,flags==1);
   assert_eq!(pending.continuation,0x401806);assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(before,-4)?));
   for reg in [0,1,2,3,5,6,7]{assert_eq!(c.r[reg],registers[reg]);}
   assert_eq!((pending.call_flags.cf,pending.call_flags.zf,pending.call_flags.sf,pending.call_flags.of),call_flags);assert_eq!(rt.load(marker,32)?.known_scalar()?,91);rt.check_lock(lease)?;
   assert!(e.state().is_err());assert!(epilog_run(&mut rt,&mut c,e,&mut b).is_err());
   assert_eq!(rt.locks.len(),1);assert!(e.registry.normal_epoch.as_ref().unwrap().frames[0].installed);
   Err::<(),_>("pending delivery has no containment/dispatch certificate")
  }),Err("normal call suspended for owned exception"));
  assert_eq!(m.owned_context,original);assert!(r.normal_epoch.as_ref().unwrap().pending_exception.is_some());
 }
}
fn pending_handler_activation(){
 for mode in 0..14{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let context=m.owned_context;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut pending=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   let registers=c.r;let flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
   let mut dispatcher=cpu(&mut rt,0xc000,200);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
   for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
   if mode==4{dispatcher.r[4]=c.r[4];}
   if mode==6{rt.store(CrtCpu::pointer(dispatcher.r[4])?,32,CrtValue::Scalar{bits:0,known:0xffff})?;}
   let result=pending.execute_handler(&mut rt,&c,e,&b,&mut dispatcher,0x401900,|rt,h|{
    // Explicit native callback cut, with real protected CALL/RET. The marker
    // write must survive both success and rejection; no expected output stub.
    rt.store(marker,32,CrtValue::scalar(92))?;
    if mode==1{return Err("authored handler failure");}
    if mode==2{h.r[3]=CrtValue::scalar(777);}
    if mode==3{rt.store(b.at(rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?;}
    h.r[0]=if mode==10{CrtValue::Scalar{bits:1,known:0xffff}}else if mode==11{CrtValue::Pointer(marker)}else{CrtValue::scalar(1)};if mode==5{Ok(h.r[0])}else{h.finish(rt)}
   });
   assert_eq!(c.r,registers);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),flags);
   assert_eq!(rt.load(marker,32)?.known_scalar()?,if mode==4||mode==6{91}else{92});
   if mode==0||mode>=7{
    let mut receipt=result?;if mode!=10&&mode!=11{assert_eq!(receipt.value,CrtValue::scalar(1));}assert_eq!(receipt.frame,pending.frame);
    assert_eq!((receipt.identity,receipt.epoch,receipt.generation),(pending.identity,pending.epoch,pending.generation));
    assert_eq!(pending.delivery,CrtNormalDelivery::Returned);pending.dispatch_source(&rt,&c,e,&b)?;
    assert!(pending.execute_handler(&mut rt,&c,e,&b,&mut dispatcher,0x401900,|_,_|panic!("replayed")).is_err());
    match mode{7=>receipt.generation+=1,8=>receipt.epoch+=1,9=>receipt.identity.owner+=1,
     12=>rt.store(b.at(&rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?,13=>receipt.frame.generation+=1,_=>{}}
    let receipt_level=receipt.level;let consumed=pending.take_handler_result(receipt,&rt,&c,e,&b);
    if mode==0{assert_eq!(consumed?,1);assert_eq!(pending.delivery,CrtNormalDelivery::ResultTaken);
     let replay=CrtNormalHandlerReturn{identity:pending.identity,epoch:pending.epoch,frame:pending.frame,generation:pending.generation,level:receipt_level,value:CrtValue::scalar(1)};
     assert!(pending.take_handler_result(replay,&rt,&c,e,&b).is_err());
    }else{assert!(consumed.is_err());assert_eq!(pending.delivery,CrtNormalDelivery::Failed);}
   }else{assert!(result.is_err());assert_eq!(pending.delivery,if mode==4||mode==6{CrtNormalDelivery::Pending}else{CrtNormalDelivery::Failed});}
   assert!(e.state().is_err());assert!(epilog_run(&mut rt,&mut c,e,&mut b).is_err());
   Err::<(),_>("component callback is not a disposition/restoration proof")
  });assert!(result.is_err());assert_eq!(m.owned_context,context);
 }
}
fn captured_objects(){
 for mode in 0..7{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
   let record=rt.resolve_absolute(0x50000,CrtRegionKind::Context)?;let context=rt.resolve_absolute(0x51000,CrtRegionKind::Context)?;
   for(offset,value)in [(0,0xe0420042),(4,0),(8,0),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
   if mode!=1{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(if mode==2{0}else{0x9500}))?;}
   // Captured ESP is deliberately different from the interrupted CALL ESP;
   // all other context bytes remain unknown.
   let objects=CrtNormalObjects::bind(&event,&rt,e,record,if mode==3{record}else{context});
   if (1..=3).contains(&mode){assert!(objects.is_err());return Err("rejected captured input");}
   let objects=objects?;
   rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;
   objects.check_original_context(&event,&rt,e)?;
   let selector=rt.resolve_absolute(0x415128,CrtRegionKind::Module)?;
   rt.store(selector,32,CrtValue::Scalar{bits:0,known:0})?;assert!(objects.check_original_context(&event,&rt,e).is_err());
   rt.store(selector,32,CrtValue::scalar(0x401bf9))?;objects.check_original_context(&event,&rt,e)?;
   assert_ne!(objects.captured_esp,CrtCpu::pointer(c.r[4])?.address());
   assert_eq!(rt.load(context,32)?,CrtValue::Scalar{bits:0,known:0});
   let mut d=cpu(&mut rt,0xc000,200);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
   for(i,value)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,value)?;}
   if mode==4{rt.store(sp,32,CrtValue::Pointer(context))?;}
   if mode==6{rt.store(selector,32,CrtValue::Scalar{bits:0,known:0})?;}
   let result=event.execute_context_checked_handler(&objects,&mut rt,&c,e,&b,&mut d,0x401900,|rt,h|{
    assert_ne!(mode,6,"unproved selector reached handler body");
    if mode==5{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9600))?;}
    // The existing decoded original helper executes over the same live
    // captured objects immediately before this explicit callback body cut.
    h.r[0]=CrtValue::scalar(1);h.finish(rt)
   });
   if mode==0{let receipt=result?;assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b)?,1);}else{assert!(result.is_err());}
   assert!(e.state().is_err());Err::<(),_>("captured inputs do not prove OS delivery/resumption")
  }).is_err());
 }
}
fn reject_normal_exception(){
 for mode in 0..10{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let sp=CrtCpu::pointer(c.r[4])?;
   match mode{0=>rt.store(rt.offset(sp,4)?,32,CrtValue::scalar(2))?,1=>rt.store(rt.offset(sp,8)?,32,CrtValue::scalar(1))?,
    2=>rt.store(sp,32,CrtValue::scalar(0xf0420042))?,3=>rt.store(sp,32,CrtValue::Scalar{bits:0,known:0})?,
    4=>{c.r[4]=CrtValue::Pointer(b.at(&rt,b.layout.low)?);},_=>{}}
   let before=c.r;let generation=rt.generation;
   let mut site=raise_site();
   match mode{5=>site.continuation=0x401805,6=>site.iat=0x8000,7=>site.iat=0x401800,8=>site.iat=0x41ffff,9=>site.iat=0xffff_fffc,_=>{}}
   assert!(CrtNormalException::issue(&mut rt,&mut c,e,&b,site).is_err());
   assert_eq!(c.r,before);assert_eq!(rt.generation,generation);assert!(e.state()?.pending_exception.is_none());
   c.r[4]=CrtValue::Pointer(sp);c.discard(&mut rt,16)?;c.r[0]=CrtValue::scalar(0);epilog_run(&mut rt,&mut c,e,&mut b)?;Ok(())
  }).unwrap();
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"live-finally"=>live_finally_cases(),"owned-loop"=>owned_loop_cases(),"owned-local"=>owned_local_cases(),"owned"=>owned_main_cases(),"path-edges"=>path_edges(),"live"=>live_dispatch(),"objects"=>captured_objects(),"handler"=>pending_handler_activation(),"pending"=>pending_normal_exception(),"pending-reject"=>reject_normal_exception(),"file"=>file_scope_normal(),"file-failure"=>file_scope_failure(),"nested"=>nested_actual(),"mutations"=>mutations(),"consumed"=>consumed_mutation(),"failure"=>body_failure(),"certificate"=>wrong_certificate(),"observed"=>observed(),_=>panic!("case")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        let (p, epilog_bytes) = if let Ok(path)=std::env::var("W2L_EH4_CODE") {
            let root=std::path::Path::new(&path);
            let bytes=std::fs::read(root.join("helper.bin")).unwrap();
            let p=PrologProof::prove(Region{bytes:&bytes,origin:0x401e60},12,0x41b400,0x41c000,0x402210).unwrap();
            (p,std::fs::read(root.join("epilog.bin")).unwrap())
        }else{(prolog(),epilog_bytes())};
        let e = EpilogProof::prove(Region {bytes:&epilog_bytes,origin:0x404696}, &p).unwrap();
        let file_scope = file_scope(&p).emit_component("file_run").unwrap();
        let memory = include_str!("guest_memory.rs").split("#[cfg(test)]").next().unwrap().replace("//!", "//");
        // Reuse only the explicitly labelled completed-event fixture, not any
        // expected native result or frame projection under test.
        let fixture = emitted_literal(include_str!("thread_registry_normal_tests.rs"))
            .split("fn complete(").next().unwrap().replace("0x408000", "0x41c000");
        let raise = super::normal_frame::NormalRaiseCallProof::prove(&[0xff,0x15,0,0x50,0x41,0],0x401800,0x415000).unwrap().emit_site();
        let context_literal=bytes_hex("558bec813d28514100f91b4000741f648b0d180000008b45088b80c40000003b410872053b410476056a0d59cd295dc3");
        let context_code=match std::env::var("W2L_EH4_CODE"){Ok(path)=>std::fs::read(std::path::Path::new(&path).join("original-context-check.bin")).unwrap(),Err(_)=>context_literal};
        let context_proof=crate::handler_context::prove_context_check(&context_code,0x402877,0x415128).unwrap();
        let scope_bytes=match std::env::var("W2L_EH4_CODE") { Ok(path)=>std::fs::read(std::path::Path::new(&path).join("handler-scope-store.bin")).unwrap(), Err(_)=>vec![0x89,0x58,0x0c] };
        let scope_store=super::normal_frame::NormalScopeStoreProof::prove(&scope_bytes,0x402355).unwrap().emit("original_scope_store");
        let permuted_store=super::normal_frame::NormalScopeStoreProof::prove(&[0x89,0x51,0x0c],0x402600).unwrap().emit("permuted_scope_store");
        let owned_scope_store=super::normal_frame::NormalScopeStoreProof::prove(&scope_bytes,0x402355).unwrap().emit_owned("owned_selected_scope_store",0,-2);
        let owned_permuted_store=super::normal_frame::NormalScopeStoreProof::prove(&[0x89,0x51,0x0c],0x402600).unwrap().emit_owned("owned_permuted_scope_store",0,-2);

        let handler_bytes=|file:&str,literal:&str|match std::env::var("W2L_EH4_CODE"){Ok(path)=>std::fs::read(std::path::Path::new(&path).join(file)).unwrap(),Err(_)=>bytes_hex(literal)};
        let handler_prolog=super::normal_frame::emit_handler_prolog(&handler_bytes("handler-prolog.bin","558bec83ec1c"),0x402210).unwrap();
        let installer=crate::handler_bridge::prove_installer(&handler_bytes("handler-installer.bin","8945e48b45108945e88d45e48943fc"),0x402263,&crate::handler_bridge::InstallerLayout{handler_start:-28,handler_end:0,owner_start:-48,owner_end:0,writable_handler_words:vec![-28,-24],writable_owner_words:vec![-20]}).unwrap();
        let install=format!("fn live_install(pair:&mut CrtHandlerPair,frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<()>{{ {} }}",installer.live_body());
        let filter=crate::selection::prove_filter(&bytes_hex("8b55ec8b028b08894de48b55e433c081fa420042e00f94c0c3"),0x1333,&crate::selection::FilterLayout{start:-32,end:0,exception_pointers_offset:-20,writable_words:vec![-28]},0xe0420042).unwrap();
        let filter_source=format!("fn decoded_filter(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",filter.live_body());
        let false_filter=crate::selection::prove_filter(&bytes_hex("8b55ec8b028b08894de48b55e433c081fa430042e00f94c0c3"),0x1433,&crate::selection::FilterLayout{start:-32,end:0,exception_pointers_offset:-20,writable_words:vec![-28]},0xe0420042).unwrap();
        let false_filter_source=format!("fn decoded_false_filter(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",false_filter.live_body());
        let normalizer=handler_bytes("event-normalizer.bin","558bec51833db8cc4100018b4d087c5c81f9b40200c0740881f9b50200c0754c0fae5dfc8b45fc83f03fa8817442a9040200007507b88e0000c0c9c3a902010000742da9080400007507b8910000c0c9c3a9100800007507b8930000c0c9c3a920100000b88f0000c00f44c88bc1c9c3b8900000c0c9c3");
        assert!(crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xc00002b4).is_err());
        assert!(crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::new(),0xe0420042).is_err());
        let normalizer_source=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0420042).unwrap().normal_call("original_normalizer_call");
        let guard=handler_bytes("original-guard-validator.bin","558bec568b7508578b7d0c8b0683f8fe740d8b4e0403cf330c38e85df3ffff8b46088b4e0c03cf330c385f5e5de94af3ffff");
        let security=handler_bytes("original-security-check.bin","3b0d00c041007501c3e97c020000");
        let header_bytes=handler_bytes("file-scope-header.bin","feffffff00000000d4ffffff00000000");
        let header:[i32;4]=header_bytes.chunks_exact(4).map(|c|i32::from_le_bytes(c.try_into().unwrap())).collect::<Vec<_>>().try_into().unwrap();
        let header_source=format!("fn original_scope_header()->[i32;4]{{{:?}}}",header);
        let guard_source=p.guard_proof(&guard,0x4021d0,&security,0x40154c,header).unwrap().normal_call("original_guard_call");
        assert!(p.guard_proof(&guard,0x4021d0,&security,0x40154c,[-2,0,-40,0]).is_err());
        let prefix_bytes=handler_bytes("original-handler-prefix.bin","558bec83ec1c538b5d085657c645ff00ff33c745f401000000e8ed27010089038b5d0c8b43088d7310330500c0410056508975f08945f8e884ffffffff7510e8230600008b450883c4108b7b0cf6400466755a8945e48b45108945e88d45e48943fc");
        let prefix=crate::handler_checks::prove_prefix(&prefix_bytes,0x402210,&crate::handler_checks::Bindings{normalizer_va:0x414a1b,guard_va:0x4021d0,context_va:0x402877,cookie_va:0x41c000,installer_va:0x402263}).unwrap();
        let mut alternative_prefix=prefix_bytes.clone();alternative_prefix.splice(0..1,[0xff,0xf5]);
        let alternative=crate::handler_checks::prove_prefix(&alternative_prefix,0x40220f,&crate::handler_checks::Bindings{normalizer_va:0x414a1b,guard_va:0x4021d0,context_va:0x402877,cookie_va:0x41c000,installer_va:0x402263}).unwrap();
        assert_eq!(prefix.caller_body(),alternative.caller_body());
        let prefix_normalizer=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0420042).unwrap().prefix_call("normalizer_prefix_call");
        let prefix_front=format!("fn original_prefix_front(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu,objects:&CrtNormalObjects)->RegistryResult<()>{{frame.validate()?;objects.validate(frame.event,frame.rt,frame.epoch)?;let sp=CrtCpu::pointer(cpu.r[4])?;frame.rt.valid(frame.rt.offset(sp,-{})?,{})?;{} Ok(())}}",prefix.temporary_bytes,prefix.temporary_bytes,prefix.normalizer_front());
        let guard_prefix=p.guard_proof(&guard,0x4021d0,&security,0x40154c,header).unwrap().prefix_call("guard_prefix_call");
        let prefix_caller=format!("fn original_prefix_caller(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu,objects:&CrtNormalObjects)->RegistryResult<()>{{frame.validate()?;objects.validate(frame.event,frame.rt,frame.epoch)?;if frame.rt.load(frame.rt.offset(objects.record,4)?,32)?.known_scalar()?!=0{{return Err(\"prefix full search flags\");}}let sp=CrtCpu::pointer(cpu.r[4])?;frame.rt.valid(frame.rt.offset(sp,-{})?,{})?;{}Ok(())}}",prefix.temporary_bytes,prefix.temporary_bytes,prefix.caller_body());
        let bridge_bytes=handler_bytes("original-filter-bridge.bin","555657538bea33c033db33d233f633ffffd15b5f5e5dc3");
        let bridge=crate::unwind_bridges::prove_filter(&bridge_bytes,0x402800).unwrap();
        let bridge_native=format!("fn original_filter_bridge<F>(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu,target:CrtPointer,expected:&[u8],mut invoke:F)->RegistryResult<CrtValue> where F:FnMut(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",bridge.filter_native().unwrap());
        let target_filter=handler_bytes("main-filter-0.bin","8b55ec8b028b08898df8fcffff8b95f8fcffff8995f4fcffff33c081bdf4fcffff424242e00f94c0c3");
        let target_failure=crate::selection::prove_filter(&target_filter,0x401333,&crate::selection::FilterLayout{start:-32,end:0,exception_pointers_offset:-20,writable_words:vec![-28]},0xe0420042).err().unwrap();
        assert_eq!(target_failure,"selection: unowned frame word");
        let mut bad_bridge=bridge_bytes.clone();bad_bridge[17]=0xd0;assert!(crate::unwind_bridges::prove_filter(&bad_bridge,0x402800).is_err());
        let main_bytes=handler_bytes("main-prolog.bin","558bec6afe6818b24100681022400064a1000000005081c404fdffffa100c041003145f833c58945e4535657508d45f064a3000000008965e8");
        let main=crate::frame_proof::prove_frame(&main_bytes,0x401280,0x41c000,&std::collections::BTreeSet::from([0x41b218]),&std::collections::BTreeSet::from([0x402210])).unwrap();
        let inner_bytes=handler_bytes("Inner-prolog.bin","558bec6afe68d0b14100681022400064a1000000005083ec10535657a100c041003145f833c5508d45f064a300000000");
        let inner=crate::frame_proof::prove_frame(&inner_bytes,0x4010c0,0x41c000,&std::collections::BTreeSet::from([0x41b1d0]),&std::collections::BTreeSet::from([0x402210])).unwrap();
        let main_init=crate::crt_owned_frame::emit_initializer(&main,"initialize_main_owned");let inner_init=crate::crt_owned_frame::emit_initializer(&inner,"initialize_inner_owned");
        let local_bytes=handler_bytes("owned-local-body.bin","5356578b5424108b4424148b4c2418555250515168b027400064ff3500000000a100c0410033c489442408648925000000008b4424308b58088b4c242c33198b700c83fefe0f84460000008b54243483fafe74083bf20f86350000008d34768d5cb3108b0b89480c837b04000f85c0ffffff68010100008b4308e8a1020000b9010000008b4308e8b4020000e9a1ffffff648f050000000083c4185f5e5bc3");
        let local_proof=crate::local_unwind::prove(&local_bytes,0x402710,crate::local_unwind::Kind::Body,&crate::local_unwind::Bindings{body:0x402710,nested_handler:0x4027b0,cookie:0x41c000,notify:0x402a30,invoke:0x402a50,check_cookie:0x401990}).unwrap();
        // The body proof validates the original stack/head shape before emission.
        let mut stack_nodes=std::collections::BTreeMap::new();let mut offset=0usize;
        while offset<50{let mut decoder=iced_x86::Decoder::with_ip(32,&local_bytes[offset..50],u64::from(0x402710+offset as u32),iced_x86::DecoderOptions::NONE);let instruction=decoder.decode();let pc=instruction.ip()as u32;let node=crate::crt_stream_ir::Graph::decode_instruction(&local_bytes[offset..offset+instruction.len()],pc).unwrap();offset+=instruction.len();stack_nodes.insert(pc,node);}
        assert_eq!(offset,50);let stack_graph=crate::crt_stream_ir::Graph{origin:0x402710,end:0x402742,nodes:stack_nodes};
        let stack_entry=crate::crt_stream_emit::emit_body_with_exit(&stack_graph,|_,_|Err("local prolog call".into()),&std::collections::BTreeMap::from([(0x41c000,"CrtRegionKind::Module".into())]),64,|pc,op|match(pc,op){
         (0x402729,crate::crt_stream_ir::Op::FsPush)=>Ok("let t=&record.registry.temporary[record.active_index()?];let head=rt.thread_head(record.registry.identity.instance,t.id.generation,CrtNormalBinding::head_bits(t.previous))?;cpu.push(rt,CrtValue::ThreadHead(head))?;".into()),
         (0x40273b,crate::crt_stream_ir::Op::FsWrite(_))=>Ok("let t=&record.registry.temporary[record.active_index()?];if CrtCpu::pointer(cpu.r[4])?.address()!=t.low{return Err(\"local FS stack identity\");}record.install_head(40,0x4027b0)?;".into()),
         _=>Err("local prolog thread effect".into())},|_,_|Ok(String::new()),|_,_|Ok(None),Some(0x402742)).unwrap();
        let stack_exit_graph=crate::crt_stream_ir::Graph::decode(&local_bytes[152..],0x4027a8).unwrap();
        let stack_exit=crate::crt_stream_emit::emit_body(&stack_exit_graph,|_,_|Err("local tail call".into()),&Default::default(),32).unwrap();
        let stack_source=format!(r#"fn original_local_stack_entry(rt:&mut CrtStreamRuntime,record:&mut LocalRecord<'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{
let at=rt.resolve_absolute(0x402710,CrtRegionKind::Module)?;for(i,b)in {local_bytes:?}.into_iter().enumerate(){{if rt.load(rt.offset(at,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("local body changed");}}}}{stack_entry}
}}
fn original_local_stack_exit(rt:&mut CrtStreamRuntime,record:&mut LocalRecord<'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{
// The body proof binds original POP FS:[0] here; the rest uses ordinary lowering.
let t=&record.registry.temporary[record.active_index()?];if CrtCpu::pointer(cpu.r[4])?.address()!=t.low{{return Err("local POP FS stack");}}record.restore_previous_head()?;let v=cpu.pop(rt)?;if !matches!(v,CrtValue::ThreadHead(_)){{return Err("local POP FS authority");}}{stack_exit}
}}
fn map_local_body(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x402710,{length},CrtRegionKind::Module,Some(&{local_bytes:?}))?;Ok(())}}
"#,length=local_bytes.len());
        let mut loop_nodes=std::collections::BTreeMap::new();let mut offset=50usize;
        while offset<145{let mut d=iced_x86::Decoder::with_ip(32,&local_bytes[offset..145],u64::from(0x402710+offset as u32),iced_x86::DecoderOptions::NONE);let i=d.decode();let pc=i.ip()as u32;let node=crate::crt_stream_ir::Graph::decode_instruction(&local_bytes[offset..offset+i.len()],pc).unwrap();offset+=i.len();loop_nodes.insert(pc,node);}assert_eq!(offset,145);
        let loop_graph=crate::crt_stream_ir::Graph{origin:0x402742,end:0x4027a1,nodes:loop_nodes};
        let loop_body=crate::crt_stream_emit::emit_body_with_store(&loop_graph,|pc,target|match(pc,target){
         (0x40278a,crate::crt_stream_ir::Target::Direct(0x402a30))=>Ok("cpu.validate_active(effects.rt)?;let target=cpu.r[0].known_scalar()?;if effects.rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::scalar(0x101){return Err(\"local notify original argument\");}if fault==21{let sp=CrtCpu::pointer(cpu.r[4])?;effects.rt.store(effects.rt.offset(sp,-8)?,32,CrtValue::ProtectedReturn(7777))?;}if fault==22{effects.rt.store(CrtCpu::pointer(cpu.r[4])?,32,CrtValue::scalar(0))?;}effects.notify_call(cpu,target,0x101,0x40278f)?;cpu.validate_active(effects.rt)?;".into()),
         (0x402797,crate::crt_stream_ir::Target::Direct(0x402a50))=>Ok("cpu.validate_active(effects.rt)?;let target=cpu.r[0].known_scalar()?;let abnormal=cpu.r[1].known_scalar()?;if fault==27{cpu.r[5]=CrtValue::Pointer(effects.rt.resolve_absolute(effects.storage.image.ebp+4,CrtRegionKind::Stack)?);}effects.finally_call(cpu,target,abnormal,0x40279c)?;cpu.validate_active(effects.rt)?;".into()),
         _=>Err("local loop unbound call".into())},&Default::default(),4096,|_,_|Err("local loop unexpected thread effect".into()),|pc,_|{
         let mut out=String::new();if pc==0x402742{out.push_str("effects.decode_scope()?;");}
         if pc==0x40274d{out.push_str("if fault==16{cpu.r[1]=CrtValue::scalar(effects.record.registry.cookie_address+4);}if cpu.r[1].known_scalar()?!=effects.record.registry.cookie_address{return Err(\"local cookie address provenance\");}cpu.r[1]=CrtValue::Pointer(effects.rt.resolve_absolute(effects.record.registry.cookie_address,CrtRegionKind::Module)?);");}
         if pc==0x40274f{out.push_str("let bits=cpu.r[3].known_scalar()?;if bits!=effects.storage.image.scope_va{return Err(\"local decoded table provenance\");}cpu.r[3]=CrtValue::Pointer(effects.rt.resolve_absolute(bits,CrtRegionKind::Module)?);");}
         if pc==0x40276c{out.push_str("let level=cpu.r[6].known_scalar()? as i32;let row=effects.scope_row(level)?;if row.parent!= -2&&(row.parent<0||row.parent>=level){return Err(\"local native ranking proof\");}");}
         if pc!=0x402775&&!matches!(pc,0x40278a|0x402797){out.push_str("let rt=&mut *effects.rt;");}Ok(out)
        },|_,_|Ok(None),Some(0x4027a1),|pc,address,width|{
         if pc!=0x402775||width!=32||address.base!=Some(0)||address.index.is_some()||address.displacement!=12{return Err("local loop unexpected store".into());}
         Ok(Some("let owner=effects.rt.resolve_absolute(effects.storage.image.record,CrtRegionKind::Stack)?;if fault==17{cpu.r[0]=CrtValue::Pointer(effects.rt.offset(owner,4)?);}if cpu.r[0]!=CrtValue::Pointer(owner){return Err(\"local scope MOV destination\");}let parent=v.known_scalar()? as i32;effects.write_try_level(parent)?;".into()))
        }).unwrap();
        let native_loop=format!("fn original_native_local_loop<F,N>(effects:&mut CrtOwnedLocalEffects<'_,'_,F,N>,cpu:&mut CrtCpu,fault:usize)->RegistryResult<CrtValue> where F:FnMut(u32,i32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>,bool)->RegistryResult<()>,N:FnMut(u32,u32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>)->RegistryResult<()>{{effects.install_temporary(40,0x4027b0)?;{loop_body}}}");
        let mut corrupt=local_bytes.clone();corrupt[103]=0x10;assert!(crate::local_unwind::prove(&corrupt,0x402710,crate::local_unwind::Kind::Body,&crate::local_unwind::Bindings{body:0x402710,nested_handler:0x4027b0,cookie:0x41c000,notify:0x402a30,invoke:0x402a50,check_cookie:0x401990}).is_err());
        let local_types=crate::local_unwind::EMITTED_TYPES;
        let mut callback_source=String::new();
        for (at,add) in [(0x401100,3u8),(0x401200,7u8)]{
         let code=[0x8b,0x02,0x6b,0xc0,10,0x83,0xc0,add,0x89,0x02,0xc3];let g=crate::crt_stream_ir::Graph::decode(&code,at).unwrap();let body=crate::crt_stream_emit::emit_body(&g,|_,_|Err("independent cleanup callback has no imports".into()),&Default::default(),32).unwrap();callback_source.push_str(&format!("fn independent_cleanup_{at}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{let p=rt.resolve_absolute({at},CrtRegionKind::Module)?;for(i,byte)in {code:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=byte as u32{{return Err(\"cleanup code changed\");}}}}{body}}}"));
        }
        callback_source.push_str(r#"fn owned_callback_invoke(rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>,target:u32,marker:CrtPointer)->RegistryResult<()>{
record.validate_binding(storage.binding,&storage.image)?;let sp=rt.resolve_absolute(0x9800,CrtRegionKind::Stack)?;rt.store(sp,32,CrtValue::ProtectedReturn(941))?;let mut cpu=CrtCpu::new(sp,941)?;cpu.r[2]=CrtValue::Pointer(marker);cpu.entry=cpu.r;
cpu.call_activation(rt,0x402799,0,|rt,child|match target{0x401100=>independent_cleanup_4198656(rt,child),0x401200=>independent_cleanup_4198912(rt,child),_=>Err("independent cleanup target unbound")})?;
rt.consume_stack(sp,CrtValue::ProtectedReturn(941))?;Ok(())}"#);

        let nested_bytes=handler_bytes("owned-nested-handler.bin","8b4c2404f7410406000000b80100000074338b4424088b480833c8e87cedffff558b6818ff700cff7010ff7014e82effffff83c40c5d8b4424088b5424108902b803000000c3");
        callback_source.push_str(&format!("fn original_nested_handler_bytes()->Vec<u8>{{vec!{nested_bytes:?}}}"));
        // Actual collided-path loads and store, independently sliced from original bytes.
        let collided=&nested_bytes[0x36..0x40];
        assert_eq!(collided,&[0x8b,0x44,0x24,8,0x8b,0x54,0x24,16,0x89,2]);
        let graph=crate::crt_stream_ir::Graph::decode_linear_fragment(collided,0x4027e6).unwrap();
        let body=crate::crt_stream_emit::emit_linear_fragment(&graph,&Default::default()).unwrap();
        callback_source.push_str(&format!("fn original_collided_dispatcher_write(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{body}}}"));
        let mut mappings=String::from("fn map_original_cleanups(rt:&mut CrtStreamRuntime)->RegistryResult<()>{");
        let mut cases=String::new();
        for(name,at,hex)in [("CleanupA",0x401000,"8b4c24048b0103c003c003c003c083c001890183410407c3"),("CleanupB",0x401020,"8b4c24048b0103c003c003c003c083c00289018341040bc3"),("CleanupC",0x401040,"8b4c24048b0103c003c003c003c083c00389018341040dc3")]{
         let code=handler_bytes(&format!("owned-{name}.bin"),hex);let graph=crate::crt_stream_ir::Graph::decode(&code,at).unwrap();let body=crate::crt_stream_emit::emit_body(&graph,|_,_|Err("original cleanup has no calls".into()),&Default::default(),64).unwrap();
         callback_source.push_str(&format!("fn original_cleanup_{at}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{let p=rt.resolve_absolute({at},CrtRegionKind::Module)?;for(i,byte)in {code:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=byte as u32{{return Err(\"original cleanup code changed\");}}}}{body}}}"));
         mappings.push_str(&format!("rt.map_region({at},{},CrtRegionKind::Module,Some(&{code:?}))?;",code.len()));cases.push_str(&format!("{at}=>original_cleanup_{at}(rt,child),"));
        }
        mappings.push_str("Ok(())}");callback_source.push_str(&mappings);
        callback_source.push_str(&format!(r#"fn original_cleanup_invoke(rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>,target:u32,trace:CrtPointer)->RegistryResult<()>{{
record.validate_binding(storage.binding,&storage.image)?;require_original_notification(rt,storage,target,0x101)?;rt.valid(trace,8)?;
for offset in [0,4]{{let at=rt.offset(trace,offset)?;let relative=i32::try_from(i64::from(at.address())-i64::from(storage.image.ebp)).map_err(|_|"cleanup trace offset")?;if trace.cap!=storage.entry.cap||!storage.ordinary.contains(&relative){{return Err("cleanup trace ordinary ownership");}}}}
let sp=rt.resolve_absolute(0x9800,CrtRegionKind::Stack)?;rt.store(sp,32,CrtValue::ProtectedReturn(942))?;let mut cpu=CrtCpu::new(sp,942)?;cpu.push(rt,CrtValue::Pointer(trace))?;
cpu.call_activation(rt,0x402799,0,|rt,child|match target{{{cases}_=>Err("original cleanup target unbound")}})?;cpu.discard(rt,4)?;rt.consume_stack(sp,CrtValue::ProtectedReturn(942))?;Ok(())}}"#));
        let notification_code=handler_bytes("owned-notification.bin","5351bb70c041008b4c240c894b08894304896b0c55515058595d595bc20400");
        let invoke_bridge=handler_bytes("original-finally-bridge.bin","ffd0c3");
        let invoke_proof=crate::unwind_bridges::prove_call(&invoke_bridge,0x402a50).unwrap();assert_eq!(invoke_proof.calls.len(),1);
        callback_source.push_str(&format!("fn original_finally_bridge_bytes()->&'static[u8]{{&{invoke_bridge:?}}}fn map_finally_bridge(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x402a50,{},CrtRegionKind::Module,Some(&{invoke_bridge:?}))?;Ok(())}}",invoke_bridge.len()));
        callback_source.push_str(crate::unwind_bridges::EMITTED_TYPES);
        callback_source.push_str(&crate::crt_owned_frame::emit_notification(&notification_code,0x402a30,crate::unwind_bridges::NotificationBinding{target_word:0x41c074,action_word:0x41c078,frame_word:0x41c07c},0x40278e).unwrap());
        let selected=handler_bytes("original-selected-transfer.bin","8bea8bf18bc16a01e80302000033c033db33c933d233ffffe6");
        let binding=crate::unwind_bridges::NotificationBinding{target_word:0x41c074,action_word:0x41c078,frame_word:0x41c07c};
        callback_source.push_str(&crate::crt_owned_search::emit_selected(&selected,0x402820,&notification_code,0x402a30,binding).unwrap());
        let pivot=handler_bytes("original-landing-pivot.bin","8b65e8");callback_source.push_str(&crate::crt_owned_search::emit_landing_pivot(&pivot,0x40135c).unwrap());assert!(crate::crt_owned_search::emit_landing_pivot(&[0x8b,0x65,0xe4],0x40135c).is_err());
        let context=handler_bytes("original-landing-context.bin","c78510fdffff01000000c745fcfeffffff8d8d18fdffffc781b00000004d00000089a1c400000089a9b40000008d05a51340008981b8000000");callback_source.push_str(&crate::crt_owned_search::emit_landing_context(&context,0x40135f).unwrap());let mut bad=context.clone();bad[19]^=1;assert!(crate::crt_owned_search::emit_landing_context(&bad,0x40135f).is_err());
        callback_source.push_str(&format!("fn map_landing_context(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x40135f,{},CrtRegionKind::Module,Some(&{context:?}))?;rt.map_region(0x4013a5,1,CrtRegionKind::Module,Some(&[0x89]))?;Ok(())}}",context.len()));
        for offset in [9,24]{let mut bad=selected.clone();bad[offset]^=1;assert!(crate::crt_owned_search::emit_selected(&bad,0x402820,&notification_code,0x402a30,binding).is_err());}
        callback_source.push_str(&format!("fn map_selected_regions(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x402820,{},CrtRegionKind::Module,Some(&{selected:?}))?;rt.map_region(0x40135c,3,CrtRegionKind::Module,Some(&[0x8b,0x65,0xe8]))?;Ok(())}}",selected.len()));
        callback_source.push_str(r#"fn fixture_notify_invoke(rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>,target:u32,reason:u32,fault:usize)->RegistryResult<()>{
let sp=rt.resolve_absolute(0x9400,CrtRegionKind::Stack)?;rt.store(sp,32,CrtValue::ProtectedReturn(943))?;let mut caller=CrtCpu::new(sp,943)?;caller.r[0]=CrtValue::Pointer(rt.resolve_absolute(target,CrtRegionKind::Module)?);caller.r[5]=CrtValue::Pointer(rt.resolve_absolute(storage.image.ebp,CrtRegionKind::Stack)?);caller.entry=caller.r;
if fault==21{caller.r[0]=CrtValue::scalar(target);}
if fault==22{rt.consume_stack(sp,CrtValue::ProtectedReturn(943))?;}
if fault==23{rt.store(rt.offset(sp,-8)?,32,CrtValue::ProtectedReturn(944))?;}
original_notify_invoke(rt,storage,record,&mut caller,target,reason)?;assert_eq!(caller.r[4],CrtValue::Pointer(sp));rt.consume_stack(sp,CrtValue::ProtectedReturn(943))?;Ok(())}"#);
        let local_source=format!("fn owned_original_local(effects:&mut impl LocalUnwindEffects,target_level:i32,exception_flags:u32)->RegistryResult<Option<i32>>{{{}}}",local_proof.source);
        let owned_types=crate::crt_owned_frame::EMITTED_TYPES;
        let original_local_store=super::normal_frame::NormalScopeStoreProof::prove(&handler_bytes("local-level-store.bin","89480c"),0x402775).unwrap().emit_owned_local("original_local_level_store",0,-2);
        let main_filter=crate::selection::prove_filter(&target_filter,0x401333,&crate::selection::FilterLayout{start:main.esp_offset(),end:0,exception_pointers_offset:-20,writable_words:vec![-776,-780]},0xe0424242).unwrap();
        let owned_filter=format!("fn owned_main_filter(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{ if cpu.r[5]!=CrtValue::Pointer(frame.owner_frame()?){{return Err(\"owned filter EBP binding\");}} {} }}",main_filter.live_body());
        let owned_bridge=format!("fn owned_filter_bridge<F>(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,target:CrtPointer,expected:&[u8],mut invoke:F)->RegistryResult<CrtValue> where F:FnMut(&mut CrtOwnedFrameView<'_>,&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",bridge.filter_native().unwrap());
        let main_filter_bytes=format!("fn original_main_filter_bytes()->Vec<u8>{{vec!{:?}}}",target_filter);
        let activation_bytes=handler_bytes("main-activate.bin","c745fc00000000");
        let activation=crate::crt_owned_frame::emit_activation(&main,&activation_bytes,0x40130f,"activate_main_owned").unwrap();
        assert!(crate::crt_owned_frame::emit_activation(&main,&[0x90],0x40130f,"bad").is_err());
        let owned_prolog=super::normal_frame::emit_handler_prolog_for(&handler_bytes("handler-prolog.bin","558bec83ec1c"),0x402210,"owned_handler_prolog","CrtOwnedFrameView<'_>").unwrap();
        let main_header_bytes=handler_bytes("Main-scope-header.bin","e4ffffff00000000e4fcffff00000000");
        let main_header:[i32;4]=main_header_bytes.chunks_exact(4).map(|c|i32::from_le_bytes(c.try_into().unwrap())).collect::<Vec<_>>().try_into().unwrap();
        let owned_normalizer=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0424242).unwrap().owned_prefix_call("normalizer_prefix_call");
        let owned_guard=crate::handler_guard::prove_guard(&guard,0x4021d0,&security,0x40154c,0x41c000,main_header,&main).unwrap().owned_prefix_call("guard_prefix_call");
        let owned_context=context_proof.owned_prefix_call("context_prefix_call");
        let owned_prefix=format!(r#"mod owned_prefix_helpers{{use super::*;
{owned_normalizer}
{owned_guard}
{owned_context}
pub(super) fn execute(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,objects:&CrtOwnedPrefixInput)->RegistryResult<()>{{
 let result=(||{{objects.validate(frame,cpu)?;
  if cpu.r!=cpu.entry||frame.storage.input.is_none_or(|(pair,_,_,_)|pair.is_some()){{return Err("owned prefix original entry/already installed");}}
  {body}
  objects.installed(frame,cpu)
 }})();if result.is_err(){{frame.failed=true;}}result
}}
}}"#,body=prefix.caller_body());
        let delivery_normalizer=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0424242).unwrap().owned_delivery_prefix_call("normalizer_prefix_call");
        let delivery_context=context_proof.owned_delivery_prefix_call("context_prefix_call");
        let delivery_main_guard=crate::handler_guard::prove_guard(&guard,0x4021d0,&security,0x40154c,0x41c000,main_header,&main).unwrap().owned_prefix_call("guard_main");
        let delivery_inner_guard=crate::handler_guard::prove_guard(&guard,0x4021d0,&security,0x40154c,0x41c000,[-2,0,-48,0],&inner).unwrap().owned_prefix_call("guard_inner");
        let inner_table=handler_bytes("Inner-scope-table.bin","feffffff00000000d0ffffff00000000feffffff000000007f11400000000000000000006e114000");
        let inner_data=format!("fn original_inner_table()->Vec<u8>{{vec!{inner_table:?}}}");
        let delivery_prefix=format!(r#"mod owned_delivery_prefix_helpers{{use super::*;
{delivery_normalizer}
{delivery_main_guard}
{delivery_inner_guard}
fn guard_prefix_call(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,continuation:u32)->RegistryResult<()>{{
 match frame.scope_address(){{0x41b218=>guard_main(frame,cpu,continuation),0x41b1d0=>guard_inner(frame,cpu,continuation),_=>Err("unbound target guard proof")}}
}}
{delivery_context}
pub(super) fn main_guard_call(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,continuation:u32)->RegistryResult<()>{{guard_main(frame,cpu,continuation)}}
pub(super) fn guard_call(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,continuation:u32)->RegistryResult<()>{{guard_inner(frame,cpu,continuation)}}
pub(super) fn execute(session:&CrtOwnedUnwind<'_>,frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,token:&CrtUnwindDelivery)->RegistryResult<u32>{{
 let result=(||{{let binding=CrtOwnedDeliveryPrefix::bind(session,frame,cpu,token,{temporary})?;let objects=&binding;objects.validate_prefix_source(frame)?;{body}}})();if result.is_err(){{frame.failed=true;}}result
}}
}}"#,temporary=prefix.temporary_bytes,body=prefix.unwind_caller);
        let unwind_tail=handler_bytes("original-unwind-caller.bin","83fffe741e6800c0410056bafeffffff8bcbe88c05000056ff75f8e8f3feffff83c4088b45f45f5e5b8be55dc3");
        let wrapper=handler_bytes("original-local-wrapper.bin","558b6c24085251ff742414e8a0feffff83c40c5dc20800");
        let bindings=crate::local_unwind::Bindings{body:0x402710,nested_handler:0x4027b0,cookie:0x41c000,notify:0x402a30,invoke:0x402a50,check_cookie:0x401990};
        let wrapper_proof=crate::local_unwind::prove(&wrapper,0x402860,crate::local_unwind::Kind::Wrapper,&bindings).unwrap();assert_eq!(wrapper_proof.callee_pop_bytes,8);
        let wrapper_graph=crate::crt_stream_ir::Graph::decode(&wrapper,0x402860).unwrap();
        let wrapper_body=crate::crt_stream_emit::emit_body_with_hooks(&wrapper_graph,|pc,target|{
         if (pc,target)!=(0x40286b,crate::crt_stream_ir::Target::Direct(0x402710)){return Err("unwind wrapper unproved call".into());}
         Ok("let sp=CrtCpu::pointer(cpu.r[4])?;let owner=frame.owner_frame()?;for(i,v)in [CrtValue::scalar(frame.cookie_address()),CrtValue::Pointer(frame.rt.offset(owner,-16)?),CrtValue::scalar((-2i32)as u32)].into_iter().enumerate(){if frame.rt.load(frame.rt.offset(sp,i as i64*4)?,32)?!=v{return Err(\"local body argument provenance\");}}frame.call(cpu,0x402870,|f,body|{connected_inner_cleanup(session,f,body,token,fault,source_guard)?;Ok(body.r[0])})?;".into())
        },&Default::default(),128,|_,_|Err("unwind wrapper thread effect".into()),|_,op|Ok(if matches!(op,crate::crt_stream_ir::Op::Call(_)){String::new()}else{"let rt=&mut *frame.rt;".into()}),|_,_|Ok(None)).unwrap();
        let tail_graph=crate::crt_stream_ir::Graph::decode(&unwind_tail,0x4022bd).unwrap();
        let tail_body=crate::crt_stream_emit::emit_body_with_exit(&tail_graph,|pc,target|match(pc,target){
         (0x4022cf,crate::crt_stream_ir::Target::Direct(0x402860))=>Ok("frame.call_pop(cpu,0x4022d4,if fault==9{0}else{8},|f,child|original_local_wrapper(f,child,session,token,fault,source_guard))?;".into()),
         (0x4022d8,crate::crt_stream_ir::Target::Direct(0x4021d0))=>Ok("owned_delivery_prefix_helpers::guard_call(frame,cpu,0x4022dd)?;".into()),
         _=>Err("unwind caller unproved call".into())
        },&Default::default(),128,|_,_|Err("unwind caller thread effect".into()),|_,op|Ok(if matches!(op,crate::crt_stream_ir::Op::Call(_)){String::new()}else{"let rt=&mut *frame.rt;".into()}),|_,_|Ok(None),Some(0x4022e0)).unwrap();
        let unwind_caller=format!(r#"fn original_local_wrapper(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,session:&CrtOwnedUnwind<'_>,token:&CrtUnwindDelivery,fault:usize,source_guard:CrtPointer)->RegistryResult<CrtValue>{{
for(i,b)in {wrapper:?}.into_iter().enumerate(){{if frame.rt.load(frame.rt.offset(frame.rt.resolve_absolute(0x402860,CrtRegionKind::Module)?,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("local wrapper code changed");}}}}{wrapper_body}
}}
fn original_unwind_caller(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,session:&CrtOwnedUnwind<'_>,token:&CrtUnwindDelivery,fault:usize,source_guard:CrtPointer)->RegistryResult<CrtValue>{{
session.validate_delivery(frame,cpu,token)?;for(i,b)in {unwind_tail:?}.into_iter().enumerate(){{if frame.rt.load(frame.rt.offset(frame.rt.resolve_absolute(0x4022bd,CrtRegionKind::Module)?,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("unwind caller code changed");}}}}{tail_body}
}}
fn map_local_wrapper(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x402860,{wrapper_len},CrtRegionKind::Module,Some(&{wrapper:?}))?;Ok(())}}
"#,wrapper_len=wrapper.len());
        let main_table=handler_bytes("Main-scope-table.bin","e4ffffff00000000e4fcffff00000000feffffff331340005c134000");
        let handler_complete=handler_bytes("handler-complete.bin","558bec83ec1c538b5d085657c645ff00ff33c745f401000000e8ed27010089038b5d0c8b43088d7310330500c0410056508975f08945f8e884ffffffff7510e8230600008b450883c4108b7b0cf6400466755a8945e48b45108945e88d45e48943fc83fffe74698b4df88d47028d04478b1c818d04818b48048945ec85c974148bd6e869050000b101884dff85c078147f48eb038a4dff8bfb83fbfe75c984c9742eeb20c745f400000000eb1783fffe741e6800c0410056bafeffffff8bcbe88c05000056ff75f8e8f3feffff83c4088b45f45f5e5b8be55dc38b4508813863736de07538833dc052410000742f68c0524100e8381e010083c40485c0741b8b35c05241008bce6a01ff7508ff1528514100ffd68b75f083c4088b45088b4d0c8bd0e8090500008b450c39780c74126800c04100568bd78bc8e8120500008b450c56ff75f889580ce873feffff8b4dec83c4088bd68b4908e8b3040000cc");
        assert!(handler_complete.starts_with(&prefix_bytes));
        let dispatch_bindings=crate::handler_dispatch::Bindings{filter_bridge:0x402800,global_unwind:0x402840,local_unwind:0x402860,guard:0x4021d0,selected_transfer:0x402820,cookie:0x41c000};
        let filters=std::collections::BTreeMap::from([(0x401333,crate::selection::OriginalFilter{origin:0x401333,bytes:&target_filter})]);
        let filter_layout=crate::selection::FilterLayout{start:main.esp_offset(),end:0,exception_pointers_offset:-20,writable_words:vec![-776,-780]};
        let dispatch=crate::handler_dispatch::prove_dispatch(&handler_complete[prefix_bytes.len()..],prefix.end,&prefix,dispatch_bindings,crate::handler_dispatch::Entry::Search,&main_table,0,0xe0424242,&filters,&filter_layout,&std::collections::BTreeSet::from([0x401333,0x40135c])).unwrap();
        let owned_search=crate::crt_owned_search::emit(crate::crt_owned_search::Input{proof:&dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:main.scope_va(),table:&main_table,bridge:0x402800,filters:&filters},"owned_search_to_global_call").unwrap();
        let post_global=crate::crt_owned_search::emit_post_global(crate::crt_owned_search::Input{proof:&dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:main.scope_va(),table:&main_table,bridge:0x402800,filters:&filters},"owned_post_global_caller").unwrap();
        let mut changed_post=handler_complete[prefix_bytes.len()..].to_vec();changed_post[(0x402337-prefix.end)as usize]^=1;
        assert!(crate::crt_owned_search::emit_post_global(crate::crt_owned_search::Input{proof:&dispatch,origin:prefix.end,code:&changed_post,table_va:main.scope_va(),table:&main_table,bridge:0x402800,filters:&filters},"bad_post").is_err());
        let mut changed=handler_complete[prefix_bytes.len()..].to_vec();changed[0]^=1;
        assert!(crate::crt_owned_search::emit(crate::crt_owned_search::Input{proof:&dispatch,origin:prefix.end,code:&changed,table_va:main.scope_va(),table:&main_table,bridge:0x402800,filters:&filters},"bad").is_err());
        let mut foreign_table=main_table.clone();foreign_table[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert!(crate::crt_owned_search::emit(crate::crt_owned_search::Input{proof:&dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:main.scope_va(),table:&foreign_table,bridge:0x402800,filters:&filters},"mismatched_parent").is_err());
        let code_data=format!("fn original_main_table()->Vec<u8>{{vec!{:?}}}fn original_handler_body()->Vec<u8>{{vec!{:?}}}",main_table,&handler_complete[prefix_bytes.len()..]);
        let global_code=handler_bytes("global-wrapper.bin","558bec5356576a0052685528400051ff15405041005f5e5b5dc3");
        let global_proof=crate::unwind_bridges::prove_global(&global_code,0x402840,0x415040).unwrap();assert_eq!(global_proof.calls.len(),1);
        let global_graph=crate::crt_stream_ir::Graph::decode(&global_code,0x402840).unwrap();
        let global_body=crate::crt_stream_emit::emit_body_with_hooks(&global_graph,|pc,target|{
         assert_eq!((pc,target),(0x40284f,crate::crt_stream_ir::Target::Import(0x415040)));
         Ok("objects.validate_prefix_source(frame)?;let sp=CrtCpu::pointer(cpu.r[4])?;let owner=frame.owner_frame()?;for(i,value)in [CrtValue::Pointer(frame.rt.offset(owner,-16)?),CrtValue::scalar(0x402855),CrtValue::Pointer(objects.record),CrtValue::scalar(0)].into_iter().enumerate(){if frame.rt.load(frame.rt.offset(sp,i as i64*4)?,32)?!=value{return Err(\"original RtlUnwind argument shape\");}}return Err(\"RtlUnwind requires owned continuation and effect contract\");".into())
        },&Default::default(),64,|_,_|Err("unexpected thread effect".into()),|_,op|Ok(if matches!(op,crate::crt_stream_ir::Op::Call(_)){String::new()}else{"let rt=&mut *frame.rt;".into()}),|_,_|Ok(None)).unwrap();
        let global_source=format!("fn original_global_to_api(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,objects:&CrtOwnedPrefixInput)->RegistryResult<CrtValue>{{frame.preflight_bridge(cpu,{})?;{global_body}}}",global_proof.temporary_bytes);
        let argument_check="objects.validate_prefix_source(frame)?;let sp=CrtCpu::pointer(cpu.r[4])?;let owner=frame.owner_frame()?;for(i,value)in [CrtValue::Pointer(frame.rt.offset(owner,-16)?),CrtValue::scalar(0x402855),CrtValue::Pointer(objects.record),CrtValue::scalar(0)].into_iter().enumerate(){if frame.rt.load(frame.rt.offset(sp,i as i64*4)?,32)?!=value{return Err(\"original RtlUnwind argument shape\");}}";
        let global_private=global_proof.calls[0].entry_depth.checked_sub(4).unwrap();
        let delivery_body=crate::crt_stream_emit::emit_body_with_hooks(&global_graph,|pc,target|{
         assert_eq!((pc,target),(0x40284f,crate::crt_stream_ir::Target::Import(0x415040)));
         Ok(format!("{argument_check}let mut pending=CrtOwnedUnwind::begin(frame,cpu,objects,{global_private})?;let cut=probe(frame,cpu,&mut pending)?;if let Some(cut)=cut{{cut.apply(frame,cpu,0x402855)?;}}else{{return Err(\"RtlUnwind requires owned continuation and effect contract\");}}"))
        },&Default::default(),64,|_,_|Err("unexpected thread effect".into()),|_,op|Ok(if matches!(op,crate::crt_stream_ir::Op::Call(_)){String::new()}else{"let rt=&mut *frame.rt;".into()}),|_,_|Ok(None)).unwrap();
        let delivery_source=format!("fn original_global_delivery_cut<F>(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,objects:&CrtOwnedPrefixInput,mut probe:F)->RegistryResult<CrtValue> where F:FnMut(&mut CrtOwnedFrameView<'_>,&mut CrtCpu,&mut CrtOwnedUnwind<'_>)->RegistryResult<Option<CrtUnwindResumeCut>>{{frame.preflight_bridge(cpu,{})?;{delivery_body}}}",global_proof.temporary_bytes);
        let tail_body=crate::crt_stream_emit::emit_body_with_hooks(&global_graph,|pc,target|{
         assert_eq!((pc,target),(0x40284f,crate::crt_stream_ir::Target::Import(0x415040)));
         Ok(format!(r#"{argument_check}
// Test-only externally supplied continuation cut: no protected API CALL or
// actual API completion is claimed. Production's hook above remains rejection.
if fault==2{{let p=frame.rt.offset(sp,16)?;frame.rt.store(p,32,CrtValue::scalar(1))?;}}
if fault==3{{frame.rt.consume_stack(CrtCpu::pointer(cpu.entry[4])?,CrtValue::ProtectedReturn(cpu.return_id))?;}}
cpu.discard(frame.rt,16)?;let resume_sp=cpu.r[4];cpu.r=[CrtValue::Scalar{{bits:0,known:0}};8];cpu.r[4]=resume_sp;cpu.r[0]=CrtValue::scalar(0);cpu.flags=CrtFlags::unknown();
if fault==1{{cpu.condition(0)?;}}
"#))
        },&Default::default(),64,|_,_|Err("unexpected thread effect".into()),|_,op|Ok(if matches!(op,crate::crt_stream_ir::Op::Call(_)){String::new()}else{"let rt=&mut *frame.rt;".into()}),|_,_|Ok(None)).unwrap();
        let tail_source=format!("fn original_global_tail_cut(frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,objects:&CrtOwnedPrefixInput,fault:u32)->RegistryResult<CrtValue>{{frame.preflight_bridge(cpu,{})?;{tail_body}}}",global_proof.temporary_bytes);
        let edge_steps=[crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0x83,0xf8,1],next:Some(0x430003)},crate::crt_stream_emit::PathStep{pc:0x430003,bytes:&[0x74,5],next:Some(0x430005)},crate::crt_stream_emit::PathStep{pc:0x430005,bytes:&[0xe8,0xf6,0x0f,0,0],next:None}];
        let edge_body=crate::crt_stream_emit::emit_proved_path(&edge_steps,|_,_|Ok("return Ok(());".into()),&Default::default(),|_,_|Ok(String::new())).unwrap();
        let path_edges=format!("fn native_path_edge(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<()>{{{edge_body}}}");
        let bad_edge=[crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0x74,2],next:Some(0x430005)},crate::crt_stream_emit::PathStep{pc:0x430005,bytes:&[0xe8,0,0,0,0],next:None}];
        assert!(crate::crt_stream_emit::emit_proved_path(&bad_edge,|_,_|Ok(String::new()),&Default::default(),|_,_|Ok(String::new())).is_err());
        let repeated=[crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0xeb,0xfe],next:Some(0x430000)},crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0xeb,0xfe],next:None}];
        assert!(crate::crt_stream_emit::emit_proved_path(&repeated,|_,_|Ok(String::new()),&Default::default(),|_,_|Ok(String::new())).is_err());
        let overlapping=[crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0xeb,0xff],next:Some(0x430001)},crate::crt_stream_emit::PathStep{pc:0x430001,bytes:&[0xff,0x15,0,0x50,0x41,0],next:None}];
        assert!(crate::crt_stream_emit::emit_proved_path(&overlapping,|_,_|Ok("return Ok(());".into()),&Default::default(),|_,_|Ok(String::new())).is_err());
        let unproved_return=[crate::crt_stream_emit::PathStep{pc:0x430000,bytes:&[0xc3],next:None}];
        assert!(crate::crt_stream_emit::emit_proved_path(&unproved_return,|_,_|Ok(String::new()),&Default::default(),|_,_|Ok(String::new())).is_err());
        assert!(crate::crt_stream_ir::Graph::decode_instruction(&[0x90,0x90],0x430000).is_err());

        let owned_header=format!("fn original_main_header()->[i32;4]{{{:?}}}",main_header);
        let prefix_metadata=format!("fn owned_prefix_handler()->u32{{{}}}fn owned_prefix_temporary()->u32{{{}}}",prefix.entry,prefix.temporary_bytes);
        let context_types=crate::handler_context::EMITTED_TYPES;
        let context_check=context_proof.normal_object_check();
        let finally_source=crate::crt_finally_tests::emit();
        let finally_cases=crate::crt_finally_tests::CASES;
        let source = format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{fixture}\n{file_scope}\n{context_types}\n{context_check}\n{scope_store}\n{permuted_store}\n{install}\n{handler_prolog}\n{filter_source}\n{false_filter_source}\n{normalizer_source}\n{guard_source}\n{header_source}\n{prefix_normalizer}\n{prefix_front}\n{guard_prefix}\n{prefix_caller}\n{bridge_native}\n{local_types}\n{owned_types}\n{local_source}\n{callback_source}\n{finally_source}\n{finally_cases}\n{original_local_store}\n{main_init}\n{inner_init}\n{owned_filter}\n{owned_bridge}\n{main_filter_bytes}\n{activation}\n{owned_prolog}\n{owned_prefix}\n{delivery_prefix}
{inner_data}
{unwind_caller}
{stack_source}
{native_loop}\n{owned_header}\n{owned_scope_store}\n{owned_permuted_store}\n{global_source}\n{delivery_source}\n{tail_source}\n{owned_search}
{post_global}\n{code_data}\n{path_edges}\n{prefix_metadata}\nfn raise_site()->CrtNormalRaiseSite{{{{{raise}}}}}\n{CASES}",
            include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
            emitted_literal(include_str!("frame_proof.rs")),emitted_literal(include_str!("thread_registry.rs")),
            crate::crt_stream_runtime::EMITTED_TYPES,crate::crt_stream_cpu::EMITTED_TYPES,
            super::normal_frame::EMITTED_TYPES,p.emit("helper_run").unwrap(),e.emit("epilog_run").unwrap());
        let dir=std::env::temp_dir().join(format!("w2l-normal-native-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();let file=dir.join("run.rs");
        let binary=dir.join(if cfg!(windows){"run.exe"}else{"run"});let source=source.replace("\r\n","\n");
        if let Ok(path)=std::env::var("W2L_EH4_EVIDENCE") {std::fs::create_dir_all(&path).unwrap();std::fs::write(std::path::Path::new(&path).join("normal-wrapper.rs"),&source).unwrap();}
        std::fs::write(&file,source).unwrap();
        let build=std::process::Command::new("rustc").args(["--edition=2021","-Awarnings"]).arg(&file).arg("-o").arg(&binary).output().unwrap();
        assert!(build.status.success(),"{}",String::from_utf8_lossy(&build.stderr));binary
    });
    let output = std::process::Command::new(binary)
        .arg(case)
        .output()
        .unwrap();
    if case == "observed" {
        if let Ok(path) = std::env::var("W2L_EH4_EVIDENCE") {
            std::fs::write(
                std::path::Path::new(&path).join("normal-wrapper-results.txt"),
                &output.stdout,
            )
            .unwrap();
        }
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn original_prolog_and_epilog_execute_nested_live_registry_lifecycles() {
    run("nested");
}
#[test]
fn actual_storage_unknown_masks_foreign_arenas_and_stale_epochs_reject() {
    run("mutations");
}
#[test]
fn consumed_slot_receipts_require_actual_pop_and_restored_register() {
    run("consumed");
}
#[test]
fn unresolved_body_effects_remain_visible_and_block_completion() {
    run("failure");
}
#[test]
fn emitted_ret_immediate_cannot_use_another_registry_plan() {
    run("certificate");
}
#[test]
fn epilog_wrong_offsets_order_prefixes_and_cleanup_reject() {
    let original = epilog_bytes();
    let p = prolog();
    for (offset, value) in [
        (2, 0xf4),
        (3, 0x65),
        (10, 0x58),
        (11, 0x5e),
        (12, 0x5f),
        (13, 0x59),
        (14, 0x90),
        (16, 2),
        (17, 2),
    ] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert!(
            EpilogProof::prove(
                Region {
                    bytes: &bytes,
                    origin: 0x404696
                },
                &p
            )
            .is_err(),
            "mutation {offset}"
        );
    }
    for n in 0..original.len() {
        assert!(EpilogProof::prove(
            Region {
                bytes: &original[..n],
                origin: 0x404696
            },
            &p
        )
        .is_err());
    }
}

#[test]
#[ignore = "requires separately instrumented original Windows wrapper vectors"]
fn original_windows_wrapper_state_matches_native_normal_lifecycle() {
    run("observed");
}

#[test]
fn file_scope_original_lock_cleanup_and_epilog_execute_with_live_registry() {
    run("file");
}
#[test]
fn file_scope_unclosed_body_effects_do_not_synthesize_cleanup_or_return() {
    run("file-failure");
}

#[test]
fn file_scope_certificate_rejects_effect_and_ownership_mutations() {
    let p = prolog();
    let originals=[
        bytes_hex("8365e4008b4508ff30e8beffffff598365fc008b4d0ce8370c00008bf08975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00"),
        bytes_hex("8bff558bec8b450883c02050ff154c5041005dc3"),
        bytes_hex("8bff558bec8b450883c02050ff15505041005dc3"),
        bytes_hex("8b4510ff30e893ffffff59c3")];
    let prove = |b: &[Vec<u8>; 4]| {
        super::file_scope::FileScopeProof::prove(
            super::file_scope::Input {
                wrapper: Region {
                    bytes: &b[0],
                    origin: 0x404668,
                },
                lock: Region {
                    bytes: &b[1],
                    origin: 0x404634,
                },
                unlock: Region {
                    bytes: &b[2],
                    origin: 0x404648,
                },
                cleanup: Region {
                    bytes: &b[3],
                    origin: 0x4046ab,
                },
                enter_iat: 0x41504c,
                leave_iat: 0x415050,
                driver: 0x4052ba,
            },
            &p,
        )
    };
    assert!(prove(&originals).is_ok());
    // Independent mutations: initialized local into EH4 metadata, missing
    // activation, premature scope disable, altered callee/cleanup target,
    // partial register source, wrong lock object/ABI and unwind entry as normal.
    for (region, offset, value) in [
        (0, 2, 0xf0),
        (0, 17, 0xfe),
        (0, 32, 0xf0),
        (0, 21, 0x90),
        (0, 10, 0xbf),
        (0, 39, 0x18),
        (0, 27, 0x66),
        (1, 10, 0x24),
        (2, 14, 0x4c),
        (3, 2, 0x0c),
        (3, 6, 0x94),
    ] {
        let mut b = originals.clone();
        b[region][offset] = value;
        assert!(prove(&b).is_err(), "region {region}, offset {offset}");
    }
    for region in 0..4 {
        let mut b = originals.clone();
        b[region].pop();
        assert!(prove(&b).is_err());
    }
    let mut b = originals.clone();
    let n = b[0].len();
    b[0][n - 2] = 0;
    assert!(prove(&b).is_err());
    let mut b = originals.clone();
    b[3].splice(0..0, [0x8b, 0x75, 0xe4]);
    assert!(prove(&b).is_err());
}

#[test]
fn normal_exception_issue_preserves_guest_call_state_and_blocks_normal_cleanup() {
    run("pending");
}
#[test]
fn normal_exception_invalid_arguments_and_continuations_have_no_issue_effect() {
    run("pending-reject");
}

#[test]
fn normal_raise_certificate_requires_exact_original_call_and_disjoint_iat() {
    use super::normal_frame::NormalRaiseCallProof as Proof;
    let bytes = [0xff, 0x15, 0, 0x50, 0x41, 0];
    assert!(Proof::prove(&bytes, 0x401800, 0x415000).is_ok());
    for cut in 0..6 {
        assert!(Proof::prove(&bytes[..cut], 0x401800, 0x415000).is_err());
    }
    for offset in 0..6 {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(Proof::prove(&changed, 0x401800, 0x415000).is_err());
    }
    for origin in [0, 0xfffffffc, 0x414ffd, 0x415000, 0x415003] {
        assert!(Proof::prove(&bytes, origin, 0x415000).is_err());
    }
    for iat in [0, 0x415001, 0xfffffffc] {
        assert!(Proof::prove(&bytes, 0x401800, iat).is_err());
    }
    let mut prefixed = vec![0x66];
    prefixed.extend(bytes);
    assert!(Proof::prove(&prefixed, 0x401800, 0x415000).is_err());
}

#[test]
fn suspended_handler_call_returns_owned_receipt_and_preserves_failures() {
    run("handler");
}

#[test]
fn captured_objects_bind_live_handler_arguments_without_inventing_registers() {
    run("objects");
}

#[test]
fn live_handler_storage_nested_calls_and_failure_effects_are_coherent() {
    run("live");
}
#[test]
fn scope_store_decoder_rejects_partial_prefixed_and_unbound_operands() {
    use super::normal_frame::NormalScopeStoreProof as Proof;
    for code in [
        vec![0x66, 0x89, 0x58, 12],
        vec![0x89, 0x58, 8],
        vec![0x89, 0xd8],
        vec![0x89, 0x58, 12, 0x90],
        vec![0x89, 0x18],
        vec![0x89, 0x60, 12],
        vec![0x89, 0x58],
    ] {
        assert!(Proof::prove(&code, 0x402500).is_err());
    }
    assert!(Proof::prove(&[0x89, 0x58, 12], u32::MAX - 1).is_err());
}

#[test]
fn handler_prolog_rejects_changed_allocation_and_truncated_code() {
    for bytes in [
        vec![0x55, 0x8b, 0xec, 0x83, 0xec, 0x18],
        vec![0x55, 0x8b, 0xec],
        vec![0x55, 0x8b, 0xec, 0x83, 0xec, 0x1c, 0x90],
    ] {
        assert!(super::normal_frame::emit_handler_prolog(&bytes, 0x402210).is_err());
    }
}

#[test]
fn owned_main_frame_storage_executes_original_filter_and_rejects_other_owners() {
    run("owned");
}

#[test]
fn instruction_path_checks_reject_unknown_flags_and_disagreeing_original_edges() {
    run("path-edges");
}

#[test]
fn original_local_store_writes_canonical_owned_storage_in_live_registry_lifetime() {
    run("owned-local");
}

#[test]
fn decoded_local_loop_uses_live_storage_and_preserves_callback_failure_effects() {
    run("owned-loop");
}

#[test]
fn original_finally_dispatch_writes_live_fields_in_instruction_order() {
    run("live-finally");
}
