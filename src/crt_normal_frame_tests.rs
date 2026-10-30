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
fn runtime_stdio(r:&ThreadRegistry)->CrtStreamRuntime{let mut rt=CrtStreamRuntime::file_array(r.identity.owner,r.identity.instance,0x41c080,3,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt}
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

struct OwnedCaseTiming{mode:usize,started:std::time::Instant,enabled:bool}
impl Drop for OwnedCaseTiming{fn drop(&mut self){if self.enabled{eprintln!("owned-end {} {}",self.mode,self.started.elapsed().as_micros());}}}
fn owned_main_cases(){
 for mode in 0..202{
 let enabled=std::env::var_os("W2L_CASE_TIMINGS").is_some();if enabled{eprintln!("owned-start {mode}");}let _timing=OwnedCaseTiming{mode,started:std::time::Instant::now(),enabled};
  let mut m=Machine::new_dispatch_known((0..if mode>=75{2}else{1}).map(|_|FrameSpec{scopes:vec![]}).collect(),0,[None;10],Some(0)).unwrap();
  let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=if mode>=194{runtime_stdio(&r)}else{runtime(&r)};
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
  if mode>=183{for at in [0x41c950,0x41c954,0x41c95c]{rt.map_region(at,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();}}
  let activated=if mode>=183{let module=map_main_initial(&mut rt).unwrap();initialize_main_live(&mut rt,&r,&m,&mut storage,module)}else{activate_main_owned(&mut rt,&r,&m,&mut storage)};
  if mode==1{assert!(activated.is_err());}else{activated.unwrap();assert_eq!(rt.load(level,32).unwrap(),CrtValue::scalar(0));assert!(activate_main_owned(&mut rt,&r,&m,&mut storage).is_err());}
  let mut initial_event=None;let mut capture_alias=None;
  let mut delivery_target=if mode>=75{
   let b=m.owned_binding(1).unwrap();let sp=rt.resolve_absolute(if mode==76{0xd800}else{0xd000},CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(72)).unwrap();let mut c=CrtCpu::new(sp,72).unwrap();
   assert!(m.issue_owned_event(binding).is_err());
   let mut target=if mode>=183{initialize_initial_raise_owned(&mut rt,&mut r,&m,b,&c).unwrap()}else{initialize_inner_scalars_owned(&mut rt,&mut r,&m,b,&c).unwrap()};
   if mode>=183{map_initial_raise(&mut rt).unwrap();let event=issue_initial_raise(&mut rt,&r,&mut m,&mut target,&mut c).unwrap();capture_alias=Some(event.captured_context().clone());let before=c.r;assert!(event.captured_context().preflight(m.owner()).is_ok());assert!(issue_initial_raise(&mut rt,&r,&mut m,&mut target,&mut c).is_err());assert_eq!(c.r,before);initial_event=Some(event);assert!(initial_event.as_mut().unwrap().finish(&m,&r).is_err());assert!(initial_event.as_mut().unwrap().begin_restoration(&m,&r).is_err());}if mode==122{target.scope_store(&mut rt,&r,&m,1,0).unwrap();}Some(target)
  }else{None};
  if initial_event.is_none(){m.issue_owned_event(m.owned_binding(if mode>=75{1}else{0}).unwrap()).unwrap();}r.contain(storage.id).unwrap();
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
             if mode==158||mode>=172{let mut prepared=prepared.unwrap();assert!(view.storage.selected_jump.is_none());assert_eq!(view.rt.load(view.rt.offset(prepared.ready.owner,-752).unwrap(),32).unwrap(),CrtValue::scalar(1));assert_eq!(view.rt.load(view.rt.offset(prepared.context,176).unwrap(),32).unwrap(),CrtValue::scalar(77));assert_eq!(view.rt.load(view.rt.offset(prepared.context,196).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.ready.sp));assert_eq!(view.rt.load(view.rt.offset(prepared.context,180).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.ready.owner));assert_eq!(view.rt.load(view.rt.offset(prepared.context,184).unwrap(),32).unwrap(),CrtValue::Pointer(prepared.target));assert_eq!(view.machine.phase,Phase::Cleanup);assert!(c.validate_active(view.rt).is_err());
              if mode>=183{assert_eq!(untouched_before,CrtValue::scalar(0));}else{assert!(untouched_before.known_scalar().is_err());}
              map_context_transfer(view.rt).unwrap();let flags=c.flags;let preserved=[c.r[2],c.r[3],c.r[6],c.r[7]];
              if mode==172{prepared.ready.event+=1;}
              if mode==173{let p=view.rt.offset(prepared.context,184).unwrap();view.rt.store(p,32,CrtValue::scalar(0x4013a5)).unwrap();}
              if mode==174{view.rt.store(view.rt.resolve_absolute(0x401250,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
              if mode==175{view.rt.store(view.rt.offset(prepared.ready.sp,-4).unwrap(),32,CrtValue::ProtectedReturn(999)).unwrap();}
              if mode==176{view.rt.store(view.rt.resolve_absolute(0x4013a5,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
              if mode==177{view.storage.prepared_context=None;}
              let duplicate=CrtPreparedContext{ready:CrtLandingReady{anchor:prepared.ready.anchor,event:prepared.ready.event,source:prepared.ready.source,owner:prepared.ready.owner,sp:prepared.ready.sp,id:prepared.ready.id},context:prepared.context,target:prepared.target};
              let registers=c.r;let transfer=owned_context_transfer(&mut view,&mut c,prepared);
              if (172..178).contains(&mode){assert!(transfer.is_err(),"restore mode {mode}");assert_eq!(c.r,registers);continue;}
              let mut done=transfer.unwrap();
              assert_eq!(done.anchor,view.rt.anchor);assert_eq!(done.event,view.machine.event);assert_eq!(done.source,view.storage.id);assert_eq!(done.target.address(),0x4013a5);assert_eq!(done.registers,c.r);
              assert_eq!([c.r[2],c.r[3],c.r[6],c.r[7]],preserved);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));
              for(offset,value)in [(-756,CrtValue::scalar(77)),(-760,c.r[4]),(-764,c.r[5])]{assert_eq!(view.rt.load(view.rt.offset(CrtCpu::pointer(done.registers[5]).unwrap(),offset).unwrap(),32).unwrap(),value);}
              assert!(!c.returned);assert!(c.validate_active(view.rt).is_err());assert!(view.storage.prepared_context.is_none());assert_eq!(view.machine.phase,Phase::Cleanup);
              let replay=CrtRestoredLanding{id:done.id,anchor:done.anchor,event:done.event,source:done.source,target:done.target,registers:done.registers};
              if mode==178{done.event+=1;}
              if mode==179{c.r[0]=CrtValue::scalar(78);}
              if mode==180{let p=view.rt.offset(CrtCpu::pointer(c.r[5]).unwrap(),-756).unwrap();view.rt.store(p,32,CrtValue::scalar(78)).unwrap();}
              if mode==181{view.storage.restored_landing=None;}
              if mode==182{view.machine.owned_context.as_mut().unwrap()[3]=Some(1234);}
              if mode==184{initial_event.as_ref().unwrap().captured.lifetime.set(EventLifetime::Expired);}
              let completion=complete_owned_restoration_event(&mut view,&c,done,initial_event.as_mut());
              if (178..183).contains(&mode){assert!(completion.is_err(),"completion mode {mode}");assert_eq!(view.machine.phase,Phase::Cleanup);assert!(view.registry.normal_authority.get().is_none());continue;}
              if mode==184{assert!(completion.is_err());assert_eq!(view.machine.phase,Phase::Restore);assert!(view.registry.normal_authority.get().is_none());continue;}
              let projection=completion.unwrap();if mode>=183{assert_eq!(initial_event.as_ref().unwrap().captured.lifetime.get(),EventLifetime::Finished);assert!(capture_alias.as_ref().unwrap().preflight(view.machine.owner()).is_err());assert!(initial_event.as_ref().unwrap().normal_permit.borrow().is_some());}else{assert!(view.registry.normal_authority.get().is_none());}assert_eq!(view.machine.phase,Phase::Done);assert_eq!(projection[0],Some(77));assert_eq!(projection[4],Some(view.storage.image.esp));assert_eq!(projection[5],Some(view.storage.image.ebp));assert_eq!(projection[8],Some(0x4013a5));for i in [1,2,3,6,7,9]{assert_eq!(projection[i],None);}assert!(view.storage.restored_landing.is_none());
              if mode>=183{
               let registers=c.r;let flags=c.flags;let mut corrupted=CrtCpu::new(view.storage.entry,view.storage.return_id).unwrap();corrupted.r=c.r;assert!(bind_main_continuation(view.rt,view.registry,view.machine,view.storage,initial_event.as_ref().unwrap(),&mut corrupted).is_err());
               bind_main_continuation(view.rt,view.registry,view.machine,view.storage,initial_event.as_ref().unwrap(),&mut c).unwrap();assert_eq!(c.r,registers);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));assert_eq!(c.return_id,view.storage.return_id);c.validate_active(view.rt).unwrap();assert!(bind_main_continuation(view.rt,view.registry,view.machine,view.storage,initial_event.as_ref().unwrap(),&mut c).is_err());
               let plan=NormalReturnPlan{pops:vec![(-796,1,true),(-792,7,false),(-788,6,false),(-784,3,false),(0,5,false)],cookie_offset:-28,security_target:0x40154c,return_offset:4};
               let format=map_main_completion(view.rt).unwrap();if mode>=194{map_printf_native(view.rt).unwrap();if mode==197{view.rt.memory.forget(0x41d2ec,4).unwrap();}if mode==198{view.rt.store(view.rt.resolve_absolute(0x4045d8,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}if mode==199{view.rt.store(view.rt.resolve_absolute(0x401270,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}if mode==201{let file=view.rt.file();view.rt.memory.release(file.cap,file.owner).unwrap();}}let globals=(0..6).map(|i|view.rt.resolve_absolute(0x41c948+i*4,CrtRegionKind::Module).unwrap()).collect::<Vec<_>>();let mut calls=Vec::new();
               if mode==187{view.rt.memory.forget(globals[5].address(),4).unwrap();}
               if mode==188{view.rt.store(view.rt.resolve_absolute(0x4013b7,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
               if mode==189{let p=view.rt.offset(CrtCpu::pointer(c.r[5]).unwrap(),-748).unwrap();view.rt.store(p,32,CrtValue::scalar(0x400000)).unwrap();}
               if mode==191{view.rt.store(format,8,CrtValue::scalar(0x25)).unwrap();}
               if mode==192{view.rt.store(view.rt.resolve_absolute(0x40154c,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
               let session=NormalReturnSession::new(view.machine,view.registry,view.storage.binding,&view.storage.image,initial_event.as_ref().unwrap(),plan).unwrap();
               let mut host=CrtMainCompletion{rt:view.rt,storage:view.storage,cpu:&mut c,session,globals,format,printf_pc:0x401466,printf_target:0x401520,security_continuation:0x401518,security:original_completion_security,printf:|rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,_session:&mut NormalReturnSession<'_>,request:PrintRequest<'_>|{assert_eq!(cpu.entry[0],CrtValue::scalar(0x15180));assert_eq!(cpu.entry[1],CrtValue::scalar(0x1020));assert_eq!(cpu.entry[2],CrtValue::scalar(0x1000));assert_eq!(request.arguments.len(),17);assert_eq!(&request.arguments[..5],&[0x15180,0x1000,0x1020,0x1040,0x1250]);if mode>=194{if mode==200{let p=rt.offset(CrtCpu::pointer(cpu.r[4])?,8)?;rt.store(p,32,CrtValue::Pointer(p))?;}return original_printf(rt,cpu,_session,|rt,core,_session|{let sp=CrtCpu::pointer(core.r[4])?;for i in [4,8]{let v=rt.load(rt.offset(sp,i)?,32)?.known_scalar()?;if v!=0{return Err("printf options outside frozen basic domain");}}let file=CrtCpu::pointer(rt.load(rt.offset(sp,12)?,32)?)?;rt.file_record(file)?;assert_eq!(file.address(),0x41c0b8);assert_eq!(rt.load(file,32),Err("CRT unlocked FILE record access"));assert_eq!(rt.load(rt.offset(sp,16)?,32)?,CrtValue::Pointer(rt.resolve_absolute(request.format,CrtRegionKind::Module)?));assert_eq!(rt.load(rt.offset(sp,20)?,32)?,CrtValue::scalar(0));let args=CrtCpu::pointer(rt.load(rt.offset(sp,24)?,32)?)?;for(i,&n)in request.arguments.iter().enumerate(){if rt.load(rt.offset(args,i as i64*4)?,32)?.known_scalar()?!=n{return Err("printf actual varargs mismatch");}}calls.push(request.arguments.to_vec());if mode==196{let object=rt.offset(CrtCpu::pointer(core.r[4])?,-96)?;let result=original_formatter_to_locale_state(rt,core);assert_eq!(result,Err("CRT unknown scalar bits observed"));assert_eq!(rt.load(object,32)?,CrtValue::scalar(0));for offset in [8,20,28,36]{assert_eq!(rt.load(rt.offset(object,offset)?,8)?,CrtValue::scalar(0));}assert!(rt.load(rt.resolve_absolute(0x41ce7c,CrtRegionKind::Module)?,32)?.known_scalar().is_err());return result;}core.r[0]=CrtValue::scalar(if mode==195{u32::MAX}else{0});core.finish(rt)});}calls.push(request.arguments.to_vec());if mode==185{return Err("independent formatter failure after effect");}if mode==193{let original=rt.load(rt.resolve_absolute(_session.entry_sp,CrtRegionKind::Stack)?,32)?;let alias=rt.map_region(0x71000,4,CrtRegionKind::Result,None)?;rt.store(alias,32,original)?;}if mode==186{let p=rt.offset(CrtCpu::pointer(cpu.r[5])?,-28)?;rt.store(p,32,CrtValue::scalar(0))?;}cpu.r[0]=CrtValue::scalar(if mode==190{u32::MAX}else{0});cpu.finish(rt)}};
               let result=run_main_completion(&mut host);if (185..190).contains(&mode)||(191..194).contains(&mode)||mode>=196{assert!(result.is_err(),"completion live mode {mode}");assert!(!host.cpu.returned);assert_ne!(host.session.machine.phase,Phase::Returned);if mode==186{assert_eq!(host.cpu.r[0],CrtValue::scalar(1));}if mode==187{assert!(CrtCpu::pointer(host.cpu.r[4]).unwrap().address()<host.storage.image.esp);}drop(host);assert_eq!(view.machine.phase,Phase::Blocked);assert_eq!(calls.len(),usize::from(mode==185||mode==186||mode==192||mode==193||mode==196));continue;}let outcome=result.unwrap();let receipt=host.finish(&outcome).unwrap();assert_eq!(receipt.value,1);assert_eq!(host.session.machine.phase,Phase::Returned);assert!(host.cpu.returned);assert!(host.rt.tags.values().all(|v|*v!=CrtValue::ProtectedReturn(host.storage.return_id)));drop(host);assert_eq!(calls.len(),1);assert!(initial_event.as_ref().unwrap().take_normal_permit().is_err());continue;
              }
              assert!(complete_owned_restoration(&mut view,&c,replay).is_err());assert!(owned_context_transfer(&mut view,&mut c,duplicate).is_err());continue;}

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
    let receipt=result.expect("supported live handler must return a receipt");
    assert_eq!(rt.load(marker,32)?.known_scalar()?,94);assert_eq!(receipt.level,-2);
    if mode==17{rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;assert!(event.take_handler_result(receipt,&rt,&c,e,&b).is_err());}
    else {assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b).expect("supported live result must be consumed"),1);assert!(e.state().is_err());}
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
    let mut receipt=result.expect("supported handler must return a receipt");if mode!=10&&mode!=11{assert_eq!(receipt.value,CrtValue::scalar(1));}assert_eq!(receipt.frame,pending.frame);
    assert_eq!((receipt.identity,receipt.epoch,receipt.generation),(pending.identity,pending.epoch,pending.generation));
    assert_eq!(pending.delivery,CrtNormalDelivery::Returned);pending.dispatch_source(&rt,&c,e,&b)?;
    assert!(pending.execute_handler(&mut rt,&c,e,&b,&mut dispatcher,0x401900,|_,_|panic!("replayed")).is_err());
    match mode{7=>receipt.generation+=1,8=>receipt.epoch+=1,9=>receipt.identity.owner+=1,
     12=>rt.store(b.at(&rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?,13=>receipt.frame.generation+=1,_=>{}}
    let receipt_level=receipt.level;let consumed=pending.take_handler_result(receipt,&rt,&c,e,&b);
    if mode==0{assert_eq!(consumed.expect("supported result must be consumed"),1);assert_eq!(pending.delivery,CrtNormalDelivery::ResultTaken);
     let replay=CrtNormalHandlerReturn{identity:pending.identity,epoch:pending.epoch,frame:pending.frame,generation:pending.generation,level:receipt_level,value:CrtValue::scalar(1)};
     assert!(pending.take_handler_result(replay,&rt,&c,e,&b).is_err());
    }else{assert!(consumed.is_err());assert_eq!(pending.delivery,CrtNormalDelivery::Failed);}
   }else{assert!(result.is_err());assert_eq!(pending.delivery,if mode==4||mode==6{CrtNormalDelivery::Pending}else{CrtNormalDelivery::Failed});}
   assert!(e.state().is_err());assert!(epilog_run(&mut rt,&mut c,e,&mut b).is_err());
   Err::<(),_>("component callback is not a disposition/restoration proof")
  });assert!(result.is_err());assert_eq!(m.owned_context,context);
 }
}
fn delivery_children(){for mode in 0..14{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let context=m.owned_context;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
  let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
  for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;let saved=c.r;let pending=event.generation;
  let mut d=cpu(&mut rt,0xc000,200);d.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(d.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  let mut expired=None;
  let result=event.execute_child_handler(&mut rt,&c,e,&b,&mut d,0x401900,|rt,h,child|{
   assert_eq!(child.state()?.pending_exception,Some(pending));assert!(child.top(b.id.unwrap()).is_err());assert!(b.authority(rt,child).is_err());
   expired=child.delivery;
   if mode==1{let image=b.storage_image(rt,&c)?;assert!(child.return_to_caller(b.id.unwrap(),&image,0xe010).is_err());return Err("parent retirement rejected");}
   if mode==2{let mut alias=cpu(rt,0xd000,801);alias.r[4]=c.r[4];alias.entry[4]=c.r[4];alias.return_id=event_return_id(pending);assert!(CrtNormalBinding::bind(rt,&alias,child,epilog_run_layout()).is_err());return Err("overlap rejected");}
   if mode==3{child.registry.normal_epoch.as_mut().unwrap().pending_exception=None;assert!(child.state().is_err());return Err("revoked event");}
   if mode==4{child.delivery.as_mut().unwrap().event+=1;assert!(child.state().is_err());return Err("wrong event");}
   if mode==5{child.delivery.as_mut().unwrap().lease+=1;assert!(child.state().is_err());return Err("wrong lease");}
   rt.store(marker,32,CrtValue::scalar(92))?;
   for value in [3,2,1]{h.push(rt,CrtValue::scalar(value))?;}
   h.call_activation(rt,0x401910,12,|rt,nested|{
    let mut nb=CrtNormalBinding::bind(rt,nested,child,epilog_run_layout())?;start(rt,nested,child,&mut nb,801)?;
    if mode==6{return Ok(CrtValue::scalar(0));}
    if mode==7{rt.store(nb.at(rt,nb.layout.guard)?,32,CrtValue::scalar(0))?;}
    if mode==8{for arg in [0,0,0,0xe0420042]{nested.push(rt,CrtValue::scalar(arg))?;}let before=nested.r;let generation=rt.generation;assert!(CrtNormalException::issue(rt,nested,child,&nb,raise_site()).is_err());assert_eq!(nested.r,before);assert_eq!(rt.generation,generation);nested.discard(rt,16)?;}
    if mode==9{return Err("independent callback failure after write");}
    if mode==10{for value in [6,5,4]{nested.push(rt,CrtValue::scalar(value))?;}nested.call_activation(rt,0x401920,12,|rt,deeper|{let mut db=CrtNormalBinding::bind(rt,deeper,child,epilog_run_layout())?;start(rt,deeper,child,&mut db,803)?;deeper.r[0]=CrtValue::scalar(4);let value=epilog_run(rt,deeper,child,&mut db)?;assert!(db.authority(rt,child).is_err());Ok(value)})?;}
    nested.r[0]=CrtValue::scalar(17);let value=epilog_run(rt,nested,child,&mut nb)?;assert!(nb.authority(rt,child).is_err());Ok(value)
   })?;
   if mode==11{rt.store(b.at(rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?;}
   if mode==12{child.registry.normal_epoch.as_mut().unwrap().context[0]=Some(99);}
   if mode==13{child.delivery.as_mut().unwrap().floor+=1;}
   h.r[0]=CrtValue::scalar(1);h.finish(rt)
  });
  assert_eq!(c.r,saved);assert!(e.state().is_err());
  if matches!(mode,0|8|10){let receipt=result.expect("supported delivery callback must complete");assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b).expect("supported live result must be consumed"),1);assert_eq!(e.registry.normal_epoch.as_ref().unwrap().pending_exception,Some(pending));assert!(e.registry.normal_epoch.as_ref().unwrap().delivery.is_none());
   let stale=NormalCallEpoch{registry:&mut *e.registry,generation:e.generation,delivery:expired};assert!(stale.state().is_err());
   assert!(event.execute_child_handler(&mut rt,&c,e,&b,&mut d,0x401900,|_,_,_|panic!("replay")).is_err());
  }else{assert!(result.is_err(),"delivery mode {mode}");assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
  if !matches!(mode,1..=5){assert_eq!(rt.load(marker,32)?,CrtValue::scalar(92));}
  Err::<(),_>("child completion is not exception restoration")
 });assert!(result.is_err());assert_eq!(m.owned_context,context);
}}
fn event_return_id(generation:u64)->u64{generation|(1u64<<63)}
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
   assert_ne!(objects.captured_esp,CrtValue::scalar(CrtCpu::pointer(c.r[4])?.address()));
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
   if mode==0{let receipt=result.expect("supported delivery callback must complete");assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b).expect("supported live result must be consumed"),1);}else{assert!(result.is_err());}
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
fn main_initial_rejections(){for mode in 0..5{
 let m=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);let sp=rt.resolve_absolute(0xe000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(71)).unwrap();let c=CrtCpu::new(sp,71).unwrap();let mut storage=initialize_main_owned(&mut rt,&mut r,&m,m.owned_binding(0).unwrap(),&c).unwrap();let mut module=map_main_initial(&mut rt).unwrap();let owner=rt.resolve_absolute(storage.image.ebp,CrtRegionKind::Stack).unwrap();let guard=rt.offset(owner,-28).unwrap();let prior=rt.load(guard,32).unwrap();
 if mode==0{rt.store(rt.resolve_absolute(0x4012b9,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
 if mode==1{rt.store(rt.offset(owner,-744).unwrap(),32,CrtValue::Pointer(storage.entry)).unwrap();}
 if mode==2{let p=rt.resolve_absolute(storage.image.esp,CrtRegionKind::Stack).unwrap();rt.store(rt.offset(p,-4).unwrap(),32,CrtValue::ProtectedReturn(999)).unwrap();}
 if mode==3{module=storage.entry;}
 if mode==4{initialize_main_live(&mut rt,&r,&m,&mut storage,module).unwrap();}
 assert!(initialize_main_live(&mut rt,&r,&m,&mut storage,module).is_err(),"main init mode {mode}");assert_eq!(rt.load(guard,32).unwrap(),prior);assert!(!m.event_issued);
 if mode==1||mode==3{assert_eq!(rt.load(rt.offset(owner,-768).unwrap(),32).unwrap(),CrtValue::scalar(300));assert_eq!(storage.image.try_level,-2);}
}}
fn initial_raise_rejections(){for mode in 0..6{
 let mut m=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();let mut r=ThreadRegistry::new(m.owner(),0x8000,0xf000,&[(0x400000,0x420000)],0x41c000).unwrap();let mut rt=runtime(&r);let sp=rt.resolve_absolute(0xe000,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(72)).unwrap();let mut c=CrtCpu::new(sp,72).unwrap();let b=m.owned_binding(0).unwrap();let mut storage=initialize_initial_raise_owned(&mut rt,&mut r,&m,b,&c).unwrap();map_initial_raise(&mut rt).unwrap();
 if mode==0{rt.store(rt.resolve_absolute(0x401117,CrtRegionKind::Module).unwrap(),8,CrtValue::scalar(0x90)).unwrap();}
 if mode==1{let p=rt.resolve_absolute(storage.image.esp,CrtRegionKind::Stack).unwrap();rt.store(p,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 if mode==2{let p=rt.offset(storage.entry,i64::from(storage.image.esp)-i64::from(storage.image.entry_sp)-4).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(999)).unwrap();}
 if mode==3{c.returned=true;}
 if mode==4{c.r[0]=CrtValue::scalar(4);}
 if mode==5{let p=rt.offset(storage.entry,i64::from(storage.image.esp)-i64::from(storage.image.entry_sp)+12).unwrap();rt.store(p,32,CrtValue::Pointer(storage.entry)).unwrap();}
 let before=c.r;let generation=rt.generation;assert!(issue_initial_raise(&mut rt,&r,&mut m,&mut storage,&mut c).is_err(),"initial mode {mode}");assert!(!m.event_issued);assert_eq!(c.r,before);assert_eq!(rt.generation,generation);assert!(storage.raise_call.is_none());
}}
fn map_allocator_state(rt:&mut CrtStreamRuntime,init:CrtInitialization){
 rt.map_region(0x41d2c8,4,CrtRegionKind::Module,None).unwrap();rt.map_region(0x41ce80,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();let ptd=rt.map_region(0x6ff0,20,CrtRegionKind::ThreadData,None).unwrap();let errno=rt.offset(ptd,16).unwrap();rt.store(errno,32,CrtValue::scalar(73)).unwrap();rt.map_region(0x41c130,4,CrtRegionKind::Module,Some(&73u32.to_le_bytes())).unwrap();let sp=rt.resolve_absolute(0xcf00,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(800)).unwrap();let mut c=CrtCpu::new(sp,800).unwrap();heap_producer(rt,&mut c,init,true,Some(false),(0,0),true,errno,&mut vec![],&mut |_,_|Err("startup handler not bound")).unwrap();assert!(c.returned);
}
fn registered_allocation(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,e:&mut NormalCallEpoch<'_>,init:CrtInitialization)->RegistryResult<CrtValue>{
 let argument=rt.load(rt.offset(CrtCpu::pointer(c.r[4])?,4)?,32)?.known_scalar()?;if argument>=8192{return Err("manager invalid-request API path remains unbound");}
 let mut b=CrtNormalBinding::bind_initializing(rt,c,e,manager_epilog_layout(),init)?;
 c.push(rt,CrtValue::scalar(16))?;c.push(rt,CrtValue::scalar(0x41b6a0))?;c.push(rt,CrtValue::ProtectedReturn(901))?;
 manager_prolog(rt,c,901,b.token,|rt,c,record,head|b.install(rt,c,e,record,head))?;
 let(mut held,mut events)=(None,vec![]);manager(rt,c,init,1,false,false,&mut held,&mut events)?;manager_return_move(rt,c)?;manager_epilog(rt,c,e,&mut b)
}
fn inherited_registered_manager(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let lock=rt.map_region(0x41d1f8,24,CrtRegionKind::Module,None).unwrap();rt.construct_global_lock(init,7,lock,1).unwrap();let table=rt.map_region(0x41cf08,512,CrtRegionKind::Module,Some(&[0;512])).unwrap();rt.map_region(0x41d108,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();
 map_allocator_state(&mut rt,init);let ids=[rt.bind_descriptor(0,44).unwrap(),rt.bind_descriptor(1,45).unwrap(),rt.bind_descriptor(2,46).unwrap()];let serialized=rt.map_region(0x7100,19,CrtRegionKind::Result,None).unwrap();rt.store(serialized,32,CrtValue::scalar(3)).unwrap();for(i,f)in[1,9,1].into_iter().enumerate(){rt.store(rt.offset(serialized,4+i as i64).unwrap(),8,CrtValue::scalar(f)).unwrap();}for(i,v)in[CrtValue::Handle(ids[0]),CrtValue::Handle(ids[1]),CrtValue::scalar(u32::MAX)].into_iter().enumerate(){rt.store(rt.offset(serialized,7+i as i64*4).unwrap(),32,v).unwrap();}
 r.with_normal_calls(&m,&mut permit,&main,|e|{let mut c=cpu(&mut rt,0xe000,71);c.return_pop=0;let saved=c.r;let arg=rt.offset(CrtCpu::pointer(c.r[4])?,4)?;rt.store(arg,32,CrtValue::scalar(8192))?;assert!(registered_allocation(&mut rt,&mut c,e,init).is_err());assert_eq!(c.r,saved);assert_eq!(e.head()?,previous);let(mut allocations,mut queries)=(vec![],vec![]);inherit_registered(&mut rt,&mut c,serialized,false,&mut allocations,&mut queries,e,init)?;assert!(c.returned);for i in [3,5,6,7]{assert_eq!(c.r[i],saved[i]);}assert_eq!(allocations,[3]);assert_eq!(queries,[0]);assert_eq!(e.head()?,previous);assert!(rt.global_locks.is_empty());let block=CrtCpu::pointer(rt.load(table,32)?)?;assert_eq!(rt.load(rt.offset(block,24)?,32)?,CrtValue::Handle(ids[0]));assert_eq!(rt.load(rt.offset(block,80)?,32)?,CrtValue::Handle(ids[1]));assert_eq!(rt.load(rt.offset(block,136)?,32)?,CrtValue::scalar(u32::MAX));Ok(())}).unwrap();assert_eq!(r.head,previous);
}
fn manager_registered(){for mode in 0..5{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let lock=rt.map_region(0x41d1f8,24,CrtRegionKind::Module,None).unwrap();rt.construct_global_lock(init,7,lock,1).unwrap();rt.map_region(0x41cf08,512,CrtRegionKind::Module,Some(&[0;512])).unwrap();let capacity=rt.map_region(0x41d108,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();map_allocator_state(&mut rt,init);
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};c.entry=c.r;let caller=CrtCpu::pointer(c.r[4])?;rt.store(rt.offset(caller,4)?,32,CrtValue::scalar(3))?;
  assert!(CrtNormalBinding::bind(&rt,&c,e,manager_epilog_layout()).is_err());
  if mode==4{let(_,foreign)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536)?;assert!(CrtNormalBinding::bind_initializing(&rt,&c,e,manager_epilog_layout(),foreign).is_err());}
  let mut b=CrtNormalBinding::bind_initializing(&rt,&c,e,manager_epilog_layout(),init)?;
  c.push(&mut rt,CrtValue::scalar(16))?;c.push(&mut rt,CrtValue::scalar(0x41b6a0))?;c.push(&mut rt,CrtValue::ProtectedReturn(99))?;
  manager_prolog(&mut rt,&mut c,99,b.token,|rt,c,record,head|b.install(rt,c,e,record,head))?;assert!(matches!(e.head()?,RegistryHead::Normal(_)));
  let(mut held,mut events)=(None,vec![]);manager(&mut rt,&mut c,init,if mode==3{0}else{1},false,false,&mut held,&mut events)?;assert!(held.is_none());assert_eq!(events,[1,2]);assert!(!c.returned);
  manager_return_move(&mut rt,&mut c)?;
  if mode==3{assert_eq!(rt.errno,Some(12));}
  if mode==1{rt.store(b.at(&rt,b.layout.guard)?,32,CrtValue::scalar(0))?;}
  if mode==2{rt.end_initialization(init)?;}
  let result=manager_epilog(&mut rt,&mut c,e,&mut b);
  if mode==1||mode==2{assert!(result.is_err());assert!(!c.returned);return Err("expected corrupt or revoked initialization");}
  assert_eq!(result?,CrtValue::scalar(if mode==3{12}else{0}));assert!(c.returned);assert_eq!(e.head()?,previous);assert!(rt.global_locks.is_empty());assert_eq!(rt.load(capacity,32)?.known_scalar()?,if mode==3{0}else{64});Ok(())
 });
 if mode==1||mode==2{assert!(result.is_err());}else{result.unwrap();assert_eq!(r.head,previous);}
}}
fn cxx_registered_unwind(){for mode in 0..24{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let previous=r.head;let mut rt=runtime(&r);
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();let scope=rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},if mode==7{CrtRegionKind::Module}else{CrtRegionKind::ThreadData},None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,if mode==3{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if mode==4{i32::MAX as u32}else{2})}).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(if mode==19{64}else{0})).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(23,24,[0,0,0]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(match mode{1|15=>0,2=>1,_=>u32::MAX})).unwrap();
 let notice=rt.map_region(0x41c070,if mode==15{12}else{16},CrtRegionKind::Module,None).unwrap();
 let mut calls=0;let mut child_returned=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut parent=cpu(&mut rt,0xd000,81);let mut outer=if mode==14{Some(CrtNormalBinding::bind(&rt,&parent,epoch,epilog_run_layout())?)}else{None};if let Some(b)=&mut outer{start(&mut rt,&mut parent,epoch,b,82)?;}
  let mut c=cpu(&mut rt,if mode==19{0xbf00}else{0xc000},71);c.return_pop=0;let saved=c.r;
  for(offset,value)in [(4,CrtValue::Pointer(rt.offset(frame.bp,-12)?)),(8,CrtValue::scalar(0)),(12,CrtValue::Pointer(metadata))]{let p=rt.offset(CrtCpu::pointer(c.r[4])?,offset)?;rt.store(p,32,value)?;}
  if mode==5{rt.store(metadata,32,CrtValue::scalar(0))?;}if mode==6{rt.store(scope,32,CrtValue::scalar(0))?;}
  if mode==17{rt.store(count,32,CrtValue::Pointer(frame.bp))?;}
  if mode==20{rt.store(rt.resolve_absolute(0xbfb8,CrtRegionKind::Stack)?,32,CrtValue::ProtectedReturn(999))?;}
  if mode==22{rt.store(state,32,CrtValue::Scalar{bits:0,known:0})?;}
  if mode==23{rt.store(rt.offset(CrtCpu::pointer(c.r[4])?,12)?,32,CrtValue::Pointer(rt.offset(metadata,4)?))?;}
  let value=cxx_unwind_wrapper(&mut rt,&mut c,epoch,&owner,&frame,&record,&mut |rt,child|{
   calls+=1;
   if mode==16{rt.store(rt.offset(notice,4)?,32,CrtValue::scalar(17))?;return Err("independent provider failure after write");}
   if mode==18{rt.store(scope,32,CrtValue::scalar(0))?;}
   if mode==21&&calls==3{rt.store(rt.resolve_absolute(0xbfb4,CrtRegionKind::Stack)?,32,CrtValue::scalar(0))?;}
   if calls==2{match mode{9=>rt.retire_region(ptd)?,10=>rt.store(count,32,CrtValue::scalar(91))?,11=>rt.store(CrtCpu::pointer(owner.entry[4])?,32,CrtValue::ProtectedReturn(999))?,12=>{let other=rt.map_region(0x6100,40,CrtRegionKind::ThreadData,None)?;rt.store(rt.offset(other,24)?,32,CrtValue::scalar(3))?;child.clobber(CrtValue::Pointer(other));return child.finish(rt);},13=>{let guard=rt.resolve_absolute(0xbfb4,CrtRegionKind::Stack)?;rt.store(guard,32,CrtValue::scalar(0))?;},_=>{}}}
   child.clobber(CrtValue::Pointer(ptd));child.finish(rt)
  });
  child_returned=c.returned;
  if mode==0||mode==14||mode==19{value?;assert!(c.returned);assert_eq!(rt.load(count,32)?,CrtValue::scalar(2));assert_eq!(calls,3);for i in [3,5,6,7]{assert_eq!(c.r[i],saved[i]);}if let Some(b)=&mut outer{parent.r[0]=CrtValue::scalar(0);epilog_run(&mut rt,&mut parent,epoch,b)?;}Ok(())}else{let err=value.unwrap_err();if mode==1||mode==2{assert_eq!(err,"C++ original action jumps to unbound terminate40770c");assert_eq!(rt.load(state,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(count,32)?,CrtValue::scalar(3));assert!(epoch.state().is_err());assert_eq!(rt.load(rt.offset(notice,4)?,32)?,CrtValue::scalar(0x4026fc));assert_eq!(rt.load(rt.offset(notice,8)?,32)?,CrtValue::scalar(0x103));assert_eq!(rt.load(rt.offset(notice,12)?,32)?,CrtValue::Pointer(frame.bp));}Err(err)}
 });
 if mode==0||mode==14||mode==19{result.unwrap();assert_eq!(r.head,previous);}else{assert!(result.is_err(),"mode {mode}");assert!(!child_returned);}
 if mode==10{assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(91));}
 if mode==15{assert_eq!(rt.load(rt.offset(notice,8).unwrap(),32).unwrap(),CrtValue::scalar(0x103));assert_eq!(rt.load(rt.offset(notice,4).unwrap(),32).unwrap(),CrtValue::scalar(0x4026fc));assert_eq!(rt.load(state,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(3));}
 if mode==16{assert_eq!(rt.load(rt.offset(notice,4).unwrap(),32).unwrap(),CrtValue::scalar(17));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(2));}
 if mode==21{assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(2));}
 if mode==20||mode==22||mode==23{assert_eq!(calls,0);}
 if mode==5||mode==6{assert_eq!(calls,0);assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(2));}
 if mode==3||mode==4||mode==7||mode==8{assert_eq!(calls,1);}
}}
fn cxx_cached_unwind(){for mode in 0..14{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent unwind dependency",0x720000).unwrap();let function=rt.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==6{CrtValue::scalar(0)}else{CrtValue::Function(function)}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==10{0x401bfau32}else{0x401bf9u32}).to_le_bytes())).unwrap();rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},CrtRegionKind::ThreadData,None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,CrtValue::scalar(2)).unwrap();let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,3,if mode==2{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();
 if mode==7{let alias=CrtValue::Pointer(rt.offset(ptd,4).unwrap());assert!(rt.bind_fls(fiber,4,alias).is_err());rt.fls.get_mut(&3).unwrap().1=alias;}
 if mode==3{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}if mode==4{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.retire_region(ptd).unwrap();}if mode==11{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(index,32,CrtValue::scalar(u32::MAX)).unwrap();}rt.end_initialization(init).unwrap();
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();let notice=rt.map_region(0x41c070,16,CrtRegionKind::Module,None).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(23,24,[0,0,0]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{0}else{u32::MAX})).unwrap();
 let(mut other,_)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536).unwrap();let foreign=other.bind_fiber(other.thread).unwrap();rt.last_os_error=if mode==13{None}else{Some(77)};let saved_error=rt.last_os_error;let refs=rt.module_references.len();let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();
 let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut c=cpu(&mut rt,0xc000,71);c.return_pop=0;let saved=c.r;let sp=CrtCpu::pointer(c.r[4])?;for(offset,v)in [(4,CrtValue::Pointer(rt.offset(frame.bp,-12)?)),(8,CrtValue::scalar(0)),(12,CrtValue::Pointer(metadata))]{rt.store(rt.offset(sp,offset)?,32,v)?;}
  let result=cxx_unwind_cached(&mut rt,&mut c,epoch,&owner,&frame,&record,if mode==5{foreign}else{fiber},slot);
  if mode==0||mode==13{result?;assert!(c.returned);assert_eq!(rt.load(count,32)?,CrtValue::scalar(2));for i in [3,5,6,7]{assert_eq!(c.r[i],saved[i]);}let returned=c.r;let generation=rt.generation;assert!(cxx_unwind_cached(&mut rt,&mut c,epoch,&owner,&frame,&record,fiber,slot).is_err());assert_eq!(c.r,returned);assert_eq!(rt.generation,generation);Ok(())}else{assert!(!c.returned);let error=result.unwrap_err();if mode==1{assert_eq!(error,"C++ original action jumps to unbound terminate40770c");assert_eq!(rt.load(state,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(count,32)?,CrtValue::scalar(3));assert_eq!(rt.load(rt.offset(notice,8)?,32)?,CrtValue::scalar(0x103));}Err(error)}
 });
 if mode==0||mode==13{result.unwrap();assert_eq!(r.head,previous);}else{assert!(result.is_err(),"mode {mode}");}
 assert_eq!(rt.initialization,None);assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_before);assert_eq!(rt.last_os_error,if mode==2{None}else{saved_error});
 if mode!=1&&mode!=9{assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(2));}
}}
fn delivery_cached_unwind(){for delivery_mode in 0..4{let mode=0;
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let _previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent unwind dependency",0x720000).unwrap();let function=rt.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==6{CrtValue::scalar(0)}else{CrtValue::Function(function)}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==10{0x401bfau32}else{0x401bf9u32}).to_le_bytes())).unwrap();rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},CrtRegionKind::ThreadData,None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,CrtValue::scalar(2)).unwrap();let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,3,if mode==2{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();
 if mode==7{let alias=CrtValue::Pointer(rt.offset(ptd,4).unwrap());assert!(rt.bind_fls(fiber,4,alias).is_err());rt.fls.get_mut(&3).unwrap().1=alias;}
 if mode==3{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}if mode==4{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.retire_region(ptd).unwrap();}if mode==11{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(index,32,CrtValue::scalar(u32::MAX)).unwrap();}rt.end_initialization(init).unwrap();
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();let notice=rt.map_region(0x41c070,16,CrtRegionKind::Module,None).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(23,24,[0,0,0]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{0}else{u32::MAX})).unwrap();
 let(mut other,_)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536).unwrap();let foreign=other.bind_fiber(other.thread).unwrap();rt.last_os_error=if mode==13{None}else{Some(77)};let saved_error=rt.last_os_error;let refs=rt.module_references.len();let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();

 let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut interrupted=cpu(&mut rt,0xd000,771);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,epoch,epilog_run_layout())?;start(&mut rt,&mut interrupted,epoch,&mut binding,772)?;
  for arg in [0,0,0,0xe0420042]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,epoch,&binding,raise_site())?;let saved=interrupted.r;let event_generation=event.generation;
  let mut dispatcher=cpu(&mut rt,0xc000,773);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  if delivery_mode==1{rt.store(state,32,CrtValue::scalar(0))?;}
  if delivery_mode==2{rt.retire_fls(fiber,slot)?;rt.bind_fls(fiber,3,CrtValue::Pointer(ptd))?;}
  let result=event.execute_child_handler(&mut rt,&interrupted,epoch,&binding,&mut dispatcher,0x401900,|rt,h,child|{
   for _ in 0..if delivery_mode==3{2}else{1}{
    for value in [CrtValue::Pointer(metadata),CrtValue::scalar(0),CrtValue::Pointer(rt.offset(frame.bp,-12)?)]{h.push(rt,value)?;}
    h.call_activation(rt,0x401910,0,|rt,c|cxx_unwind_cached(rt,c,child,&owner,&frame,&record,fiber,slot))?;h.discard(rt,12)?;
    assert_eq!(child.state()?.pending_exception,Some(event_generation));assert!(child.top(binding.id.unwrap()).is_err());assert_eq!(rt.load(count,32)?,CrtValue::scalar(2));
   }
   h.r[0]=CrtValue::scalar(1);h.finish(rt)
  });
  assert_eq!(interrupted.r,saved);assert!(epoch.state().is_err());
  if delivery_mode==0||delivery_mode==3{let receipt=result.expect("supported delivery callback must complete");assert_eq!(event.take_handler_result(receipt,&rt,&interrupted,epoch,&binding)?,1);assert!(epoch.registry.normal_epoch.as_ref().unwrap().delivery.is_none());}
  else{let error=result.err().expect("unsupported delivery must reject");if delivery_mode==1{assert_eq!(error,"C++ original action jumps to unbound terminate40770c");assert_eq!(rt.load(count,32)?,CrtValue::scalar(3));assert_eq!(rt.load(state,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(rt.offset(notice,8)?,32)?,CrtValue::scalar(0x103));}assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
  Err::<(),_>("original child unwind completion is not OS delivery/restoration")
 });assert!(result.is_err());assert_eq!(rt.initialization,None);assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_before);assert_eq!(rt.last_os_error,saved_error);
}}
fn dispatcher_delivery_unwind(prefix:bool){for delivery_mode in 0..if prefix{14}else{8}{let mode=0;
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let _previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent unwind dependency",0x720000).unwrap();let function=rt.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==6{CrtValue::scalar(0)}else{CrtValue::Function(function)}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==10{0x401bfau32}else{0x401bf9u32}).to_le_bytes())).unwrap();rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},CrtRegionKind::ThreadData,None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,CrtValue::scalar(2)).unwrap();let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,3,if mode==2{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();
 if mode==7{let alias=CrtValue::Pointer(rt.offset(ptd,4).unwrap());assert!(rt.bind_fls(fiber,4,alias).is_err());rt.fls.get_mut(&3).unwrap().1=alias;}
 if mode==3{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}if mode==4{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.retire_region(ptd).unwrap();}if mode==11{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(index,32,CrtValue::scalar(u32::MAX)).unwrap();}rt.end_initialization(init).unwrap();
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();let notice=rt.map_region(0x41c070,16,CrtRegionKind::Module,None).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(23,24,[0,0,0]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{0}else{u32::MAX})).unwrap();
 let(mut other,_)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536).unwrap();let foreign=other.bind_fiber(other.thread).unwrap();rt.last_os_error=if mode==13{None}else{Some(77)};let saved_error=rt.last_os_error;let refs=rt.module_references.len();let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();

 let stack=rt.resolve_absolute(0x9000,CrtRegionKind::Stack).unwrap();let cp=rt.map_region(0x50000,200,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(cp,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let mut context=CrtCxxContext::bind(&rt,&owner,&frame,cp,stack).unwrap();
 let exception=rt.map_region(0x51000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(0xe06d7363)).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(2)).unwrap();rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(0)).unwrap();
 let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut interrupted=cpu(&mut rt,0xd000,771);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,epoch,epilog_run_layout())?;start(&mut rt,&mut interrupted,epoch,&mut binding,772)?;
  for arg in [0,0,0,0xe0420042]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,epoch,&binding,raise_site())?;let saved=interrupted.r;let event_generation=event.generation;
  let mut dispatcher=cpu(&mut rt,0xc000,773);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  if delivery_mode==1{rt.store(state,32,CrtValue::scalar(0))?;}
  if delivery_mode==2{rt.retire_fls(fiber,slot)?;rt.bind_fls(fiber,3,CrtValue::Pointer(ptd))?;}
  let result=event.execute_child_handler(&mut rt,&interrupted,epoch,&binding,&mut dispatcher,0x401900,|rt,h,child|{
   if delivery_mode==13{let mut alias=CrtCpu::new(binding.caller,interrupted.return_id)?;let before=alias.r;let generation=rt.generation;let error=cxx_handler_prefix(rt,&mut alias,&owner,&frame,&record,&context,child,fiber,slot).err().expect("parent alias must reject before effects");assert_eq!(error,"delivery child stack aliases live frame/arguments");assert_eq!(alias.r,before);assert_eq!(rt.generation,generation);return Err(error);}
   if delivery_mode==4{context.retire();}
   if delivery_mode==5{rt.store(rt.offset(cp,196)?,32,CrtValue::scalar(frame.low.address()))?;}
   if delivery_mode==6{child.delivery.as_mut().unwrap().lease+=1;}
   if delivery_mode==3{rt.store(rt.offset(exception,4)?,32,CrtValue::Scalar{bits:0,known:0})?;}
   if delivery_mode==8{rt.store(frame.low,32,CrtValue::scalar(0))?;}
   if delivery_mode==9{owner.return_id+=1;}
   if delivery_mode==12{rt.store(metadata,32,CrtValue::scalar(0))?;}
   h.r[0]=if delivery_mode==10{CrtValue::Scalar{bits:0,known:0}}else if delivery_mode==11{CrtValue::scalar(0xdeadbeef)}else{CrtValue::Pointer(metadata)};
   for value in [CrtValue::scalar(0),CrtValue::Pointer(cp),CrtValue::Pointer(rt.offset(frame.bp,if delivery_mode==7{-8}else{-12})?),CrtValue::Pointer(exception)]{h.push(rt,value)?;}
   let value=h.call_activation(rt,0x401910,0,|rt,c|if prefix{cxx_handler_prefix(rt,c,&owner,&frame,&record,&context,child,fiber,slot)}else{cxx_common(rt,c,&owner,&frame,&context,&record,child,fiber,slot)})?;assert_eq!(value,CrtValue::scalar(1));h.discard(rt,16)?;
   assert_eq!(child.state()?.pending_exception,Some(event_generation));assert!(child.top(binding.id.unwrap()).is_err());assert_eq!(rt.load(count,32)?,CrtValue::scalar(2));
   h.finish(rt)
  });
  assert_eq!(interrupted.r,saved);assert!(epoch.state().is_err());
  if matches!(delivery_mode,0|10|11){let receipt=result.expect("supported delivery callback must complete");assert_eq!(event.take_handler_result(receipt,&rt,&interrupted,epoch,&binding)?,1);assert!(epoch.registry.normal_epoch.as_ref().unwrap().delivery.is_none());}
  else{let error=result.err().expect("unsupported delivery must reject");if delivery_mode==1{assert_eq!(error,"C++ original action jumps to unbound terminate40770c");assert_eq!(rt.load(count,32)?,CrtValue::scalar(3));assert_eq!(rt.load(state,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(rt.offset(notice,8)?,32)?,CrtValue::scalar(0x103));}assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
  Err::<(),_>("original child unwind completion is not OS delivery/restoration")
 });assert!(result.is_err());assert_eq!(rt.initialization,None);assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_before);assert_eq!(rt.last_os_error,saved_error);
}}
fn bound_invocation(){for delivery_mode in 0..34{let prefix=true;let mode=0;
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let _previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent unwind dependency",0x720000).unwrap();let function=rt.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==6{CrtValue::scalar(0)}else{CrtValue::Function(function)}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==10{0x401bfau32}else{0x401bf9u32}).to_le_bytes())).unwrap();rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},CrtRegionKind::ThreadData,None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,CrtValue::scalar(2)).unwrap();let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,3,if mode==2{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();
 if mode==7{let alias=CrtValue::Pointer(rt.offset(ptd,4).unwrap());assert!(rt.bind_fls(fiber,4,alias).is_err());rt.fls.get_mut(&3).unwrap().1=alias;}
 if mode==3{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}if mode==4{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.retire_region(ptd).unwrap();}if mode==11{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(index,32,CrtValue::scalar(u32::MAX)).unwrap();}rt.end_initialization(init).unwrap();
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();let notice=rt.map_region(0x41c070,16,CrtRegionKind::Module,None).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(23,24,[0,0,0]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{0}else{u32::MAX})).unwrap();
 let(mut other,_)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536).unwrap();let foreign=other.bind_fiber(other.thread).unwrap();rt.last_os_error=if mode==13{None}else{Some(77)};let saved_error=rt.last_os_error;let refs=rt.module_references.len();let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();

 let stack=rt.resolve_absolute(0x9000,CrtRegionKind::Stack).unwrap();let cp=rt.map_region(0x50000,if delivery_mode==22{200}else{716},CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(cp,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let mut context=CrtCxxContext::bind(&rt,&owner,&frame,cp,stack).unwrap();
 let exception=rt.map_region(0x51000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(0xe06d7363)).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(if delivery_mode==29{3}else{2})).unwrap();rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(0)).unwrap();
 let mut checked=false;let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut interrupted=cpu(&mut rt,0xd000,771);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,epoch,epilog_run_layout())?;start(&mut rt,&mut interrupted,epoch,&mut binding,772)?;
  for arg in [0,0,if delivery_mode==29{1}else{0},0xe06d7363]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,epoch,&binding,raise_site())?;let saved=interrupted.r;let event_generation=event.generation;
  let mut dispatcher=cpu(&mut rt,0xc000,773);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  let token=CrtCxxInvocation::bind_unwind(&event,&rt,epoch,&owner,&frame,&record,&context,exception);if delivery_mode==22{assert!(token.is_err(),"truncated capture must reject at binding");checked=true;return Err("truncated captured object");}let mut invocation=token.expect("valid supplied unwind capture must bind");
  let sp=CrtCpu::pointer(dispatcher.r[4])?;for(i,value)in [CrtValue::Pointer(exception),CrtValue::Pointer(rt.offset(frame.bp,if delivery_mode==7||delivery_mode==13{-8}else{-12})?),CrtValue::Pointer(cp),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,value)?;}
  match delivery_mode{
   1=>rt.store(state,32,CrtValue::scalar(0))?,
   2=>{rt.retire_fls(fiber,slot)?;rt.bind_fls(fiber,3,CrtValue::Pointer(ptd))?;},
   3=>rt.store(rt.offset(exception,4)?,32,CrtValue::Scalar{bits:0,known:0})?,
   4=>context.retire(),5=>rt.store(rt.offset(cp,196)?,32,CrtValue::scalar(frame.low.address()))?,
   6|14=>invocation.event+=1,8=>rt.store(frame.low,32,CrtValue::scalar(0))?,9=>owner.return_id+=1,
   10=>dispatcher.r[0]=CrtValue::Scalar{bits:0,known:0},11=>dispatcher.r[0]=CrtValue::scalar(0xdeadbeef),
   12=>rt.store(metadata,32,CrtValue::scalar(0))?,15=>rt.retire_region(cp)?,
   16=>rt.store(exception,32,CrtValue::scalar(0xe0420042))?,
   18=>{event.delivery=CrtNormalDelivery::Calling;assert!(CrtCxxInvocation::bind_unwind(&event,&rt,epoch,&owner,&frame,&record,&context,exception).is_err());event.delivery=CrtNormalDelivery::Pending;},
   19=>invocation.phase=CxxInvocationPhase::Consumed,
   20=>rt.store(exception,32,CrtValue::Scalar{bits:0,known:0})?,
   21=>invocation.context=rt.map_region(0x52000,716,CrtRegionKind::Context,None)?,23=>rt.store(rt.offset(exception,4)?,32,CrtValue::scalar(0x42))?,_=>{}
  }
  let before=dispatcher.r;let generation=rt.generation;
  let result=cxx_invoke_unwind(&mut event,&mut invocation,&mut rt,&interrupted,epoch,&binding,&mut dispatcher,&owner,&frame,&record,&context,fiber,slot,0x401900);
  assert_eq!(interrupted.r,saved);assert!(epoch.state().is_err());
  if matches!(delivery_mode,0|10|11|17|18|24..=33){let mut receipt=result.expect("bound original invocation must complete");assert_eq!(invocation.phase,CxxInvocationPhase::Consumed);match delivery_mode{24=>rt.retire_region(cp)?,25=>rt.store(rt.offset(cp,196)?,32,CrtValue::Pointer(rt.offset(frame.low,-4)?))?,26=>invocation.lease=invocation.lease.map(|n|n+1),27=>receipt.lease+=1,28=>context.retire(),30=>receipt.executed[0]+=1,31=>receipt.owner+=1,32=>receipt.bp=rt.offset(receipt.bp,4)?,33=>{frame.handler+=1;rt.store(rt.offset(frame.bp,-8)?,32,CrtValue::scalar(frame.handler))?;},_=>{}}
   let replay=if delivery_mode==29{Some(CxxInvocationReturn{handler:CrtNormalHandlerReturn{identity:receipt.handler.identity,epoch:receipt.handler.epoch,frame:receipt.handler.frame,generation:receipt.handler.generation,level:receipt.handler.level,value:receipt.handler.value},lease:receipt.lease,executed:receipt.executed,owner:receipt.owner,bp:receipt.bp})}else{None};
   let taken=cxx_take_invocation_result(&mut event,&mut invocation,receipt,&rt,&interrupted,epoch,&binding,&owner,&frame,&record,&context);
   if (24..=28).contains(&delivery_mode)||delivery_mode>=30{if delivery_mode>=30{assert_eq!(taken,Err(if delivery_mode==33{"C++ invocation executed handler identity"}else{"C++ receipt executed target/owner mismatch"}));}assert!(taken.is_err());assert_eq!(event.delivery,CrtNormalDelivery::Failed);assert_eq!(invocation.phase,CxxInvocationPhase::Failed);}else{assert_eq!(taken.expect("live bound result must be consumed"),1);assert_eq!(invocation.phase,CxxInvocationPhase::ResultTaken);}
   if let Some(replay)=replay{assert!(cxx_take_invocation_result(&mut event,&mut invocation,replay,&rt,&interrupted,epoch,&binding,&owner,&frame,&record,&context).is_err());assert_eq!(invocation.phase,CxxInvocationPhase::Failed);}
   if delivery_mode==17{let r=dispatcher.r;let g=rt.generation;assert!(cxx_invoke_unwind(&mut event,&mut invocation,&mut rt,&interrupted,epoch,&binding,&mut dispatcher,&owner,&frame,&record,&context,fiber,slot,0x401900).is_err());assert_eq!(dispatcher.r,r);assert_eq!(rt.generation,g);}assert!(epoch.registry.normal_epoch.as_ref().unwrap().delivery.is_none());}
  else{let error=result.err().expect("unsupported delivery must reject");if delivery_mode==1{assert_eq!(error,"C++ original action jumps to unbound terminate40770c");assert_eq!(rt.load(count,32)?,CrtValue::scalar(3));assert_eq!(rt.load(state,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(rt.offset(notice,8)?,32)?,CrtValue::scalar(0x103));}assert_eq!(invocation.phase,CxxInvocationPhase::Failed);if !matches!(delivery_mode,1|2|8){assert_eq!(dispatcher.r,before);assert_eq!(rt.generation,generation);}assert_eq!(event.delivery,if matches!(delivery_mode,1|2|8){CrtNormalDelivery::Failed}else{CrtNormalDelivery::Pending});}
  checked=true;Err::<(),_>("original child unwind completion is not OS delivery/restoration")
 });assert!(result.is_err());assert!(checked,"invocation case {} failed before its assertions",delivery_mode);assert_eq!(rt.initialization,None);assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_before);assert_eq!(rt.last_os_error,saved_error);
}}
fn ordered_search_cases(){for mode in 0..85{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;let mut escaped_event=None;let mut escaped_lease=None;
 let mut ucrt_slot=None;
 let selected=if mode>=21{
  let(mut next,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();
  next.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();next.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
  let(module,_)=next.module_acquire_result(init,"independent selected search dependency",0x720000).unwrap();let f=next.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();
  let cache=next.map_region(0x41cd14,if mode>=76{16}else{12},CrtRegionKind::Module,None).unwrap();next.store(next.offset(cache,8).unwrap(),32,CrtValue::Function(f)).unwrap();
  next.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();next.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();next.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
  if mode>=76{
   let set=next.module_export_result(init,module,"FlsSetValue",0x722000).unwrap();next.store(next.offset(cache,12).unwrap(),32,CrtValue::Function(set)).unwrap();
   next.map_region(0x415d60,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();next.map_region(0x415d68,12,CrtRegionKind::Input,Some(b"FlsSetValue\0")).unwrap();
   next.map_region(0x41c128,1,CrtRegionKind::Module,Some(&[0])).unwrap();
   next.map_region(0x41ce80,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();let heap=next.process_heap_result(init,true,Some(false)).unwrap();let cell=next.map_region(0x41d2c8,4,CrtRegionKind::Module,None).unwrap();next.store(cell,32,heap).unwrap();
   let lock=next.map_region(0x41d198,24,CrtRegionKind::Module,None).unwrap();next.construct_global_lock(init,3,lock,1).unwrap();next.map_region(0x41b740,28,CrtRegionKind::Module,Some(&abort_scope_bytes())).unwrap();next.map_region(0x41d2d8,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
   let p=next.map_region(0x7100,32,CrtRegionKind::ThreadData,None).unwrap();next.store(next.offset(p,16).unwrap(),32,CrtValue::scalar(73)).unwrap();
  }
  let ptd=next.map_region(0x6000,40,CrtRegionKind::ThreadData,None).unwrap();next.store(next.offset(ptd,24).unwrap(),32,CrtValue::scalar(2)).unwrap();next.store(next.offset(ptd,32).unwrap(),32,if mode==74{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(0)}).unwrap();let fiber=next.bind_fiber(next.thread).unwrap();let slot=next.bind_fls(fiber,3,if mode>=75{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();if mode>=76{next.map_region(0x41d130,1,CrtRegionKind::Module,Some(&[0])).unwrap();next.map_region(0x41c170,4,CrtRegionKind::Module,Some(&4u32.to_le_bytes())).unwrap();let p=next.resolve_absolute(0x7100,CrtRegionKind::ThreadData).unwrap();ucrt_slot=Some(next.bind_fls(fiber,4,CrtValue::Pointer(p)).unwrap());}if mode==55{next.bind_descriptor(1,44).unwrap();}next.end_initialization(init).unwrap();rt=next;Some((fiber,slot))
 }else{None};
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut ancestor=cpu(&mut rt,0xe800,1300);ancestor.return_pop=0;ancestor.push(&mut rt,CrtValue::scalar(if mode>=21{0}else{(mode%3)*16}))?;ancestor.r[0]=CrtValue::scalar(0x414ad6);
  let mut ab=CrtCxxChainBinding::bind(&rt,&ancestor,e)?;let mut af=CrtPtdFrame::new(&rt,&ancestor,ab.token,0x414ad6,0x41c000)?;
  ptd_prolog_registered(&mut rt,&mut ancestor,e,&mut af,&mut ab,0x40a33e).expect("original predecessor installation");let predecessor=e.head()?;
  let mut c=cpu(&mut rt,0xd000,1301);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,1302)?;
  for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;let saved=c.r;
  let record=rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;let context=rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
  if mode==0{
   event.generation+=1;assert_eq!(event.produce_record_fields(&mut rt,&c,e,&b,record),Err("normal exception stale/foreign ownership"));event.generation-=1;
   assert!(rt.load(record,32)?.known_scalar().is_err());assert!(event.produced_record.is_none());
   let old=c.r[0];c.r[0]=CrtValue::scalar(0x1234);
   assert_eq!(event.produce_record_fields(&mut rt,&c,e,&b,record),Err("normal exception changed interrupted activation"));c.r[0]=old;
   assert!(event.produced_record.is_none());assert!(rt.load(record,32)?.known_scalar().is_err());
   let forged=CrtPointer{kind:CrtRegionKind::Stack,..record};assert_eq!(event.produce_record_fields(&mut rt,&c,e,&b,forged),Err("normal record producer phase/role/replay"));

   let initialized=rt.map_region(0x54000,80,CrtRegionKind::Context,Some(&[0;80]))?;
   assert_eq!(event.produce_record_fields(&mut rt,&c,e,&b,initialized),Err("normal record producer requires fresh storage"));assert!(event.produced_record.is_none());
  }
  event.produce_record_fields(&mut rt,&c,e,&b,record).expect("record fields from actual pending API arguments");
  assert_eq!(rt.load(rt.offset(record,4)?,32)?,CrtValue::Scalar{bits:0,known:1});
  assert_eq!(event.produce_record_fields(&mut rt,&c,e,&b,record),Err("normal record producer phase/role/replay"));
  assert!(rt.load(rt.offset(record,12)?,32)?.known_scalar().is_err());assert!(rt.load(rt.offset(record,20)?,32)?.known_scalar().is_err());
  // Supplied input boundary: nested-record link and captured ESP are not
  // acquired by the API-argument record producer.
  rt.store(rt.offset(record,8)?,32,CrtValue::scalar(0))?;
  // Delivered system flag bits are an explicit component input, not an API
  // argument consequence. Unknown reserved bits cannot become zero silently.
  if mode<49{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9500))?;}
  assert_eq!(CrtNormalObjects::bind(&event,&rt,e,record,context).err(),Some("CRT scalar knowledge/type"));
  rt.store(rt.offset(record,4)?,32,CrtValue::scalar(0))?;
  let capture=if mode>=49{CrtValue::Scalar{bits:0,known:0}}else if mode>=37{match mode{
   38=>CrtValue::Scalar{bits:0,known:0},
   39=>CrtValue::Scalar{bits:0,known:0xffffefff},
   40=>CrtValue::Scalar{bits:0xe000,known:0xffffefff},
   47=>CrtValue::Scalar{bits:0x8000,known:0xffffefff},
   41=>CrtValue::Scalar{bits:0x10000,known:0xfffffffe},
   _=>CrtValue::Scalar{bits:0x9500,known:0xfffffff0}
  }}else{CrtValue::scalar(0x9500)};
  if mode<49{rt.store(rt.offset(context,0xc4)?,32,capture)?;}
  if matches!(mode,38|39|41){assert_eq!(CrtNormalObjects::bind(&event,&rt,e,record,context).err(),Some("captured stack comparison unknown"));assert_eq!(event.delivery,CrtNormalDelivery::Pending);checked=true;return Err("ordered rejection checked");}
  let mut objects=if mode>=49{
   map_live_search_return(&mut rt)?;
   rt.store(rt.resolve_absolute(0x415128,CrtRegionKind::Module)?,32,CrtValue::scalar(0x401bf9))?;
   assert!((0..716).all(|i|matches!(rt.load(rt.offset(context,i).unwrap(),8).unwrap(),CrtValue::Scalar{known,..}if known&255==0)));
   if mode==65{rt.store(rt.offset(context,712)?,32,CrtValue::Scalar{bits:1,known:1})?;assert_eq!(event.bind_unobserved_context(&mut rt,&c,e,&b,record,context).err(),Some("unobserved context requires unknown storage"));assert!(event.unobserved.is_none());assert!(rt.unobserved_contexts.is_empty());checked=true;return Err("ordered rejection checked");}
   event.bind_unobserved_context(&mut rt,&c,e,&b,record,context).expect("no-read lease from live pending CALL")
  }else{CrtNormalObjects::bind(&event,&rt,e,record,context)?};
  let mut d=cpu(&mut rt,0xc000,1303);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
  for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,v)?;}
  if mode<49{map_live_search_return(&mut rt)?;}
  if (37..49).contains(&mode){let selector=rt.resolve_absolute(0x415128,CrtRegionKind::Module)?;rt.store(selector,32,CrtValue::scalar(0))?;objects.check_original_context(&event,&rt,e)?;}
  if mode>=21{rt.store(rt.resolve_absolute(0x415128,CrtRegionKind::Module)?,32,CrtValue::scalar(0x401bf9))?;}
  if mode>=49{
   let lease=objects.unobserved.as_ref().unwrap().clone();lease.validate(&rt)?;
   assert_eq!(objects.capture_view(e).err(),Some("unobserved context has no captured predicates"));
   assert_eq!(rt.load(rt.offset(context,0xc4)?,32),Err("unobserved context raw read requires acquisition proof"));
   if mode==54{let alias=rt.resolve_absolute(context.address()+700,CrtRegionKind::Context)?;assert_eq!(rt.load(alias,8),Err("unobserved context raw read requires acquisition proof"));}
   if mode==55{let alias=rt.offset(context,4)?;assert_eq!(rt.store(alias,32,CrtValue::scalar(7)),Err("unobserved context write requires effect proof"));
    let fd=rt.descriptors.iter().find(|d|d.id.number==1).unwrap().id;let lock=rt.lock_descriptor(rt.thread,fd)?;rt.descriptor(fd)?;
    struct Never;impl CrtBackend for Never{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->RegistryResult<CrtWriteResult>{panic!("context escaped to external backend")}}
    for count in [0,4]{assert_eq!(rt.write_once(fd,alias,count,&mut Never).err(),Some("unobserved context external observation unproved"));}rt.unlock_descriptor(lock)?;
   }
   if mode==67{assert_eq!(CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site()).err(),Some("normal exception nested delivery contract unbound"));lease.validate(&rt)?;}
   if mode==56{assert_eq!(event.bind_unobserved_context(&mut rt,&c,e,&b,record,context).err(),Some("unobserved context source/phase/replay"));}
   let expected=match mode{
    50=>{event.generation+=1;Some("normal exception stale/foreign ownership")},
    51=>{event.frame.generation+=1;Some("normal exception stale/foreign ownership")},
    52=>{rt.store(rt.resolve_absolute(0x415128,CrtRegionKind::Module)?,32,CrtValue::scalar(0))?;Some("unobserved context selector changed")},
    53=>{rt.store(rt.resolve_absolute(0x402877,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;Some("unobserved context helper changed")},
    58=>{rt.memory.release(context.cap,context.owner).map_err(|_|"retire lease storage")?;Some("CRT pointer lifetime")},
    60=>{rt.store(rt.resolve_absolute(0x41ccb8,CrtRegionKind::Module)?,32,CrtValue::scalar(9))?;event.fail_capture();assert_eq!(rt.load(rt.resolve_absolute(0x41ccb8,CrtRegionKind::Module)?,32)?,CrtValue::scalar(9));Some("unobserved context expired/foreign lease")},
    61=>{objects.unobserved.as_mut().unwrap().live=std::rc::Rc::new(std::cell::Cell::new(true));Some("unobserved context wrong event/object")},
    68=>{rt.memory.write(context.address()+712,&[1,0,0,0]).map_err(|_|"independent external corruption")?;Some("unobserved context storage changed")},
    62=>{objects.context=rt.map_region(0x55000,716,CrtRegionKind::Context,None)?;Some("unobserved context wrong event/object")},
    _=>None,
   };
   if let Some(error)=expected{assert_eq!(objects.validate(&event,&rt,e),Err(error),"lease case {mode}");checked=true;return Err("ordered rejection checked");}
  }
  let mut search=CrtOrderedSearch::begin(&event,&objects,&rt,&c,e,&b).expect("pending source cursor");assert_eq!(search.previous,predecessor);
  if (70..=73).contains(&mode){let at=[0x414a1b,0x4021d0,0x40154c,0x402877][(mode-70)as usize];rt.store(rt.resolve_absolute(at,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
  if mode==10{rt.store(rt.resolve_absolute(0x402210,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?;}
  if mode==11{search.handler+=1;}
  if mode==12||mode==69{rt.store(rt.resolve_absolute(0x41ccb8,CrtRegionKind::Module)?,32,CrtValue::Scalar{bits:0,known:0})?;}
  if mode==13{search.current=predecessor;}
  if mode==14{search.event+=1;}
  if mode==19{assert_eq!(CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site()).err(),Some("normal exception nested delivery contract unbound"));assert_eq!(event.delivery,CrtNormalDelivery::Pending);}
  let returned=original_live_search_return_dispatch(&mut search,&mut event,&objects,&mut rt,&c,e,&b,&mut d,0x401900);
  if (10..=14).contains(&mode)||(69..=73).contains(&mode){
   let expected=match mode{10|70..=72=>"live search original code/table changed",73=>"unobserved context helper changed",12|69=>"CRT scalar knowledge/type",_=>"ordered search stale source/order/children"};
   assert_eq!(returned.err(),Some(expected),"dispatch negative {mode}");
   if mode==12||mode==69{assert_eq!(c.r,saved);assert_eq!(rt.load(rt.resolve_absolute(0xbfac,CrtRegionKind::Stack)?,32)?,CrtValue::scalar(1));assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
   if mode>=69{
    let lease=objects.unobserved.as_ref().unwrap();assert!(!lease.live.get());
    assert_eq!(lease.validate(&rt),Err("unobserved context expired/foreign lease"));
    assert_eq!(rt.load(context,32),Err("unobserved context raw read requires acquisition proof"));
    assert_eq!(rt.store(context,32,CrtValue::scalar(0)),Err("unobserved context write requires effect proof"));
    assert!((0..716).all(|i|matches!(rt.load_unsealed(rt.offset(context,i).unwrap(),8).unwrap(),CrtValue::Scalar{known,..}if known&255==0)));
   }
   checked=true;return Err("ordered rejection checked");
  }
  let mut returned=returned.expect("receipt follows actual original prefix and terminal RET");
  assert_eq!(returned.handler,0x402210);assert_eq!(returned.receipt.value,CrtValue::scalar(1));
  assert_eq!(c.r,saved);assert_eq!(e.registry.head,RegistryHead::Normal(event.frame));assert!(e.state().is_err());
  if mode==18{assert_eq!(original_live_search_return_dispatch(&mut search,&mut event,&objects,&mut rt,&c,e,&b,&mut d,0x401900).err(),Some("ordered search handler/phase mismatch"));checked=true;return Err("ordered rejection checked");}
  let replay=if mode==5{Some(CrtOrderedReturn{serial:returned.serial,source:returned.source,previous:returned.previous,handler:returned.handler,receipt:CrtNormalHandlerReturn{identity:returned.receipt.identity,epoch:returned.receipt.epoch,frame:returned.receipt.frame,generation:returned.receipt.generation,level:returned.receipt.level,value:returned.receipt.value}})}else{None};
  match mode{
   1=>returned.handler+=1,2=>returned.source.generation+=1,3=>returned.previous=RegistryHead::Normal(event.frame),4=>returned.serial+=1,
   6=>rt.memory.release(context.cap,context.owner).map_err(|_|"test context retirement")?,
   7=>event.generation+=1,
   8=>rt.consume_stack(CrtCpu::pointer(ancestor.entry[4])?,CrtValue::ProtectedReturn(ancestor.return_id))?,
   9=>rt.store(rt.resolve_absolute(0x402275,CrtRegionKind::Module)?,8,CrtValue::scalar(0x90))?,
   15=>{let other=rt.map_region(0x52000,716,CrtRegionKind::Context,None)?;rt.store(rt.offset(other,0xc4)?,32,CrtValue::scalar(0x9500))?;objects=CrtNormalObjects::bind(&event,&rt,e,record,other)?;},
   20=>{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9600))?;objects=CrtNormalObjects::bind(&event,&rt,e,record,context)?;},
   16=>{let extra=e.registry.cxx[0].clone();e.registry.cxx.push(extra);},
   17=>{let at=rt.resolve_absolute(e.registry.cxx[0].record+4,CrtRegionKind::Stack)?;rt.store(at,32,CrtValue::scalar(0x414ad7))?;},
   _=>{}
  }
  if mode==59{let lease=objects.unobserved.as_ref().unwrap().clone();drop(event);assert_eq!(lease.validate(&rt),Err("unobserved context expired/foreign lease"));assert_eq!(rt.load(context,32),Err("unobserved context raw read requires acquisition proof"));checked=true;return Err("ordered rejection checked");}
  if mode==64{escaped_lease=Some(objects.unobserved.as_ref().unwrap().clone());escaped_event=Some(event);checked=true;return Err("ordered rejection checked");}
  let taken=original_live_search_return_advance(&mut search,returned,&mut event,&objects,&rt,&c,e,&b);
  if matches!(mode,0|5|19|21..=68|74..=84){assert_eq!(taken,Ok(predecessor));assert_eq!(search.current,predecessor);assert_eq!(e.registry.head,RegistryHead::Normal(event.frame));assert_eq!(event.delivery,CrtNormalDelivery::ResultTaken);assert_eq!(c.r,saved);
   if let Some((fiber,slot))=selected{
    rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes()))?;rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes()))?;
    let rec=cxx_bind(&rt,&ancestor,&af)?;let stack=rt.resolve_absolute(0x9000,CrtRegionKind::Stack)?;
    rt.store(rt.offset(CrtCpu::pointer(d.r[4])?,4)?,32,CrtValue::Pointer(rt.offset(af.bp,-12)?))?;
    if mode==22{search.current=RegistryHead::Normal(event.frame);}
    if mode==23{ancestor.return_id+=1;}
    if mode==24{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9600))?;}
    if mode==25{rt.store(rt.offset(af.bp,-8)?,32,CrtValue::scalar(0x414ad7))?;}
    if mode==66{
     let alternate=alternate_context_check();
     for(i,&byte)in alternate.iter().enumerate(){rt.store(rt.resolve_absolute(0x402877+i as u32,CrtRegionKind::Module)?,8,CrtValue::scalar(u32::from(byte)))?;}
     objects.unobserved.as_mut().unwrap().code=alternate;event.unobserved.as_mut().unwrap().code=alternate;
    }
    let result=if mode>=76{
     cxx_invoke_selected_search_with(&mut search,&mut event,&objects,&mut rt,&c,e,&b,&mut d,&ancestor,&af,&rec,stack,fiber,slot,0x401900,Some(&mut CrtLazyPtdBackend{fiber:if mode==79{CrtFiber{thread:fiber.thread+1,..fiber}}else{fiber},slot,api:&mut|_,_,_|Err("selected lazy loader remains unbound"),setter:&mut|rt,_,value|{
       if let CrtValue::Pointer(p)=value{if mode==78{rt.store(rt.offset(p,32)?,32,CrtValue::Scalar{bits:0,known:0})?;}}
       Ok((u32::from(!matches!(mode,77|81)||!matches!(value,CrtValue::Pointer(_))),Some(100)))
      },allocation:&mut|rt,c,epoch,target|{
       if target==0x4077ff{return abort_entry_original(rt,c,epoch);}
       if target==0x407cf0{let sp=CrtCpu::pointer(c.r[4])?;assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::scalar(1));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(40));
        let CrtValue::Heap(heap)=rt.load(rt.resolve_absolute(0x41d2c8,CrtRegionKind::Module)?,32)? else{return Err("pending allocator heap provenance")};
        let value=calloc_live_original(rt,c,heap,&mut|rt,c|ptd_get_registered(rt,c,epoch,fiber,ucrt_slot.ok_or("missing UCRT slot")?),if mode==84{(0,usize::MAX)}else{(1,1)},false,rt.resolve_absolute(0x7110,CrtRegionKind::ThreadData)?,&mut vec![],&mut|_,_|Err("pending calloc new handler remains unbound"))?;
        if mode==80{rt.memory.release(context.cap,context.owner).map_err(|_|"test capture retirement")?;}
        if mode==82{rt.free_allocation(CrtCpu::pointer(value)?)?;}Ok(value)
       }else{assert_eq!(target,0x407d50);original_free(rt,c,&mut|_,_,_,_|Ok((0,Some(5))),&mut|rt,c|{
        let p=rt.resolve_absolute(0x7100,CrtRegionKind::ThreadData)?;
        if mode==81{rt.store(rt.offset(p,16)?,32,CrtValue::scalar(74))?;return Err("selected errno failure after prior write");}
        ptd_get_registered(rt,c,epoch,fiber,ucrt_slot.ok_or("missing UCRT slot")?)
       })}
      }}))
    }else{cxx_invoke_selected_search(&mut search,&mut event,&objects,&mut rt,&c,e,&b,&mut d,&ancestor,&af,&rec,stack,fiber,slot,0x401900)};
    if mode>=76{
     if matches!(mode,76|83){let receipt=result.expect("same-event lazy original handler must return");assert_eq!(receipt.receipt.value,CrtValue::scalar(1));let CrtValue::Pointer(actual)=rt.fls_get(fiber,slot,3)? else{panic!("missing actual allocation")};assert_eq!(actual.kind,CrtRegionKind::Buffer);rt.dispatcher_ptd(actual)?;
      if mode==83{event.generation+=1;}
      let taken=cxx_take_selected_search(&mut search,&mut event,&objects,receipt,&rt,&c,e,&b,&ancestor,&af,&rec);
      assert_eq!(taken,if mode==83{Err("normal exception stale/foreign ownership")}else{Ok(1)});
     }else{let expected=match mode{77=>"shared exit managed-runtime query 0x401d51 unbound",78=>"CRT unknown scalar bits observed",79=>"CRT fiber identity/lifetime",80=>"CRT pointer lifetime",81=>"selected errno failure after prior write",82=>"CRT stale/foreign pointer",84=>"shared exit managed-runtime query 0x401d51 unbound",_=>unreachable!()};assert_eq!(result.err(),Some(expected),"lazy pending case {mode}");assert_eq!(search.phase,3);assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
     if mode==77||mode==84{let exit=e.registry.cxx.iter().find(|f|f.handler==0x414af3&&f.linked).expect("actual inline shared-exit FS installation before rejection");let record=rt.resolve_absolute(exit.record,CrtRegionKind::Stack)?;assert_eq!(rt.load(rt.offset(record,4)?,32)?,CrtValue::scalar(0x414af3));assert_eq!(rt.load(rt.offset(record,8)?,32)?,CrtValue::scalar(u32::MAX));assert!(rt.tags.values().any(|&v|v==CrtValue::ProtectedReturn(exit.owner)));}
     if mode==84{assert_eq!(rt.fls_get(fiber,slot,3)?,CrtValue::scalar(0));assert!(rt.heap_ptds.is_empty());assert_eq!(rt.load(rt.resolve_absolute(0x7110,CrtRegionKind::ThreadData)?,32)?,CrtValue::scalar(12));assert_eq!(rt.errno,None);}
     if mode==77||mode==81{assert_eq!(rt.uncertain_allocations.len(),1);let p=rt.uncertain_allocations[0];assert!(rt.valid(p,0).is_err());assert!(rt.memory.validate(p.cap,p.owner).is_ok());let field=rt.resolve_absolute(0x7110,CrtRegionKind::ThreadData)?;assert_eq!(rt.load(field,32)?,CrtValue::scalar(if mode==77{13}else{74}));assert!(rt.completed_failed_frees.is_empty());}
     assert_eq!(c.r,saved);assert!(!objects.unobserved.as_ref().unwrap().live.get());checked=true;return Err("ordered rejection checked");
    }
    if mode==21||(mode>=26&&mode!=47&&mode!=66&&mode<74){
     let mut receipt=result.expect("selected original C++ search must return");assert_eq!(receipt.receipt.value,CrtValue::scalar(1));
     if mode==26{receipt.registration.generation+=1;}
     if mode==27{receipt.serial+=1;}
     if mode==34{e.registry.normal_epoch.as_mut().unwrap().previous=RegistryHead::BorrowedRoot(e.registry.identity);}
     if mode==35{e.registry.normal_epoch.as_mut().unwrap().selected.generation+=1;}
     if mode==36{let RegistryHead::Owned(id)=search.root else{panic!("owned root")};let index=e.registry.frame_index(id)?;e.registry.frames[index].live=false;}
     if mode==31{let RegistryHead::Owned(id)=e.registry.cxx[0].previous else{panic!("expected owned predecessor")};let index=e.registry.frame_index(id)?;e.registry.frames[index].linked=false;}
     if mode==32{e.registry.cxx[0].previous=RegistryHead::BorrowedRoot(e.registry.identity);}
     if mode==33{objects.record=rt.map_region(0x53000,80,CrtRegionKind::Context,None)?;}
     if mode==28{rt.store(rt.resolve_absolute(0x41b42c,CrtRegionKind::Module)?,8,CrtValue::scalar(0))?;}
     if mode==30{assert_eq!(cxx_invoke_selected_search(&mut search,&mut event,&objects,&mut rt,&c,e,&b,&mut d,&ancestor,&af,&rec,stack,fiber,slot,0x401900).err(),Some("selected C++ repeated execution"));checked=true;return Err("ordered rejection checked");}
     let replay=if mode==29{Some(CrtSelectedCxxReturn{receipt:CrtNormalHandlerReturn{identity:receipt.receipt.identity,epoch:receipt.receipt.epoch,frame:receipt.receipt.frame,generation:receipt.receipt.generation,level:receipt.receipt.level,value:receipt.receipt.value},serial:receipt.serial,registration:receipt.registration,handler:receipt.handler,owner:receipt.owner,context:CrtCxxContext::bind_normal(&rt,&ancestor,&af,&objects,stack)?})}else{None};
     if mode>=37{assert!(receipt.context.esp.is_none());if mode<49{assert!(rt.load(rt.offset(context,0xc4)?,32)?.known_scalar().is_err());}else{assert_eq!(receipt.context.numeric_esp().err(),Some("C++ unwind requires numeric captured ESP"));}}
     if mode==43{assert_eq!(receipt.context.numeric_esp().err(),Some("C++ unwind requires numeric captured ESP"));}
     if mode==57{receipt.context.esp=Some(rt.offset(stack,0x500)?);receipt.context.esp_value=CrtValue::scalar(0x9500);assert_eq!(receipt.context.check(&rt,&ancestor,&af),Err("C++ unobserved context representation"));receipt.context.esp=None;receipt.context.esp_value=CrtValue::Scalar{bits:0,known:0};}
     if mode==42{rt.store(rt.offset(context,0xc4)?,32,CrtValue::Scalar{bits:0x9510,known:0xfffffff0})?;}
     if mode==44{event.generation+=1;}
     if mode==45{rt.memory.release(context.cap,context.owner).map_err(|_|"test partial capture retirement")?;}
     if mode==46{let other=rt.map_region(0x55000,716,CrtRegionKind::Context,None)?;rt.store(rt.offset(other,0xc4)?,32,capture)?;objects=CrtNormalObjects::bind(&event,&rt,e,record,other)?;}
     if mode==48{rt.store(rt.offset(context,0xc4)?,32,CrtValue::Scalar{bits:0x9500,known:0xffffffe0})?;}
     if mode==63{objects.unobserved.as_ref().unwrap().revoke();}
     let got=cxx_take_selected_search(&mut search,&mut event,&objects,receipt,&rt,&c,e,&b,&ancestor,&af,&rec);
     if mode==63{assert_eq!(got,Err("unobserved context expired/foreign lease"));}
     else if matches!(mode,26|27|28|31|32|33|34|35|36|42|44|45|46|48){assert_eq!(got,Err(match mode{28=>"C++ metadata mutated/unknown",31=>"ordered search incoming owned predecessor unlinked",32=>"ordered search stale source/order/children",33=>"normal record producer object mismatch",34|35=>"ordered search incoming root authority changed",36=>"registry stale frame",42|48=>"normal exception captured ESP input changed",44=>"normal exception stale/foreign ownership",45=>"CRT pointer lifetime",46=>"ordered search stale source/order/children",_=>"selected C++ foreign/replayed executed receipt"}));}
     else{assert_eq!(got,Ok(1));assert_eq!(search.phase,5);assert_eq!(search.current,e.registry.cxx[0].previous);assert_eq!(event.delivery,CrtNormalDelivery::ResultTaken);}
     if let Some(replay)=replay{assert_eq!(cxx_take_selected_search(&mut search,&mut event,&objects,replay,&rt,&c,e,&b,&ancestor,&af,&rec),Err("ordered search stale source/order/children"));}
    }else{
     let error=result.err().expect("invalid selected registration must reject");
     assert_eq!(error,match mode{22=>"ordered search stale source/order/children",23=>"PTD frame owner/caller lifetime",24=>"normal exception captured ESP input changed",25=>"ordered search expired predecessor storage",47=>"captured stack comparison unknown",66=>"unobserved context different helper proof",74=>"CRT unknown scalar bits observed",75=>"C++ PTD lazy setter/allocation/free effect unbound",_=>unreachable!()},"selected case {mode}");assert_eq!(search.phase,3);
    }
    if mode>=74{assert_eq!(event.delivery,CrtNormalDelivery::Failed);assert_eq!(rt.load(record,32)?,CrtValue::scalar(0xe0420042));assert_eq!(rt.last_os_error,None);}
    if mode>=49{assert_eq!(objects.unobserved.as_ref().unwrap().validate(&rt),Err("unobserved context expired/foreign lease"));assert!((0..716).all(|i|matches!(rt.load_unsealed(rt.offset(context,i).unwrap(),8).unwrap(),CrtValue::Scalar{known,..}if known&255==0)));}
    assert_eq!(c.r,saved);if mode!=45&&mode<49{assert_eq!(rt.load(rt.offset(context,0xc4)?,32)?,if mode==24{CrtValue::scalar(0x9600)}else if mode==42{CrtValue::Scalar{bits:0x9510,known:0xfffffff0}}else if mode==48{CrtValue::Scalar{bits:0x9500,known:0xffffffe0}}else{capture});}
    checked=true;return Err("ordered rejection checked");
   }
   if let Some(replay)=replay{assert_eq!(original_live_search_return_advance(&mut search,replay,&mut event,&objects,&rt,&c,e,&b),Err("ordered search stale source/order/children"));}
  }else{
   let expected=match mode{1=>"ordered search wrong executed handler",2..=4=>"ordered search foreign/replayed executed receipt",6=>"CRT pointer lifetime",7=>"normal exception stale/foreign ownership",8|17=>"ordered search expired predecessor storage",9=>"live search original code/table changed",15|16|20=>"ordered search stale source/order/children",_=>unreachable!()};
   assert_eq!(taken,Err(expected),"consume negative {mode}");assert_ne!(search.current,predecessor);
  }
  checked=true;Err::<(),_>("ordered rejection checked")
 });assert_eq!(result,Err(if mode==12||mode==69{"CRT scalar knowledge/type"}else if mode==74{"CRT unknown scalar bits observed"}else if mode==75{"C++ PTD lazy setter/allocation/free effect unbound"}else if matches!(mode,77..=82|84){match mode{77=>"shared exit managed-runtime query 0x401d51 unbound",78=>"CRT unknown scalar bits observed",79=>"CRT fiber identity/lifetime",80=>"CRT pointer lifetime",81=>"selected errno failure after prior write",82=>"CRT stale/foreign pointer",84=>"shared exit managed-runtime query 0x401d51 unbound",_=>unreachable!()}}else{"ordered rejection checked"}),"outer case {mode}");assert!(checked,"case {mode} did not reach its required assertion");
 if mode==64{let lease=escaped_lease.unwrap();assert!(lease.live.get(),"event deliberately retained outside epoch");assert!(!lease.epoch_live.get());assert_eq!(lease.validate(&rt),Err("unobserved context expired/foreign lease"));drop(escaped_event);assert!(!lease.live.get());}
}}
fn live_return_cases(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xd000,1200);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,1201)?;
  for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;let saved=c.r;
  let record=rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;let context=rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
  for(offset,value)in [(0,event.code),(4,0),(8,0),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
  rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9500))?;
  let objects=CrtNormalObjects::bind(&event,&rt,e,record,context)?;
  let mut d=cpu(&mut rt,0xc000,1202);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
  for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,v)?;}
  map_live_search_return(&mut rt)?;
  let receipt=event.execute_live_handler(&objects,&mut rt,&c,e,&b,&mut d,0x401900,original_live_search_return_adapter).expect("original prefix, guard and RET must execute");
  assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b)?,1);assert_eq!(c.r,saved);assert_eq!(rt.load(CrtCpu::pointer(c.r[4])?,32)?,CrtValue::ProtectedReturn(event.return_id));
  assert!(matches!(rt.load(b.at(&rt,b.layout.bp-20)?,32)?,CrtValue::Scalar{known:u32::MAX,..}),"expired exception-pair pointer loses dereference authority");
  checked=true;Err::<(),_>("checked search return leaves original exception pending")
 });assert_eq!(result,Err("checked search return leaves original exception pending"));assert!(checked);
}
fn original_live_search_return_adapter(f:&mut CrtLiveFrame<'_,'_>,c:&mut CrtCpu)->RegistryResult<CrtValue>{
 let objects=CrtNormalObjects::bind(f.event,f.rt,f.epoch,CrtCpu::pointer(f.rt.load(f.rt.offset(CrtCpu::pointer(c.entry[4])?,4)?,32)?)?,CrtCpu::pointer(f.rt.load(f.rt.offset(CrtCpu::pointer(c.entry[4])?,12)?,32)?)?)?;
 original_live_search_return(f,c,&objects)
}
fn chain_effect_lifetime(){for mode in 0..4{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut parent=cpu(&mut rt,0xe800,1101);parent.return_pop=0;parent.push(&mut rt,CrtValue::scalar(0))?;parent.r[0]=CrtValue::scalar(0x414ad6);
  let mut pb=CrtCxxChainBinding::bind(&rt,&parent,e)?;let mut pf=CrtPtdFrame::new(&rt,&parent,pb.token,0x414ad6,0x41c000)?;
  ptd_prolog_registered(&mut rt,&mut parent,e,&mut pf,&mut pb,0x40a33e).expect("live predecessor setup");
  if mode%2==0{
   let mut child=cpu(&mut rt,0xe000,1102);child.return_pop=0;child.push(&mut rt,CrtValue::scalar(4))?;child.r[0]=CrtValue::scalar(0x414ad6);
   let mut b=CrtCxxChainBinding::bind(&rt,&child,e)?;let mut f=CrtPtdFrame::new(&rt,&child,b.token,0x414ad6,0x41c000)?;
   if mode==2{ptd_prolog_registered(&mut rt,&mut child,e,&mut f,&mut b,0x40a33e).expect("live child setup");}
   rt.consume_stack(CrtCpu::pointer(parent.entry[4])?,CrtValue::ProtectedReturn(parent.return_id)).expect("independent owner retirement");let before=e.head()?;
   let got=if mode==0{ptd_prolog_registered(&mut rt,&mut child,e,&mut f,&mut b,0x40a33e)}else{ptd_epilog_registered(&mut rt,&mut child,e,&mut f,&mut b,0x40a3b8)};
   assert_eq!(got,Err("C++ inherited owner/record lifetime"),"mode {}",mode);assert_eq!(e.registry.head,before);
  }else{
   let mut child=cpu(&mut rt,0xe000,1103);let mut b=CrtNormalBinding::bind(&rt,&child,e,epilog_run_layout())?;
   if mode==3{start(&mut rt,&mut child,e,&mut b,1104).expect("live EH4 child setup");}
   rt.consume_stack(CrtCpu::pointer(parent.entry[4])?,CrtValue::ProtectedReturn(parent.return_id)).expect("independent owner retirement");let before=e.head()?;
   let got=if mode==1{start(&mut rt,&mut child,e,&mut b,1104)}else{epilog_run(&mut rt,&mut child,e,&mut b).map(|_|())};
   assert_eq!(got,Err("C++ inherited owner/record lifetime"),"mode {}",mode);assert_eq!(e.registry.head,before);
  }
  checked=true;Err::<(),_>("effect-time rejection checked")
 });assert!(result.is_err());assert!(checked,"mode {} failed before exercising the intended boundary",mode);
}}

fn abort_locked_cases(){for mode in 0..12{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();
 rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let cookie_bytes=0x12345678u32.to_le_bytes();rt.map_region(0x41c000,4,CrtRegionKind::Module,if mode==5{None}else{Some(&cookie_bytes)}).unwrap();
 let scope=rt.map_region(0x41b740,28,CrtRegionKind::Module,Some(&abort_scope_bytes())).unwrap();
 let bits=if mode==1{0x80000001u32}else{0};let encoded=bits.rotate_left(24)^0x12345678;
 let encoded_bytes=encoded.to_le_bytes();rt.map_region(0x41d2d8,4,CrtRegionKind::Module,if mode==4{None}else{Some(&encoded_bytes)}).unwrap();
 let lock=rt.map_region(if mode==3{0x420000}else{0x41d198},24,CrtRegionKind::Module,None).unwrap();if mode!=2{rt.construct_global_lock(init,3,lock,1).unwrap();}rt.end_initialization(init).unwrap();
 if mode==8{rt.store(scope,32,CrtValue::scalar(0)).unwrap();}
 let marker=rt.map_region(0x7000,4,CrtRegionKind::ThreadData,Some(&0u32.to_le_bytes())).unwrap();let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let head=e.head()?;let mut c=cpu(&mut rt,0xe000,2101);c.return_pop=0;let mut visited=false;
  let got=abort_query_original(&mut rt,&mut c,&mut|rt,c|abort_locked_original(rt,c,e,&mut|rt|{
   visited=true;rt.store(marker,32,CrtValue::scalar(1))?;
   match mode{6=>return Err("independent finally failure after write"),7=>{rt.memory.release(lock.cap,lock.owner).map_err(|_|"independent lock retirement")?;},9=>{rt.lock_global(rt.thread,3)?;},10=>{rt.thread+=1;},11=>{rt.store(scope,32,CrtValue::scalar(0))?;},_=>{}}Ok(())
  }));
  if matches!(mode,0|1|4){let value=got.expect("original registered locked query must return");assert_eq!(value,if mode==4{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(bits)});assert!(visited);assert!(c.returned);assert!(rt.global_locks.is_empty());assert_eq!(e.head()?,head);assert!(e.state()?.frames.is_empty());}
  else{let error=got.err().expect("unsafe query must reject");let expected=match mode{2=>"CRT unconstructed indexed lock",3=>"CRT global table/object mismatch",5=>"CRT scalar knowledge/type",6=>"independent finally failure after write",7=>"CRT pointer lifetime",8|11=>"C++ metadata mutated/unknown",9|10=>"CRT stale/foreign/unordered global lock",_=>unreachable!()};assert_eq!(error,expected,"locked query case {mode}");assert!(!c.returned);if mode==6||mode==7||mode==9||mode==10{assert!(visited);assert_eq!(rt.load(marker,32)?,CrtValue::scalar(1));assert_eq!(rt.global_locks.len(),if mode==9{2}else{1});}else if mode==11{assert!(visited);assert_eq!(rt.load(marker,32)?,CrtValue::scalar(1));assert!(rt.global_locks.is_empty());}else{assert!(!visited);assert!(rt.global_locks.is_empty());}}
  checked=true;Err::<(),_>("locked query component checked")
 });assert!(result.is_err());assert!(checked,"query case {mode} skipped assertions");
}}

fn registered_errno_cases(){for mode in 0..16{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;
 rt.map_region(0x41d130,1,CrtRegionKind::Module,Some(&[0])).unwrap();let index=rt.map_region(0x41c170,4,CrtRegionKind::Module,Some(&4u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x7100,32,CrtRegionKind::ThreadData,None).unwrap();let field=rt.offset(ptd,16).unwrap();rt.store(field,32,CrtValue::scalar(73)).unwrap();
 let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,4,if matches!(mode,5|11|12){CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();rt.last_os_error=Some(97);
 let outcome=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut interrupted=cpu(&mut rt,0xd000,1901);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,e,epilog_run_layout())?;start(&mut rt,&mut interrupted,e,&mut binding,1902)?;
  for arg in [0,0,0,0xe0420042]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,e,&binding,raise_site())?;let saved=interrupted.r;
  let mut dispatcher=cpu(&mut rt,0xc000,1903);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  let result=event.execute_child_handler(&mut rt,&interrupted,e,&binding,&mut dispatcher,0x401900,|rt,h,child|{
   let mut outer=None;
   if mode>=14{h.push(rt,CrtValue::scalar(16))?;h.r[0]=CrtValue::scalar(0x414ad6);let mut b=CrtCxxChainBinding::bind(rt,h,child)?;let mut f=CrtPtdFrame::new(rt,h,b.token,0x414ad6,0x41c000)?;ptd_prolog_registered(rt,h,child,&mut f,&mut b,0x401901)?;outer=Some((f,b));}
   let head=child.head()?;let frames=child.registry.cxx.len();let generation=child.state()?.generation;
   match mode{
    1=>{rt.retire_fls(fiber,slot)?;rt.bind_fls(fiber,4,CrtValue::Pointer(ptd))?;},
    3=>rt.retire_region(ptd)?,4=>rt.store(index,32,CrtValue::scalar(3))?,
    6=>child.generation+=1,
    7=>{let ptr=rt.offset(CrtCpu::pointer(h.r[4])?,-28)?;rt.store(ptr,32,CrtValue::ProtectedReturn(9999))?;},
    8=>{let ptr=rt.offset(CrtCpu::pointer(h.r[4])?,-28)?;rt.store(ptr,32,CrtValue::Pointer(index))?;},
    9=>{rt.fls.get_mut(&4).unwrap().1=CrtValue::Pointer(rt.offset(ptd,4)?);},
    10=>{child.delivery.as_mut().unwrap().event+=1;},
    15=>{let(f,_)=outer.as_ref().unwrap();rt.store(rt.offset(f.bp,-8)?,32,CrtValue::scalar(0))?;},
    _=>{}
   }
   let value=h.call_activation(rt,0x401905,0,|rt,c|errno_routed_call(rt,c,|rt,c|{
    if mode==11||mode==12{ptd_get_registered_with_lazy(rt,c,child,fiber,slot,|rt,lazy|{
     rt.store(field,32,CrtValue::scalar(74))?;
     if mode==11{return Err("independent lazy failure after write");}
     let bp=CrtCpu::pointer(lazy.r[5])?;rt.store(rt.offset(bp,-8)?,32,CrtValue::scalar(0))?;
     lazy.clobber(CrtValue::Pointer(ptd));lazy.finish(rt)
    })}else{let value=ptd_get_registered(rt,c,child,if mode==2{CrtFiber{thread:fiber.thread+1,..fiber}}else{fiber},slot)?;
     if mode==13{assert_eq!(ptd_get_registered(rt,c,child,fiber,slot),Err("CRT active caller lifetime/return authority"));}
     Ok(value)
    }
   }))?;
   assert_eq!(child.head()?,head);assert_eq!(child.registry.cxx.len(),frames);assert_eq!(child.state()?.generation,generation);assert_eq!(rt.last_os_error,Some(97));
   let view=CrtCpu::pointer(value)?;assert_eq!((view.cap,view.owner,view.address(),view.size),(field.cap,field.owner,field.address(),4));rt.store(view,32,CrtValue::scalar(12))?;if let Some((ref mut f,ref mut b))=outer{ptd_epilog_registered(rt,h,child,f,b,0x401906)?;}h.r[0]=CrtValue::scalar(1);h.finish(rt)
  });
  assert_eq!(interrupted.r,saved);assert!(e.state().is_err());
  if matches!(mode,0|8|13|14){let receipt=result.expect("original registered errno must return");assert_eq!(event.take_handler_result(receipt,&rt,&interrupted,e,&binding)?,1);assert_eq!(rt.load(field,32)?,CrtValue::scalar(12));assert!(e.registry.cxx.is_empty());}
  else{let expected=match mode{1=>"CRT FLS owner/reused index",2=>"CRT fiber identity/lifetime",3=>"CRT stale/foreign pointer",4=>"CRT unbound FLS index",5=>"PTD lazy acquisition/recursive errno unbound",6=>"normal call stale epoch",7=>"PTD frame overlaps protected/typed storage",9=>"CRT FLS PTD root/extent",10=>"delivery child expired/foreign suspension authority",11=>"independent lazy failure after write",12=>"PTD live record/chain identity",15=>"C++ inherited owner/record lifetime",_=>unreachable!()};assert_eq!(result.err(),Some(expected),"registered errno case {mode}");assert_eq!(event.delivery,CrtNormalDelivery::Failed);if mode==11||mode==12{assert_eq!(rt.load(field,32)?,CrtValue::scalar(74));}}
  checked=true;Err::<(),_>("registered errno component complete; OS delivery remains unproved")
 });assert!(outcome.is_err());assert!(checked,"registered errno case {mode} skipped assertions");
}}


fn inline_exit_cases(){for mode in 0..20{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe800,990);c.return_pop=0;let entry=c.entry;let previous=e.head()?;
  for(i,v)in [3,2,u32::from(mode==2)].into_iter().enumerate(){rt.store(rt.offset(CrtCpu::pointer(c.r[4])?,4+i as i64*4)?,32,CrtValue::scalar(v))?;}
  let mut f=CrtInlineExit::new(&rt,&c,e)?;
  shared_exit_prolog(&mut rt,&mut c,e,&mut f).expect("original inline prolog must install");
  assert_eq!(c.r[5],CrtValue::Pointer(rt.resolve_absolute(0xe7fc,CrtRegionKind::Stack)?));assert_eq!(c.r[4],CrtValue::Pointer(rt.resolve_absolute(0xe7d4,CrtRegionKind::Stack)?));
  let id=f.id.expect("original FS write must register");assert_eq!(e.head()?,RegistryHead::Cxx(id));assert_eq!(e.registry.cxx.last().unwrap().handler,0x414af3);
  assert_eq!(rt.load(rt.offset(f.bp,-12)?,32)?,CrtValue::ThreadHead(f.token));assert_eq!(rt.load(rt.offset(f.bp,-8)?,32)?,CrtValue::scalar(0x414af3));assert_eq!(rt.load(rt.offset(f.bp,-4)?,32)?,CrtValue::scalar(u32::MAX));assert_eq!(rt.load(f.low,32)?,CrtValue::scalar(0x12345678^0xe7fc));
  let marker=rt.offset(f.bp,-20)?;rt.store(marker,32,CrtValue::scalar(77))?;
  if matches!(mode,1|2){
   let outcome=shared_exit_front(&mut rt,&mut c,e,&mut f);assert_eq!(outcome,Err(if mode==1{"shared exit managed-runtime query 0x401d51 unbound"}else{"shared exit lock/cleanup manager 0x406cfa unbound"}));assert!(!c.returned);assert_eq!(e.head()?,RegistryHead::Cxx(id));assert!(e.registry.cxx.last().unwrap().linked);
   if mode==2{assert_eq!(rt.load(rt.offset(f.bp,-13)?,8)?,CrtValue::scalar(0));assert_eq!(rt.load(rt.offset(f.bp,-24)?,32)?,CrtValue::scalar(2));assert_eq!(rt.load(rt.offset(f.bp,-20)?,32)?,CrtValue::scalar(2));let sp=CrtCpu::pointer(c.r[4])?;assert_eq!(rt.load(sp,32)?,CrtValue::Pointer(rt.offset(f.bp,-24)?));}
  }else if mode==9||mode==15{
   let mut inner=cpu(&mut rt,0xe000,991);inner.return_pop=0;let mut nf=CrtInlineExit::new(&rt,&inner,e)?;shared_exit_prolog(&mut rt,&mut inner,e,&mut nf)?;
   if mode==9{assert_eq!(shared_exit_return(&mut rt,&mut c,e,&mut f),Err("inline exit live/LIFO record"));assert!(!c.returned);assert_eq!(e.registry.cxx.len(),2);}
   else{shared_exit_return(&mut rt,&mut inner,e,&mut nf).expect("nested original epilog must return");assert_eq!(e.head()?,RegistryHead::Cxx(id));shared_exit_return(&mut rt,&mut c,e,&mut f).expect("outer original epilog must return");assert_eq!(e.head()?,previous);assert!(e.registry.cxx.is_empty());}
  }else{
   if mode==3{rt.thread+=1;}if mode==4{rt.bind_fiber(rt.thread)?;}if mode==5{rt.owner+=1;}
   if mode==6{assert_eq!(rt.store(CrtCpu::pointer(entry[4])?,32,CrtValue::scalar(0)),Err("CRT protected saved/return overwrite"));}
   if mode==7{rt.store(rt.offset(f.bp,-8)?,32,CrtValue::scalar(0x414ad6))?;}
   if mode==8{rt.store(rt.offset(f.bp,-4)?,32,CrtValue::Scalar{bits:0,known:0})?;}
   if mode==10||mode==19{f.unlink(&rt,&c,e,CrtValue::ThreadHead(f.token))?;assert_eq!(e.head()?,previous);if mode==19{c.returned=true;c.r[4]=CrtValue::Pointer(rt.offset(CrtCpu::pointer(entry[4])?,4)?);c.r[5]=entry[5];}assert_eq!(f.retire(&mut rt,&c,e),Err("inline exit incomplete return"));assert_eq!(f.phase,2);assert_eq!(rt.load(marker,32)?,CrtValue::scalar(77));checked=true;return Err("independent failure after original unlink");}
   if mode==11{assert_eq!(f.install(&rt,&c,e,CrtValue::Pointer(rt.offset(f.bp,-12)?)),Err("inline exit original installation/replay"));}
   if mode==12{e.generation+=1;}
   if mode==13{rt.memory.release(f.low.cap,f.low.owner).map_err(|_|"test storage release")?;}
   if mode==14{assert_eq!(rt.store(f.bp,32,CrtValue::scalar(0)),Err("CRT protected saved/return overwrite"));}
   if mode==16{rt.store(f.low,32,CrtValue::scalar(0))?;}// Original normal epilog discards guard; no invented check.
   if mode==17{c.push(&mut rt,CrtValue::scalar(1))?;}
   if mode==18{assert_eq!(f.retire(&mut rt,&c,e),Err("inline exit incomplete return"));}
   let outcome=shared_exit_return(&mut rt,&mut c,e,&mut f);
   if matches!(mode,0|6|11|14|16|18){outcome.expect("original inline epilog must return");assert!(c.returned);assert_eq!(e.head()?,previous);assert!(e.registry.cxx.is_empty());assert_eq!(f.phase,3);assert_eq!(c.r[5],entry[5]);assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(CrtCpu::pointer(entry[4])?,4)?));assert_eq!(shared_exit_return(&mut rt,&mut c,e,&mut f),Err("CRT active caller lifetime/return authority"));assert!(rt.load(rt.offset(f.bp,-12)?,32)?.known_scalar().is_err());}
   else{let expected=match mode{3|4|5=>"inline exit stale owner/event/fiber",7=>"C++ inherited owner/record lifetime",8=>"CRT scalar knowledge/type",12=>"normal call stale epoch",13=>"CRT pointer lifetime",17=>"inline exit return stack/saved frame",_=>unreachable!()};assert_eq!(outcome,Err(expected),"inline case {mode}");assert!(!c.returned);assert!(e.registry.cxx.iter().any(|n|n.id==id&&n.linked));}
  }
  checked=true;Err::<(),_>("inline frame component complete; exit effects unbound")
 });assert!(result.is_err());assert!(checked,"inline exit case {mode} skipped assertions");
}}



fn inline_exit_image(){for managed in [false,true]{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let mut bytes=vec![0;512];bytes[..2].copy_from_slice(b"MZ");bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());bytes[0x80..0x84].copy_from_slice(b"PE\0\0");bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());bytes[0xf4]=15;bytes[0x168]=u8::from(managed);rt.bootstrap_main_image(init,0x500000,&bytes).unwrap();rt.end_initialization(init).unwrap();let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe800,998);c.return_pop=0;rt.store(rt.offset(CrtCpu::pointer(c.r[4])?,12)?,32,CrtValue::scalar(0))?;let mut f=CrtInlineExit::new(&rt,&c,e)?;shared_exit_prolog(&mut rt,&mut c,e,&mut f)?;
  let got=shared_exit_front(&mut rt,&mut c,e,&mut f);assert_eq!(got,Err(if managed{"shared exit managed termination 0x406f55 unbound"}else{"shared exit lock/cleanup manager 0x406cfa unbound"}));assert!(!c.returned);assert_eq!(e.head()?,RegistryHead::Cxx(f.id.unwrap()));assert!(e.registry.cxx.last().unwrap().linked);checked=true;Err::<(),_>("exit image input component; main-image producer remains unproved")
 });assert!(result.is_err());assert!(checked);
}}
fn inline_exit_delivery(){for mode in 0..4{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt.bootstrap_main_image(init,0x500000,&[0;512]).unwrap();rt.end_initialization(init).unwrap();let mut checked=false;
 let outcome=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut interrupted=cpu(&mut rt,0xd000,994);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,e,epilog_run_layout())?;start(&mut rt,&mut interrupted,e,&mut binding,995)?;
  for arg in [0,0,0,0xe0420042]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,e,&binding,raise_site())?;let saved=interrupted.r;
  let mut dispatcher=cpu(&mut rt,0xc000,996);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  let result=event.execute_child_handler(&mut rt,&interrupted,e,&binding,&mut dispatcher,0x401900,|rt,h,child|{
   h.call_activation(rt,0x401905,0,|rt,c|{
    CrtModuleImage::main(rt)?.validate(rt)?;let mut f=CrtInlineExit::new(rt,c,child)?;shared_exit_prolog(rt,c,child,&mut f)?;
    if mode==1{f.lease=None;}if mode==2{child.delivery=None;}if mode==3{child.registry.normal_epoch.as_mut().unwrap().pending_exception=None;}
    shared_exit_return(rt,c,child,&mut f)
   })?;h.r[0]=CrtValue::scalar(1);h.finish(rt)
  });assert_eq!(interrupted.r,saved);assert!(e.state().is_err());CrtModuleImage::main(&rt)?.validate(&rt)?;
  if mode==0{let receipt=result.expect("owned delivery child original inline return");assert_eq!(event.take_handler_result(receipt,&rt,&interrupted,e,&binding)?,1);assert!(e.registry.cxx.is_empty());}
  else{assert_eq!(result.err(),Some(match mode{1=>"inline exit stale owner/event/fiber",2=>"normal call suspended for owned exception",3=>"delivery child expired/foreign suspension authority",_=>unreachable!()}));assert_eq!(event.delivery,CrtNormalDelivery::Failed);assert!(e.registry.cxx.iter().any(|f|f.handler==0x414af3&&f.linked));}
  checked=true;Err::<(),_>("inline exit delivery component; acquisition unproved")
 });assert!(outcome.is_err());assert!(checked,"inline delivery {mode} skipped assertions");
}}

fn shared_chain_delivery(){for mode in 0..5{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut checked=false;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut ancestor=cpu(&mut rt,0xe800,970);ancestor.return_pop=0;ancestor.push(&mut rt,CrtValue::scalar(16))?;ancestor.r[0]=CrtValue::scalar(0x414ad6);
  let mut ancestor_binding=CrtCxxChainBinding::bind(&rt,&ancestor,e)?;let mut ancestor_frame=CrtPtdFrame::new(&rt,&ancestor,ancestor_binding.token,0x414ad6,0x41c000)?;
  ptd_prolog_registered(&mut rt,&mut ancestor,e,&mut ancestor_frame,&mut ancestor_binding,0x40a33e).expect("registered C++ ancestor before source");let ancestor_head=e.head()?;
  let mut interrupted=cpu(&mut rt,0xd000,971);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,e,epilog_run_layout())?;assert_eq!(binding.previous,ancestor_head);start(&mut rt,&mut interrupted,e,&mut binding,972)?;
  for arg in [0,0,0,0xe0420042]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let mut event=CrtNormalException::issue(&mut rt,&mut interrupted,e,&binding,raise_site())?;let saved=interrupted.r;let generation=event.generation;
  let mut dispatcher=cpu(&mut rt,0xc000,973);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
  for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
  let receipt=event.execute_child_handler(&mut rt,&interrupted,e,&binding,&mut dispatcher,0x401900,|rt,h,child|{
   if mode==4{return ptd_epilog_registered(rt,&mut ancestor,child,&mut ancestor_frame,&mut ancestor_binding,0x40a3b8).map(|_|CrtValue::scalar(0));}
   h.push(rt,CrtValue::scalar(16))?;h.r[0]=CrtValue::scalar(0x414ad6);
   let mut b=CrtCxxChainBinding::bind(rt,h,child)?;let mut f=CrtPtdFrame::new(rt,h,b.token,0x414ad6,0x41c000)?;
   if mode==2{b.lease=None;return ptd_prolog_registered(rt,h,child,&mut f,&mut b,0x40a33e).map(|_|CrtValue::scalar(0));}
   ptd_prolog_registered(rt,h,child,&mut f,&mut b,0x40a33e).expect("delivery owns original C++ child");assert_eq!(child.state()?.pending_exception,Some(generation));assert!(child.top(binding.id.unwrap()).is_err());
   if mode==3{return ptd_prolog_registered(rt,h,child,&mut f,&mut b,0x40a33e).map(|_|CrtValue::scalar(0));}
   if mode==1{ptd_epilog_with_fs(rt,h,&mut f,0x40a3b8,|rt,f,v,enter|b.effect(rt,child,f,v,enter))?;assert_eq!(child.registry.head,RegistryHead::Normal(binding.id.unwrap()));assert_eq!(child.registry.cxx.len(),2);}else{ptd_epilog_registered(rt,h,child,&mut f,&mut b,0x40a3b8).expect("delivery child fully retires");}
   h.r[0]=CrtValue::scalar(1);h.finish(rt)
  });assert_eq!(interrupted.r,saved);assert!(e.state().is_err());
  if mode==0{let receipt=receipt.expect("completed child preserves suspension");assert_eq!(event.take_handler_result(receipt,&rt,&interrupted,e,&binding).expect("matching receipt"),1);assert_eq!(e.registry.cxx.len(),1);assert_eq!(RegistryHead::Cxx(e.registry.cxx[0].id),ancestor_head);}
  else{let expected=match mode{1=>"delivery child incomplete return or changed context",2|4=>"C++ chain stale owner/epoch/lease",3=>"PTD prolog replay",_=>unreachable!()};assert_eq!(receipt.err(),Some(expected),"mode {}",mode);assert_eq!(event.delivery,CrtNormalDelivery::Failed);}
  checked=true;Err::<(),_>("delivery acquisition and restoration remain external gates")
 });assert!(result.is_err());assert!(checked,"mode {} failed before its intended boundary",mode);
}}

fn shared_chain_nested(){for fault in 0..5{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let root=r.head;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut a=cpu(&mut rt,0xe800,901);a.return_pop=0;a.push(&mut rt,CrtValue::scalar(0))?;a.r[0]=CrtValue::scalar(0x414ad6);
  let mut ab=CrtCxxChainBinding::bind(&rt,&a,e)?;let mut af=CrtPtdFrame::new(&rt,&a,ab.token,0x414ad6,0x41c000)?;
  if fault==1{
   let failed=ptd_prolog_with_fs(&mut rt,&mut a,&mut af,0x40a33e,|rt,f,v,enter|{ab.effect(rt,e,f,v,enter)?;Err("independent later-effect failure")});
   assert_eq!(failed,Err("independent later-effect failure"));assert_eq!(e.registry.head,RegistryHead::Cxx(ab.id.expect("actual FS write published before failure")));assert_eq!(af.phase,3);return e.fail("preserved failed helper effects");
  }
  ptd_prolog_registered(&mut rt,&mut a,e,&mut af,&mut ab,0x40a33e).expect("outer registered prolog");let first=e.head()?;
  if fault==2{let before=e.head()?;assert!(rt.store(rt.offset(af.bp,-12)?,32,CrtValue::ProtectedReturn(902)).is_err());assert_eq!(e.head()?,before);return Err("rejected typed predecessor alias");}
  let sp=0xe000;let mut b=cpu(&mut rt,sp,902);b.return_pop=0;b.push(&mut rt,CrtValue::scalar(0))?;b.r[0]=CrtValue::scalar(0x414ad6);
  let mut bb=CrtCxxChainBinding::bind(&rt,&b,e)?;let mut bf=CrtPtdFrame::new(&rt,&b,bb.token,0x414ad6,0x41c000)?;
  if fault==3{bb.previous=root;}
  let got=ptd_prolog_registered(&mut rt,&mut b,e,&mut bf,&mut bb,0x40a33e);
  if matches!(fault,2|3){assert!(got.is_err());return Err("rejected alias/stale predecessor");}got.expect("direct nested C++ installation");let second=e.head()?;
  assert_ne!(first,second);assert_eq!(e.registry.cxx.last().unwrap().previous,first);
  ptd_epilog_registered(&mut rt,&mut b,e,&mut bf,&mut bb,0x40a3b8).expect("nested epilog");b.finish(&mut rt)?;assert_eq!(e.head()?,first);
  if fault==4{return ptd_epilog_registered(&mut rt,&mut b,e,&mut bf,&mut bb,0x40a3b8);}
  ptd_epilog_registered(&mut rt,&mut a,e,&mut af,&mut ab,0x40a3b8).expect("outer epilog");a.finish(&mut rt)?;Ok(())
 });if fault==0{result.expect("nested original C++ chain succeeds");assert_eq!(r.head,root);}else{let expected=match fault{1=>"preserved failed helper effects",2=>"rejected typed predecessor alias",3=>"C++ chain changed predecessor/replay",4=>"C++ chain stale owner/epoch/lease",_=>unreachable!()};assert_eq!(result,Err(expected),"fault {}",fault);assert!(!r.cxx.is_empty());}
}}

fn shared_chain_cases(){for mode in 0..14{
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let root=r.head;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut outer=cpu(&mut rt,0xe800,801);outer.return_pop=0;outer.push(&mut rt,CrtValue::scalar(if mode==12{256}else{16}))?;outer.r[0]=CrtValue::scalar(0x414ad6);
  let mut a=CrtCxxChainBinding::bind(&rt,&outer,e)?;let mut af=CrtPtdFrame::new(&rt,&outer,a.token,0x414ad6,0x41c000)?;
  ptd_prolog_registered(&mut rt,&mut outer,e,&mut af,&mut a,0x40a33e).expect("first original C++ registration");let first=e.head()?;assert_ne!(first,root);
  if mode==1{return ptd_prolog_registered(&mut rt,&mut outer,e,&mut af,&mut a,0x40a33e);}
  if mode==13{let entry=CrtCpu::pointer(outer.entry[4])?;rt.consume_stack(entry,CrtValue::ProtectedReturn(outer.return_id))?;let normal=cpu(&mut rt,0xe000,802);assert!(matches!(CrtNormalBinding::bind(&rt,&normal,e,epilog_run_layout()),Err("C++ inherited owner/record lifetime")));assert_eq!(e.head()?,first);return e.fail("rejected stale C++ predecessor owner");}
  let mut normal=cpu(&mut rt,0xe000,802);let mut n=CrtNormalBinding::bind(&rt,&normal,e,epilog_run_layout())?;
  assert_eq!(n.previous,first);start(&mut rt,&mut normal,e,&mut n,803).expect("EH4 inherits actual C++ head");let nh=e.head()?;
  if mode==2{return ptd_epilog_registered(&mut rt,&mut outer,e,&mut af,&mut a,0x40a3b8);}
  let mut inner=cpu(&mut rt,0xd800,804);inner.return_pop=0;inner.push(&mut rt,CrtValue::scalar(if mode==11{4}else{0}))?;inner.r[0]=CrtValue::scalar(0x414ad6);
  let mut b=CrtCxxChainBinding::bind(&rt,&inner,e)?;let mut bf=CrtPtdFrame::new(&rt,&inner,b.token,0x414ad6,0x41c000)?;
  if mode==3{b.previous=root;}
  if mode==4{b.epoch+=1;}
  if mode==5{b.owner+=1;}
  if mode==6{b.token=a.token;}
  if matches!(mode,3..=6){return ptd_prolog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a33e);}
  ptd_prolog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a33e).expect("second C++ registration above EH4");let second=e.head()?;assert_ne!(second,first);
  assert_eq!(e.registry.cxx.len(),2);assert_eq!(e.registry.cxx.last().unwrap().previous,nh);
  if mode==7{assert_eq!(rt.store(rt.offset(bf.bp,-12)?,32,CrtValue::ThreadHead(a.token)),Err("CRT protected saved/return overwrite"));assert_eq!(e.head()?,second);return e.fail("rejected typed predecessor overwrite");}
  if mode==8{rt.store(bf.low,32,CrtValue::scalar(0))?;return ptd_epilog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a3b8);}
  if mode==9{e.registry.head=first;return ptd_epilog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a3b8);}
  if mode==10{e.registry.normal_epoch.as_mut().unwrap().pending_exception=Some(990);return ptd_epilog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a3b8);}
  ptd_epilog_registered(&mut rt,&mut inner,e,&mut bf,&mut b,0x40a3b8).expect("inner original unlink and retirement");assert_eq!(e.head()?,nh);inner.finish(&mut rt)?;
  normal.r[0]=CrtValue::scalar(23);assert_eq!(epilog_run(&mut rt,&mut normal,e,&mut n)?.known_scalar()?,23);assert_eq!(e.head()?,first);
  ptd_epilog_registered(&mut rt,&mut outer,e,&mut af,&mut a,0x40a3b8).expect("outer original unlink and retirement");assert_eq!(e.head()?,root);assert!(e.registry.cxx.is_empty());outer.finish(&mut rt)?;assert!(a.identity(&rt,e,&af).is_err());Ok(())
 });if matches!(mode,0|11|12){result.expect("mixed chain completes original LIFO epilogs");assert_eq!(r.head,root);}else{let expected=match mode{1=>"PTD prolog replay",2|9=>"C++ chain non-LIFO unlink/identity",3=>"C++ chain changed predecessor/replay",4..=6=>"C++ chain stale owner/epoch/lease",7=>"rejected typed predecessor overwrite",8=>"PTD guard changed",10=>"normal call suspended for owned exception",13=>"rejected stale C++ predecessor owner",_=>unreachable!()};assert_eq!(result,Err(expected),"mode {}",mode);assert!(r.failure.is_some());assert!(!r.cxx.is_empty(),"failed path preserves published registration");}
}}

fn chain_ownership_gap(){let delivery_mode=0;let mode=0;
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let _previous=r.head;
 let(mut rt,init)=CrtStreamRuntime::new_initializing(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent unwind dependency",0x720000).unwrap();let function=rt.module_export_result(init,module,"FlsGetValue",0x721000).unwrap();let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==6{CrtValue::scalar(0)}else{CrtValue::Function(function)}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==10{0x401bfau32}else{0x401bf9u32}).to_le_bytes())).unwrap();rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x6000,if mode==8{28}else{40},CrtRegionKind::ThreadData,None).unwrap();let count=rt.offset(ptd,24).unwrap();rt.store(count,32,CrtValue::scalar(2)).unwrap();let fiber=rt.bind_fiber(rt.thread).unwrap();let slot=rt.bind_fls(fiber,3,if mode==2{CrtValue::scalar(0)}else{CrtValue::Pointer(ptd)}).unwrap();
 if mode==7{let alias=CrtValue::Pointer(rt.offset(ptd,4).unwrap());assert!(rt.bind_fls(fiber,4,alias).is_err());rt.fls.get_mut(&3).unwrap().1=alias;}
 if mode==3{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}if mode==4{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.retire_region(ptd).unwrap();}if mode==11{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(index,32,CrtValue::scalar(u32::MAX)).unwrap();}rt.end_initialization(init).unwrap();
 let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&cxx_meta_bytes())).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&cxx_map_bytes())).unwrap();rt.map_region(0x41b298,40,CrtRegionKind::Module,Some(&cxx_scope_bytes())).unwrap();let notice=rt.map_region(0x41c070,16,CrtRegionKind::Module,None).unwrap();
 let mut owner=cpu(&mut rt,0xe800,701);owner.return_pop=0;owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let predecessor=rt.thread_head(r.identity.instance,1,CrtNormalBinding::head_bits(r.head)).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{0}else{u32::MAX})).unwrap();
 let(mut other,_)=CrtStreamRuntime::new_initializing(rt.owner,rt.thread,0x8000,65536).unwrap();let foreign=other.bind_fiber(other.thread).unwrap();rt.last_os_error=if mode==13{None}else{Some(77)};let saved_error=rt.last_os_error;let refs=rt.module_references.len();let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();

 let stack=rt.resolve_absolute(0x9000,CrtRegionKind::Stack).unwrap();let cp=rt.map_region(0x50000,if delivery_mode==22{200}else{716},CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(cp,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let mut context=CrtCxxContext::bind(&rt,&owner,&frame,cp,stack).unwrap();
 let exception=rt.map_region(0x51000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(0xe06d7363)).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(if delivery_mode==29{3}else{2})).unwrap();rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(0)).unwrap();

 let old_head=r.head;let first_current=frame.current;
 let mut sibling=cpu(&mut rt,0xe000,801);sibling.return_pop=0;sibling.push(&mut rt,CrtValue::scalar(0)).unwrap();sibling.r[0]=CrtValue::scalar(0x414ad6);
 let mut second=CrtPtdFrame::new(&rt,&sibling,predecessor,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut sibling,&mut second,0x40a33e).unwrap();
 let second_record=cxx_bind(&rt,&sibling,&second).unwrap();
 frame.live(&rt,&owner).unwrap();second.live(&rt,&sibling).unwrap();
 assert_eq!(frame.previous,second.previous);assert_ne!(first_current,second.current);
 // Both instruction-proved FS stores updated their own frame view. Neither
 // was published to the shared registry head: local liveness is not selection.
 assert_eq!(r.head,old_head);assert_eq!(frame.current,first_current);
 let stack=rt.resolve_absolute(0x9000,CrtRegionKind::Stack).unwrap();
 let ca=rt.map_region(0x53000,716,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(ca,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();
 let cb=rt.map_region(0x54000,716,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(cb,196).unwrap(),32,CrtValue::Pointer(second.low)).unwrap();
 let context_a=CrtCxxContext::bind(&rt,&owner,&frame,ca,stack).unwrap();let context_b=CrtCxxContext::bind(&rt,&sibling,&second,cb,stack).unwrap();
 let exception=rt.map_region(0x55000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(0xe06d7363)).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(2)).unwrap();
 let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let mut interrupted=cpu(&mut rt,0xd000,771);let mut binding=CrtNormalBinding::bind(&rt,&interrupted,epoch,epilog_run_layout())?;start(&mut rt,&mut interrupted,epoch,&mut binding,772)?;
  for arg in [0,0,0,0xe06d7363]{interrupted.push(&mut rt,CrtValue::scalar(arg))?;}
  let event=CrtNormalException::issue(&mut rt,&mut interrupted,epoch,&binding,raise_site())?;
  assert_eq!(binding.previous,old_head,"normal source did not inherit either local C++ head");
  let one=CrtCxxInvocation::bind_unwind(&event,&rt,epoch,&owner,&frame,&record,&context_a,exception).expect("supplied owner A binds");
  let two=CrtCxxInvocation::bind_unwind(&event,&rt,epoch,&sibling,&second,&second_record,&context_b,exception).expect("supplied owner B binds");
  assert_eq!(one.event,two.event);assert_ne!(one.bp,two.bp);
  assert_eq!(epoch.registry.head,RegistryHead::Normal(event.frame));assert!(epoch.state().is_err());
  // Deliberately do not select either candidate or invoke either handler.
  // The observation demonstrates a missing producer, not thread-chain proof.
  Err::<(),_>("two local FS views cannot establish actual handler selection")
 });assert!(result.is_err());
}
struct EntropyObservations{time:u64,counter:u64,seen:Vec<u8>,fail:u8}
impl CrtEntropyBackend for EntropyObservations{
 fn filetime(&mut self)->Result<u64,&'static str>{self.seen.push(0);if self.fail==1{Err("independent time acquisition failure")}else{Ok(self.time)}}
 fn counter(&mut self)->Result<u64,&'static str>{self.seen.push(3);if self.fail==2{Err("independent counter acquisition failure")}else{Ok(self.counter)}}
}
fn canonical_cookie_entropy(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..16{
  let(m,mut registry,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let head=registry.head;
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&file).unwrap();let image=rt.main_image.unwrap();
  rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
  let cookie=rt.process_image_pointer(image,0x41c000,4).unwrap();let complement=rt.process_image_pointer(image,0x41c040,4).unwrap();let initial_cookie=rt.load(cookie,32).unwrap();let initial_complement=rt.load(complement,32).unwrap();
  let inputs=CrtEntropyInputs::bind(&rt,init,0x10203040,0x50607080).unwrap();
  let entry=0xd000+mode*16;let mix_address=entry-20;
  let mut b=EntropyObservations{time:0x89abcdef01234567,counter:0xfedcba9876543210,seen:Vec::new(),fail:0};
  // Independent API observations selected to exercise original repair branches.
  // The backend returns raw 64-bit observations, never a cookie or XOR result.
  if mode==1{b.time=0;b.counter=u64::from(mix_address^inputs.process_id^inputs.thread_id^0xbb40e64e);}
  if mode==2{b.time=0;b.counter=u64::from(mix_address^inputs.process_id^inputs.thread_id^0x11);}
  if mode==3{b.time=u64::MAX;b.counter=0;}
  if mode==4{b.fail=1;}if mode==5{b.fail=2;}
  if mode==6{rt.end_initialization(init).unwrap();}
  if mode==7{rt.thread+=1;}
  if mode==8{rt.owner+=1;}
  if mode==9{rt.memory.release(cookie.cap,cookie.owner).unwrap();}
  if mode==10{assert!(CrtEntropyInputs::bind(&rt,init,0,12).is_err());}
  if mode==11{let(other,_)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();assert!(inputs.validate(&other).is_err());}
  if mode==12{b.time=0;b.counter=0;}
  if mode==13{b.time=1u64<<63;b.counter=1;}
  if mode==14{b.time=0x100000000;b.counter=0x100000000;}
  let mut c=cpu(&mut rt,entry,1000+u64::from(mode));c.return_pop=0;let saved=c.entry;
  let got=original_cookie_init_connected(&mut rt,&mut c,&inputs,&mut b);
  if (4..=9).contains(&mode){
   let expected=match mode{4=>"independent time acquisition failure",5=>"independent counter acquisition failure",6|7=>"CRT initialization owner/lifetime",8=>"CRT process image owner/lifetime",9=>"CRT pointer lifetime",_=>unreachable!()};assert_eq!(got,Err(expected),"entropy rejection {mode}");assert!(!c.returned);
   if mode!=9{assert_eq!(rt.load(cookie,32).unwrap(),initial_cookie);assert_eq!(rt.load(complement,32).unwrap(),initial_complement);}
   if mode==4||mode==5{
    assert_eq!(b.seen,if mode==4{vec![0]}else{vec![0,3]});
    let local=rt.resolve_absolute(entry-28,CrtRegionKind::Stack).unwrap();
    let expected=if mode==4{0}else{b.time};assert_eq!(rt.load(local,32).unwrap(),CrtValue::scalar(expected as u32));assert_eq!(rt.load(rt.offset(local,4).unwrap(),32).unwrap(),CrtValue::scalar((expected>>32)as u32));
    if mode==5{let q=rt.resolve_absolute(entry-36,CrtRegionKind::Stack).unwrap();assert_eq!(CrtCpu::bits(rt.load(q,32).unwrap()).unwrap().1,0);assert_eq!(CrtCpu::bits(rt.load(rt.offset(q,4).unwrap(),32).unwrap()).unwrap().1,0);}
   }else{assert!(b.seen.is_empty());}
  }else{
   got.expect("original default-cookie helper and store must return");assert!(c.returned);assert_eq!(b.seen,vec![0,3]);
   let raw=(b.time as u32)^((b.time>>32)as u32)^inputs.thread_id^inputs.process_id^(b.counter as u32)^((b.counter>>32)as u32)^mix_address;
   let expected=if raw==0xbb40e64e{0xbb40e64f}else if raw&0xffff0000==0{raw|((raw|0x4711)<<16)}else{raw};
   assert_eq!(rt.load(cookie,32).unwrap(),CrtValue::scalar(expected));assert_eq!(rt.load(complement,32).unwrap(),CrtValue::scalar(!expected));for i in [3,5,6,7]{assert_eq!(c.r[i],saved[i]);}
   let count=b.seen.len();assert_eq!(original_cookie_init_connected(&mut rt,&mut c,&inputs,&mut b),Err("CRT active caller lifetime/return authority"));assert_eq!(b.seen.len(),count);
   rt.end_initialization(init).unwrap();
   registry.with_normal_calls(&m,&mut permit,&main,|epoch|{let mut frame=cpu(&mut rt,0xe000,5000+u64::from(mode));let mut binding=CrtNormalBinding::bind(&rt,&frame,epoch,epilog_run_layout())?;start(&mut rt,&mut frame,epoch,&mut binding,9000+u64::from(mode))?;assert_eq!(rt.load(cookie,32)?,CrtValue::scalar(expected));frame.r[0]=CrtValue::scalar(63);let value=epilog_run(&mut rt,&mut frame,epoch,&mut binding)?;assert_eq!(value,CrtValue::scalar(63));assert!(binding.authority(&rt,epoch).is_err());Ok(())}).expect("entropy-produced cookie feeds original registered record lifecycle");assert_eq!(registry.head,head);
  }
 }
}
fn entropy_api_boundaries(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..9{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();
  let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,100).unwrap();let p=rt.offset(sp,16).unwrap();let q=rt.offset(p,4).unwrap();let bp=rt.offset(sp,40).unwrap();rt.store(p,32,CrtValue::scalar(0x12345678)).unwrap();
  rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(p)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();c.r[5]=CrtValue::Pointer(bp);c.entry=c.r;c.return_pop=4;
  if mode==2{rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(rt.subrange(p,4).unwrap())).unwrap();}
  if mode==3{rt.store(q,32,CrtValue::ProtectedReturn(88)).unwrap();}
  if mode==4{rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(sp)).unwrap();}
  if mode==5{rt.memory.release(stack.cap,stack.owner).unwrap();}
  if mode==6{rt.end_initialization(init).unwrap();}
  let mut b=EntropyObservations{time:0x0102030405060708,counter:0xfedcba9876543210,seen:Vec::new(),fail:if mode==7{1}else if mode==8{2}else{0}};
  let kind=if mode==1||mode==8{3}else{0};let got=entropy_api(&mut rt,&mut c,&inputs,&mut b,kind);
  if (2..=8).contains(&mode){assert_eq!(got,Err(match mode{2=>"CRT pointer complete range/identity",3=>"CRT scalar pair role/typed alias",4=>"entropy output is not an owned local pair",5=>"CRT pointer lifetime",6=>"CRT initialization owner/lifetime",7=>"independent time acquisition failure",8=>"independent counter acquisition failure",_=>unreachable!()}),"API mode {mode}");assert!(!c.returned);if mode!=5{assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(0x12345678));}assert_eq!(b.seen,if mode==7||mode==8{vec![kind]}else{vec![]});}
  else{let value=got.expect("valid pair API returns");assert_eq!(value,CrtValue::Scalar{bits:0,known:0});assert!(c.returned);let bits=if kind==0{b.time}else{b.counter};assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(bits as u32));assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar((bits>>32)as u32));assert_eq!(b.seen,vec![kind]);assert!(entropy_api(&mut rt,&mut c,&inputs,&mut b,kind).is_err());assert_eq!(b.seen,vec![kind]);}
 }
}
fn native_entropy_startup(){
 #[cfg(target_os="linux")] {
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 let(m,mut registry,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);
 let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&file).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
 let(mut inputs,mut backend)=CrtNativeEntropy::acquire(&rt,init).expect("native acquisition");assert_eq!(inputs.process_id,std::process::id());assert_ne!(inputs.thread_id,0);
 backend.validate(&rt,&inputs).unwrap();let low=backend.filetime().unwrap();let counter_before=backend.counter().unwrap();let upper=entropy_filetime_duration(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap()).unwrap();assert!(low>=116444736000000000);assert!(upper>=116444736000000000);assert!(backend.counter().unwrap()>=counter_before);
 assert_eq!(std::thread::scope(|scope|scope.spawn(||backend.host()).join().unwrap()),Err("native entropy host lifetime/thread"));
 let old=inputs.thread_id;inputs.thread_id=old.wrapping_add(1);assert_eq!(backend.validate(&rt,&inputs),Err("native entropy runtime binding"));inputs.thread_id=old;
 let(other,oi)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&file).unwrap();let other_inputs=CrtEntropyInputs::bind(&other,oi,inputs.process_id,inputs.thread_id).unwrap();assert_eq!(backend.validate(&other,&other_inputs),Err("native entropy runtime binding"));
 let saved_origin=backend.origin;backend.origin=std::time::Instant::now().checked_add(std::time::Duration::from_secs(3600)).unwrap();let mut failed=cpu(&mut rt,0xc000,7099);failed.return_pop=0;assert_eq!(original_cookie_init_connected(&mut rt,&mut failed,&inputs,&mut backend),Err("native monotonic clock reversed"));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41c000,4).unwrap(),32).unwrap(),CrtValue::scalar(0xbb40e64e));assert!(!failed.returned);backend.origin=saved_origin;
 let mut c=cpu(&mut rt,0xd000,7100);c.return_pop=0;original_cookie_init_connected(&mut rt,&mut c,&inputs,&mut backend).expect("original default helper with actual runtime acquisition");assert!(c.returned);
 let cookie=rt.process_image_pointer(inputs.image,0x41c000,4).unwrap();let value=rt.load(cookie,32).unwrap().known_scalar().unwrap();assert_ne!(value,0xbb40e64e);assert_ne!(value&0xffff0000,0);let complement=rt.process_image_pointer(inputs.image,0x41c040,4).unwrap();assert_eq!(rt.load(complement,32).unwrap(),CrtValue::scalar(!value));
 rt.end_initialization(init).unwrap();assert_eq!(backend.validate(&rt,&inputs),Err("CRT initialization owner/lifetime"));
 registry.with_normal_calls(&m,&mut permit,&main,|epoch|{let mut frame=cpu(&mut rt,0xe000,7200);let mut binding=CrtNormalBinding::bind(&rt,&frame,epoch,epilog_run_layout())?;start(&mut rt,&mut frame,epoch,&mut binding,7300)?;frame.r[0]=CrtValue::scalar(63);assert_eq!(epilog_run(&mut rt,&mut frame,epoch,&mut binding)?,CrtValue::scalar(63));Ok(())}).expect("native-produced cookie original record cycle");
 }
}
fn startup_entry_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..9{
  let(m,mut registry,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut image_file=file.clone();if mode==8{let code=startup_helper_code();let offsets:Vec<_>=image_file.windows(code.len()).enumerate().filter(|(_,b)|*b==code.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&image_file).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
  let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut backend=EntropyObservations{time:0x102030405060708,counter:0x8899aabbccddeeff,seen:vec![],fail:if mode==1{1}else{0}};let mut c=cpu(&mut rt,0xd000,8000);c.return_pop=0;
  if mode==6{
   #[cfg(target_os="linux")] let got={let(native_inputs,mut native)=CrtNativeEntropy::acquire(&rt,init).unwrap();registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected(&mut rt,&mut c,&native_inputs,&mut native,None,epoch))};
   #[cfg(not(target_os="linux"))] let got=registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected(&mut rt,&mut c,&inputs,&mut backend,None,epoch));
   assert_eq!(got,Err("startup processor feature contract unbound at 0x401ebe"));assert!(!c.returned);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41ccb8,4).unwrap(),32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41c058,4).unwrap(),32).unwrap().known_scalar().unwrap()&1,1);continue;
  }
  if mode==2{rt.end_initialization(init).unwrap();}
  if mode==3{let p=rt.process_image_pointer(inputs.image,0x41c000,4).unwrap();rt.memory.release(p.cap,p.owner).unwrap();}
  let shim=startup_shim(&mut rt,&mut c,&inputs,&mut backend,None,None);
  if mode==1||mode==2||mode==3{assert_eq!(shim,Err(match mode{1=>"independent time acquisition failure",2=>"CRT initialization owner/lifetime",_=>"CRT initialization storage lifetime"}));assert!(!c.returned);continue;}
  shim.expect("entry CALL and JMP reach bounded startup");assert!(!c.returned);assert_eq!(c.r[4],c.entry[4]);
  if mode==7{c.push(&mut rt,CrtValue::scalar(0)).unwrap();assert_eq!(c.call_activation(&mut rt,0x430000,0,|rt,c|startup_initializer(rt,c,&inputs,&mut backend,None,None,None)),Err("startup processor feature contract unbound at 0x401ebe"));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cc84,1).unwrap(),8).unwrap(),CrtValue::scalar(1));continue;}
  let flag=rt.process_image_pointer(inputs.image,0x41c058,4).unwrap();let cpuword=rt.process_image_pointer(inputs.image,0x41ccb8,4).unwrap();let byte=rt.process_image_pointer(inputs.image,0x41cc84,1).unwrap();rt.store(flag,32,CrtValue::scalar(0x20)).unwrap();rt.store(cpuword,32,CrtValue::scalar(9)).unwrap();let prior=rt.load(byte,8).unwrap();
  if mode==4{rt.end_initialization(init).unwrap();}
  let got=registry.with_normal_calls(&m,&mut permit,&main,|epoch|{let mut binding=CrtNormalBinding::bind_initializing(&rt,&c,epoch,startup_layout(),init)?;
   if mode==5{rt.store(rt.process_image_pointer(inputs.image,0x41c000,4)?,32,CrtValue::Scalar{bits:0,known:0})?;}
   startup_prefix(&mut rt,&mut c,&inputs,&mut backend,None,None,epoch,&mut binding)?;Err::<(),_>("unexpected startup prefix return")
  });
  assert_eq!(got,Err(match mode{4=>"CRT initialization owner/lifetime",5=>"CRT scalar knowledge/type",8=>"startup helper live code changed",_=>"startup processor feature contract unbound at 0x401ebe"}));assert!(!c.returned);assert_eq!(rt.load(byte,8).unwrap(),prior);
  assert_eq!(rt.load(flag,32).unwrap(),CrtValue::scalar(if mode>=4{0x20}else{0x21}));assert_eq!(rt.load(cpuword,32).unwrap(),CrtValue::scalar(if mode>=4{9}else{0}));
 }
}

fn ucrt_reference_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..10{for old in [0u32,1,u32::MAX,0x7fffffff]{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();
  let object=rt.process_image_pointer(inputs.image,0x41d150,24).unwrap();rt.construct_global_lock(init,5,object,1).unwrap();let lease=rt.lock_global(rt.thread,5).unwrap();
  let p=rt.process_image_pointer(inputs.image,0x41c240,4).unwrap();rt.store(p,32,CrtValue::scalar(old)).unwrap();let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let mut c=CrtCpu::new(stack,99).unwrap();c.flags=CrtFlags{cf:Some(true),zf:Some(true),sf:Some(false),of:Some(false)};
  if mode==1{rt.unlock_global(lease).unwrap();}if mode==2{rt.thread+=1;}if mode==3{rt.store(p,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==4{rt.end_initialization(init).expect_err("live lease prevents ending initialization");rt.unlock_global(lease).unwrap();rt.end_initialization(init).unwrap();}if mode==5{rt.memory.release(p.cap,p.owner).unwrap();}
  let target=if mode==6{rt.offset(p,1).unwrap()}else if mode==7{object}else if mode==8{let(mut other,oi)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let x=CrtEntropyInputs::bind(&other,oi,17,19).unwrap();other.process_image_pointer(x.image,0x41c240,4).unwrap()}else{p};
  if mode==9{rt.unlock_global(lease).unwrap();rt.lock_global(rt.thread,5).unwrap();}
  let result=c.increment_reference(&mut rt,init,inputs.image,lease,target);
  if mode==0{result.expect("owned reference increment must execute");assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(old.wrapping_add(1)));assert_eq!(c.flags.cf,Some(true));assert_eq!(c.flags.of,Some(old==0x7fffffff));assert_eq!(c.flags.zf,Some(old==u32::MAX));assert_eq!(c.flags.sf,Some(old.wrapping_add(1)>>31!=0));}else{assert!(result.is_err(),"reference mode {mode} must reject");assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(true),Some(false),Some(false)));if mode!=3&&mode!=5{assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(old));}}
 }}
}
fn ucrt_replacement_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..20{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let f=rt.bind_fiber(9).unwrap();let idx=rt.native_fls_allocate(init,None).unwrap();rt.native_fls_set(init,f,idx.index,CrtValue::scalar(u32::MAX)).unwrap();let slot=rt.fls.get(&idx.index).unwrap().0;let ticket=rt.begin_heap_ptd_allocation(f,slot).unwrap();let p=rt.native_heap_allocate(init,heap,8,if mode==15{40}else{868}).unwrap();rt.bind_heap_ptd_layout(ticket,p,if mode==15{CrtPtdLayout::Vcruntime}else{CrtPtdLayout::Ucrt}).unwrap();rt.native_fls_set(init,f,idx.index,CrtValue::Pointer(p)).unwrap();
  let object=rt.process_image_pointer(inputs.image,0x41d1b0,24).unwrap();rt.construct_global_lock(init,4,object,1).unwrap();let lease=rt.lock_global(rt.thread,4).unwrap();let locale=rt.process_image_pointer(inputs.image,0x41c178,160).unwrap();let counter=rt.offset(locale,12).unwrap();let before=rt.load(counter,32).unwrap().known_scalar().unwrap();
  let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(999)).unwrap();let mut c=CrtCpu::new(sp,999).unwrap();let root=if mode==3{rt.offset(p,4).unwrap()}else{p};rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(root)).unwrap();let value=if mode==1{0}else if mode==9{0x9000}else if mode==16{0xf00000}else{0x41c178};rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::scalar(value)).unwrap();
  if mode==2{rt.store(rt.offset(p,76).unwrap(),32,CrtValue::scalar(0x41c178)).unwrap();}if mode==4{rt.free_allocation(p).unwrap();}if mode==5{rt.fiber=None;rt.bind_fiber(9).unwrap();}if mode==6{rt.unlock_global(lease).unwrap();}if mode==10{rt.fls_indices.get_mut(&idx.index).unwrap().certain=false;}if mode==11{rt.store(counter,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==12{rt.store(rt.offset(locale,156).unwrap(),32,CrtValue::scalar(0x41c240)).unwrap();}if mode==18{rt.store(rt.offset(locale,156).unwrap(),32,CrtValue::scalar(0)).unwrap();}if mode==19{rt.store(rt.offset(locale,156).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==13{rt.unlock_global(lease).unwrap();rt.lock_global(rt.thread,4).unwrap();}if mode==14{rt.thread+=1;}
  if mode==17{let frame=rt.offset(sp,-256).unwrap();let argument=rt.offset(frame,64).unwrap();rt.store(argument,32,CrtValue::scalar(4)).unwrap();rt.store(rt.offset(frame,16).unwrap(),32,CrtValue::Pointer(argument)).unwrap();c.r[5]=CrtValue::Pointer(frame);c.entry=c.r;let mut held=Some(lease);ucrt_locale_cleanup(&mut rt,&mut c,&inputs,&mut held).expect("original cleanup must release once");assert!(held.is_none());rt.store(sp,32,CrtValue::ProtectedReturn(1000)).unwrap();let mut again=CrtCpu::new(sp,1000).unwrap();again.r[5]=CrtValue::Pointer(frame);again.entry=again.r;assert!(ucrt_locale_cleanup(&mut rt,&mut again,&inputs,&mut held).is_err());assert_eq!(rt.load(counter,32).unwrap(),CrtValue::scalar(before));continue;}
  let result=ucrt_locale_replace(&mut rt,&mut c,&inputs,lease);
  if matches!(mode,0|1|7|8|18){result.expect("original replacement must return");assert!(c.returned);assert_eq!(rt.load(rt.offset(p,76).unwrap(),32).unwrap(),CrtValue::scalar(value));assert_eq!(rt.load(counter,32).unwrap(),CrtValue::scalar(if mode==1{before}else{before.wrapping_add(1)}));
   if mode==7{assert!(ucrt_locale_replace(&mut rt,&mut c,&inputs,lease).is_err());}if mode==8{rt.store(sp,32,CrtValue::ProtectedReturn(1001)).unwrap();let mut again=CrtCpu::new(sp,1001).unwrap();assert_eq!(ucrt_locale_replace(&mut rt,&mut again,&inputs,lease),Err("locale prior-reference release/free unbound"));assert_eq!(rt.load(counter,32).unwrap(),CrtValue::scalar(before.wrapping_add(1)));}
  }else{assert!(result.is_err(),"replacement mode {mode} must reject");assert!(!c.returned);if mode!=4&&mode!=15{assert_eq!(rt.load(rt.offset(p,76).unwrap(),32).unwrap(),CrtValue::scalar(if matches!(mode,9|11|12|16|19){value}else if mode==2{0x41c178}else{0}));}if mode==12{assert_eq!(result,Err("locale dynamic child XADD unbound at 0x40c686"));assert_eq!(rt.load(counter,32).unwrap(),CrtValue::scalar(before.wrapping_add(1)));}}
 }
}
fn startup_feature_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..58{
  let(m,mut registry,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);
  let mut image_file=file.clone();if mode==9{let raw:Vec<_>=startup_cpu_code();let offsets:Vec<_>=image_file.windows(raw.len()).enumerate().filter(|(_,b)|*b==raw.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  if mode==20{let u16at=|at:usize|u16::from_le_bytes(image_file[at..at+2].try_into().unwrap()) as usize;let u32at=|at:usize|u32::from_le_bytes(image_file[at..at+4].try_into().unwrap()) as usize;let nt=u32at(60);let sections=nt+24+u16at(nt+20);let section=(0..u16at(nt+6)).map(|i|sections+40*i).find(|at|{let va=u32at(*at+12);va<=0x15d7c&&0x15d7c<va+u32at(*at+16)}).unwrap();let at=u32at(section+20)+0x15d7c-u32at(section+12);assert_eq!(&image_file[at..at+b"InitializeCriticalSectionEx\0".len()],b"InitializeCriticalSectionEx\0");image_file[at]=b'i';}
  if mode==19{let raw=resident_load_helper_code();let offsets:Vec<_>=image_file.windows(raw.len()).enumerate().filter(|(_,b)|*b==raw.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  if mode==24||mode==27{let raw=if mode==24{startup_fls_alloc_code()}else{startup_fls_set_code()};let offsets:Vec<_>=image_file.windows(raw.len()).enumerate().filter(|(_,b)|*b==raw.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  if mode==21{let raw=startup_fls_code();let offsets:Vec<_>=image_file.windows(raw.len()).enumerate().filter(|(_,b)|*b==raw.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  if (28..32).contains(&mode){let raw=match mode{28=>crate_table_bytes(),29=>crate_first_bytes(),30=>crate_loop_bytes(),_=>crate_second_b_bytes()};let offsets:Vec<_>=image_file.windows(raw.len()).enumerate().filter(|(_,b)|*b==raw.as_slice()).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);image_file[offsets[0]]^=1;}
  if mode>=32{let address=match mode{32=>0x40a332u32,33=>0x414268,34=>0x414254,35=>0x408061,36=>0x40a1ee,37=>0x407cf0,38=>0x40a067,39=>0x40806d,40=>0x409efb,41=>0x409f2f,42=>0x409f41,43=>0x401e60,44=>0x40a00d,45=>0x40a049,46=>0x40a05b,47=>0x40a296,48=>0x40c4ad,49=>0x40c672,50=>0x407d50,51=>0x408697,52=>0x40bf2a,53=>0x40be7a,54=>0x408079,55=>0x40bfbf,56=>0x408537,57=>0x4086db,_=>unreachable!()};let u16at=|at:usize|u16::from_le_bytes(image_file[at..at+2].try_into().unwrap())as usize;let u32at=|at:usize|u32::from_le_bytes(image_file[at..at+4].try_into().unwrap())as usize;let nt=u32at(60);let table=nt+24+u16at(nt+20);let rva=address as usize-0x400000;let section=(0..u16at(nt+6)).map(|n|table+40*n).find(|at|u32at(*at+12)<=rva&&rva<u32at(*at+12)+u32at(*at+16)).unwrap();let offset=u32at(section+20)+rva-u32at(section+12);image_file[offset]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&image_file).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
  let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mb_before=rt.load(rt.process_image_pointer(inputs.image,0x41c240,4).unwrap(),32).unwrap().known_scalar().unwrap();let mut backend=EntropyObservations{time:0x102030405060708,counter:0x8899aabbccddeeff,seen:vec![],fail:0};let mut c=cpu(&mut rt,0xd000,8100);c.return_pop=0;
  // Independent abstract CPU environments; not Windows observations or host claims.
  let mut data=CrtFeatureData{leaves:std::collections::BTreeMap::from([((0,0),[1,0,0,0]),((1,0),[0,0,0,7<<24])]),xcr0:None,reported_sse2:mode!=0};
  if mode==2||mode==3||mode==13||mode==14{data.leaves.get_mut(&(0,0)).unwrap()[0]=0x0d;data.leaves.insert((0x0d,0),[0xe7,0,0,0]);data.leaves.get_mut(&(1,0)).unwrap()[2]=(7<<26)|(1<<20);data.leaves.insert((7,0),[0,if mode==3{1<<5}else if mode>=13{0xd0030020}else{0},0,0]);data.xcr0=Some(if mode>=13{0xe7}else{7});}
  if mode==14{data.leaves.get_mut(&(0,0)).unwrap()[0]=0x24;data.leaves.get_mut(&(7,0)).unwrap()[0]=1;data.leaves.insert((7,1),[0,0,0,1<<19]);data.leaves.insert((0x24,0),[0,2,0,0]);}
  let mut features=CrtFeatureObservation::bind(&rt,init,data).unwrap();
  #[cfg(all(target_os="linux",target_arch="x86_64"))]if mode==4||mode==12{features=CrtFeatureObservation::native(&rt,init).unwrap();}
  if mode==5{features.thread+=1;}if mode==6{rt.end_initialization(init).unwrap();}
  if mode==7{let other=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&file).unwrap();features=CrtFeatureObservation::bind(&other.0,other.1,features.data.clone()).unwrap();}
  if mode==8{let p=rt.process_image_pointer(inputs.image,0x41c058,4).unwrap();rt.memory.release(p.cap,p.owner).unwrap();}
  if mode==10{features.data.leaves.remove(&(1,0));}
  if mode==11{features.host=Some((std::process::id().wrapping_add(1),std::thread::current().id()));}
  let mut platform=if mode>=15{Some(CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap())}else{None};
  if mode>=22{let p=platform.as_mut().unwrap();p.enable_fls(&mut rt,init,0x720000,0x721000).unwrap();if mode==22||mode>=32{p.enable_second_fiber(&rt,init,CrtNativePlatform::SECOND_FIBER_PROFILE).unwrap();}let f=p.fls.unwrap();if mode==23{rt.provider_destroy(init,f.module).unwrap();}if mode==25{rt.providers.get_mut(&f.module.handle).unwrap().exports.clear();}if mode==26{for _ in 0..64{rt.native_fls_allocate(init,None).unwrap();}}}
  if mode==16{rt.provider_destroy(init,platform.as_ref().unwrap().function.module).unwrap();}
  if mode==17{let p=rt.process_image_pointer(inputs.image,0x415d7c,2).unwrap();/* immutable name storage must remain protected */assert!(rt.store(p,16,CrtValue::scalar(0)).is_err());}
  if mode==18{let p=platform.as_ref().unwrap();for _ in 0..255{rt.native_provider_acquire(init,p.function).unwrap();}}
  let got=if mode>=15{registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected_platform(&mut rt,&mut c,&inputs,&mut backend,Some(&features),platform.as_ref(),epoch))}else if mode==12{
   #[cfg(all(target_os="linux",target_arch="x86_64"))]{let(i,mut b)=CrtNativeEntropy::acquire(&rt,init).unwrap();registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected(&mut rt,&mut c,&i,&mut b,Some(&features),epoch))}
   #[cfg(not(all(target_os="linux",target_arch="x86_64")))]{registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected(&mut rt,&mut c,&inputs,&mut backend,Some(&features),epoch))}
  }else{registry.with_normal_calls(&m,&mut permit,&main,|epoch|startup_connected(&mut rt,&mut c,&inputs,&mut backend,Some(&features),epoch))};
  let expected=match mode{31=>"initializer helper code changed",28=>"original initializer table changed",29=>"initializer helper code changed",30=>"initializer loop code changed",27=>"startup module live code changed",22=>"startup GetStartupInfoW effects unbound at 0x408543",32=>"PTD getter code changed",33=>"PTD prolog code changed",34=>"PTD epilog code changed",35=>"PTD FLS thunk changed",36..=38=>"UCRT original code changed",39=>"UCRT setter code changed",40=>"locale body code changed",41=>"locale helper code changed",42=>"locale cleanup code changed",43=>"startup helper live code changed",44=>"locale body code changed",45=>"locale helper code changed",46=>"locale cleanup code changed",47|48=>"locale replacement/reference code changed",49=>"locale child code changed",50=>"UCRT free code changed",51|52|57=>"descriptor startup code changed",53=>"descriptor constructor code changed",54=>"startup lock thunk changed",55=>"descriptor cleanup code changed",56=>"startup inherit code changed",23=>"CRT unloaded module",24=>"startup module live code changed",25=>"CRT native named export publication incomplete",26=>"CRT native FLS index capacity",21=>"startup module live code changed",20=>"CRT native named export unsupported",19=>"startup resolver live code changed",15|17=>"native platform FLS provider not enabled",16=>"CRT unloaded module",18=>"CRT native provider reference budget",5=>"CPU observation owner/lifetime",6|7=>"CRT initialization owner/lifetime",8=>"CRT initialization storage lifetime",9=>"CPU classifier live code changed",10=>"CPU query outside observed leaf domain",11=>"CPU observation host lifetime/thread",_=>"startup LoadLibraryExW effects unbound at 0x402b00"};
  assert_eq!(got,Err(expected),"CPU startup mode {mode}");assert!(!c.returned);
  if mode==54{assert!(rt.heap_ptds.is_empty());assert!(rt.record_objects.is_empty());assert!(rt.global_locks.is_empty());assert!(!rt.regions.iter().any(|r|r.pointer.kind==CrtRegionKind::Descriptor));continue;}
  if mode>=51{assert!(registry.cxx.is_empty());assert!(matches!(registry.head,RegistryHead::Normal(_)));let count=if mode==51||mode==57{0}else if mode==52||mode==56{1}else{2};assert_eq!(rt.global_locks.len(),count,"descriptor failure mode {mode}");let allocated=matches!(mode,54..=56);assert_eq!(rt.regions.iter().filter(|r|r.pointer.kind==CrtRegionKind::Descriptor).count(),usize::from(allocated));assert_eq!(rt.record_objects.len(),if mode==55||mode==56{64}else{0});let cap=rt.load(rt.process_image_pointer(inputs.image,0x41d108,4).unwrap(),32).unwrap();assert_eq!(cap,CrtValue::scalar(if mode==55||mode==56{64}else{0}));continue;}
  if mode>=44{assert_eq!(registry.cxx.len(),1);assert!(registry.cxx[0].linked);let held=matches!(mode,46..=49);assert_eq!(rt.global_locks.len(),usize::from(held));assert_eq!(matches!(registry.head,RegistryHead::Normal(_)),held);let(slot,CrtValue::Pointer(p))=*rt.fls.get(&1).unwrap()else{panic!("published UCRT")};rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).unwrap();assert_eq!(rt.load(rt.offset(p,76).unwrap(),32).unwrap(),CrtValue::scalar(if mode==44||mode==45||mode==47{0}else{0x41c178}));continue;}
  if mode>=40{if mode==43{assert!(rt.heap_ptds.is_empty());assert!(registry.cxx.is_empty());}else{assert_eq!(registry.cxx.len(),1);if mode==42{assert!(matches!(registry.head,RegistryHead::Normal(_)));}else{assert_eq!(registry.head,RegistryHead::Cxx(registry.cxx[0].id));}let(slot,CrtValue::Pointer(p))=*rt.fls.get(&1).unwrap()else{panic!("actual UCRT publication")};rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).unwrap();assert_eq!(rt.global_locks.len(),usize::from(mode==42));let counter=rt.process_image_pointer(inputs.image,0x41c240,4).unwrap();assert_eq!(rt.load(counter,32).unwrap(),CrtValue::scalar(if mode==42{mb_before.wrapping_add(1)}else{mb_before}));}continue;}
  if mode>=36{assert_eq!(rt.fls_indices.len(),2);assert!(rt.global_locks.is_empty());assert_eq!(registry.cxx.len(),1);assert!(registry.cxx[0].linked);assert_eq!(registry.head,RegistryHead::Cxx(registry.cxx[0].id));let(slot,value)=*rt.fls.get(&1).unwrap();if mode==38{let CrtValue::Pointer(p)=value else{panic!("published UCRT allocation")};assert_eq!(p.size,868);rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).unwrap();assert_eq!(rt.heap_ptds[0].layout,CrtPtdLayout::Ucrt);for n in (0..868).step_by(4){assert_eq!(rt.load(rt.offset(p,n).unwrap(),32).unwrap(),CrtValue::scalar(0));}assert_eq!(rt.regions.iter().filter(|r|r.heap).count(),1);}else{assert_eq!(value,CrtValue::scalar(if mode==37{u32::MAX}else{0}));assert!(!rt.regions.iter().any(|r|r.heap));}continue;}
  if mode>=32{assert_eq!(rt.fls_indices.len(),2);assert_eq!(rt.fls.len(),1);assert!(!rt.fls.contains_key(&1));assert!(rt.global_locks.is_empty());assert_eq!(registry.cxx.len(),usize::from(mode==35));if mode==35{let f=&registry.cxx[0];assert!(f.linked);assert_eq!(f.handler,0x414ad6);assert_eq!(registry.head,RegistryHead::Cxx(f.id));}continue;}

  if mode<=4||matches!(mode,12..=15|17|18){let tier=rt.load(rt.process_image_pointer(inputs.image,0x41ccb8,4).unwrap(),32).unwrap().known_scalar().unwrap();if mode<=3{assert_eq!(tier,[0,1,3,5][mode]);}if mode==13||mode==14{assert_eq!(tier,6);}let flags=rt.load(rt.process_image_pointer(inputs.image,0x41c058,4).unwrap(),32).unwrap().known_scalar().unwrap();assert_eq!(flags&1,1);if mode>=1{assert_ne!(flags&2,0);}}
  if mode==20{assert_eq!(rt.module_references.len(),2);let cell=rt.process_image_pointer(inputs.image,0x41cd24,4).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));}
  if mode>=22{assert!(rt.global_objects.contains_key(&0));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cd04,4).unwrap(),32).unwrap(),CrtValue::scalar(1));if mode!=22&&mode<28{assert!(rt.fls.is_empty());}
   let cell=rt.process_image_pointer(inputs.image,0x41c060,4).unwrap();
   if mode==22||mode>=28{assert_eq!(rt.fls.len(),if mode==22{2}else{1});if mode==31{let cookie=rt.load(rt.process_image_pointer(inputs.image,0x41c000,4).unwrap(),32).unwrap();assert_ne!(cookie,CrtValue::scalar(0));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cea0,4).unwrap(),32).unwrap(),cookie);for address in [0x41d2cc,0x41d2d0,0x41cd3c,0x41ce5c]{assert_eq!(rt.load(rt.process_image_pointer(inputs.image,address,4).unwrap(),32).unwrap(),CrtValue::scalar(0));}}if mode==22{assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41ceac,4).unwrap(),32).unwrap(),CrtValue::Module(platform.as_ref().unwrap().function.module));assert_eq!(rt.last_os_error,None);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41e00c,4).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.global_locks.len(),1);rt.check_global(*rt.global_locks.last().unwrap()).unwrap();let CrtValue::Heap(heap)=rt.load(rt.process_image_pointer(inputs.image,0x41d2c8,4).unwrap(),32).unwrap()else{panic!("missing actual heap store")};rt.heap_identity(heap).unwrap();assert_eq!(heap.process,rt.memory.process_heap());assert_eq!(heap.exceptions,None);assert_eq!(rt.global_objects.values().count(),16);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41d2b8,4).unwrap(),32).unwrap(),CrtValue::scalar(15));let page=rt.process_image_pointer(inputs.image,0x41e000,128).unwrap();assert!(rt.memory.validate_writable(page.cap,page.owner,page.address(),128).is_err());assert!(rt.store(page,32,CrtValue::scalar(5)).is_err());rt.memory.validate_readable(page.cap,page.owner,page.address(),128).unwrap();assert_eq!(CrtCpu::number(c.r[3]).unwrap(),0);let cookie=rt.load(rt.process_image_pointer(inputs.image,0x41c000,4).unwrap(),32).unwrap();for address in [0x41cea0,0x41d2cc,0x41d2d0,0x41d2d4,0x41d2d8,0x41d2dc,0x41cd3c,0x41ce5c]{assert_eq!(rt.load(rt.process_image_pointer(inputs.image,address,4).unwrap(),32).unwrap(),cookie);}}let (slot,value)=*rt.fls.get(&0).unwrap();assert_eq!(value,CrtValue::scalar(0x41ccc4));assert_eq!(slot.fiber,rt.fiber.unwrap());assert_eq!(rt.fls_get(slot.fiber,slot,0).unwrap(),value);assert!(CrtCpu::pointer(value).is_err());assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41d134,4).unwrap(),32).unwrap(),CrtValue::scalar(if mode==22||mode==31{0x41c178}else{0}));assert_eq!(rt.fls_indices.len(),if mode==22{2}else{1});if mode==22{let second=rt.fls_indices.get(&1).unwrap();rt.fls_index(second.id).unwrap();assert!(second.native&&!second.input_binding);let (value_slot,value)=*rt.fls.get(&1).unwrap();let CrtValue::Pointer(ptd)=value else{panic!("UCRT pointer must be published")};assert_eq!(ptd.size,868);assert_eq!(ptd.kind,CrtRegionKind::Buffer);assert_eq!(value_slot.allocation,second.id);assert_eq!(value_slot.fiber,rt.fiber.unwrap());assert!(registry.cxx.is_empty());assert!(matches!(registry.head,RegistryHead::Normal(_)));assert_eq!(rt.regions.iter().filter(|r|r.heap).count(),2);rt.heap_ptd_layout_view(ptd,value_slot,CrtPtdLayout::Ucrt).unwrap();assert!(rt.dispatcher_ptd(ptd).is_err());assert_eq!(rt.global_locks.len(),1);rt.check_global(*rt.global_locks.last().unwrap()).unwrap();assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41c240,4).unwrap(),32).unwrap(),CrtValue::scalar(mb_before.wrapping_add(1)));for (offset,width,value) in [(0,32,0x415ef0),(24,32,1),(848,32,1),(72,32,0x41c240),(108,16,67),(370,16,67),(844,32,0),(76,32,0x41c178)]{assert_eq!(rt.load(rt.offset(ptd,offset).unwrap(),width).unwrap(),CrtValue::scalar(value));}assert_eq!(second.callback,Some((inputs.image,rt.process_image_code(inputs.image,0x40a100,1).unwrap())));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41c170,4).unwrap(),32).unwrap(),CrtValue::scalar(1));let CrtValue::Pointer(block)=rt.load(rt.process_image_pointer(inputs.image,0x41cf08,4).unwrap(),32).unwrap()else{panic!("actual descriptor publication")};assert_eq!(block.kind,CrtRegionKind::Descriptor);assert_eq!(block.size,64*56);assert_eq!(rt.record_objects.len(),64);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41d108,4).unwrap(),32).unwrap(),CrtValue::scalar(64));for n in 0..64{let record=rt.offset(block,n*56).unwrap();rt.record_lock_live(record).unwrap();assert!(rt.load(record,8).is_err());for(offset,width,value)in[(24,32,u32::MAX),(32,32,0),(36,32,0),(40,32,0x0a0a0000),(44,8,10),(46,32,0),(50,8,0)]{assert_eq!(rt.load(rt.offset(record,offset).unwrap(),width).unwrap(),CrtValue::scalar(value));}}}let e=rt.fls_indices.get(&0).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(e.callback,Some((inputs.image,rt.process_image_code(inputs.image,0x4028a7,1).unwrap())));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cd14,4).unwrap(),32).unwrap(),CrtValue::Function(platform.as_ref().unwrap().fls.unwrap()));}
   else if mode==27{assert_eq!(rt.fls_indices.len(),1);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));}
   else{assert_eq!(rt.fls_indices.len(),if mode==26{64}else{0});assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(u32::MAX));}
  }
  if mode==21{assert!(rt.global_objects.contains_key(&0));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cd04,4).unwrap(),32).unwrap(),CrtValue::scalar(1));assert!(rt.fls_indices.is_empty());}
  if mode==19{assert_eq!(rt.module_references.len(),1);}
  if mode==15||mode==17{assert_eq!(rt.module_references.len(),2);let cell=rt.process_image_pointer(inputs.image,0x41cd0c,4).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::Module(platform.as_ref().unwrap().function.module));let function_cell=rt.process_image_pointer(inputs.image,0x41cd24,4).unwrap();assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::Function(platform.as_ref().unwrap().function));assert_eq!(rt.global_objects.values().count(),1);assert!(rt.global_objects.contains_key(&0));let count=rt.process_image_pointer(inputs.image,0x41cd04,4).unwrap();assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(1));let a=rt.lock_global(rt.thread,0).unwrap();let b=rt.lock_global(rt.thread,0).unwrap();rt.unlock_global(b).unwrap();rt.unlock_global(a).unwrap();}
  if matches!(mode,5|7|9|10|11){assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41ccb8,4).unwrap(),32).unwrap(),CrtValue::scalar(0));}
 }
}

fn constructor_guard_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..10{
  let mut image_file=file.clone();if mode>=8{let rva=if mode==8{0x1bf9}else{0x15128};let u16at=|at:usize|u16::from_le_bytes(image_file[at..at+2].try_into().unwrap()) as usize;let u32at=|at:usize|u32::from_le_bytes(image_file[at..at+4].try_into().unwrap()) as usize;let nt=u32at(60);let sections=nt+24+u16at(nt+20);let section=(0..u16at(nt+6)).map(|i|sections+40*i).find(|at|{let va=u32at(*at+12);va<=rva&&rva<va+u32at(*at+16)}).unwrap();let at=u32at(section+20)+rva-u32at(section+12);image_file[at]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&image_file).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut c=cpu(&mut rt,0xd000,8999);let p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let f=p.function;c.r[1]=CrtValue::Function(f);c.r[6]=CrtValue::Function(f);
  if mode==1{c.r[6]=CrtValue::scalar(f.address);}
  if mode==2{rt.exports.get_mut(&f.serial).unwrap().callable=false;}
  if mode==3{rt.providers.get_mut(&f.module.handle).unwrap().exports.clear();}
  if mode==4{rt.modules.get_mut(&f.module.handle).unwrap().certain=false;}
  if mode==5{c.return_id+=1;}
  c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:None,of:Some(true)};let before_flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
  let before=c.r;let refs=rt.module_references.len();let got=startup_constructor_guard(&mut rt,&mut c,&inputs);
  if mode==0||mode==6||mode==7{assert_eq!(got,Ok(()));assert_eq!(c.r,before);assert!(!c.returned);let mut receipt=Some(f);if mode==6{let mut wrong=f;wrong.address+=4;assert_eq!(startup_take_guard(&rt,&inputs,&mut receipt,wrong),Err("startup indirect guard receipt replay/target"));assert!(receipt.is_none());}else{startup_take_guard(&rt,&inputs,&mut receipt,f).unwrap();assert_eq!(startup_take_guard(&rt,&inputs,&mut receipt,f),Err("startup indirect guard receipt replay/target"));}}
  else{assert_eq!(got,Err(match mode{1=>"startup guard export mismatch",2=>"CRT native provider export implementation unbound",3=>"CRT native named export publication incomplete",4=>"CRT module owner/generation/lifetime",5=>"CRT active caller lifetime/return authority",8=>"startup constructor guard code changed",9=>"startup constructor live guard target",_=>unreachable!()}));assert_eq!(c.r,before);}
  assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),before_flags);assert_eq!(rt.module_references.len(),refs);assert!(rt.global_objects.is_empty());
 }
}

fn resident_loader_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..4{
  let mut image=file.clone();if mode==3{let pattern=resident_load_helper_code();let found:Vec<_>=image.windows(pattern.len()).enumerate().filter(|(_,w)|*w==pattern.as_slice()).map(|(i,_)|i).collect();assert_eq!(found.len(),1);image[found[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&image).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut c=cpu(&mut rt,0xd000,8990);c.return_pop=0;
  let(m,r)=rt.module_acquire_result(init,"kernel32.dll",0x700000).unwrap();let entries=if mode==1{vec![]}else{vec![("kernel32.dll".into(),m)]};let loader=CrtResidentLoader::bind(&rt,&entries).unwrap();if mode==2{rt.module_release_result(init,r,true).unwrap();}
  let name=rt.process_image_pointer(inputs.image,0x415d04,18).unwrap();c.push(&mut rt,CrtValue::Pointer(name)).unwrap();let mut calls=vec![];
  let got=c.call_activation(&mut rt,0x402aa4,0,|rt,c|cxx_load_helper_mapped(rt,c,CrtResolverAccess::Initializing(init),&inputs,&mut |rt,c,iat|{calls.push(iat);loader.call(rt,c,init,iat)}));
  if mode==0{assert_eq!(got,Ok(CrtValue::Module(m)));assert_eq!(calls,vec![0x415074]);assert_eq!(rt.module_references.len(),2);c.discard(&mut rt,4).unwrap();c.finish(&mut rt).unwrap();assert!(c.returned);}
  else{assert_eq!(got,Err(match mode{1=>"resident loader search/first-load effects unbound",2=>"CRT unloaded module",3=>"startup resolver live code changed",_=>unreachable!()}));assert_eq!(calls.len(),usize::from(mode!=3));assert!(!c.returned);assert_eq!(rt.module_references.len(),usize::from(mode!=2));}
 }
}
fn startup_resolver_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..14{
  let mut image=file.clone();if mode==7{let code=[0x55,0x8b,0xec,0x51,0x51,0x8b,0x45,0x08,0x57];let matches:Vec<_>=image.windows(code.len()).enumerate().filter(|(_,w)|*w==code).map(|(i,_)|i).collect();assert_eq!(matches.len(),1);image[matches[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&image).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut c=cpu(&mut rt,0xd000,8910);c.return_pop=0;if mode!=12{c.r[1]=CrtValue::Scalar{bits:0,known:0};}
  let fc=rt.process_image_pointer(inputs.image,0x41cd24,4).unwrap();let mc=rt.process_image_pointer(inputs.image,0x41cd0c,4).unwrap();let mut acquired=None;
  if matches!(mode,3|4|5){let(m,r)=rt.module_acquire_result(init,"independent synchronization module",0x700000).unwrap();let fun=rt.module_export_result(init,m,if mode==4{"WrongSymbol"}else{"InitializeCriticalSectionEx"},0x701000).unwrap();rt.store(fc,32,CrtValue::Function(fun)).unwrap();if mode==5{rt.module_release_result(init,r,true).unwrap();}}
  if mode==6{rt.bind_loader_cell(init,fc,false).unwrap();}if mode==8{rt.end_initialization(init).unwrap();}
  for n in [0x415d7c,0x415d74,if mode==9{0x9000}else{0x415d7c},if mode==10{5}else{4}]{c.push(&mut rt,CrtValue::scalar(n)).unwrap();}
  let mut calls=vec![];
  let got=c.call_activation(&mut rt,0x402c47,0,|rt,c|startup_resolver(rt,c,&inputs,&mut |rt,c,iat|{
   calls.push(iat);let sp=CrtCpu::pointer(c.r[4])?;let v=match iat{
    0x415074=>{assert!(matches!(mode,0|1|2|11|13));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(0));assert_eq!(rt.load(rt.offset(sp,12)?,32)?,CrtValue::scalar(0x800));
     if mode==1{rt.last_os_error=Some(126);CrtValue::scalar(0)}else{let(m,r)=rt.module_acquire_result(init,"independent synchronization module",0x700000)?;acquired=Some(r);if mode==13{let code=rt.process_image_code(inputs.image,0x402a53,1)?;rt.memory.release(code.cap,code.owner).unwrap();}CrtValue::Module(m)}},
    0x415070=>{let CrtValue::Module(m)=rt.load(rt.offset(sp,4)?,32)?else{panic!()};if mode==2{CrtValue::scalar(0)}else if mode==11{return Err("independent export failure after module publication");}else{CrtValue::Function(rt.module_export_result(init,m,"InitializeCriticalSectionEx",0x701000)?)}},
    _=>panic!("unexpected resolver import {iat:x}")};c.clobber(v);c.finish_pop(rt,if iat==0x415074{12}else{8})}));
  match mode{
   0|3=>{let CrtValue::Function(f)=got.unwrap_or_else(|e|panic!("resolver success mode {mode}: {e}"))else{panic!()};rt.function_identity(f,Some("InitializeCriticalSectionEx")).unwrap();assert_eq!(rt.load(fc,32).unwrap(),CrtValue::Function(f));assert_eq!(calls.len(),if mode==0{2}else{0});c.discard(&mut rt,16).unwrap();c.finish(&mut rt).unwrap();assert!(c.returned);},
   1|2=>{assert_eq!(got.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(fc,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(calls.len(),2);if mode==1{assert_eq!(rt.load(mc,32).unwrap(),CrtValue::scalar(u32::MAX));}else{assert!(matches!(rt.load(mc,32).unwrap(),CrtValue::Module(_)));}},
   _=>{assert!(got.is_err(),"resolver mode {mode} unexpectedly succeeded");if mode==13{assert_eq!(got,Err("CRT pointer lifetime"));assert_eq!(calls,vec![0x415074]);assert!(acquired.is_some());assert_eq!(rt.module_references.len(),1);assert_eq!(rt.load(mc,32).unwrap(),CrtValue::scalar(0));}else if mode==11{assert_eq!(got,Err("independent export failure after module publication"));assert!(acquired.is_some());assert!(matches!(rt.load(mc,32).unwrap(),CrtValue::Module(_)));assert_eq!(rt.load(fc,32).unwrap(),CrtValue::scalar(0));}else{assert_eq!(got,Err(match mode{4=>"CRT export owner/symbol",5=>"CRT unloaded module",6=>"startup loader cell owner/kind",7=>"startup resolver live code changed",8=>"CRT initialization owner/lifetime",9=>"CRT process image section range",10=>"startup resolver function table bound",12=>"CRT protected saved/return overwrite",_=>unreachable!()}));assert!(calls.is_empty());}}
  }
 }
 // Guest callbacks remain owned by executable main-image storage, never by a
 // numerically equal unrelated or narrowed pointer. No callback is executed.
 for mode in 0..4{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let image=rt.main_image.unwrap();let p=rt.process_image_code(image,0x4028a7,1).unwrap();
  let callback=if mode==1{rt.subrange(p,1).unwrap()}else if mode==2{rt.process_image_pointer(image,0x41ccc4,1).unwrap()}else{p};
  let id=rt.fls_allocation_result(init,7,Some((image,callback)));
  if mode==1||mode==2{assert!(id.is_err());assert!(rt.fls_indices.is_empty());}else{let id=id.unwrap().unwrap();rt.fls_index(id).unwrap();if mode==3{rt.memory.release(p.cap,p.owner).unwrap();assert!(rt.fls_index(id).is_err());}else{let f=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls_fiber(f,id).unwrap();let bootstrap=rt.process_image_pointer(image,0x41ccc4,40).unwrap();assert_eq!(rt.fls_set(f,slot,7,CrtValue::Pointer(bootstrap),true,None),Err("CRT FLS PTD root/extent"));assert_eq!(rt.fls_get(f,slot,7).unwrap(),CrtValue::scalar(0));}}
 }
}
// These authored callback outcomes exercise the original loop protocol, not
// translations of the original callback bodies or new Windows comparisons.
fn cache_publication_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..22{
  let mut file=original.clone();if mode==8||mode==9{let last=if mode==8{0x4c}else{0x50};let n=[0x8b,0xff,0x55,0x8b,0xec,0x6b,0x45,0x08,0x18,0x05,0x50,0xd1,0x41,0,0x50,0xff,0x15,last,0x50,0x41,0,0x5d,0xc3];let at:Vec<_>=file.windows(n.len()).enumerate().filter(|(_,b)|*b==n).map(|(i,_)|i).collect();assert_eq!(at.len(),1);file[at[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let stack=rt.map_region(0x9000,0x7000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();p.enable_fls(&mut rt,init,0x720000,0x721000).unwrap();p.enable_second_fiber(&rt,init,CrtNativePlatform::SECOND_FIBER_PROFILE).unwrap();
  let bootstrap=rt.process_image_pointer(inputs.image,0x41ccec,24).unwrap();rt.construct_global_lock(init,0,bootstrap,1).unwrap();
  if mode==13{for logical in 0..15{let q=rt.process_image_pointer(inputs.image,0x41d150+logical*24,24).unwrap();rt.construct_global_lock(init,(logical+5)%15+1,q,1).unwrap();}}
  else{let mut setup=cpu(&mut rt,0xd000,9900);setup.return_pop=0;setup.r[1]=CrtValue::Scalar{bits:0,known:0};setup.call_activation(&mut rt,0x430000,0,|rt,c|startup_lock_loop(rt,c,&inputs,&mut startup_lock_api)).unwrap();setup.finish(&mut rt).unwrap();}
  let target=rt.process_image_pointer(inputs.image,0x41d2a0,24).unwrap();let cache=rt.process_image_pointer(inputs.image,0x41e00c,4).unwrap();let page=rt.process_image_pointer(inputs.image,0x41e000,128).unwrap();let output=rt.offset(stack,0x1000).unwrap();rt.protect_image_data(inputs.image,page,128,2,output).unwrap();let slot=rt.check_global_address(14,0x41d150,0x41d2a0).unwrap();assert_eq!(slot,if mode==13{5}else{15});
  if matches!(mode,10|12|15|19){
   if mode==15{assert!(rt.lock_global(rt.thread+1,slot).is_err());assert!(rt.global_locks.is_empty());continue;}
   let mut lease=None;let mut invoke=|rt:&mut CrtStreamRuntime,index:u32,enter:bool,id:u64|{let mut c=cpu(rt,0xe000,id);c.return_pop=0;c.push(rt,CrtValue::scalar(index)).unwrap();let got=c.call_activation(rt,0x430000,0,|rt,c|startup_second_lock(rt,c,&inputs,enter,&mut lease));if got.is_ok(){c.discard(rt,4).unwrap();c.finish(rt).unwrap();assert!(c.returned);}else{assert!(!c.returned);}got};
   if mode==10{assert_eq!(invoke(&mut rt,32,true,9901),Err("CRT global index/address overflow"));assert!(rt.global_locks.is_empty());continue;}
   invoke(&mut rt,14,true,9902).unwrap();assert_eq!(rt.global_locks.last().unwrap().index,slot);
   if mode==19{assert_eq!(invoke(&mut rt,13,false,9903),Err("resolver release wrong owned slot"));assert_eq!(rt.global_locks.len(),1);continue;}
   invoke(&mut rt,14,false,9904).unwrap();assert!(rt.global_locks.is_empty());assert_eq!(invoke(&mut rt,14,false,9905),Err("resolver release without acquisition"));assert!(rt.global_locks.is_empty());continue;
  }
  if mode==20{assert_eq!(rt.protect_image_data(inputs.image,target,24,2,output),Err("CRT opaque global lock bytes"));rt.memory.protect_data_with_old((target.cap,target.owner,target.address(),24),2,(output.cap,output.owner,output.address())).unwrap();assert_eq!(rt.lock_global(rt.thread,slot),Err("CRT global lock permission"));}if mode==11{rt.global_objects.remove(&slot);}if mode==14{rt.global_objects.insert(31,*rt.global_objects.get(&slot).unwrap());}
  let outer=if mode==1{Some(rt.lock_global(rt.thread,slot).unwrap())}else{None};let baseline=rt.global_locks.len();let mut c=cpu(&mut rt,0xd000,9910);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};let mut protections=vec![];
  let got=c.call_activation(&mut rt,0x430000,0,|rt,c|startup_fiber_init(rt,c,&inputs,Some(&p),&mut |rt,c,i,platform,iat|{
   let flags=if iat==0x4150b0{let sp=CrtCpu::pointer(c.r[4])?;Some(rt.load(rt.offset(sp,12)?,32)?.known_scalar()?)}else{None};
   if let Some(flags)=flags{assert_eq!(rt.global_locks.len(),baseline+1);assert_eq!(rt.global_locks.last().unwrap().index,slot);protections.push(flags);if mode==2&&flags==4{return Err("independent before write-enable");}if mode==4&&flags==2{return Err("independent before restore");}if mode==16&&flags==2{rt.last_os_error=Some(5);c.clobber(CrtValue::scalar(0));return c.finish_pop(rt,16);}}
   let value=startup_fiber_api(rt,c,i,platform,iat)?;
   if let Some(flags)=flags{let writable=rt.memory.validate_writable(page.cap,page.owner,page.address(),128).is_ok();assert_eq!(writable,flags==4);
    assert_eq!(rt.load(cache,32)?.known_scalar()?,if flags==4{0}else{u32::MAX});
    if mode==3&&flags==4{return Err("independent after write-enable");}if mode==5&&flags==2{return Err("independent after restore");}if mode==6&&flags==4{rt.thread+=1;}if mode==7&&flags==4{rt.memory.release(target.cap,target.owner).unwrap();}if mode==17&&flags==4{let token=*rt.global_locks.last().unwrap();rt.unlock_global(token)?;}if mode==18&&flags==4{rt.lock_global(rt.thread,0)?;}if mode==21&&flags==4{assert_eq!(rt.protect_image_data(i.image,target,24,2,output),Err("CRT opaque global lock bytes"));rt.memory.protect_data_with_old((target.cap,target.owner,target.address(),24),2,(output.cap,output.owner,output.address())).unwrap();}
   }Ok(value)
  }));
  assert!(got.is_err(),"cache mode {mode} unexpectedly returned");assert!(!c.returned);
  let cached=rt.load(cache,32).unwrap().known_scalar().unwrap();let writable=rt.memory.validate_writable(page.cap,page.owner,page.address(),128).is_ok();
  if matches!(mode,0|1|13){assert_eq!(got,Err("startup registered PTD acquisition context unbound at 0x40a428"));assert_eq!(protections,vec![4,2]);assert_eq!(cached,u32::MAX);assert!(!writable);assert_eq!(rt.global_locks.len(),baseline);assert_eq!(rt.fls_indices.len(),1);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41c170,4).unwrap(),32).unwrap(),CrtValue::scalar(0));if let Some(token)=outer{rt.check_global(token).unwrap();rt.unlock_global(token).unwrap();}assert!(rt.global_locks.is_empty());}
  else{assert!(rt.fls_indices.is_empty());let expected=match mode{2=>"independent before write-enable",3=>"independent after write-enable",4=>"independent before restore",5=>"independent after restore",6|17|18=>"CRT stale/foreign/unordered global lock",7=>"CRT pointer lifetime",8|9=>"indexed lock helper changed",11=>"CRT global table/object mismatch",14=>"CRT ambiguous indexed lock",16=>"startup second resolver abort effect unbound",20|21=>"CRT global lock permission",_=>panic!("mode")};assert_eq!(got,Err(expected));assert_eq!(cached,if matches!(mode,4|5|9|16){u32::MAX}else{0});assert_eq!(writable,matches!(mode,3|4|6|7|16|17|18|21));assert_eq!(rt.global_locks.len(),if matches!(mode,8|11|14|17|20){0}else if mode==18{2}else{1});}
 }
}
fn second_fiber_profile_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..12{
  let mut file=original.clone();if mode==5{let n:Vec<_>="api-ms-win-core-fibers-l1-1-2".encode_utf16().flat_map(u16::to_le_bytes).collect();let at:Vec<_>=file.windows(n.len()).enumerate().filter(|(_,b)|*b==n.as_slice()).map(|(i,_)|i).collect();assert_eq!(at.len(),1);file[at[0]+n.len()-2]=b'9';}if mode==6{let n=b"FlsGetValue2\0";let at:Vec<_>=file.windows(n.len()).enumerate().filter(|(_,b)|*b==n.as_slice()).map(|(i,_)|i).collect();assert_eq!(at.len(),1);file[at[0]+11]=b'X';}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut p=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();p.enable_fls(&mut rt,init,0x720000,0x721000).unwrap();
  if mode==2{assert_eq!(p.enable_second_fiber(&rt,init,"unmeasured-target"),Err("second fiber profile unsupported/already enabled"));assert!(!p.second_fiber);}else if mode!=1{p.enable_second_fiber(&rt,init,CrtNativePlatform::SECOND_FIBER_PROFILE).unwrap();assert!(p.enable_second_fiber(&rt,init,CrtNativePlatform::SECOND_FIBER_PROFILE).is_err());}
  let module=p.function.module;let cell=rt.process_image_pointer(inputs.image,0x41ceac,4).unwrap();let cache=rt.process_image_pointer(inputs.image,0x41e00c,4).unwrap();
  if mode==3{rt.provider_destroy(init,module).unwrap();}if mode==4{for _ in 0..254{rt.native_provider_acquire(init,p.function).unwrap();}}if mode==7{let mut f=p.function;f.serial+=10000;f.address+=0x100;rt.exports.insert(f.serial,CrtExport{function:f,symbol:"FlsGetValue2".into(),target:module,callable:false,api:None});}
  if mode==10{let refs=rt.module_references.len();for name in ["api-ms-win-core-fibers-l1-1-2","KERNELBASE.DLL"]{assert_eq!(p.load(&mut rt,init,name,0,0x800),Ok(module));}assert_eq!(rt.module_references.len(),refs+2);assert!(rt.provider_destroy(init,module).is_err());let owned:Vec<_>=rt.module_references.values().copied().filter(|r|r.module==module&&Some(*r)!=rt.providers[&module.handle].root).collect();assert_eq!(owned.len(),2);rt.native_provider_release(init,CrtNativeProviderReference{reference:owned[0],function:p.function}).unwrap();rt.module_identity(module).unwrap();rt.native_provider_release(init,CrtNativeProviderReference{reference:owned[1],function:p.function}).unwrap();assert_eq!(rt.module_references.len(),refs);assert!(p.load(&mut rt,init,"api-ms-win-core-fibers-l1-1-2",0,0).is_err());assert!(p.load(&mut rt,init,"api-ms-win-core-fibers-l1-1-3",0,0x800).is_err());continue;}
  if mode==11{let mut c=cpu(&mut rt,0xd000,9801);c.return_pop=0;let name=rt.process_image_pointer(inputs.image,0x416724,13).unwrap();c.push(&mut rt,CrtValue::Pointer(name)).unwrap();c.push(&mut rt,CrtValue::Module(module)).unwrap();rt.last_os_error=Some(55);let got=c.call_activation(&mut rt,0x430000,8,|rt,c|{c.r[3]=CrtValue::scalar(7);p.call(rt,c,init,0x415070)});assert_eq!(got,Err("native platform stdcall frame"));assert_eq!(rt.last_os_error,Some(55));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));continue;}
  let refs=rt.module_references.len();let mut c=cpu(&mut rt,0xd000,9800);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};let mut calls=vec![];let mut loads=0;
  let got=c.call_activation(&mut rt,0x430000,0,|rt,c|startup_fiber_init(rt,c,&inputs,Some(&p),&mut |rt,c,i,platform,iat|{calls.push(iat);if iat==0x415074{loads+=1;if mode==9&&loads==1{rt.last_os_error=Some(126);c.clobber(CrtValue::scalar(0));return c.finish_pop(rt,12);}}let v=startup_fiber_api(rt,c,i,platform,iat)?;if mode==8&&iat==0x415074{rt.modules.get_mut(&module.handle).unwrap().certain=false;}Ok(v)}));
  assert!(got.is_err(),"profile mode {mode} unexpectedly returned");assert!(!c.returned);assert_eq!(rt.load(cache,32).unwrap(),CrtValue::scalar(0));assert!(rt.fls_indices.is_empty());
  match mode{
   0=>{assert_eq!(got,Err("CRT unconstructed indexed lock"));assert_eq!(calls,vec![0x415074,0x415070]);assert_eq!(rt.module_references.len(),refs+1);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::Module(module));assert_eq!(rt.last_os_error,Some(127));},
   1|2|5=>{assert_eq!(got,Err("native platform API-set mapping unsupported"));assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));},
   3=>{assert_eq!(got,Err("CRT unloaded module"));assert_eq!(rt.module_references.len(),refs);},
   4=>{assert_eq!(got,Err("CRT native provider reference budget"));assert_eq!(rt.module_references.len(),refs);},
   6|7=>{assert_eq!(got,Err(if mode==6{"CRT native named export unsupported"}else{"second fiber profile contradicts export state"}));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::Module(module));assert_eq!(rt.module_references.len(),refs+1);},
   8=>{assert_eq!(got,Err("CRT module owner/generation/lifetime"));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.module_references.len(),refs+1);},
   9=>{assert_eq!(got,Err("CRT unconstructed indexed lock"));assert_eq!(calls,vec![0x415074,0x415044,0x415074,0x415070]);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41cef4,4).unwrap(),32).unwrap(),CrtValue::Module(module));assert_eq!(rt.module_references.len(),refs+1);},
   _=>panic!("case")
  }
 }
}
fn startup_fiber_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..15{
  let mut file=original.clone();if matches!(mode,4|5|10|12){let needle=match mode{4=>vec![0xe8,0x2a,0xdd,0xff,0xff,0x68,0,0xa1,0x40,0],5=>vec![0xa1,0x0c,0xe0,0x41,0,0x83,0xf8,0xff],10=>vec![0xa1,0x70,0xc1,0x41,0,0x83,0xf8,0xff,0x74,0x0d],_=>vec![0x8b,0xff,0x55,0x8b,0xec,0x5d,0xff,0x25,0x9c,0x50,0x41,0]};let at:Vec<_>=file.windows(needle.len()).enumerate().filter(|(_,w)|*w==needle.as_slice()).map(|(i,_)|i).collect();assert_eq!(at.len(),1);file[at[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let stack=rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();platform.enable_fls(&mut rt,init,0x720000,0x721000).unwrap();
  let cache=rt.process_image_pointer(inputs.image,0x41e00c,4).unwrap();let cell=rt.process_image_pointer(inputs.image,0x41c170,4).unwrap();let flag=rt.process_image_pointer(inputs.image,0x41d130,1).unwrap();rt.store(cell,32,CrtValue::scalar(777)).unwrap();rt.store(flag,8,CrtValue::scalar(123)).unwrap();
  if mode!=0&&mode!=13{rt.store(cache,32,if mode==6{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(u32::MAX)}).unwrap();}rt.protect_image_data(inputs.image,cache,4,2,rt.offset(stack,0x1000).unwrap()).unwrap();
  if mode==14{rt.exports.remove(&platform.fls.unwrap().serial);}
  if mode==2{rt.provider_destroy(init,platform.fls.unwrap().module).unwrap();}if mode==3{for _ in 0..64{rt.native_fls_allocate(init,None).unwrap();}}if mode==8{rt.protect_image_data(inputs.image,cell,4,2,rt.offset(stack,0x1000).unwrap()).unwrap();}if mode==9{rt.store(cell,32,CrtValue::scalar(u32::MAX)).unwrap();}
  let mut c=cpu(&mut rt,if mode%2==0{0xd000}else{0xc000},9700);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};let mut calls=vec![];
  let got=c.call_activation(&mut rt,0x430000,0,|rt,c|{let mut effect=|rt:&mut CrtStreamRuntime,c:&mut CrtCpu,i:&CrtEntropyInputs,p:Option<&CrtNativePlatform>,iat:u32|{calls.push(iat);if mode==13&&iat==0x415074{if calls.iter().filter(|&&x|x==0x415074).count()==2{return Err("independent second module attempt rejected");}rt.last_os_error=Some(126);c.clobber(CrtValue::scalar(0));return c.finish_pop(rt,12);}startup_fiber_api(rt,c,i,p,iat)};if mode==9||mode==10{startup_fiber_cleanup(rt,c,&inputs,Some(&platform),&mut effect)}else{startup_fiber_init(rt,c,&inputs,Some(&platform),&mut effect)}});
  if mode==9{let v=got.unwrap();assert_eq!(CrtCpu::bits(v).unwrap().0&255,1);assert!(calls.is_empty());assert!(rt.fls_indices.is_empty());assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(c.r[4],c.entry[4]);c.finish(&mut rt).unwrap();assert!(c.returned);continue;}
  assert!(got.is_err(),"second FLS mode {mode} unexpectedly returned");assert!(!c.returned);
  if matches!(mode,1|7|11){assert_eq!(got,Err("startup registered PTD acquisition context unbound at 0x40a428"));assert_eq!(calls,vec![0x41509c]);assert_eq!(rt.load(flag,8).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.fls_indices.len(),1);let entry=*rt.fls_indices.get(&0).unwrap();assert_eq!(entry.callback,Some((inputs.image,rt.process_image_code(inputs.image,0x40a100,1).unwrap())));rt.fls_index(entry.id).unwrap();
   if mode==7{let fiber=rt.fiber.unwrap();let slot=rt.bind_fls_fiber(fiber,entry.id).unwrap();rt.native_fls_set(init,fiber,0,CrtValue::scalar(123)).unwrap();let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let foreign=other.bind_fiber(9).unwrap();assert!(rt.bind_fls_fiber(foreign,entry.id).is_err());assert!(other.fls_index(entry.id).is_err());rt.fls_indices.get_mut(&0).unwrap().certain=false;assert!(rt.fls_get(fiber,slot,0).is_err());assert!(other.initialization(oi).is_ok());}
   if mode==11{let mut cleanup=cpu(&mut rt,0xe000,9701);cleanup.return_pop=0;let result=cleanup.call_activation(&mut rt,0x430000,0,|rt,c|startup_fiber_cleanup(rt,c,&inputs,Some(&platform),&mut startup_fiber_api));assert_eq!(result,Err("startup FlsFree callback/teardown contract unbound"));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.fls_indices.len(),1);rt.fls_index(entry.id).unwrap();}
  }else if mode==0{assert_eq!(got,Err("native platform API-set mapping unsupported"));assert_eq!(calls,vec![0x415074]);assert_eq!(rt.load(flag,8).unwrap(),CrtValue::scalar(123));assert!(rt.fls_indices.is_empty());}
  else if mode==13{assert_eq!(got,Err("independent second module attempt rejected"));assert_eq!(calls,vec![0x415074,0x415044,0x415074]);assert_eq!(rt.load(rt.process_image_pointer(inputs.image,0x41ceac,4).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.load(cache,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(flag,8).unwrap(),CrtValue::scalar(123));assert!(rt.fls_indices.is_empty());}
  else if mode==8{assert_eq!(got,Err("CRT storage write"));assert_eq!(calls,vec![0x41509c]);assert_eq!(rt.fls_indices.len(),1);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(777));assert_eq!(rt.load(flag,8).unwrap(),CrtValue::scalar(0));}
  else{assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(777));assert_eq!(rt.fls_indices.len(),if mode==3{64}else{0});if matches!(mode,4|5|6|10|12){assert!(calls.is_empty());}if mode==2||mode==3||mode==14{assert_eq!(calls,vec![0x41509c]);assert_eq!(rt.load(flag,8).unwrap(),CrtValue::scalar(0));if mode==14{assert_eq!(got,Err("CRT native named export unsupported"));}}}
 }
}
fn startup_heap_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..11{
  let mut file=original.clone();if mode==6{let needle=[0xff,0x15,0xf8,0x50,0x41,0,0x85,0xc0,0xa3,0xc8,0xd2,0x41,0];let offsets:Vec<_>=file.windows(needle.len()).enumerate().filter(|(_,b)|*b==needle).map(|(i,_)|i).collect();assert_eq!(offsets.len(),1);file[offsets[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let stack=rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let cell=rt.process_image_pointer(inputs.image,0x41d2c8,4).unwrap();let mut expected=None;let mut allocation=None;
  if mode==1||mode==2{let CrtValue::Heap(h)=rt.process_heap_result(init,true,if mode==1{Some(false)}else{None}).unwrap()else{panic!()};expected=Some(h);if mode==1{allocation=rt.allocate(32,true,true).unwrap();}}
  let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(foreign)=other.process_heap_result(oi,true,Some(false)).unwrap()else{panic!()};
  if mode==4{let CrtValue::Heap(mut h)=rt.native_process_heap(init).unwrap()else{panic!()};h.process=foreign.process;rt.heap=Some(h);}if mode==5{rt.end_initialization(init).unwrap();}if mode==7{rt.protect_image_data(inputs.image,cell,4,2,rt.offset(stack,0x1000).unwrap()).unwrap();}if mode==9{rt.store(cell,32,CrtValue::scalar(77)).unwrap();}
  let before_errno=rt.canonical_errno;let before_heap=rt.heap;let mut c=cpu(&mut rt,0xd000,9600);c.return_pop=0;let saved=c.entry;let mut effects=0;
  let got=c.call_activation(&mut rt,0x430000,0,|rt,c|startup_heap_original(rt,c,&inputs,&mut |rt,c,i|{effects+=1;if mode==3{c.clobber(CrtValue::Heap(foreign));return c.finish(rt);}if mode==9{c.clobber(CrtValue::scalar(0));return c.finish(rt);}if mode==10{rt.native_process_heap(i.init)?;return Err("independent failure after heap acquisition");}startup_heap_api(rt,c,i)}));
  if matches!(mode,0|1|2|8){let value=got.unwrap_or_else(|e|panic!("heap success mode {mode}: {e}"));let(bits,known)=CrtCpu::bits(value).unwrap();assert_eq!(bits&255,1);assert_eq!(known&255,255);let CrtValue::Heap(heap)=rt.load(cell,32).unwrap()else{panic!()};rt.heap_identity(heap).unwrap();assert_eq!(heap.process,rt.memory.process_heap());assert_eq!(heap.exceptions,if mode==1{Some(false)}else{None});if let Some(h)=expected{assert_eq!(h,heap);}assert_eq!(rt.native_process_heap(init).unwrap(),CrtValue::Heap(heap));assert_eq!(rt.canonical_errno,before_errno);if let Some(p)=allocation{assert_eq!(rt.memory.heap_capability(heap.process,p.base).unwrap(),p.cap);}for r in [3,5,6,7]{assert_eq!(c.r[r],saved[r]);}assert_eq!(c.r[4],saved[4]);c.finish(&mut rt).unwrap();assert!(c.returned);
   if mode==8{let mut clear=cpu(&mut rt,0xe000,9601);clear.return_pop=0;clear.call_activation(&mut rt,0x430000,0,|rt,c|startup_table_heap_clear(rt,c,&inputs)).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));rt.heap_identity(heap).unwrap();assert_eq!(rt.native_process_heap(init).unwrap(),CrtValue::Heap(heap));let p=rt.allocate(8,true,true).unwrap().unwrap();assert_eq!(rt.memory.heap_capability(heap.process,p.base).unwrap(),p.cap);}
  }else if mode==9{let v=got.unwrap();assert_eq!(v,CrtValue::scalar(0));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert!(rt.heap.is_none());assert_eq!(effects,1);}
  else{assert!(got.is_err(),"heap negative mode {mode} unexpectedly succeeded");assert!(!c.returned);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(effects,usize::from(!matches!(mode,5|6)));if mode==7||mode==10{assert!(rt.heap.is_some());assert_eq!(got,Err(if mode==7{"CRT storage write"}else{"independent failure after heap acquisition"}));}else{assert_eq!(rt.heap,before_heap);}}
 }
 // Closed process authority and same-anchor/foreign-space forgery both reject.
 let(mut a,ai)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(h)=a.native_process_heap(ai).unwrap()else{panic!()};let sp=a.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let mut c=CrtCpu::new(sp,9602).unwrap();for(x,y)in[(CrtValue::Heap(h),CrtValue::scalar(0)),(CrtValue::scalar(0),CrtValue::Heap(h))]{assert_eq!(c.binary(&a,4,x,y,32).unwrap(),CrtValue::scalar(0));assert_eq!((c.flags.zf,c.flags.cf,c.flags.of,c.flags.sf),(Some(true),Some(false),Some(false),Some(false)));}assert!(c.binary(&a,4,CrtValue::Heap(h),CrtValue::scalar(1),32).is_err());assert!(c.binary(&a,4,CrtValue::Heap(h),CrtValue::Scalar{bits:0,known:255},32).is_err());assert!(c.binary(&a,4,CrtValue::Heap(h),CrtValue::scalar(0),16).is_err());a.closed=true;assert!(c.binary(&a,4,CrtValue::Heap(h),CrtValue::scalar(0),32).is_err());assert!(a.heap_identity(h).is_err());assert!(a.native_process_heap(ai).is_err());
}
fn startup_lock_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..14{
  let mut file=original.clone();if matches!(mode,6..=8){let needle=match mode{6=>vec![0x8b,0xff,0x56,0x57,0xbf,0x50,0xd1,0x41,0],7=>vec![0x8b,0xff,0x55,0x8b,0xec,0x5d,0xff,0x25,0xac,0x50,0x41,0],_=>vec![0x8b,0xff,0x56,0x8b,0x35,0xb8,0xd2,0x41,0]};let at:Vec<_>=file.windows(needle.len()).enumerate().filter(|(_,w)|*w==needle.as_slice()).map(|(i,_)|i).collect();assert_eq!(at.len(),1);file[at[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let stack=rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();let f=platform.function;
  let count=rt.process_image_pointer(inputs.image,0x41d2b8,4).unwrap();let objects=rt.process_image_pointer(inputs.image,0x41d150,360).unwrap();let output=rt.offset(stack,0x1000).unwrap();
  if mode==9{rt.provider_destroy(init,f.module).unwrap();}if mode==10{rt.protect_image_data(inputs.image,objects,360,2,output).unwrap();}if mode==11{rt.store(count,32,CrtValue::scalar(1)).unwrap();}if mode==12{rt.memory.release(objects.cap,objects.owner).unwrap();}
  let mut c=cpu(&mut rt,if mode%2==0{0xd000}else{0xc000},9500);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};let saved=c.entry;let mut events=vec![];let mut initialized=0usize;
  let failed=match mode{1=>Some(0),2=>Some(1),3|5|8=>Some(7),4=>Some(14),_=>None};
  let got=c.call_activation(&mut rt,0x430000,0,|rt,c|startup_lock_loop(rt,c,&inputs,&mut |rt,c,i,iat|{
   let sp=CrtCpu::pointer(c.r[4])?;let address=CrtCpu::number(rt.load(rt.offset(sp,4)?,32)?)?;events.push((iat,address));
   if iat==0x4150ac{assert_eq!(address,0x41d150+initialized as u32*24);assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(4000));assert_eq!(rt.load(rt.offset(sp,12)?,32)?,CrtValue::scalar(0));if failed==Some(initialized){c.clobber(CrtValue::scalar(0));return c.finish_pop(rt,12);}initialized+=1;}
   let result=startup_lock_api(rt,c,i,iat)?;if mode==13&&iat==0x4150ac&&initialized==1{rt.modules.get_mut(&f.module.handle).unwrap().certain=false;}if mode==5&&iat==0x415054{return Err("independent delete failure after actual effect");}Ok(result)
  }));
  if mode<=4{let v=got.unwrap_or_else(|e|panic!("lock success mode {mode}: {e}"));let(bits,known)=CrtCpu::bits(v).unwrap();assert_eq!(known&255,255);assert_eq!(bits&255,u32::from(mode==0));let n=failed.unwrap_or(15);let mut expected:Vec<_>=(0..=n.min(14)).map(|j|(0x4150ac,0x41d150+j as u32*24)).collect();if failed.is_some(){expected.extend((0..n).rev().map(|j|(0x415054,0x41d150+j as u32*24)));}assert_eq!(events,expected);assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(if mode==0{15}else{0}));assert_eq!(rt.global_objects.values().count(),if mode==0{15}else{0});for j in [3,5,6,7]{assert_eq!(c.r[j],saved[j]);}assert_eq!(c.r[4],saved[4]);c.finish(&mut rt).unwrap();assert!(c.returned);
   if mode==0{let mut cleanup=cpu(&mut rt,0xe000,9501);cleanup.return_pop=0;cleanup.push(&mut rt,CrtValue::scalar(0)).unwrap();cleanup.call_activation(&mut rt,0x430000,0,|rt,c|startup_lock_cleanup(rt,c,&inputs,&mut startup_lock_api)).unwrap();assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(0));assert!(rt.global_objects.is_empty());assert!(rt.native_sync.is_empty());}
  }else{assert!(got.is_err(),"lock negative mode {mode} unexpectedly succeeded");assert!(!c.returned);if mode==5{assert_eq!(got,Err("independent delete failure after actual effect"));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(7));assert_eq!(rt.global_objects.values().count(),6);}else if mode==8{assert_eq!(got,Err("startup locks code changed"));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(7));assert_eq!(rt.global_objects.values().count(),7);}else if mode==13{assert_eq!(got,Err("CRT module owner/generation/lifetime"));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(1));assert_eq!(rt.global_objects.values().count(),1);}else{assert!(rt.global_objects.is_empty());}}
 }
}
fn virtual_protect_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..21{
  let mut file=original.clone();
  if mode==8{let bytes=[0x8b,0xff,0x55,0x8b,0xec,0x51,0x8d,0x45,0xfc,0x50,0x6a,2,0x68,0x80,0,0,0];let matches:Vec<_>=file.windows(bytes.len()).enumerate().filter(|(_,b)|*b==bytes).map(|(i,_)|i).collect();assert_eq!(matches.len(),1);file[matches[0]]^=1;}
  if mode==9{let bytes=b"VirtualProtect\0";let matches:Vec<_>=file.windows(bytes.len()).enumerate().filter(|(_,b)|*b==bytes).map(|(i,_)|i).collect();assert_eq!(matches.len(),1);file[matches[0]]=b'X';}
  if mode==10{let u32at=|at|u32::from_le_bytes(file[at..at+4].try_into().unwrap())as usize;let nt=u32at(60);let count=u16::from_le_bytes(file[nt+6..nt+8].try_into().unwrap())as usize;let section=(0..count).map(|i|nt+248+40*i).find(|&at|u32at(at+12)<=0x150b0&&0x150b0<u32at(at+12)+u32at(at+16)).unwrap();let offset=u32at(section+20)+0x150b0-u32at(section+12);file[offset]^=4;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let stack=rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();
  let target=rt.process_image_pointer(inputs.image,0x41e000,128).unwrap();let output=rt.offset(stack,0x2000).unwrap();rt.store(output,32,CrtValue::scalar(0xdeadbeef)).unwrap();let prior=rt.memory.read(target.address(),128).unwrap().to_vec();let mut c=cpu(&mut rt,0xd000,9200);c.return_pop=0;c.r[1]=CrtValue::Scalar{bits:0,known:0};
  if matches!(mode,0|8|9|10){
   let got=c.call_activation(&mut rt,0x430000,0,|rt,c|startup_table_third(rt,c,&inputs));
   if mode==0{assert_eq!(got.unwrap().known_scalar().unwrap()&255,1);assert_eq!(c.r[4],c.entry[4]);rt.memory.validate_readable(target.cap,target.owner,target.address(),128).unwrap();assert!(rt.memory.validate_writable(target.cap,target.owner,target.address(),128).is_err());c.finish(&mut rt).unwrap();assert!(c.returned);}
   else{assert!(got.is_err(),"original protect mutation {mode} unexpectedly accepted");assert_eq!(got,Err(match mode{8=>"initializer helper code changed",9=>"CRT original named import unbound",10=>"CRT import ambiguous/changed IAT",_=>unreachable!()}));rt.memory.validate_writable(target.cap,target.owner,target.address(),128).unwrap();assert!(!c.returned);}
   assert_eq!(rt.memory.read(target.address(),128).unwrap(),prior);continue;
  }
  if mode==18||mode==19{let q=rt.offset(target,if mode==19{64}else{0}).unwrap();rt.construct_global_lock(init,0,q,1).unwrap();}if mode==20{rt.construct_lock(init,rt.file()).unwrap();}
  let argument_target=if mode==20{rt.process_image_pointer(inputs.image,0x41c000,1).unwrap()}else if mode==14{rt.subrange(target,128).unwrap()}else if mode==15{rt.process_image_code(inputs.image,0x4017a4,1).unwrap()}else{target};
  let mut out=output;if mode==3{out=target;}if mode==7{out=rt.offset(stack,0x5ffe).unwrap();}if mode==13{let p=rt.map_region(0x20000,4096,CrtRegionKind::Stack,None).unwrap();rt.memory.release(p.cap,p.owner).unwrap();out=p;}
  if mode==6{rt.store(output,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
  c.push(&mut rt,CrtValue::Pointer(out)).unwrap();c.push(&mut rt,CrtValue::scalar(if mode==1{0x40}else if mode==16{1}else{2})).unwrap();c.push(&mut rt,if mode==5{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if mode>=18{1}else{128})}).unwrap();c.push(&mut rt,CrtValue::Pointer(argument_target)).unwrap();
  if mode==4{rt.memory.release(target.cap,target.owner).unwrap();}
  let got=c.call_activation(&mut rt,0x430000,if mode==11{12}else{16},|rt,c|{if mode==2{let sp=CrtCpu::pointer(c.r[4])?;rt.store(rt.offset(sp,16)?,32,CrtValue::Pointer(sp))?;}if mode==12{c.r[3]=CrtValue::scalar(7);}c.virtual_protect_call(rt,inputs.image)});
  if matches!(mode,6|16|17){assert_eq!(got,Ok(CrtValue::scalar(1)));assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(4));assert_eq!(c.r[4],c.entry[4]);assert!(rt.memory.validate_writable(target.cap,target.owner,target.address(),128).is_err());
   if mode==16{assert!(rt.load(target,32).is_err());rt.protect_image_data(inputs.image,target,128,2,output).unwrap();assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(1));}
   if mode==17{rt.protect_image_data(inputs.image,target,128,4,output).unwrap();assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(2));rt.store(target,32,CrtValue::scalar(73)).unwrap();assert_eq!(rt.load(target,32).unwrap(),CrtValue::scalar(73));}
   c.finish(&mut rt).unwrap();assert!(c.returned);
  }else{assert!(got.is_err(),"protect ABI mode {mode} unexpectedly succeeded");assert!(!c.returned);assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(0xdeadbeef));if mode!=4{rt.memory.validate_writable(target.cap,target.owner,target.address(),128).unwrap();if mode!=18&&mode!=19{assert_eq!(rt.memory.read(target.address(),128).unwrap(),prior);}else{let lease=rt.lock_global(rt.thread,0).unwrap();rt.unlock_global(lease).unwrap();}}}
 }
 // Typed pointer tags may not bypass a page's read permission, nor can a
 // protection round-trip create pointer authority or revive stale storage.
 let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&original).unwrap();let image=rt.main_image.unwrap();let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let p=rt.process_image_pointer(image,0x41e000,128).unwrap();let pointee=rt.process_image_pointer(image,0x41d000,4).unwrap();rt.store(p,32,CrtValue::Pointer(pointee)).unwrap();let out=rt.offset(stack,16).unwrap();
 rt.protect_image_data(image,p,128,1,out).unwrap();assert_eq!(rt.load(p,32),Err("CRT read permission"));rt.protect_image_data(image,p,128,2,out).unwrap();assert_eq!(rt.load(p,32).unwrap(),CrtValue::Pointer(pointee));rt.memory.release(pointee.cap,pointee.owner).unwrap();assert_eq!(rt.load(p,32).unwrap(),CrtValue::Pointer(pointee));assert!(rt.load(pointee,32).is_err());assert!(rt.protect_image_data(image,p,128,4,out).is_err());assert!(rt.initialization(init).is_err());
}
fn initializer_table_cases(){
 let original=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..18{
  let mut file=original.clone();let bytes=crate_table_bytes();let positions:Vec<_>=file.windows(bytes.len()).enumerate().filter(|(_,b)|*b==bytes.as_slice()).map(|(i,_)|i).collect();assert_eq!(positions.len(),1);let at=positions[0];
  let mut pairs=vec![(0x407558u32,0x407587u32),(0x408113,0x408167),(0,0x401bd5),(0x401bd5,0)];
  if mode==14{pairs=vec![(0x407558,0x407587);16];}if mode==13{pairs.clear();}
  for(i,(a,b))in pairs.iter().enumerate(){file[at+i*8..at+i*8+4].copy_from_slice(&a.to_le_bytes());file[at+i*8+4..at+i*8+8].copy_from_slice(&b.to_le_bytes());}
  if mode==8{/* locate guard by PE section, not byte uniqueness */let nt=u32::from_le_bytes(file[60..64].try_into().unwrap())as usize;let count=u16::from_le_bytes(file[nt+6..nt+8].try_into().unwrap())as usize;let sections=nt+24+u16::from_le_bytes(file[nt+20..nt+22].try_into().unwrap())as usize;for i in 0..count{let section=sections+i*40;let va=u32::from_le_bytes(file[section+12..section+16].try_into().unwrap());let size=u32::from_le_bytes(file[section+16..section+20].try_into().unwrap());if va<=0x1bf9&&0x1bf9<va+size{let raw=u32::from_le_bytes(file[section+20..section+24].try_into().unwrap());file[(raw+0x1bf9-va+1)as usize]=4;}}}
  if mode==9{let code=crate_loop_bytes();let ps:Vec<_>=file.windows(code.len()).enumerate().filter(|(_,b)|*b==code.as_slice()).map(|(i,_)|i).collect();assert_eq!(ps.len(),1);file[ps[0]]^=1;}
  let(mut rt,init,stale)=if mode==16||mode==17{let(mut r,i)=CrtStreamRuntime::new_initializing(7,9,0x8000,1048576).unwrap();let old=r.map_region(0x415fb8,128,CrtRegionKind::Input,Some(&[0;128])).unwrap();let p=r.offset(old,if mode==16{0}else{pairs.len()as i64*8}).unwrap();r.retire_region(old).unwrap();r.bootstrap_pe32(i,&file).unwrap();(r,i,Some(p))}else{let(r,i)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();(r,i,None)};rt.map_region(0x9000,0x2000,CrtRegionKind::Stack,None).unwrap();let image=rt.main_image.unwrap();let marker=rt.process_image_pointer(image,0x41d134,4).unwrap();let mut c=cpu(&mut rt,0xa000,9921);c.return_pop=0;let before=c.r;
  let sp=CrtCpu::pointer(c.r[4]).unwrap();let begin=0x415fb8u32+if mode==11{1}else{0};let end=if mode==15{0x415fb8+136}else{begin+pairs.len()as u32*8};rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::scalar(begin)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::scalar(end)).unwrap();
  let table=rt.process_image_pointer(image,0x415fb8,128).unwrap();if let Some(p)=stale{rt.store(rt.offset(sp,if mode==16{4}else{8}).unwrap(),32,CrtValue::Pointer(p)).unwrap();}let code=rt.process_image_code(image,0x40c926,104).unwrap();if mode==10{rt.memory.release(table.cap,table.owner).unwrap();}
  let failure=match mode{1=>Some(0),2=>Some(1),3|4|12=>Some(3),14=>Some(15),_=>None};let mut events=vec![];
  let got=startup_table_loop(&mut rt,&mut c,image,&mut |rt,c,index,cleanup,target|{
   assert_eq!(target.address(),if cleanup{pairs[index].1}else{pairs[index].0});events.push((index,cleanup));
   let n=rt.load(marker,32)?.known_scalar()?;rt.store(marker,32,CrtValue::scalar(n+1))?;
   if mode==5&&index==0{rt.memory.release(table.cap,table.owner).unwrap();}if mode==6&&index==0{rt.memory.release(code.cap,code.owner).unwrap();}
   if cleanup&&mode==4{return Err("independent cleanup failure after write");}if cleanup&&mode==12{c.r[3]=CrtValue::scalar(9);}
   c.clobber(CrtValue::scalar(u32::from(failure!=Some(index)||cleanup)));
   if mode==7{return Ok(c.r[0]);}c.finish(rt)
  });
  if matches!(mode,0..=3|13|14){let result=got.unwrap();assert_eq!(CrtCpu::bits(result).unwrap().0&255,u32::from(failure.is_none()));assert!(c.returned);for r in [3,5,6,7]{assert_eq!(c.r[r],before[r]);}
   let mut expected=vec![];for(i,p)in pairs.iter().enumerate(){if p.0!=0{expected.push((i,false));if failure==Some(i){break;}}}if let Some(f)=failure{for i in (0..f).rev(){if pairs[i].0!=0&&pairs[i].1!=0{expected.push((i,true));}}}assert_eq!(events,expected,"initializer mode {mode}");assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(events.len()as u32));
  }else{assert!(got.is_err(),"initializer mode {mode} unexpectedly succeeded");assert!(!c.returned);if matches!(mode,8..=11|15..=17){assert!(events.is_empty());assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(0));}else{assert!(!events.is_empty());assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(events.len()as u32));}if mode==4{assert_eq!(got,Err("independent cleanup failure after write"));assert_eq!(events,vec![(0,false),(1,false),(3,false),(1,true)]);}if mode==7{assert_eq!(got,Err("CRT callee missing exact protected RET"));}}
 }
}
fn original_fls_wrapper_fallback_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..3{
  let mut file=file.clone();if mode==2{let bytes=startup_fls_alloc_code();let matches:Vec<_>=file.windows(bytes.len()).enumerate().filter(|(_,b)|*b==bytes.as_slice()).map(|(i,_)|i).collect();assert_eq!(matches.len(),1);file[matches[0]+58]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();rt.map_region(0x9000,0x1000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut c=cpu(&mut rt,0x9800,9911);let before=c.r;let mut calls=0;
  let result=startup_fls_alloc(&mut rt,&mut c,&inputs,&mut |rt,c,pc,target|{assert_eq!((pc,target),(0x402b53,0x402a53));calls+=1;c.clobber(CrtValue::scalar(if mode==1{1}else{0}));c.finish(rt)});
  assert_eq!(result,Err(match mode{0=>"startup TLS allocation fallback unbound",1=>"startup FLS guard provenance",_=>"startup module live code changed"}));assert!(!c.returned);assert!(rt.fls_indices.is_empty());assert_eq!(calls,if mode==2{0}else{1});
  if mode==0{assert_eq!(c.r[4],before[4]);assert_eq!(c.r[5],before[5]);assert_eq!(c.r[6],before[6]);assert_eq!(rt.load(CrtCpu::pointer(c.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(9911));}
 }
}
fn native_fls_producer_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..10{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();
  let image=rt.main_image.unwrap();rt.map_region(0x9000,0x1000,CrtRegionKind::Stack,None).unwrap();let mut c=cpu(&mut rt,0x9800,9701);c.return_pop=4;
  let callback=rt.process_image_code(image,0x4028a7,1).unwrap();let value=if mode==1{CrtValue::scalar(0)}else{CrtValue::Pointer(callback)};let arg=rt.offset(CrtCpu::pointer(c.r[4]).unwrap(),4).unwrap();rt.store(arg,32,value).unwrap();
  if mode==2{c.r[6]=CrtValue::scalar(42);}if mode==3{c.return_pop=0;}
  if mode==4{for _ in 0..64{rt.native_fls_allocate(init,None).unwrap();}}
  if mode==5{rt.serial=u64::MAX;}
  if mode==6{rt.thread+=1;}
  if mode==7{rt.store(arg,32,CrtValue::scalar(0x41ccc4)).unwrap();}
  if mode==8{rt.store(arg,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
  if mode==9{rt.memory.release(callback.cap,callback.owner).unwrap();}
  let serial=rt.serial;let count=rt.fls_indices.len();rt.last_os_error=Some(87);
  let got=c.native_fls_alloc_call(&mut rt,init,image);
  if mode<=1{
   assert_eq!(got,Ok(CrtValue::scalar(0)));assert!(c.returned);assert_eq!(CrtCpu::pointer(c.r[4]).unwrap().address(),0x9808);assert_eq!(rt.last_os_error,None);
   let id=rt.fls_indices.get(&0).unwrap().id;assert_eq!(rt.fls_indices.get(&0).unwrap().callback,if mode==0{Some((image,callback))}else{None});assert!(rt.fls.is_empty());
   let fiber=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls_fiber(fiber,id).unwrap();assert_eq!(rt.fls_get(fiber,slot,0),Ok(CrtValue::scalar(0)));
   let other=CrtFiber{serial:fiber.serial+1,..fiber};assert!(rt.fls_get(other,slot,0).is_err());
   rt.detach_empty_fls_fiber(fiber,slot).unwrap();rt.fls_free_index_result(init,id,true).unwrap();let next=rt.native_fls_allocate(init,None).unwrap();assert_eq!(next.index,0);assert_ne!(next,id);assert!(rt.fls_index(id).is_err());assert!(rt.bind_fls_fiber(fiber,id).is_err());
   assert!(c.native_fls_alloc_call(&mut rt,init,image).is_err());
  }else{
   assert!(got.is_err(),"native FLS mode {mode}: unexpected success");assert!(!c.returned);assert_eq!(rt.serial,serial);assert_eq!(rt.fls_indices.len(),count);assert!(rt.fls.is_empty());assert_eq!(rt.last_os_error,Some(87));
   if mode==2||mode==3{assert_eq!(got,Err("CRT FLS allocation stdcall frame"));}if mode==4{assert_eq!(got,Err("CRT native FLS index capacity"));}if mode==5{assert_eq!(got,Err("CRT FLS serial"));}if mode==8{assert_eq!(got,Err("CRT FLS callback provenance"));}
  }
 }
}
fn startup_module_cases(){
 let file=std::fs::read(std::env::var("W2L_PE_MAPPING_INPUT").unwrap()).unwrap();
 for mode in 0..9{
  let(m,registry,_,_)=fixture_with_extra(&[(0x410000,0x420000)]);let _=m;let mut image=file.clone();if mode==7{let b=startup_modules_code();let found:Vec<_>=image.windows(b.len()).enumerate().filter(|(_,v)|*v==b.as_slice()).map(|(i,_)|i).collect();assert_eq!(found.len(),1);image[found[0]]^=1;}
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(registry.identity.owner,registry.identity.instance,0x41c080,3,1048576,&image).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let inputs=CrtEntropyInputs::bind(&rt,init,17,19).unwrap();let mut c=cpu(&mut rt,0xd000,8900);c.return_pop=0;
  let lock=rt.process_image_pointer(inputs.image,0x41ccec,24).unwrap();let count=rt.process_image_pointer(inputs.image,0x41cd04,4).unwrap();let slot=rt.process_image_pointer(inputs.image,0x41c060,4).unwrap();
  if mode==4{rt.end_initialization(init).unwrap();}if mode==5{rt.store(lock,32,CrtValue::Pointer(lock)).unwrap();}if mode==6{rt.construct_global_lock(init,1,lock,1).unwrap();}
  let mut events=vec![];let fiber=rt.bind_fiber(rt.thread).unwrap();let mut allocation=None;
  let got=startup_modules(&mut rt,&mut c,&inputs,&mut |rt,c,pc,target|match(pc,target){
   (0x4024ca,0x4029b4)=>startup_locks(rt,c,&inputs,&mut |rt,c,pc,target|{if (pc,target)==(0x4029e6,0x4029f0){return startup_destroy(rt,c,&inputs,&mut |_,_,_,_|Err("unexpected empty destruction call"));}assert_eq!((pc,target),(0x4029c5,0x402c2d));events.push("construct");let ok=rt.construct_global_lock(init,0,lock,u32::from(mode!=0))?;c.clobber(CrtValue::scalar(u32::from(ok)));c.finish(rt)}),
   (0x4024d6,0x402963)=>startup_fls(rt,c,&inputs,&mut |rt,c,pc,target|match(pc,target){
    (0x402968,0x402b3e)=>{events.push("allocation observation");let result=if mode==1||mode==8{u32::MAX}else{7};let callback=rt.process_image_code(inputs.image,0x4028a7,1)?;allocation=rt.fls_allocation_result(init,result,Some((inputs.image,callback)))?;if let Some(id)=allocation{rt.bind_fls_fiber(fiber,id)?;}c.clobber(CrtValue::scalar(result));c.finish(rt)},
    (0x402981,0x402bef)=>{events.push("publication boundary");let sp=CrtCpu::pointer(c.r[4])?;assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::scalar(7));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(0x41ccc4));Err(if mode==3{"independent publication failure"}else{"startup module sentinel ownership unbound"})},
    _=>Err("unexpected FLS component call")}),
   (0x4024df,0x4029f0)=>startup_destroy(rt,c,&inputs,&mut |rt,c,pc,target|{assert_eq!((pc,target),(0x402a06,0x415054));events.push("destroy");if mode==8{return Err("independent destruction failure");}rt.destroy_global_lock(init,0)?;c.clobber(CrtValue::Scalar{bits:0,known:0});c.finish_pop(rt,4)}),
   _=>Err("unexpected startup component call")});
  if mode==0||mode==1{assert!(got.is_ok(),"startup mode {mode}: {got:?}");assert_eq!(c.get(0,8,0).unwrap().known_scalar().unwrap(),0);assert!(c.returned);assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(0));assert!(rt.global_objects.is_empty());if mode==1{assert_eq!(events,vec!["construct","allocation observation","destroy"]);assert_eq!(rt.load(slot,32).unwrap(),CrtValue::scalar(u32::MAX));}}
  else{assert_eq!(got,Err(match mode{3=>"independent publication failure",4=>"CRT initialization owner/lifetime",7=>"startup module live code changed",8=>"independent destruction failure",5|6=>"CRT global lock role/index/alias",_=>"startup module sentinel ownership unbound"}));assert!(!c.returned);if mode==8{assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(1));assert_eq!(rt.load(slot,32).unwrap(),CrtValue::scalar(u32::MAX));assert!(rt.global_objects.contains_key(&0));}if mode==2||mode==3{let id=allocation.expect("original published slot needs allocation owner");rt.fls_index(id).unwrap();assert_eq!(rt.fls.get(&7).unwrap().0.allocation,id);assert_eq!(rt.fls.get(&7).unwrap().1,CrtValue::scalar(0));assert_eq!(rt.load(count,32).unwrap(),CrtValue::scalar(1));assert_eq!(rt.load(slot,32).unwrap(),CrtValue::scalar(7));assert!(rt.global_objects.contains_key(&0));}}
 }
}
fn canonical_startup_storage(){
 let path=std::env::var("W2L_PE_MAPPING_INPUT").expect("unchanged authored input required");let file=std::fs::read(path).unwrap();
 for mode in 0..8{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(r.identity.owner,r.identity.instance,0x41c080,3,1048576,&file).unwrap();
  rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let image=rt.main_image.unwrap();
  let cookie=rt.process_image_pointer(image,0x41c000,4).unwrap();let complement=rt.process_image_pointer(image,0x41c040,4).unwrap();
  let prior_cookie=rt.load(cookie,32).unwrap();let prior_complement=rt.load(complement,32).unwrap();let head=r.head;
  if mode==0||mode==1{
   if mode==1{rt.store(cookie,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
   let mut c=cpu(&mut rt,0xd000,901);c.return_pop=0;let got=original_cookie_init(&mut rt,&mut c);
   assert_eq!(got,Err(if mode==0{"cookie entropy producer unbound"}else{"CRT unknown scalar bits observed"}));assert!(!c.returned);assert_eq!(CrtCpu::pointer(c.r[4]).unwrap().address(),0xd000-8);assert_eq!(rt.load(CrtCpu::pointer(c.r[4]).unwrap(),32).unwrap(),c.entry[7]);assert_eq!(rt.load(rt.offset(CrtCpu::pointer(c.r[4]).unwrap(),4).unwrap(),32).unwrap(),c.entry[6]);assert_eq!(rt.load(complement,32).unwrap(),prior_complement);if mode==0{assert_eq!(rt.load(cookie,32).unwrap(),prior_cookie);}assert_eq!(r.head,head);continue;
  }
  // Explicit independently established-cookie input: this does not model the
  // unresolved entropy call. The original instructions write its complement.
  rt.store(cookie,32,CrtValue::scalar(0x12345678)).unwrap();
  let mut c=cpu(&mut rt,0xd000,902);c.return_pop=0;original_cookie_init(&mut rt,&mut c).expect("existing-cookie original initialization");assert!(c.returned);assert_eq!(rt.load(complement,32).unwrap(),CrtValue::scalar(!0x12345678));
  assert!(rt.map_region(0x41c000,4,CrtRegionKind::Module,None).is_err());
  if mode==6{let code=rt.process_image_pointer(image,0x401b71,75).unwrap();assert!(rt.store(code,8,CrtValue::scalar(0)).is_err());}
  rt.end_initialization(init).unwrap();
  let got=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let mut c=cpu(&mut rt,0xe000,71);let mut binding=CrtNormalBinding::bind(&rt,&c,epoch,epilog_run_layout())?;
   if mode==7{rt.memory.release(cookie.cap,cookie.owner).unwrap();return start(&mut rt,&mut c,epoch,&mut binding,99);}
   start(&mut rt,&mut c,epoch,&mut binding,99)?;
   assert_eq!(rt.load(rt.resolve_absolute(0x41c000,CrtRegionKind::Module)?,32)?,CrtValue::scalar(0x12345678));assert!(binding.id.is_some());
   if mode==3{rt.store(cookie,32,CrtValue::scalar(0x12345679))?;}
   if mode==4{rt.store(binding.at(&rt,binding.layout.guard)?,32,CrtValue::scalar(0))?;}
   if mode==5{rt.memory.release(cookie.cap,cookie.owner).unwrap();}
   c.r[0]=CrtValue::scalar(63);let value=epilog_run(&mut rt,&mut c,epoch,&mut binding)?;assert_eq!(value,CrtValue::scalar(63));assert!(binding.authority(&rt,epoch).is_err());Ok(())
  });
  if matches!(mode,3|4|5|7){assert_eq!(got,Err(match mode{3=>"CRT normal actual record/cookie/return changed",4=>"CRT normal saved known-mask/type/guard changed",5|7=>"CRT pointer lifetime",_=>unreachable!()}),"unsafe record mode {mode}");}else{got.expect("mapped cookie and original record prolog/epilog");assert_eq!(r.head,head);assert_eq!(rt.load(cookie,32).unwrap(),CrtValue::scalar(0x12345678));}
 }
 // Independent classes of existing cookie bits, not observed process results.
 for bits in [0u32,1,65535,65536,0x80000000,u32::MAX,0x12345678,0xbb40e64e]{
  let(mut rt,init)=CrtStreamRuntime::new_initializing_pe32(7,9,0x41c080,3,1048576,&file).unwrap();let token=rt.main_image.unwrap();let p=rt.process_image_pointer(token,0x41c000,4).unwrap();let q=rt.process_image_pointer(token,0x41c040,4).unwrap();rt.store(p,32,CrtValue::scalar(bits)).unwrap();let before=rt.load(q,32).unwrap();rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();let mut c=cpu(&mut rt,0xe000,81);c.return_pop=0;let got=original_cookie_init(&mut rt,&mut c);
  if bits==0xbb40e64e||bits&0xffff0000==0{assert_eq!(got,Err("cookie entropy producer unbound"));assert_eq!(rt.load(q,32).unwrap(),before);assert!(!c.returned);}else{got.expect("independent established cookie path");assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar(!bits));assert!(c.returned);assert_eq!((c.flags.cf,c.flags.of,c.flags.zf,c.flags.sf),(Some(false),Some(false),Some(false),Some(bits&0x80000000!=0)));rt.store(q,32,CrtValue::scalar(0xa55a1234)).unwrap();assert_eq!(original_cookie_init(&mut rt,&mut c),Err("CRT active caller lifetime/return authority"));assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar(0xa55a1234));}
  assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(bits));rt.end_initialization(init).unwrap();
 }

}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"canonical-startup"=>{ucrt_replacement_cases();ucrt_reference_cases();canonical_startup_storage();canonical_cookie_entropy();entropy_api_boundaries();native_entropy_startup();startup_entry_cases();startup_feature_cases();native_fls_producer_cases();initializer_table_cases();virtual_protect_cases();startup_lock_cases();startup_heap_cases();startup_fiber_cases();second_fiber_profile_cases();cache_publication_cases();original_fls_wrapper_fallback_cases();startup_module_cases();startup_resolver_cases();constructor_guard_cases();resident_loader_cases()},"inline-exit"=>{inline_exit_cases();inline_exit_delivery();inline_exit_image()},"abort-locked"=>abort_locked_cases(),"registered-errno"=>registered_errno_cases(),"ordered-search"=>ordered_search_cases(),"live-return"=>live_return_cases(),"chain-effect-lifetime"=>chain_effect_lifetime(),"shared-chain"=>{shared_chain_cases();shared_chain_nested();shared_chain_delivery()},"chain-ownership-gap"=>chain_ownership_gap(),"bound-cxx-invocation"=>bound_invocation(),"prefix-delivery-unwind"=>dispatcher_delivery_unwind(true),"dispatcher-delivery-unwind"=>dispatcher_delivery_unwind(false),"delivery-cached-unwind"=>delivery_cached_unwind(),"delivery-children"=>delivery_children(),"cxx-cached-unwind"=>cxx_cached_unwind(),"cxx-unwind"=>cxx_registered_unwind(),"manager-inherited"=>inherited_registered_manager(),"manager"=>manager_registered(),"live-finally"=>live_finally_cases(),"owned-loop"=>owned_loop_cases(),"owned-local"=>owned_local_cases(),"owned"=>{main_initial_rejections();initial_raise_rejections();owned_main_cases()},"path-edges"=>path_edges(),"live"=>live_dispatch(),"objects"=>captured_objects(),"handler"=>pending_handler_activation(),"pending"=>pending_normal_exception(),"pending-reject"=>reject_normal_exception(),"file"=>file_scope_normal(),"file-failure"=>file_scope_failure(),"nested"=>nested_actual(),"mutations"=>mutations(),"consumed"=>consumed_mutation(),"failure"=>body_failure(),"certificate"=>wrong_certificate(),"observed"=>observed(),_=>panic!("case")}}
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
        let main_initial_code=handler_bytes("main-initial-live.bin","c78500fdffff2c010000c78510fdffff0000000068cc0200006a008d8518fdffff50e89010000083c40cc7850cfdffff00000000c78508fdffff00000000c78504fdffff000000006a00ff1508504100898514fdffffc745fc00000000");
        let main_fill=handler_bytes("main-fill-live.bin","8b4c240c0fb64424088bd78b7c240485c9740888074783e90175f88b4424048bfac3");
        let fill=crate::frame_init::FillHelper{code:&main_fill,origin:0x402370,feature_words:[0x41ccbc,0x41c058]};
        let main_initial=crate::frame_init::prove_initializer(&main,&main_initial_code,0x4012b9,&fill,0x415008).unwrap();
        let main_initial_live=format!("{}\n{}",crate::crt_owned_frame::emit_main_initialization(&main_initial,&main_initial_code,0x4012b9,&fill),crate::crt_owned_frame::NORMAL_CONTINUATION);
        let main_initial_map=format!("fn map_main_initial(rt:&mut CrtStreamRuntime)->RegistryResult<CrtPointer>{{rt.map_region(0x4012b9,{},CrtRegionKind::Module,Some(&{main_initial_code:?}))?;rt.map_region(0x402370,{},CrtRegionKind::Module,Some(&{main_fill:?}))?;rt.map_region(0x400000,1,CrtRegionKind::Module,Some(&[0x4d]))}}",main_initial_code.len(),main_fill.len());
        let inner_bytes=handler_bytes("Inner-prolog.bin","558bec6afe68d0b14100681022400064a1000000005083ec10535657a100c041003145f833c5508d45f064a300000000");
        let inner=crate::frame_proof::prove_frame(&inner_bytes,0x4010c0,0x41c000,&std::collections::BTreeSet::from([0x41b1d0]),&std::collections::BTreeSet::from([0x402210])).unwrap();
        let completion_code=handler_bytes("main-completion-live.bin","8b8504fdffff33c93b85ccfdffff0f94c1518b9508fdffff33c03b95dcfdffff0f94c0508b8d0cfdffff518b155cc9410052a158c94100508b0d54c94100518b9510fdffff528b8500fdffff508b0d50c94100518b154cc9410052a148c94100508b8dd0fdffff2b8d14fdffff51ba501240002b9514fdffff52b8401040002b8514fdffff50b9201040002b8d14fdffff51ba001040002b9514fdffff52b8805141002b8514fdffff5068a0514100e8b500000083c448813d48c94100230100007576833d4cc9410076756d813d50c94100d5000000756181bd00fdffff2c010000755583bd10fdffff01754c833d54c94100007543833d58c94100ff753a833d5cc94100ff753183bd0cfdffff4d75288b8d08fdffff3b8ddcfdffff751a8b9504fdffff3b95ccfdffff750cc785fcfcffff00000000eb0ac785fcfcffff010000008b85fcfcffff8b4df064890d00000000595f5e5b8b4de433cde8340000008be55dc3");let completion_format=handler_bytes("main-format-live.bin","7b227461626c655f727661223a256c752c22636c65616e75705f72766173223a5b256c752c256c752c256c755d2c22726573746f72655f727661223a256c752c22726573746f72655f7461726765745f727661223a256c752c227472616365223a256c752c22696e6e6572223a256c752c226f75746572223a256c752c2273656c6563746564223a256c752c2268616e646c6564223a256c752c226162616e646f6e6564223a256c752c22696e6e65725f637572736f72223a256c642c226f757465725f637572736f72223a256c642c22726573746f72655f656178223a256c752c22726573746f72655f737461636b5f657175616c223a25642c22726573746f72655f6672616d655f657175616c223a25647d0a00");
        let mut words=main.ordinary_words().iter().map(|&o|(o,crate::main_completion::Word::Uninitialized)).collect::<std::collections::BTreeMap<_,_>>();for &o in main_initial.initialized_words(){words.insert(o,crate::main_completion::Word::Scalar);}for o in [-776,-780,-756]{words.insert(o,crate::main_completion::Word::Scalar);}
        for o in [-548,-564,-760,-764]{words.insert(o,crate::main_completion::Word::Stack);}words.insert(-560,crate::main_completion::Word::Continuation);words.insert(-748,crate::main_completion::Word::Module);words.insert(-772,crate::main_completion::Word::Uninitialized);
        let completion=crate::main_completion::prove_owned(&completion_code,0x4013b7,&crate::main_completion::Layout{words,esp:-796,saved:std::collections::BTreeMap::from([(-792,7),(-788,6),(-784,3),(0,5)]),guards:std::collections::BTreeSet::from([-796,-28]),predecessor:-16},&crate::main_completion::Bindings{module_base:0x400000,module_size:0x20000,globals:(0..6).map(|i|(0x41c948+i*4,i as usize)).collect(),printf:0x401520,format:0x4151a0,security_check:0x40154c}).unwrap();
        let completion_security=handler_bytes("main-security-live.bin","3b0d00c041007501c3e97c020000");let completion_security_source=crate::crt_main_completion::emit_security(&completion_security,0x40154c).unwrap();
        let printf_routing=handler_bytes("printf-routing-live.bin","568b7424086a01e8ac30000083c4048d4c240c516a005650e833fdffffff7004ff30e8f74e000083c4185ec3");
        let printf_iob=handler_bytes("printf-iob-live.bin","8bff558bec6b4508380580c041005dc3");
        let printf_options=handler_bytes("printf-options-live.bin","b8e8d24100c3");
        let printf_entry=handler_bytes("printf-entry-live.bin","8bff558bec83ec5c56ff75188d4da4e88eedffff8b451c8b55108b75148b4d0c8945f08b45088975f48955f88945e0894de485d275238d45a4c645c0015033c0c745bc160000005050505050e84316000083c41883ceffeb3e85f674d98d45f88955ec8945cc8d4dff8d45a48955e88945d08d45e08945d48d45f48945d88d45f08945dc8d45ec508d45cc508d45e850e889e1ffff8bf08d4da4e863edffff8bc65ec9c3");
        let printf_context=handler_bytes("printf-context-live.bin","8bff558bec8bd18b4d08c6421400c70200000000c6420800c6421c00c642240085c974158b018b490489420c8bc2c6421401894a105dc20400833d7cce4100007515a130c241008b0d34c24100c6421401894a1089420c8bc25dc20400");
        let printf_native=crate::crt_printf::emit(crate::stdio_effect::Region{code:&printf_routing,origin:0x401520},crate::stdio_effect::Region{code:&printf_iob,origin:0x4045d8},crate::stdio_effect::Region{code:&printf_options,origin:0x401270},0x40643e,(0x400000,0x420000)).unwrap();
        let printf_entry_native=crate::crt_printf::emit_context_entry(&printf_entry,&printf_context).unwrap();
        let printf_native_map=format!("fn map_printf_native(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x401520,44,CrtRegionKind::Module,Some(&{printf_routing:?}))?;rt.map_region(0x4045d8,16,CrtRegionKind::Module,Some(&{printf_iob:?}))?;rt.map_region(0x401270,6,CrtRegionKind::Module,Some(&{printf_options:?}))?;rt.map_region(0x40643e,164,CrtRegionKind::Module,Some(&{printf_entry:?}))?;rt.map_region(0x4051e0,93,CrtRegionKind::Module,Some(&{printf_context:?}))?;rt.map_region(0x41d2e8,8,CrtRegionKind::Module,Some(&[0u8;8]))?;rt.map_region(0x41ce7c,4,CrtRegionKind::Module,None)?;Ok(())}}");
        let completion_body=completion.source();let completion_runtime=crate::crt_main_completion::EMITTED_TYPES;
        let completion_live=format!("{completion_security_source}\n{completion_runtime}\nfn run_main_completion<F>(host:&mut CrtMainCompletion<'_,F>)->RegistryResult<CompletionOutcome<RegistryHead>> where F:FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&mut NormalReturnSession<'_>,PrintRequest<'_>)->RegistryResult<CrtValue>{{for(i,b)in {completion_format:?}.into_iter().enumerate(){{if host.rt.load(host.rt.offset(host.format,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err(\"completion changed format\");}}}}for(i,b)in {completion_code:?}.into_iter().enumerate(){{if host.rt.load(host.rt.offset(host.rt.resolve_absolute(0x4013b7,CrtRegionKind::Module)?,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err(\"completion changed original code\");}}}}{completion_body}}}\nfn map_main_completion(rt:&mut CrtStreamRuntime)->RegistryResult<CrtPointer>{{rt.map_region(0x4013b7,{},CrtRegionKind::Module,Some(&{completion_code:?}))?;rt.map_region(0x4151a0,{},CrtRegionKind::Module,Some(&{completion_format:?}))}}",completion_code.len(),completion_format.len());
        let initial_pushes=handler_bytes("initial-raise-pushes.bin","6a006a006a0068424242e0");
        let initial_call=handler_bytes("initial-raise-call.bin","ff1500504100");
        let initial_init=handler_bytes("inner-scalar-init.bin","c745e464000000c745e000000000c745fc00000000c745fc01000000");
        let raised=crate::frame_proof::prove_frame(&[inner_bytes.clone(),initial_init,initial_pushes].concat(),0x4010c0,0x41c000,&std::collections::BTreeSet::from([0x41b1d0]),&std::collections::BTreeSet::from([0x402210])).unwrap();
        let initial_raise_types=format!("{}\n{}\n{}",emitted_literal(include_str!("exception_event.rs")),emitted_literal(include_str!("main_completion.rs")),emitted_literal(include_str!("main_return.rs")));
        let initial_raise_init=crate::crt_owned_frame::emit_initializer(&raised,"initialize_initial_raise_owned");
        let initial_raise=crate::crt_owned_frame::emit_initial_raise(&raised,&initial_call,0x415000,0xe0424242).unwrap();
        let initial_raise_map=format!("fn map_initial_raise(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x401117,6,CrtRegionKind::Module,Some(&{initial_call:?}))?;Ok(())}}");
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
        callback_source.push_str(&format!("fn map_landing_context(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x40135f,{},CrtRegionKind::Module,Some(&{context:?}))?;rt.map_region(0x4013a5,18,CrtRegionKind::Module,Some(&[0x89,0x85,0x0c,0xfd,0xff,0xff,0x89,0xa5,0x08,0xfd,0xff,0xff,0x89,0xad,0x04,0xfd,0xff,0xff]))?;Ok(())}}",context.len()));
        let restore_call=handler_bytes("original-restore-call.bin","51e8b2feffff");let restore=handler_bytes("original-restore.bin","8b4c24048b81b00000008ba1c40000008ba9b4000000ffa1b8000000");let landing=handler_bytes("original-restored-landing.bin","89850cfdffff89a508fdffff89ad04fdffff");
        callback_source.push_str(&crate::crt_owned_search::emit_context_transfer(&restore_call,&restore,&landing).unwrap());callback_source.push_str(crate::crt_owned_search::RESTORATION_COMPLETION);
        for offset in [2,8,14,20,24]{let mut changed=restore.clone();changed[offset]^=1;assert!(crate::crt_owned_search::emit_context_transfer(&restore_call,&changed,&landing).is_err());}
        callback_source.push_str(&format!("fn map_context_transfer(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region(0x401398,6,CrtRegionKind::Module,Some(&{restore_call:?}))?;rt.map_region(0x401250,28,CrtRegionKind::Module,Some(&{restore:?}))?;Ok(())}}"));
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
        let empty_dispatch=crate::handler_dispatch::prove_dispatch(&handler_complete[prefix_bytes.len()..],prefix.end,&prefix,dispatch_bindings,crate::handler_dispatch::Entry::Search,&main_table,-2,0xe0424242,&filters,&filter_layout,&std::collections::BTreeSet::from([0x401333,0x40135c])).expect("original empty-scope search proof");
        assert!(empty_dispatch.actions.iter().any(|a|matches!(a,crate::handler_dispatch::Action::ReturnDisposition{value:1,..})),"original empty-scope path must return ContinueSearch");
        assert_eq!(crate::crt_owned_search::emit(crate::crt_owned_search::Input{proof:&empty_dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:main.scope_va(),table:&main_table,bridge:0x402800,filters:&filters},"empty_search").unwrap_err(),"owned search: no global boundary");
        let return_table=handler_bytes("file-scope-table.bin","feffffff00000000d4ffffff00000000feffffff00000000a8464000");
        let return_dispatch=crate::handler_dispatch::prove_dispatch(&handler_complete[prefix_bytes.len()..],prefix.end,&prefix,dispatch_bindings,crate::handler_dispatch::Entry::Search,&return_table,-2,0xe0420042,&Default::default(),&filter_layout,&std::collections::BTreeSet::from([0x4046a8])).unwrap();
        let return_normalizer=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0420042).unwrap();
        let return_guard=p.guard_proof(&guard,0x4021d0,&security,0x40154c,header).unwrap();
        let return_callees=crate::crt_owned_search::SearchCallees{normalizer:&return_normalizer,guard:&return_guard,context:&context_proof};
        let emit_bound=|callees:&crate::crt_owned_search::SearchCallees<'_>|crate::crt_owned_search::emit_live_return(crate::crt_owned_search::Input{proof:&return_dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:0x41b400,table:&return_table,bridge:0x402800,filters:&Default::default()},&prefix,callees,"bound_test");
        let other_event=crate::selection::prove_code_identity(&normalizer,0x414a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0424242).unwrap();
        let moved_normalizer=crate::selection::prove_code_identity(&normalizer,0x424a1b,&std::collections::BTreeSet::from([0x41ccb8]),0xe0420042).unwrap();
        let moved_context=crate::handler_context::prove_context_check(&context_code,0x412877,0x415128).unwrap();
        let other_header=p.guard_proof(&guard,0x4021d0,&security,0x40154c,[-44,0,-44,0]).unwrap();
        let mut other_security=security.clone();other_security[2..6].copy_from_slice(&0x41c004u32.to_le_bytes());
        let other_cookie=crate::handler_guard::prove_guard_offsets(&guard,0x4021d0,&other_security,0x40154c,0x41c004,header,&[-44]).unwrap();
        for mismatched in [
         crate::crt_owned_search::SearchCallees{normalizer:&other_event,guard:&return_guard,context:&context_proof},
         crate::crt_owned_search::SearchCallees{normalizer:&moved_normalizer,guard:&return_guard,context:&context_proof},
         crate::crt_owned_search::SearchCallees{normalizer:&return_normalizer,guard:&return_guard,context:&moved_context},
         crate::crt_owned_search::SearchCallees{normalizer:&return_normalizer,guard:&other_header,context:&context_proof},
         crate::crt_owned_search::SearchCallees{normalizer:&return_normalizer,guard:&other_cookie,context:&context_proof},
        ]{assert_eq!(emit_bound(&mismatched).unwrap_err(),"live search: callee target/domain/header binding");}
        emit_bound(&return_callees).expect("matching original helper proofs must compose");
        // Individually valid proofs cannot claim different bytes at one address.
        let mut aliased_prefix_bytes=prefix_bytes.clone();let call=prefix.calls[0].va;
        let offset=(call-prefix.entry)as usize;
        aliased_prefix_bytes[offset+1..offset+5].copy_from_slice(&0x40154cu32.wrapping_sub(call+5).to_le_bytes());
        let aliased_prefix=crate::handler_checks::prove_prefix(&aliased_prefix_bytes,prefix.entry,&crate::handler_checks::Bindings{normalizer_va:0x40154c,guard_va:0x4021d0,context_va:0x402877,cookie_va:0x41c000,installer_va:0x402263}).unwrap();
        let aliased_normalizer=crate::selection::prove_code_identity(&normalizer,0x40154c,&std::collections::BTreeSet::from([0x41ccb8]),0xe0420042).unwrap();
        let aliased_callees=crate::crt_owned_search::SearchCallees{normalizer:&aliased_normalizer,guard:&return_guard,context:&context_proof};
        assert_eq!(crate::crt_owned_search::emit_live_return(crate::crt_owned_search::Input{proof:&return_dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:0x41b400,table:&return_table,bridge:0x402800,filters:&Default::default()},&aliased_prefix,&aliased_callees,"aliased_helpers").unwrap_err(),"live search: overlapping callee source ownership");
        let live_return=crate::crt_owned_search::emit_live_return(crate::crt_owned_search::Input{proof:&return_dispatch,origin:prefix.end,code:&handler_complete[prefix_bytes.len()..],table_va:0x41b400,table:&return_table,bridge:0x402800,filters:&Default::default()},&prefix,&return_callees,"original_live_search_return").unwrap();
        for offset in [0,2,return_dispatch.instructions.last().unwrap().pc as usize-prefix.end as usize]{
            let mut changed=handler_complete[prefix_bytes.len()..].to_vec();changed[offset]^=1;
            assert!(crate::crt_owned_search::emit_live_return(crate::crt_owned_search::Input{proof:&return_dispatch,origin:prefix.end,code:&changed,table_va:0x41b400,table:&return_table,bridge:0x402800,filters:&Default::default()},&prefix,&return_callees,"bad_return").is_err());
        }
        let return_helper_map=[return_normalizer.original(),return_guard.originals()[0],return_guard.originals()[1],context_proof.original()].iter().map(|(at,bytes)|format!("rt.map_region({at},{},CrtRegionKind::Module,Some(&{bytes:?}))?;",bytes.len())).collect::<String>();
        let live_return_map=format!("fn map_live_search_return(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{{return_helper_map}rt.map_region(0x402210,{},CrtRegionKind::Module,Some(&{handler_complete:?}))?;rt.map_region(0x41b400,{},CrtRegionKind::Module,Some(&{return_table:?}))?;rt.map_region(0x41ccb8,4,CrtRegionKind::Module,Some(&1u32.to_le_bytes()))?;rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;Ok(())}}",handler_complete.len(),return_table.len());
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
        let mut alternate_context=context_code.clone();alternate_context[1..3].copy_from_slice(&[0x89,0xe5]);
        crate::handler_context::prove_context_check(&alternate_context,0x402877,0x415128).expect("independent equivalent prolog proof");
        let context_check=format!("{}\nfn alternate_context_check()->&'static[u8]{{&{:?}}}",context_proof.normal_object_check(),alternate_context);
        let finally_source=crate::crt_finally_tests::emit();
        let finally_cases=crate::crt_finally_tests::CASES;
        let manager_p=PrologProof::prove(Region{bytes:&super::tests::bytes(),origin:0x401e60},16,0x41b6a0,0x41c000,0x402210).unwrap();
        let manager_epilog_bytes=bytes_hex("8b4df064890d00000000595f5e5bc9c3");
        let mut wrong_manager_epilog=manager_epilog_bytes.clone();wrong_manager_epilog[11]=0x5e;
        assert!(EpilogProof::prove(Region{bytes:&wrong_manager_epilog,origin:0x40bf50},&manager_p).is_err());
        let manager_e=EpilogProof::prove(Region{bytes:&manager_epilog_bytes,origin:0x40bf50},&manager_p).unwrap();
        let move_graph=crate::crt_stream_ir::Graph::decode_linear_fragment(&[0x8b,0xc6],0x40bf4e).unwrap();
        let move_body=crate::crt_stream_emit::emit_body_with_exit(&move_graph,|_,_|Err("no return-move call".into()),&Default::default(),1,|_,_|Err("no FS".into()),|_,_|Ok(String::new()),|_,_|Ok(None),Some(0x40bf50)).unwrap();
        let inherited_registered=crate::crt_standard_handles_tests::inherited_source_for(Some("let n=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;allocations.push(n);registered_allocation(rt,child,e,init)"));
        let allocator_native=format!("{} {}",crate::crt_standard_handles_tests::errno_source(),crate::crt_standard_handles_tests::allocator_source_with_errno(Some("let ptd=rt.resolve_absolute(0x6ff0,CrtRegionKind::ThreadData)?;errno_routed(rt,child,|_|Ok(CrtValue::Pointer(ptd)))")));
        let manager_native=format!("{}\n{}\n{}\nfn manager_return_move(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{move_body}}}",crate::crt_standard_handles_tests::manager_source_with_allocator(Some("let errno=rt.resolve_absolute(0x7000,CrtRegionKind::ThreadData)?;let mut requests=vec![];let result=calloc_original(rt,child,init,true,Some(false),if available{(1,1)}else{(0,usize::MAX)},true,errno,&mut requests,&mut |_,_|Err(\"startup handler not bound\"))?;if let CrtValue::Pointer(p)=result{*allocated=Some(p);}Ok(result)")),manager_p.emit("manager_prolog").unwrap(),manager_e.emit("manager_epilog").unwrap());
        let cxx_unwind=crate::crt_cxx_unwind::source(&bytes_hex(crate::crt_cxx_unwind::WRAPPER),&bytes_hex(crate::crt_cxx_unwind::BODY),&super::tests::bytes(),&bytes_hex(crate::crt_cxx_unwind::SCOPE)).unwrap();
        let mut cxx_cached=format!("{}\n{}\n{}\n{}",crate::crt_cxx_unwind::cached_source().unwrap(),crate::crt_cxx_record::delivered_common_source().unwrap(),crate::crt_cxx_record::delivered_prefix_source().unwrap(),crate::crt_cxx_record::invocation_source());
        cxx_cached.push_str(&crate::crt_cxx_record::delivered_lazy_source().unwrap());
        cxx_cached.push_str(&crate::crt_cxx_ptd::lazy_extension_source().unwrap().replace("Err(\"C++ required PTD termination effect unbound\")", "allocation(rt,cpu,0x4077ff)"));
        cxx_cached.push_str(&crate::crt_abort::registered_entry_source().unwrap());
        cxx_cached.push_str(&crate::crt_exit::source(&bytes_hex(crate::crt_exit::PREFIX),&bytes_hex(crate::crt_exit::FRONT),&bytes_hex(crate::crt_exit::RETURN)).unwrap());
        cxx_cached.push_str(&crate::crt_abort::locked_source(&super::tests::bytes()).unwrap());
        // errno_routed_call is already provided by the allocator composition.
        cxx_cached.push_str(&crate::crt_heap_free::fixture_source_without_errno());
        cxx_cached.push_str(&crate::crt_standard_handles_tests::live_allocator_with_lookup_source());
        let cxx_action=crate::crt_cxx_unwind::action_source([&bytes_hex(crate::crt_cxx_unwind::BRIDGE),&bytes_hex(crate::crt_cxx_unwind::NOTICE_PREFIX),&bytes_hex(crate::crt_cxx_unwind::NOTICE_TAIL),&bytes_hex(crate::crt_cxx_record::ACTION)]).unwrap();
        let cxx_state=crate::crt_cxx_record::unwind_state_source(&bytes_hex(crate::crt_cxx_record::UNWIND_STATE_GET),&bytes_hex(crate::crt_cxx_record::UNWIND_STATE_SET)).unwrap();
        let cxx_record=crate::crt_cxx_record::emit(&bytes_hex(crate::crt_cxx_record::METADATA),0x41b42c,&bytes_hex(crate::crt_cxx_record::UNWIND_MAP),0x41b41c).unwrap();
        let mut cxx_owner=crate::crt_ptd::helper_source(&bytes_hex(crate::crt_ptd::PROLOG),0x414268,&bytes_hex(crate::crt_ptd::EPILOG),0x414254,0x41c000).unwrap();
        cxx_owner.push_str(crate::crt_ptd::shared_chain_source());
        cxx_owner.push_str(&crate::crt_ptd::registered_source(&bytes_hex(crate::crt_ptd::GETTER)).unwrap());
        if let Ok(path)=std::env::var("W2L_EH4_EVIDENCE"){std::fs::write(std::path::Path::new(&path).join("cxx-unwind-connected.rs"),format!("{cxx_unwind}\n{cxx_cached}\n{cxx_action}")).unwrap();}
        let cxx_data=format!("fn abort_scope_bytes()->Vec<u8>{{vec!{:?}}}fn cxx_meta_bytes()->Vec<u8>{{vec!{:?}}}fn cxx_map_bytes()->Vec<u8>{{vec!{:?}}}fn cxx_scope_bytes()->Vec<u8>{{vec!{:?}}}",bytes_hex(crate::crt_abort::SCOPE),bytes_hex(crate::crt_cxx_record::METADATA),bytes_hex(crate::crt_cxx_record::UNWIND_MAP),bytes_hex(crate::crt_cxx_unwind::SCOPE));
        let cookie_code=handler_bytes("cookie-initializer.bin",crate::crt_cookie_init::CODE);
        let cookie_source=crate::crt_cookie_init::source(&cookie_code).unwrap();
        let entropy_code=handler_bytes("cookie-entropy.bin",crate::crt_cookie_init::ENTROPY_CODE);
        let entropy_imports:Vec<(u32,String,String)>=if let Ok(path)=std::env::var("W2L_EH4_CODE"){
            std::fs::read_to_string(std::path::Path::new(&path).join("cookie-imports.txt")).unwrap().lines().map(|line|{let parts:Vec<_>=line.split_whitespace().collect();assert_eq!(parts.len(),3);(u32::from_str_radix(parts[0],16).unwrap(),parts[1].into(),parts[2].into())}).collect()
        }else{crate::crt_cookie_init::IMPORTS.iter().map(|(at,name)|(*at,"kernel32.dll".into(),(*name).into())).collect()};
        let cookie_connected=crate::crt_cookie_init::connected_source(&cookie_code).unwrap();
        let entropy_source=crate::crt_cookie_init::entropy_source(&entropy_code,&entropy_imports).unwrap();
        let startup_regions:Vec<_>=crate::crt_startup_entry::REGIONS.iter().map(|(name,_,literal)|handler_bytes(&format!("{name}.bin"),literal)).collect();
        let startup_helper_bytes=handler_bytes("helper.bin",&super::tests::bytes().iter().map(|b|format!("{b:02x}")).collect::<String>());
        let module_regions:Vec<_>=crate::crt_startup_modules::REGIONS.iter().map(|(name,_,literal)|handler_bytes(&format!("startup-{name}.bin"),literal)).collect();let module_source=crate::crt_startup_modules::source(&module_regions).unwrap();
        let startup_source=crate::crt_startup_entry::source(&startup_regions,&startup_helper_bytes).unwrap();
        let feature_code=handler_bytes("startup-cpu-tail.bin",crate::crt_cpu_features::CODE);let feature_import: (u32,String,String)=if let Ok(path)=std::env::var("W2L_EH4_CODE"){let text=std::fs::read_to_string(std::path::Path::new(&path).join("startup-cpu-import.txt")).unwrap();let parts:Vec<_>=text.split_whitespace().collect();assert_eq!(parts.len(),3);(u32::from_str_radix(parts[0],16).unwrap(),parts[1].into(),parts[2].into())}else{(0x41501c,"kernel32.dll".into(),"IsProcessorFeaturePresent".into())};
        let feature_source=crate::crt_cpu_features::source(&feature_code,&feature_import).unwrap();


        let source = format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{fixture}\n{printf_native}\n{printf_entry_native}\n{printf_native_map}\n{completion_live}\n{main_initial_live}\n{main_initial_map}\n{initial_raise_types}\n{initial_raise_init}\n{initial_raise}\n{initial_raise_map}\n{file_scope}\n{context_types}\n{context_check}\n{scope_store}\n{permuted_store}\n{install}\n{handler_prolog}\n{filter_source}\n{false_filter_source}\n{normalizer_source}\n{guard_source}\n{header_source}\n{prefix_normalizer}\n{prefix_front}\n{guard_prefix}\n{prefix_caller}\n{bridge_native}\n{local_types}\n{owned_types}\n{local_source}\n{callback_source}\n{finally_source}\n{finally_cases}\n{original_local_store}\n{main_init}\n{inner_init}\n{owned_filter}\n{owned_bridge}\n{main_filter_bytes}\n{activation}\n{owned_prolog}\n{owned_prefix}\n{delivery_prefix}
{inner_data}
{unwind_caller}
{stack_source}
{native_loop}\n{owned_header}\n{owned_scope_store}\n{owned_permuted_store}\n{global_source}\n{delivery_source}\n{tail_source}\n{owned_search}
{live_return}\n{live_return_map}\n{post_global}\n{code_data}\n{path_edges}\n{prefix_metadata}\nfn raise_site()->CrtNormalRaiseSite{{{{{raise}}}}}\n{allocator_native}\n{manager_native}\n{inherited_registered}\n{cxx_unwind}\n{cxx_cached}\n{cxx_action}\n{cxx_state}\n{cxx_record}\n{cxx_owner}\n{cxx_data}\n{cookie_source}\n{cookie_connected}\n{entropy_source}\n{startup_source}\n{module_source}\n{feature_source}\n{CASES}",
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

#[test]
fn allocation_manager_registers_and_retires_original_eh4_under_startup_authority() {
    run("manager");
}

#[test]
fn inherited_producer_calls_original_manager_with_live_eh4_registration() {
    run("manager-inherited");
}

#[test]
fn original_cxx_unwind_registers_eh4_preserves_pending_action_and_counter_failures() {
    run("cxx-unwind");
}

#[test]
fn original_cxx_unwind_uses_cached_ptd_getter_without_loader_authority() {
    run("cxx-cached-unwind");
}

#[test]
fn suspended_delivery_lends_only_child_frames_and_rejects_stale_or_parent_authority() {
    run("delivery-children");
}

#[test]
fn original_cached_unwind_executes_under_pending_delivery_child_authority() {
    run("delivery-cached-unwind");
}

#[test]
fn original_common_dispatcher_calls_registered_unwind_under_pending_delivery() {
    run("dispatcher-delivery-unwind");
}

#[test]
fn original_prefix_produces_dispatcher_metadata_under_pending_delivery() {
    run("prefix-delivery-unwind");
}

#[test]
fn original_cxx_invocation_binds_pending_event_and_captured_objects() {
    run("bound-cxx-invocation");
}

#[test]
fn original_cxx_fs_views_do_not_establish_shared_thread_chain_selection() {
    run("chain-ownership-gap");
}

#[test]
fn original_cxx_and_eh4_share_live_lifo_thread_head() {
    run("shared-chain");
}

#[test]
fn shared_chain_rechecks_owner_at_original_fs_effect() {
    run("chain-effect-lifetime");
}

#[test]
fn original_empty_search_executes_guard_and_protected_return() {
    run("live-return");
}

#[test]
fn original_return_receipt_advances_only_matching_live_registration() {
    run("ordered-search");
}

#[test]
fn original_ucrt_errno_registration_preserves_pending_delivery_ownership() {
    run("registered-errno");
}

#[test]
fn original_abort_locked_query_owns_frame_lock_and_failure_effects() {
    run("abort-locked");
}

#[test]
fn original_inline_exit_record_preserves_registry_return_and_failure_lifetimes() {
    run("inline-exit");
}

#[test]
#[ignore = "requires unchanged authored PE; passed in recorded-input replay"]
fn canonical_image_cookie_and_original_record_initialization_compose() {
    run("canonical-startup");
}
