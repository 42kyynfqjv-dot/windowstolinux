//! Bounded guest FNCLEX state semantics and independent instruction conformance.
//! No host floating-point instruction is used by the generated implementation.
#[test]
fn fnclex_requires_an_effect_contract_and_rejects_waiting_or_other_forms() {
    use crate::crt_stream_ir::{Graph, Op};
    let g = Graph::decode(&[0xdb, 0xe2, 0xc3], 0x500000).unwrap();
    assert_eq!(g.nodes[&0x500000].op, Op::X87ClearExceptions);
    assert!(crate::crt_stream_emit::emit_body(
        &g,
        |_, _| Err("call".into()),
        &Default::default(),
        8
    )
    .is_err());
    assert!(Graph::decode_linear_fragment(&[0xdb, 0xe2], 0x500000).is_err());
    for raw in [
        &[0x9b, 0xdb, 0xe2][..],
        &[0x66, 0xdb, 0xe2][..],
        &[0xf0, 0xdb, 0xe2][..],
        &[0xf3, 0xdb, 0xe2][..],
        &[0xdb, 0xe3][..],
    ] {
        assert!(
            Graph::decode_instruction(raw, 0x500000).is_err(),
            "unsupported {raw:x?}"
        );
    }
}
#[test]
fn fnclex_preserves_top_and_unaffected_state_but_forgets_condition_codes() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
let mut cases=0u64;
for control in [0x037fu16,0x0340,0x0360,0xffff]{
 for status in 0..=u16::MAX{
  let mut original=CrtX87State::unknown();original.status=CrtX87Word{bits:status,known:0xffff};original.control=CrtX87Word{bits:control,known:0xffff};original.tag=CrtX87Word{bits:0x6c39,known:0xffff};original.opcode=CrtX87Word{bits:0x7ab,known:0x7ff};original.ip=[CrtValue::scalar(0x12345678),CrtValue::scalar(0x1b)];original.dp=[CrtValue::scalar(0x87654321),CrtValue::scalar(0x23)];original.mxcsr=CrtValue::scalar(0x9fc5);for(i,r)in original.registers.iter_mut().enumerate(){r.bits=[(i+1)as u8;10];r.known=[0xff;10];}
  let mut changed=original;changed.fnclex();
  for bit in 0..16{let mask=1u16<<bit;if bit<=7||bit==15{assert_eq!(changed.status.bits&mask,0);assert_ne!(changed.status.known&mask,0);}else if matches!(bit,8|9|10|14){assert_eq!(changed.status.known&mask,0);}else{assert_eq!(changed.status.bits&mask,status&mask);assert_ne!(changed.status.known&mask,0);}}
  let result=changed.status;changed.status=original.status;assert_eq!(changed,original,"unaffected control/tag/data/pointers/MXCSR");changed.status=result;let first=changed;changed.fnclex();assert_eq!(changed,first,"architectural repetition is allowed and idempotent");cases+=1;
 }
}
assert_eq!(cases,262144);
for known in [0u16,0x80ff,0x3800,0x4700,0x1357,0xaaaa,0xffff]{let mut s=CrtX87State::unknown();s.status=CrtX87Word{bits:known,known};s.fnclex();for bit in 0..16{let mask=1u16<<bit;let expected=if bit<=7||bit==15{true}else if matches!(bit,8|9|10|14){false}else{known&mask!=0};assert_eq!(s.status.known&mask!=0,expected);assert_eq!(s.status.bits&mask!=0,(11..=13).contains(&bit)&&known&mask!=0);}}
"#,
        "x87-knowledge",
    );
}
#[test]
fn fnclex_context_rejects_expiry_cross_thread_fiber_and_rebinding_before_effects() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
for mode in 0..10{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
 if mode==0{assert_eq!(rt.clear_x87_exceptions(init),Err("CRT x87 profile unbound"));assert!(rt.x87.is_none());assert_eq!(rt.configure_x87(init,"legacy-DOS"),Err("CRT x87 profile unsupported/already bound"));assert!(rt.x87.is_none());continue;}
 rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();assert_eq!(rt.x87.unwrap().state,CrtX87State::unknown());rt.clear_x87_exceptions(init).unwrap();let mut x=rt.x87.unwrap();x.state.status=CrtX87Word{bits:0xffff,known:0xffff};rt.x87=Some(x);let before=rt.x87;
 match mode{1=>rt.end_initialization(init).unwrap(),2=>rt.owner+=1,3=>rt.thread+=1,4=>{rt.bind_fiber(rt.thread).unwrap();},5=>{rt.memory.release(rt.anchor,rt.file_view.owner).unwrap();},6=>{assert_eq!(rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE),Err("CRT x87 profile unsupported/already bound"));},7=>{rt.x87.as_mut().unwrap().init.serial+=1;},8=>{let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x9000,65536).unwrap();rt.x87.as_mut().unwrap().anchor=other.anchor;},_=>{}}
 let after_mutation=rt.x87;let result=rt.clear_x87_exceptions(init);
 if mode==6||mode==9{result.expect("valid repeated instruction");assert_eq!(rt.x87.unwrap().state.status,CrtX87Word{bits:0x3800,known:0xb8ff});}else{assert_eq!(result,Err(match mode{1|3=>"CRT initialization owner/lifetime",5=>"CRT initialization storage lifetime",2|7|8=>"CRT x87 owner/lifetime",4=>"CRT x87 stationary fiber changed",_=>unreachable!()}));assert_eq!(rt.x87,after_mutation,"failure must not clear pending flags");}if mode==6{assert_eq!(before.unwrap().state.status.bits,0xffff);}
}
// An already-bound stationary fiber's retirement/reuse cannot inherit its FPU.
let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let old=rt.bind_fiber(rt.thread).unwrap();rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();rt.clear_x87_exceptions(init).unwrap();rt.retire_fiber(old).unwrap();rt.bind_fiber(rt.thread).unwrap();let before=rt.x87;assert_eq!(rt.clear_x87_exceptions(init),Err("CRT x87 stationary fiber changed"));assert_eq!(rt.x87,before);
"#,
        "x87-lifetime",
    );
}
#[test]
fn native_fnclex_observations_preserve_host_state_and_compare_only_defined_bits() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
#[cfg(all(target_arch="x86_64",target_os="linux"))]{
 #[repr(C,align(16))]struct Fx([u8;512]);let mut rows=Vec::new();
 for cw in [0x037fu16,0x0340,0x0360]{for sw in [0u16,1,2,4,8,16,32,0x80c1,0xffff,0x7f00,0x2800,0xb8ff,0xc7ff,0x1234]{
  let(mut saved,mut seeded,mut after)=(Fx([0;512]),Fx([0;512]),Fx([0;512]));let mut env=[0u8;28];
  // One authored assembly block: no Rust FP can interleave with a deliberately
  // pending unmasked exception. Restore the complete host FXSAVE state before
  // any assertion, allocation or formatting. No kernel/security setting changes.
  unsafe{std::arch::asm!("fxsave64 [{saved}]","fnstenv [{env}]","mov word ptr [{env}],{cw:x}","mov word ptr [{env}+4],{sw:x}","fldenv [{env}]","fxsave64 [{seeded}]","fnclex","fxsave64 [{after}]","fxrstor64 [{saved}]",saved=in(reg)saved.0.as_mut_ptr(),env=in(reg)env.as_mut_ptr(),seeded=in(reg)seeded.0.as_mut_ptr(),after=in(reg)after.0.as_mut_ptr(),cw=in(reg)cw,sw=in(reg)sw,options(nostack));}
  let word=|b:&[u8],n|u16::from_le_bytes(b[n..n+2].try_into().unwrap());let observed=word(&after.0,2);let initial=word(&seeded.0,2);
  assert_eq!(observed&0x80ff,0);assert_eq!(observed&0x3800,initial&0x3800);assert_eq!(word(&after.0,0),word(&seeded.0,0));assert_eq!(after.0[4],seeded.0[4]);assert_eq!(&after.0[6..28],&seeded.0[6..28]);for i in 0..8{assert_eq!(&after.0[32+i*16..42+i*16],&seeded.0[32+i*16..42+i*16]);}
  rows.push(format!("{cw:04x} {sw:04x} {initial:04x} {observed:04x}"));
 }}assert_eq!(rows.len(),42);if let Ok(path)=std::env::var("W2L_X87_EVIDENCE"){std::fs::write(std::path::Path::new(&path).join("native-fnclex-observations.txt"),rows.join("\n")+"\n").unwrap();}
}
"#,
        "x87-native-observation",
    );
}
#[test]
fn fnclex_emission_preserves_integer_state_and_cannot_replay_a_return() {
    use crate::crt_stream_ir::{Graph, Op};
    let g = Graph::decode(&[0xdb, 0xe2, 0xc3], 0x500000).unwrap();
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |_, _| Err("call".into()),
        &Default::default(),
        8,
        |_, op| {
            assert_eq!(*op, Op::X87ClearExceptions);
            Ok("cpu.validate_active(rt)?;rt.clear_x87_exceptions(init)?;".into())
        },
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
    )
    .unwrap();
    let source=format!("fn original_fnclex(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native(
        &source,
        r#"
for mode in 0..7{let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();let mut c=CrtCpu::new(sp,17).unwrap();c.r[0]=CrtValue::scalar(7);c.xmm=[[CrtValue::scalar(0x7fc01234);4];8];c.flags=if mode==6{CrtFlags::unknown()}else{CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)}};
 if mode!=1{rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();rt.x87.as_mut().unwrap().state.status=CrtX87Word{bits:0xffff,known:0xffff};}
 if mode==2{rt.end_initialization(init).unwrap();}if mode==3{rt.tags.insert(sp.address(),CrtValue::ProtectedReturn(18));}if mode==4{rt.x87.as_mut().unwrap().owner+=1;}
 let before=rt.x87;let regs=c.r;let xmm=c.xmm;let flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);let result=original_fnclex(&mut rt,&mut c,init);
 if matches!(mode,0|5|6){assert_eq!(result,Ok(CrtValue::scalar(7)));assert!(c.returned);assert_eq!(rt.x87.unwrap().state.status,CrtX87Word{bits:0x3800,known:0xb8ff});let after=rt.x87;assert_eq!(original_fnclex(&mut rt,&mut c,init),Err("CRT active caller lifetime/return authority"));assert_eq!(rt.x87,after);}else{assert_eq!(result,Err(match mode{1=>"CRT x87 profile unbound",2=>"CRT initialization owner/lifetime",3=>"CRT active caller lifetime/return authority",4=>"CRT x87 owner/lifetime",_=>unreachable!()}));assert!(!c.returned);assert_eq!(rt.x87,before);assert_eq!(c.r,regs);}
 assert_eq!(c.xmm,xmm);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),flags);for r in [0,1,2,3,5,6,7]{assert_eq!(c.r[r],regs[r]);}
}
"#,
        "x87-emission",
    );
}

#[test]
fn fp_control_forms_keep_wait_and_store_distinct_and_require_effect_binding() {
    use crate::crt_stream_ir::{Graph, Op};
    let g = Graph::decode(
        &[
            0x9b, 0xd9, 0x7d, 0xf8, 0xd9, 0x6d, 0xfc, 0x0f, 0xae, 0x5d, 0xf0, 0xc3,
        ],
        0x500000,
    )
    .unwrap();
    assert_eq!(g.nodes[&0x500000].length, 1);
    assert_eq!(g.nodes[&0x500000].op, Op::X87Wait);
    assert!(matches!(g.nodes[&0x500001].op, Op::X87StoreControl(_)));
    assert!(matches!(g.nodes[&0x500004].op, Op::X87LoadControl(_)));
    assert!(matches!(g.nodes[&0x500007].op, Op::StoreMxcsr(_)));
    assert!(crate::crt_stream_emit::emit_body(
        &g,
        |_, _| Err("call".into()),
        &Default::default(),
        32
    )
    .is_err());
    for b in [
        &[0x9b][..],
        &[0xd9, 0x7d, 0xf8],
        &[0xd9, 0x6d, 0xfc],
        &[0x0f, 0xae, 0x5d, 0xf0],
    ] {
        assert!(Graph::decode_linear_fragment(b, 0x500000).is_err());
    }
    for b in [
        &[0xf0, 0xd9, 0x7d, 0xf8][..],
        &[0x66, 0xd9, 0x6d, 0xfc],
        &[0xf3, 0x0f, 0xae, 0x5d, 0xf0],
        &[0x64, 0xd9, 0x7d, 0xf8],
        &[0x0f, 0xae, 0x55, 0xf0],
    ] {
        assert!(
            Graph::decode_instruction(b, 0x500000).is_err(),
            "unsupported {b:x?}"
        );
    }
}
#[test]
fn owned_fp_wait_store_load_preserves_unknowns_and_failure_order() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let p=rt.map_region(0x20000,16,if mode==20{CrtRegionKind::Module}else{CrtRegionKind::Stack},Some(&[0xa5;16])).unwrap();rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();rt.clear_x87_exceptions(init).unwrap();
 rt.x87.as_mut().unwrap().state.control=CrtX87Word{bits:0x037f,known:0xffff};
 let original=rt.x87.unwrap();
 match mode {
  0=>{rt.wait_x87(init).unwrap();rt.store_x87_control(init,p).unwrap();assert_eq!(rt.load(p,16),Ok(CrtValue::scalar(0x37f)));assert_eq!(rt.memory.read(p.address()+2,14).unwrap(),&[0xa5;14]);},
  1=>{rt.x87.as_mut().unwrap().state.status=CrtX87Word{bits:0x0041,known:0xffff};rt.wait_x87(init).expect("masked exception");assert_eq!(rt.x87.unwrap().state.status.known,0xb8ff);},
  2=>{let x=rt.x87.as_mut().unwrap();x.state.status=CrtX87Word{bits:0x8081,known:0xffff};x.state.control.bits&=!1;let before=rt.x87;assert_eq!(rt.wait_x87(init),Err("CRT pending x87 exception delivery unsupported"));assert_eq!(rt.x87,before);rt.store_x87_control(init,p).expect("nonwaiting store despite pending exception");assert_eq!(rt.load(p,16),Ok(CrtValue::scalar(0x37e)));},
  3=>{let x=rt.x87.as_mut().unwrap();x.state.status=CrtX87Word::unknown();x.state.control=CrtX87Word::unknown();let before=rt.x87;assert_eq!(rt.wait_x87(init),Err("CRT x87 pending exception knowledge"));assert_eq!(rt.x87,before);},
  4=>{rt.x87.as_mut().unwrap().state.control=CrtX87Word{bits:0x5a5a,known:0x0f0f};rt.store_x87_control(init,p).unwrap();assert_eq!(rt.load(p,16),Ok(CrtValue::Scalar{bits:0xa0a,known:0xffff0f0f}));assert!(rt.memory.read(p.address(),2).is_err());},
  5=>{let q=rt.offset(p,15).unwrap();let before=rt.x87;assert!(rt.store_x87_control(init,q).is_err());assert_eq!(rt.x87,before);assert_eq!(rt.memory.read(p.address(),16).unwrap(),&[0xa5;16]);},
  6=>{rt.store(p,32,CrtValue::ProtectedReturn(37)).unwrap();let before=rt.x87;assert!(rt.store_x87_control(init,p).is_err());assert_eq!(rt.x87,before);assert_eq!(rt.load(p,32),Ok(CrtValue::ProtectedReturn(37)));},
  7=>{rt.store(p,16,CrtValue::scalar(0x023f)).unwrap();rt.load_x87_control(init,p).unwrap();assert_eq!(rt.x87.unwrap().state.control,CrtX87Word{bits:0x27f,known:0xffff});rt.wait_x87(init).unwrap();},
  8=>{rt.store(p,16,CrtValue::scalar(0x037e)).unwrap();rt.x87.as_mut().unwrap().state.status=CrtX87Word{bits:1,known:0xffff};let before=rt.x87;assert_eq!(rt.load_x87_control(init,p),Err("CRT FLDCW nonclean exception state unsupported"));assert_eq!(rt.x87,before);},
  9=>{rt.store(p,16,CrtValue::Scalar{bits:0,known:0xffff0000}).unwrap();let before=rt.x87;assert!(rt.load_x87_control(init,p).is_err());assert_eq!(rt.x87,before);},
  10=>{rt.store(p,16,CrtValue::scalar(0x17f)).unwrap();let before=rt.x87;assert_eq!(rt.load_x87_control(init,p),Err("CRT FLDCW reserved control unsupported"));assert_eq!(rt.x87,before);},
  11=>{rt.configure_mxcsr_profile(init,"w2l-enabled-sse-no-daz-v1").unwrap();rt.x87.as_mut().unwrap().state.mxcsr=CrtValue::scalar(0x1f85);let before=rt.x87;rt.store_mxcsr(init,p).unwrap();assert_eq!(rt.load(p,32),Ok(CrtValue::scalar(0x1f85)));assert_eq!(rt.x87,before);},
  12=>{rt.configure_mxcsr_profile(init,"w2l-enabled-sse-no-daz-v1").unwrap();let before=rt.x87;assert!(rt.store_mxcsr(init,p).is_err());assert_eq!(rt.x87,before);},
  13=>{rt.configure_mxcsr_profile(init,"w2l-enabled-sse-no-daz-v1").unwrap();rt.x87.as_mut().unwrap().state.mxcsr=CrtValue::scalar(0x1fc0);let before=rt.x87;assert_eq!(rt.store_mxcsr(init,p),Err("CRT MXCSR reserved bits unsupported"));assert_eq!(rt.x87,before);},
  14=>{rt.end_initialization(init).unwrap();assert!(rt.wait_x87(init).is_err());assert!(rt.store_x87_control(init,p).is_err());assert!(rt.load_x87_control(init,p).is_err());assert!(rt.store_mxcsr(init,p).is_err());},
  15=>{rt.bind_fiber(rt.thread).unwrap();let before=rt.x87;assert!(rt.wait_x87(init).is_err());assert!(rt.store_x87_control(init,p).is_err());assert_eq!(rt.x87,before);},
  16=>{rt.memory.release(p.cap,p.owner).unwrap();let before=rt.x87;assert!(rt.store_x87_control(init,p).is_err());assert!(rt.load_x87_control(init,p).is_err());assert_eq!(rt.x87,before);},
  17=>{rt.x87.as_mut().unwrap().state.status=CrtX87Word{bits:0xffff,known:0xffff};rt.store_x87_control(init,p).unwrap();let x=rt.x87.unwrap();assert_eq!(x.state.status.known,0xb8ff);assert_eq!(x.state.status.bits,0xb8ff);assert_eq!(x.state.control,original.state.control);},
  18=>{rt.x87.as_mut().unwrap().owner+=1;let before=rt.x87;assert!(rt.wait_x87(init).is_err());assert!(rt.store_x87_control(init,p).is_err());assert_eq!(rt.x87,before);},
  19=>{rt.x87.as_mut().unwrap().state.mxcsr=CrtValue::scalar(0x1f80);assert_eq!(rt.store_mxcsr(init,p),Err("CRT MXCSR enabled-state profile unbound"));},
  20=>{let old=rt.map_region(0x30000,16,CrtRegionKind::Stack,Some(&[0;16])).unwrap();rt.memory.protect_data_with_old((p.cap,p.owner,p.address(),16),2,(old.cap,old.owner,old.address())).unwrap();let before=rt.x87;assert!(rt.store_x87_control(init,p).is_err());assert_eq!(rt.x87,before);assert_eq!(rt.memory.read(p.address(),16).unwrap(),&[0xa5;16]);},
  21=>{rt.store(p,32,CrtValue::Pointer(p)).unwrap();let before=rt.x87;assert!(rt.load_x87_control(init,p).is_err());assert_eq!(rt.x87,before);},
  22=>{rt.store_x87_control(init,p).unwrap();rt.store(rt.offset(p,2).unwrap(),16,CrtValue::scalar(0x17f)).unwrap();assert!(rt.load_x87_control(init,rt.offset(p,2).unwrap()).is_err());assert_eq!(rt.load(p,16),Ok(CrtValue::scalar(0x37f)));},
  _=>unreachable!()
 }
}
for mode in 0..23{one(mode);}
"#,
        "fp-owned-effects",
    );
}
#[test]
fn emitted_wait_fault_precedes_store_fault_and_retains_instruction_address() {
    use crate::crt_stream_ir::Graph;
    let g = Graph::decode(&[0x9b, 0xd9, 0x39, 0xc3], 0x500000).unwrap();
    let body = crate::crt_stream_emit::emit_body_with_thread(
        &g,
        |_, _| Err("call".into()),
        &Default::default(),
        16,
        |pc, op| crate::crt_stream_emit::fp_effect(pc, op, &Default::default(), "init"),
    )
    .unwrap();
    let extra=format!("fn run_fp(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut cpu=CrtCpu::new(sp,77).unwrap();cpu.r[0]=CrtValue::scalar(7);cpu.r[1]=CrtValue::Pointer(if mode>=2{sp}else{rt.offset(stack,32).unwrap()});rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();rt.clear_x87_exceptions(init).unwrap();rt.x87.as_mut().unwrap().state.control=CrtX87Word{bits:0x37f,known:0xffff};if mode==1{let x=rt.x87.as_mut().unwrap();x.state.control.bits&=!1;x.state.status=CrtX87Word{bits:0x8081,known:0xffff};}if mode==3{rt.x87.as_mut().unwrap().state.status=CrtX87Word{bits:0x4700,known:0xffff};}let before=rt.x87;let regs=cpu.r;let got=run_fp(&mut rt,&mut cpu,init);if mode==0{assert_eq!(got,Ok(CrtValue::scalar(7)));assert!(cpu.returned);assert_eq!(rt.fp_boundary,Some(0x500001));assert_eq!(rt.load(rt.offset(stack,32).unwrap(),16),Ok(CrtValue::scalar(0x37f)));let after=rt.x87;assert!(run_fp(&mut rt,&mut cpu,init).is_err());assert_eq!(rt.x87,after);}else{assert!(got.is_err(),"must reject mode {mode}");assert!(!cpu.returned);assert_eq!(rt.fp_boundary,Some(if mode==1{0x500000}else{0x500001}));if mode==3{let mut changed=before.unwrap();changed.state.status=CrtX87Word{bits:0,known:0xb8ff};assert_eq!(rt.x87,Some(changed),"successful WAIT undefined flags survive failed store");}else{assert_eq!(rt.x87,before);}assert_eq!(cpu.r,regs);}}
for mode in 0..4{one(mode);}
"#,
        "fp-instruction-order",
    );
}

#[test]
fn native_control_observations_match_owned_clean_effects_without_host_state_leak() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[cfg(all(target_arch="x86_64",target_os="linux"))]{
 #[repr(C,align(16))]struct Fx([u8;512]);
 #[inline(never)]fn one(cw:u16,mx:u32){
  let mut saved=Fx([0;512]);let mut output=0u16;let mut status=0u16;let mut stored_mx=0u32;
  unsafe{std::arch::asm!("fxsave64 [{saved}]","fnclex","fldcw [{input}]","ldmxcsr [{mx}]","fwait","fnstcw [{output}]","fnstsw [{status}]","stmxcsr [{stored_mx}]","fxrstor64 [{saved}]",saved=in(reg)saved.0.as_mut_ptr(),input=in(reg)&cw,mx=in(reg)&mx,output=in(reg)&mut output,status=in(reg)&mut status,stored_mx=in(reg)&mut stored_mx,options(nostack));}
  let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let p=rt.map_region(0x20000,16,CrtRegionKind::Stack,None).unwrap();rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();rt.clear_x87_exceptions(init).unwrap();rt.configure_mxcsr_profile(init,"w2l-enabled-sse-no-daz-v1").unwrap();rt.x87.as_mut().unwrap().state.mxcsr=CrtValue::scalar(mx);rt.store(p,16,CrtValue::scalar(u32::from(cw))).unwrap();rt.load_x87_control(init,p).unwrap();rt.wait_x87(init).unwrap();rt.store_x87_control(init,rt.offset(p,2).unwrap()).unwrap();rt.store_mxcsr(init,rt.offset(p,4).unwrap()).unwrap();assert_eq!(rt.load(rt.offset(p,2).unwrap(),16).unwrap().known_scalar().unwrap(),u32::from(output));assert_eq!(rt.x87.unwrap().state.status.bits&0x80ff,status&0x80ff);assert_eq!(rt.load(rt.offset(p,4).unwrap(),32).unwrap().known_scalar().unwrap(),stored_mx);
 }
 for cw in[0x003f,0x023f,0x033f,0x073f,0x0b3f,0x0f3f]{for mx in[0x1f80,0x7fbf]{one(cw,mx);}}
}
"#,
        "fp-native-control",
    );
}

#[test]
fn explicit_initial_fp_policy_produces_only_controls_and_rejects_rebinding() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[inline(never)] fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
 if mode==1{rt.end_initialization(init).unwrap();}if mode==2{rt.configure_x87(init,CrtStreamRuntime::X87_PROFILE).unwrap();let x=rt.x87.as_mut().unwrap();x.state.control=CrtX87Word{bits:0x077e,known:0xffff};x.state.status=CrtX87Word{bits:0x8081,known:0xffff};}
 let before=rt.x87;let result=rt.initialize_native_fp_profile(init,if mode==3{"host-default"}else{CrtStreamRuntime::NATIVE_FP_PROFILE});
 if mode==0{result.unwrap();let x=rt.x87.unwrap();let mut expected=CrtX87State::unknown();expected.control=CrtX87Word{bits:0x027f,known:0xffff};expected.mxcsr=CrtValue::scalar(0x1f80);assert_eq!(x.state,expected);assert_eq!(rt.wait_x87(init),Err("CRT x87 exception summary unsupported"));rt.clear_x87_exceptions(init).unwrap();rt.wait_x87(init).unwrap();let current=rt.x87;assert!(rt.initialize_native_fp_profile(init,CrtStreamRuntime::NATIVE_FP_PROFILE).is_err());assert_eq!(rt.x87,current);rt.bind_fiber(rt.thread).unwrap();assert_eq!(rt.wait_x87(init),Err("CRT x87 stationary fiber changed"));}else{assert!(result.is_err(),"invalid profile mode{mode}");assert_eq!(rt.x87,before);}
}
for mode in 0..4{one(mode);}
"#,
        "initial-fp-profile",
    );
}
