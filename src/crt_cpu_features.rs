//! Bounded feature-observation contract. It grants no SIMD execution capability.
use crate::crt_stream_ir::{Graph, Op};
pub(crate) const TYPES: &str = r#"
#[derive(Clone,Debug)]
// This scope includes the preceding cookie helper: legacy SSE2 must execute.
// reported_sse2 is the PF10/HAL predicate, not the legacy OS-enable bit.
struct CrtFeatureData{leaves:std::collections::BTreeMap<(u32,u32),[u32;4]>,xcr0:Option<u64>,reported_sse2:bool}
impl CrtFeatureData{
 fn leaf(&self,a:u32,c:u32)->Result<[u32;4],&'static str>{self.leaves.get(&(a,c)).copied().ok_or("CPU query outside observed leaf domain")}
 fn validate(&self)->Result<(),&'static str>{
  let zero=self.leaf(0,0)?;if zero[0]<1{return Err("CPU basic leaf unavailable");}let one=self.leaf(1,0)?;
  let sse=one[3]&(1<<25)!=0;let sse2=one[3]&(1<<26)!=0;let fxsr=one[3]&(1<<24)!=0;
  if !sse2||!sse||!fxsr{return Err("CPU SSE2 execution premise");}
  let xsave=one[2]&(1<<26)!=0;let osxsave=one[2]&(1<<27)!=0;let avx=one[2]&(1<<28)!=0;
  if avx&&(!xsave||!sse2){return Err("CPU AVX dependency");}
  if (osxsave&&!xsave)||osxsave!=self.xcr0.is_some(){return Err("CPU XSAVE/OS inconsistency");}
  if xsave{if zero[0]<0x0d{return Err("CPU XSAVE leaf unavailable");}self.leaf(0x0d,0)?;}
  if let Some(x)=self.xcr0{let supported=self.leaf(0x0d,0)?;let mask=u64::from(supported[0])|(u64::from(supported[3])<<32);if x&!mask!=0||(x&2==0){return Err("CPU XCR0 unsupported state");}if x&1==0||(x&4!=0&&x&2==0)||(x&0xe0!=0&&(x&0xe0!=0xe0||x&6!=6)){return Err("CPU XCR0 dependency");}}
  for (&(a,c),_) in &self.leaves{if a>zero[0]||!matches!((a,c),(0,0)|(1,0)|(7,0)|(7,1)|(0x0d,0)|(0x24,0)){return Err("CPU unexpected leaf domain");}}
  if zero[0]>=7{let seven=self.leaf(7,0)?;if seven[1]&(1<<5)!=0&&!avx{return Err("CPU AVX2 dependency");}if seven[1]&(1<<16)!=0&&seven[1]&(1<<5)==0{return Err("CPU AVX512 dependency");}if seven[0]>=1{self.leaf(7,1)?;}else if self.leaves.contains_key(&(7,1)){return Err("CPU subleaf domain");}}
  if zero[0]>=0x24{self.leaf(0x24,0)?;}Ok(())
 }
 fn xcr(&self,index:u32)->Result<u64,&'static str>{self.validate()?;if index!=0{return Err("CPU XCR selector unsupported");}self.xcr0.ok_or("CPU XGETBV requires OSXSAVE")}
 // Observation only: no feature mask is returned as permission to lower code.
 fn native()->Result<Self,&'static str>{
  #[cfg(all(target_os="linux",target_arch="x86_64"))]{
   use std::arch::x86_64::{__cpuid_count,_xgetbv};
   // x86-64 guarantees CPUID. Domain excludes per-thread CPUID faulting and
   // changing/heterogeneous CPU feature exposure during this bounded execution.
   let query=|a,c|{let r=unsafe{__cpuid_count(a,c)};[r.eax,r.ebx,r.ecx,r.edx]};
   let zero=query(0,0);if zero[0]<1{return Err("native CPU basic leaf");}let one=query(1,0);
   let mut leaves=std::collections::BTreeMap::from([((0,0),zero),((1,0),one)]);
   if zero[0]>=7{let seven=query(7,0);leaves.insert((7,0),seven);if seven[0]>=1{leaves.insert((7,1),query(7,1));}}
   if one[2]&(1<<26)!=0{if zero[0]<0x0d{return Err("native CPU XSAVE leaf unavailable");}leaves.insert((0x0d,0),query(0x0d,0));}
   if zero[0]>=0x24{leaves.insert((0x24,0),query(0x24,0));}
   // Never execute XGETBV without both architectural prerequisites.
   let xcr0=if one[2]&(3<<26)==3<<26{Some(unsafe{_xgetbv(0)})}else{None};
   // Linux x86-64 userspace ABI enables and preserves legacy SSE state.
   // This mapping makes no claim about old 32-bit Windows HAL detection.
   let data=Self{leaves,xcr0,reported_sse2:one[3]&(1<<26)!=0};data.validate()?;Ok(data)
  }
  #[cfg(not(all(target_os="linux",target_arch="x86_64")))]{Err("native CPU observation host unsupported")}
 }
}
struct CrtFeatureObservation{anchor:guest_memory::Capability,owner:u64,thread:u64,init:CrtInitialization,data:CrtFeatureData,host:Option<(u32,std::thread::ThreadId)>}
impl CrtFeatureObservation{
 fn bind(rt:&CrtStreamRuntime,init:CrtInitialization,data:CrtFeatureData)->Result<Self,&'static str>{rt.initialization(init)?;data.validate()?;Ok(Self{anchor:rt.anchor,owner:rt.owner,thread:rt.thread,init,data,host:None})}
 fn native(rt:&CrtStreamRuntime,init:CrtInitialization)->Result<Self,&'static str>{rt.initialization(init)?;let mut s=Self::bind(rt,init,CrtFeatureData::native()?)?;s.host=Some((std::process::id(),std::thread::current().id()));Ok(s)}
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  rt.initialization(self.init)?;if self.anchor!=rt.anchor||self.owner!=rt.owner||self.thread!=rt.thread{return Err("CPU observation owner/lifetime");}
  if let Some(host)=self.host{if host!=(std::process::id(),std::thread::current().id()){return Err("CPU observation host lifetime/thread");}}self.data.validate()
 }
 fn current_data(&self)->Result<CrtFeatureData,&'static str>{if self.host.is_some(){CrtFeatureData::native()}else{Ok(self.data.clone())}}
 fn query(&self,rt:&CrtStreamRuntime,c:&mut CrtCpu,xcr:bool)->Result<(),&'static str>{
  self.validate(rt)?;c.validate_active(rt)?;let data=self.current_data()?;
  if xcr{let v=data.xcr(c.r[1].known_scalar()?)?;c.r[0]=CrtValue::scalar(v as u32);c.r[2]=CrtValue::scalar((v>>32)as u32);}
  else{let a=c.r[0].known_scalar()?;let sub=c.r[1].known_scalar()?;let v=data.leaf(a,sub)?;c.r[0]=CrtValue::scalar(v[0]);c.r[3]=CrtValue::scalar(v[1]);c.r[1]=CrtValue::scalar(v[2]);c.r[2]=CrtValue::scalar(v[3]);}
  // Both instructions leave EFLAGS unchanged; never ABI-clobber EBX or flags.
  Ok(())
 }
 fn api(&self,rt:&mut CrtStreamRuntime,c:&mut CrtCpu)->Result<CrtValue,&'static str>{
  self.validate(rt)?;c.validate_active(rt)?;let sp=CrtCpu::pointer(c.r[4])?;
  if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?!=10{return Err("CPU feature selector unsupported");}
  // Exact bound caller only observes zero/nonzero via TEST EAX,EAX. This is
  // not a general BOOL-byte contract for other consumers.
  let result=CrtValue::scalar(u32::from(self.current_data()?.reported_sse2));rt.last_os_error=None;c.clobber(result);c.finish_pop(rt,4)
 }
}
"#;

pub(crate) fn source(bytes: &[u8], import: &(u32, String, String)) -> Result<String, String> {
    if import.0 != 0x41501c
        || !import.1.eq_ignore_ascii_case("kernel32.dll")
        || import.2 != "IsProcessorFeaturePresent"
    {
        return Err("startup CPU feature import identity".into());
    }
    if bytes != literal() {
        return Err("startup CPU classifier original code".into());
    }
    let graph = Graph::decode(bytes, 0x401ec4)?;
    let roles = std::collections::BTreeMap::from_iter(
        [0x41c050, 0x41c054, 0x41c058, 0x41ccb4, 0x41ccb8, 0x41ccbc]
            .map(|a| (a, "CrtRegionKind::Module".into())),
    );
    let body = crate::crt_stream_emit::emit_body_with_thread(
        &graph,
        |_, _| Err("CPU classifier call unsupported".into()),
        &roles,
        512,
        |_, op| match op {
            Op::CpuId => Ok("features.query(rt,cpu,false)?;".into()),
            Op::ReadXcr => Ok("features.query(rt,cpu,true)?;".into()),
            _ => Err("CPU classifier other external effect".into()),
        },
    )?;
    Ok(format!("{TYPES}\nfn startup_cpu_code()->Vec<u8>{{vec!{bytes:?}}}\nfn startup_cpu_tail(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,features:&CrtFeatureObservation)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;features.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x401ec4,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"CPU classifier code read\")?!=&{bytes:?}{{return Err(\"CPU classifier live code changed\");}}{body}}}",bytes.len(),bytes.len()))
}
fn literal() -> Vec<u8> {
    CODE.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) const CODE: &str = "85c00f84ef02000053565733c08d7dd833c9530fa28bf35b908907897704894f0889570c8b45d88b4de48945fc81f1696e65498b45e0356e74656c0bc88b45dc6a013547656e750bc8586a0059530fa28bf35b908907897704894f0889570c75398b45d825f03fff0f3dc006010074233d60060200741c3d7006020074153d50060300740e3d6006030074073d700603007507830dbccc4100018b55e033db33ff8955f4837dfc07895dec895de80f8c870000006a075833c9530fa28bf35b908d5dd88903897304894b0889530c8b5ddc8b45e4895df88945ecf7c3000200007407830dbccc410002837dd8017c246a075833c941530fa28bf35b908d5dd88903897304894b0889530c8b45e48b5df88945e86a24583945fc7c1d33c98d7dd8530fa28bf35b908b5df88907897704894f0889570c8b7ddc8b55f4a158c041008b0d50c0410083c8028b3554c0410083e1fec705b8cc410001000000a358c04100890d50c04100893554c04100f7c2000010000f847b01000083c804c705b8cc410002000000a358c0410083e1efb800000018890d50c0410023d0893554c041003bd00f854b01000033c90f01d08945f033f68955f48b45f08b4df483e00623ce83f8060f852a0100003bce0f8522010000a158c0410083c808c705b8cc410003000000a358c04100f6c32074798b0d54c0410083c820a358c04100ba000003d0a150c0410023da83e0fdc705b8cc410005000000a350c04100890d54c041003bda754e8b45f0bae00000008b4df423c223ce3bc275303bce752ca150c04100830d58c041004083e0db8b0d54c04100c705b8cc410006000000a350c04100890d54c04100eb0b8b0d54c04100a150c04100f745ec00008000741025fffffffe890d54c04100a350c04100f745e80000080074608b45f0bae00000008b4df423c223ce3bc2754d3bce75498bc733c9c1ef1025ff00040083e706a3b4cc410081cf29000001f7d1230d54c04100f7d7233d50c04100893d50c04100890d54c041003c01760f83e7bf890d54c04100893d50c041005f5e5b33c0c9c3";

#[test]
fn classifier_binds_original_bytes_and_queries_require_explicit_effect_contract() {
    let bytes = literal();
    let import = (
        0x41501c,
        "kernel32.dll".into(),
        "IsProcessorFeaturePresent".into(),
    );
    source(&bytes, &import).expect("complete scalar classifier lowers");
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 1;
        assert_eq!(
            source(&b, &import).unwrap_err(),
            "startup CPU classifier original code"
        );
    }
    for mode in 0..3 {
        let mut bad = import.clone();
        match mode {
            0 => bad.0 += 4,
            1 => bad.1 = "foreign.dll".into(),
            _ => bad.2.push('_'),
        };
        assert_eq!(
            source(&bytes, &bad).unwrap_err(),
            "startup CPU feature import identity"
        );
    }
    for code in [&[0x0f, 0xa2, 0xc3][..], &[0x0f, 0x01, 0xd0, 0xc3][..]] {
        let graph = Graph::decode(code, 0x450000).unwrap();
        assert!(crate::crt_stream_emit::emit_body(
            &graph,
            |_, _| Err("call".into()),
            &Default::default(),
            8
        )
        .is_err());
    }
    for code in [
        &[0xf3, 0x0f, 0xa2][..],
        &[0x66, 0x0f, 0xa2][..],
        &[0x0f, 0x01, 0xd1][..],
        &[0xc5, 0xfc, 0x58, 0xc1][..],
    ] {
        assert!(Graph::decode_instruction(code, 0x450000).is_err());
    }
}
#[test]
fn cpu_observations_reject_inconsistent_os_state_and_unknown_queries() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let basic=CrtFeatureData{leaves:std::collections::BTreeMap::from([((0,0),[1,0,0,0]),((1,0),[0,0,0,7<<24])]),xcr0:None,reported_sse2:true};
basic.validate().unwrap();let mut unreported=basic.clone();unreported.reported_sse2=false;unreported.validate().unwrap();assert_ne!(unreported.leaf(1,0).unwrap()[3]&(1<<26),0);assert_eq!(basic.xcr(0),Err("CPU XGETBV requires OSXSAVE"));assert!(basic.leaf(7,0).is_err());
for mode in 0..9{let mut d=basic.clone();if mode==4||mode==5{d.leaves.get_mut(&(0,0)).unwrap()[0]=0x0d;d.leaves.insert((7,0),[0;4]);d.leaves.insert((0x0d,0),[0xe7,0,0,0]);}match mode{
 0=>{d.leaves.get_mut(&(1,0)).unwrap()[3]&=!(1<<25);},
 1=>{d.leaves.get_mut(&(1,0)).unwrap()[3]&=!(1<<26);},
 2=>{d.leaves.get_mut(&(1,0)).unwrap()[2]=1<<27;},
 3=>{d.xcr0=Some(7);},
 4=>{d.leaves.get_mut(&(1,0)).unwrap()[2]=3<<26;d.xcr0=Some(5);},
 5=>{d.leaves.get_mut(&(1,0)).unwrap()[2]=3<<26;d.xcr0=Some(0x27);},
 6=>{d.leaves.get_mut(&(0,0)).unwrap()[0]=7;d.leaves.insert((7,0),[0,1<<5,0,0]);},
 7=>{d.leaves.insert((7,1),[0;4]);},_=>{d.leaves.get_mut(&(1,0)).unwrap()[2]=1<<28;}}
 assert_eq!(d.validate(),Err(["CPU SSE2 execution premise","CPU SSE2 execution premise","CPU XSAVE/OS inconsistency","CPU XSAVE/OS inconsistency","CPU XCR0 unsupported state","CPU XCR0 dependency","CPU AVX2 dependency","CPU unexpected leaf domain","CPU AVX dependency"][mode]),"inconsistent case {mode}");
}
let mut d=basic.clone();d.leaves.get_mut(&(0,0)).unwrap()[0]=0x0d;d.leaves.insert((7,0),[0;4]);d.leaves.insert((0x0d,0),[0xe7,0,0,0]);d.leaves.get_mut(&(1,0)).unwrap()[2]=7<<26;d.xcr0=Some(7);d.validate().unwrap();assert_eq!(d.xcr(0),Ok(7));assert_eq!(d.xcr(1),Err("CPU XCR selector unsupported"));let mut unsupported=d.clone();unsupported.xcr0=Some(0x107);assert_eq!(unsupported.validate(),Err("CPU XCR0 unsupported state"));let mut disabled=d.clone();disabled.reported_sse2=false;disabled.xcr0=Some(1);assert_eq!(disabled.validate(),Err("CPU XCR0 unsupported state"));let mut partial=d.clone();partial.xcr0=Some(0x27);assert_eq!(partial.validate(),Err("CPU XCR0 dependency"));
#[cfg(all(target_os="linux",target_arch="x86_64"))]{let host=CrtFeatureData::native().unwrap();host.validate().unwrap();assert!(host.reported_sse2);assert_eq!(host.leaf(1,0).unwrap()[3]&(1<<26),1<<26);}
"#,
        "cpu-feature-data",
    );
}

#[test]
fn cpu_queries_preserve_flags_and_reject_stale_or_pointer_authority_before_writes() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,0x4000,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x3000).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();let mut c=CrtCpu::new(sp,17).unwrap();
let d=CrtFeatureData{leaves:std::collections::BTreeMap::from([((0,0),[0x0d,0x11223344,0x55667788,0x99aabbcc]),((1,0),[0,0,7<<26,7<<24]),((7,0),[0;4]),((0x0d,0),[7,0,0,0])]),xcr0:Some(7),reported_sse2:true};let f=CrtFeatureObservation::bind(&rt,init,d).unwrap();
c.r[0]=CrtValue::scalar(0);c.r[1]=CrtValue::scalar(0);c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:None,of:Some(true)};let saved=c.r;
f.query(&rt,&mut c,false).unwrap();assert_eq!([c.r[0],c.r[3],c.r[1],c.r[2]],[0x0d,0x11223344,0x55667788,0x99aabbcc].map(CrtValue::scalar));for i in 4..8{assert_eq!(c.r[i],saved[i]);}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(false),None,Some(true)));
c.r[1]=CrtValue::scalar(0);let b=c.r[3];f.query(&rt,&mut c,true).unwrap();assert_eq!(c.r[0],CrtValue::scalar(7));assert_eq!(c.r[2],CrtValue::scalar(0));assert_eq!(c.r[1],CrtValue::scalar(0));assert_eq!(c.r[3],b);assert_eq!(c.flags.cf,Some(true));
for mode in 0..6{c.r[0]=CrtValue::scalar(1);c.r[1]=CrtValue::scalar(0);match mode{0=>c.r[0]=CrtValue::Pointer(sp),1=>c.r[0]=CrtValue::Scalar{bits:1,known:0xff},2=>c.r[1]=CrtValue::scalar(99),3=>c.returned=true,4=>rt.thread+=1,_=>rt.end_initialization(init).unwrap()};let before=c.r;let got=f.query(&rt,&mut c,false);assert_eq!(got,Err(["CRT scalar knowledge/type","CRT scalar knowledge/type","CPU query outside observed leaf domain","CRT active caller lifetime/return authority","CRT initialization owner/lifetime","CRT initialization owner/lifetime"][mode]),"query case {mode}");assert_eq!(c.r,before);if mode==3{c.returned=false;}if mode==4{rt.thread-=1;}}
"#,
        "cpu-feature-ownership",
    );
}

#[test]
fn code_observation_checks_execute_permission_bounds_and_identity() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
let mut m=guest_memory::Space::new(8192,8).unwrap();
let owner=guest_memory::Owner::Module(1);
let rx=m.map(0x1000,32,owner,guest_memory::Permissions::READ_EXECUTE,true).unwrap();
let ro=m.map(0x2000,32,owner,guest_memory::Permissions::READ,true).unwrap();
let rw=m.map(0x3000,32,owner,guest_memory::Permissions::READ_WRITE,true).unwrap();
assert_eq!(m.validate_executable(rx,owner,0x1000,32),Ok(()));
assert_eq!(m.validate_executable(ro,owner,0x2000,4),Err(guest_memory::Fault::Permission));
assert_eq!(m.validate_executable(rw,owner,0x3000,4),Err(guest_memory::Fault::Permission));
assert!(m.validate_executable(rx,owner,0x101f,2).is_err());
assert!(m.validate_executable(rx,owner,0x2000,4).is_err());
assert!(m.validate_executable(rx,guest_memory::Owner::Module(2),0x1000,4).is_err());
m.release(rx,owner).unwrap();assert!(m.validate_executable(rx,owner,0x1000,4).is_err());
"#,
        "cpu-code-permissions",
    );
}

#[test]
fn feature_api_rejects_unknown_selector_without_clobbering_prior_state() {
    crate::crt_stream_callees_tests::native(
        TYPES,
        r#"
for mode in 0..3{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,0x4000,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x3000).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();let mut c=CrtCpu::new(sp,17).unwrap();c.return_pop=4;
 let data=CrtFeatureData{leaves:std::collections::BTreeMap::from([((0,0),[1,0,0,0]),((1,0),[0,0,0,7<<24])]),xcr0:None,reported_sse2:true};let features=CrtFeatureObservation::bind(&rt,init,data).unwrap();
 rt.store(rt.offset(sp,4).unwrap(),32,match mode{0=>CrtValue::scalar(9),1=>CrtValue::Scalar{bits:10,known:0xff},_=>CrtValue::Pointer(sp)}).unwrap();rt.last_os_error=Some(73);let before=c.r;
 assert_eq!(features.api(&mut rt,&mut c),Err(if mode==0{"CPU feature selector unsupported"}else{"CRT scalar knowledge/type"}));assert_eq!(c.r,before);assert_eq!(rt.last_os_error,Some(73));assert!(!c.returned);assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(17));
}
"#,
        "cpu-feature-api",
    );
}
