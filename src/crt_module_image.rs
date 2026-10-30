//! Checked image views and original managed-image query. Canonical process
//! ownership is distinct from acquired references; mapped-image production is
//! still a bootstrap input, not proof of complete loader effects.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const QUERY:&str="6a00ff150850410085c07433b94d5a000066390875298b483c03c8813950450000751cb80b0100006639411875118379740e760b83b9e8000000000f95c0c332c0c3";
pub(crate) fn source(bytes: &[u8]) -> Result<String, String> {
    if bytes != crate::crt_ptd::raw(QUERY) {
        return Err("managed image query code binding".into());
    }
    let graph = Graph::decode(bytes, 0x401d51)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |pc, target| {
            if pc != 0x401d53 || target != Target::Import(0x415008) {
                return Err("managed image query import".into());
            }
            Ok("cpu.call_activation(rt,0x401d59,4,|rt,c|{let sp=CrtCpu::pointer(c.r[4])?;if rt.load(rt.offset(sp,4)?,32)?!=CrtValue::scalar(0){return Err(\"main module query argument\");}let value=if let Some(view)=image{view.validate(rt)?;CrtValue::Pointer(view.root)}else{CrtValue::scalar(0)};rt.last_os_error=None;c.clobber(value);c.finish_pop(rt,4)})?;".into())
        },
        &Default::default(),
        64,
        |_, _| Err("managed image query FS".into()),
        |pc, _| {
            Ok(if pc >= 0x401d59 {
                "if let Some(view)=image{view.validate(rt)?;}"
            } else {
                ""
            }
            .into())
        },
        |_, _| Ok(None),
    )?;
    Ok(format!("{TYPES}\nfn managed_image_query(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,image:Option<&CrtModuleImage>)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}"))
}
const TYPES: &str = r#"
enum CrtImageOwner{Acquired(CrtModule),Process(CrtProcessImage)}
struct CrtModuleImage{owner:CrtImageOwner,root:CrtPointer}
impl CrtModuleImage{
 // An initialization contract supplies the mapped image and executable-module
 // acquisition; matching numbers alone cannot create either capability.
 fn bind(rt:&CrtStreamRuntime,init:CrtInitialization,module:CrtModule,root:CrtPointer)->Result<Self,&'static str>{
  rt.initialization(init)?;rt.module_identity(module)?;
  if root.kind!=CrtRegionKind::Module||root.address()!=module.handle||root.base!=root.address()||root.owner!=guest_memory::Owner::Module(rt.owner)||!rt.regions.iter().any(|r|r.pointer==root){return Err("module image root/owner/extent");}
  rt.valid(root,root.size)?;Ok(Self{owner:CrtImageOwner::Acquired(module),root})
 }
 fn main(rt:&CrtStreamRuntime)->Result<Self,&'static str>{let token=rt.main_image.ok_or("main image bootstrap authority missing")?;let root=rt.process_image(token)?;Ok(Self{owner:CrtImageOwner::Process(token),root})}
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{match self.owner{CrtImageOwner::Acquired(module)=>rt.module_identity(module)?,CrtImageOwner::Process(token)=>{if rt.process_image(token)?!=self.root{return Err("main image view alias");}}}rt.valid(self.root,self.root.size)?;Ok(())}
}
"#;
#[test]
fn original_managed_query_checks_live_image_and_header_paths() {
    let extra = source(&crate::crt_ptd::raw(QUERY)).expect("original query lowering");
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..15{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let(module,reference)=rt.module_acquire_result(init,"independent image",0x500000).unwrap();
 let mut bytes=vec![0u8;512];bytes[..2].copy_from_slice(b"MZ");bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());bytes[0x80..0x84].copy_from_slice(b"PE\0\0");bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());bytes[0xf4..0xf8].copy_from_slice(&15u32.to_le_bytes());bytes[0x168..0x16c].copy_from_slice(&u32::from(mode==1).to_le_bytes());
 if mode==2{bytes[0]=0;}if mode==3{bytes[0x80]=0;}if mode==4{bytes[0x98]=0;}if mode==5{bytes[0xf4]=14;}if mode==6{bytes[0x3c..0x40].copy_from_slice(&0xfffffff0u32.to_le_bytes());}if mode==7{bytes.truncate(64);}
 let p=rt.map_region(0x500000,bytes.len()as u32,CrtRegionKind::Module,Some(&bytes)).unwrap();let view=CrtModuleImage::bind(&rt,init,module,p).unwrap();
 if mode==8{rt.module_release_result(init,reference,true).unwrap();}if mode==9{rt.memory.release(p.cap,p.owner).unwrap();}if mode==10{assert!(CrtModuleImage::bind(&rt,init,module,rt.offset(p,4).unwrap()).is_err());}
 if mode==11{rt.module_release_result(init,reference,true).unwrap();let(_,_) =rt.module_acquire_result(init,"independent image",0x500000).unwrap();}
 if mode==12{let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();other.module_acquire_result(oi,"independent image",0x500000).unwrap();assert_eq!(view.validate(&other),Err("CRT module owner/generation/lifetime"));}
 let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,800).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();let saved=c.entry;rt.last_os_error=Some(79);
 if mode==14{rt.store(rt.offset(p,0x168).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 let got=managed_image_query(&mut rt,&mut c,if mode==13{None}else{Some(&view)});
 if matches!(mode,6|7|8|9|11|14){assert_eq!(got,Err(match mode{6|7=>"CRT pointer complete range/identity",8=>"CRT unloaded module",9=>"CRT pointer lifetime",11=>"CRT module owner/generation/lifetime",14=>"CRT unknown scalar bits observed",_=>unreachable!()}),"unsafe image mode {mode}");assert!(!c.returned);if mode==8{assert_eq!(got,Err("CRT unloaded module"));}if mode==11{assert_eq!(got,Err("CRT module owner/generation/lifetime"));}assert_eq!(rt.last_os_error,if matches!(mode,8|9|11){Some(79)}else{None});}
 else{let value=got.expect("valid query path must return");let(bits,known)=CrtCpu::bits(value).unwrap();assert_eq!(known&255,255);assert_eq!(bits&255,u32::from(mode==1));assert!(c.returned);for i in [3,5,6,7]{assert_eq!(c.r[i],saved[i]);}assert_eq!(rt.last_os_error,None);}
}
"#,
        "module-image-query",
    );
    let b = crate::crt_ptd::raw(QUERY);
    for i in 0..b.len() {
        let mut m = b.clone();
        m[i] ^= 1;
        assert!(source(&m).is_err());
    }
}
#[test]
fn word_memory_compare_reads_sixteen_bits_across_register_choices() {
    let mut extra = String::new();
    for reg in [0u8, 1, 3, 6] {
        let code = [0x66, 0x39, 0x02 + reg * 8, 0xc3];
        let g = Graph::decode(&code, 0x440000).unwrap();
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |_, _| Err("no word calls".into()),
            &Default::default(),
            8,
        )
        .unwrap();
        extra.push_str(&format!("fn cmp_{reg}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for(reg,run)in [(0,cmp_0 as fn(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>),(1,cmp_1),(3,cmp_3),(6,cmp_6)]{for (word,low,expected)in [(0u16,0,(false,true,false,false)),(1,0,(false,false,false,false)),(0xffff,0,(false,false,true,false)),(0,1,(true,false,true,false)),(0x8000,1,(false,false,false,true)),(0x7fff,0xffff,(true,false,true,true))]{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();let data=rt.map_region(0x7000,2,CrtRegionKind::Module,Some(&word.to_le_bytes())).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,200).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[2]=CrtValue::Pointer(data);c.r[reg]=CrtValue::scalar(0xbeef0000|low);c.entry=c.r;run(&mut rt,&mut c).unwrap();assert_eq!((c.flags.cf.unwrap(),c.flags.zf.unwrap(),c.flags.sf.unwrap(),c.flags.of.unwrap()),expected);assert_eq!(c.r[reg],CrtValue::scalar(0xbeef0000|low));
}}
"#,
        "word-compare",
    );
}
#[test]
fn process_image_owns_mapping_once_across_threads_and_module_releases() {
    let extra = source(&crate::crt_ptd::raw(QUERY)).unwrap();
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..12{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let mut bytes=vec![0u8;512];bytes[..2].copy_from_slice(b"MZ");bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());bytes[0x80..0x84].copy_from_slice(b"PE\0\0");bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());bytes[0xf4]=15;
 if mode==10{assert!(rt.bootstrap_main_image(init,0x8000,&bytes).is_err());assert!(rt.main_image.is_none());}
 let token=rt.bootstrap_main_image(init,0x500000,&bytes).unwrap();let mut view=CrtModuleImage::main(&rt).unwrap();assert!(rt.modules.is_empty());assert!(rt.module_references.is_empty());
 assert_eq!(rt.bootstrap_main_image(init,0x600000,&bytes),Err("CRT process image already issued/closed"));assert_eq!(rt.main_image,Some(token));
 if mode==1{rt.thread+=1;}if mode==2{rt.bind_fiber(rt.thread).unwrap();}
 if mode==3{let(_,r)=rt.module_acquire_result(init,"owned reference to same base",0x500000).unwrap();rt.module_release_result(init,r,true).unwrap();assert!(rt.modules.is_empty());}
 if mode==4{rt.closed=true;}if mode==5{rt.owner+=1;}if mode==6{rt.memory.release(token.root.cap,token.root.owner).unwrap();}
 if mode==7{view.root=rt.subrange(token.root,64).unwrap();}
 if mode==8{let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();assert_eq!(other.process_image(token),Err("CRT process image owner/lifetime"));}
 if mode==9{assert_eq!(rt.store(rt.offset(token.root,0x168).unwrap(),32,CrtValue::scalar(1)),Err("CRT storage write"));assert_eq!(rt.load(rt.offset(token.root,0x168).unwrap(),32).unwrap(),CrtValue::scalar(0));}
 if mode==11{let bad=CrtProcessImage{generation:token.generation+1,..token};assert_eq!(rt.process_image(bad),Err("CRT process image owner/lifetime"));}
 if matches!(mode,4|5|6|7){assert_eq!(view.validate(&rt),Err(match mode{4|5=>"CRT process image owner/lifetime",6=>"CRT pointer lifetime",7=>"main image view alias",_=>unreachable!()}));continue;}
 view.validate(&rt).unwrap();let stack=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,400).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();let v=managed_image_query(&mut rt,&mut c,Some(&view)).unwrap();assert_eq!(CrtCpu::bits(v).unwrap().0&255,0);assert!(c.returned);assert_eq!(rt.main_image,Some(token));assert!(rt.module_references.is_empty());
}
"#,
        "process-image",
    );
}

#[test]
fn pe32_sections_initialize_original_query_without_temporary_module_owner() {
    let extra = source(&crate::crt_ptd::raw(QUERY)).unwrap();
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
fn put(b:&mut[u8],at:usize,v:u32){b[at..at+4].copy_from_slice(&v.to_le_bytes());}
fn image()->Vec<u8>{
 let mut b=vec![0u8;0x800];b[..2].copy_from_slice(b"MZ");put(&mut b,0x3c,0x80);b[0x80..0x84].copy_from_slice(b"PE\0\0");b[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());b[0x86]=3;b[0x94]=224;b[0x96]=2;b[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
 for(at,v)in [(0xa8,0x1000),(0xb4,0x500000),(0xb8,4096),(0xbc,512),(0xd0,0x4000),(0xd4,512),(0xf4,16)]{put(&mut b,at,v);}b[0xdc]=3;
 for(i,ch)in [0x60000020,0x40000040,0xc0000040].into_iter().enumerate(){let at=0x178+i*40;for(off,v)in [(8,0x300),(12,((i+1)*4096)as u32),(16,512),(20,((i+1)*512)as u32),(36,ch)]{put(&mut b,at+off,v);}}
 b[0x200]=0xc3;b[0x400]=91;b[0x600]=29;b
}
for mode in 0..29{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let mut b=image();
 match mode{
  1=>b.truncate(511),2=>b.truncate(0x700),3=>put(&mut b,0x178+12,0x2000),4=>put(&mut b,0x178+36,0xe0000020),5=>put(&mut b,0x178+20,0x400),6=>put(&mut b,0xd0,0x2000),7=>{put(&mut b,0xb4,0xffff0000);put(&mut b,0xd0,0x20000);},8=>put(&mut b,0x178+8,u32::MAX),9=>put(&mut b,0x178+40+12,0x1000),10=>b[0xdc]=1,11=>put(&mut b,0xa8,0x3000),12=>put(&mut b,0x3c,u32::MAX),13=>put(&mut b,0xd4,0x2000),14=>put(&mut b,0x178+36,0x64000020),15=>{rt.map_region(0x503000,512,CrtRegionKind::Module,Some(&vec![99;512])).unwrap();},16=>put(&mut b,0x178+40+12,0x1001),17=>put(&mut b,0x178+24,1),18=>put(&mut b,0x178+16,513),26=>put(&mut b,0x168,1),27=>{put(&mut b,0x178+80+16,0);put(&mut b,0x178+80+20,0);},28=>put(&mut b,0x178+40+36,0x42000040),_=>{}}
 if (1..=18).contains(&mode){let before=rt.regions.len();let serial=rt.serial;assert_eq!(rt.bootstrap_pe32(init,&b),Err("CRT PE32 mapping contract"),"mode {mode}");assert!(rt.main_image.is_none());assert!(rt.main_image_regions.is_empty());assert_eq!(rt.regions.len(),before);assert_eq!(rt.serial,serial);assert!(rt.memory.read(0x500000,1).is_err());if mode==15{assert_eq!(rt.memory.read(0x503000,1).unwrap(),[99]);}continue;}
 let token=rt.bootstrap_pe32(init,&b).expect("valid preferred-base PE mapping");let view=CrtModuleImage::main(&rt).unwrap();assert_eq!(rt.main_image_regions.len(),4);assert!(rt.module_references.is_empty());
 let text=rt.process_image_pointer(token,0x501000,1).unwrap();let ro=rt.process_image_pointer(token,0x502000,1).unwrap();let data=rt.process_image_pointer(token,0x503000,1).unwrap();
 assert_eq!(rt.load(ro,8).unwrap(),CrtValue::scalar(91));assert_eq!(rt.load(rt.offset(data,512).unwrap(),8).unwrap(),CrtValue::scalar(0));assert_eq!(rt.store(text,8,CrtValue::scalar(0)),Err("CRT storage write"));assert_eq!(rt.store(ro,8,CrtValue::scalar(0)),Err("CRT storage write"));rt.store(data,8,CrtValue::scalar(77)).unwrap();assert_eq!(rt.load(data,8).unwrap(),CrtValue::scalar(77));assert_eq!(rt.store(view.root,8,CrtValue::scalar(0)),Err("CRT storage write"));assert_eq!(rt.load(data,8).unwrap(),CrtValue::scalar(77));assert!(rt.process_image_pointer(token,0x500200,1).is_err());assert!(rt.process_image_pointer(token,0x5012ff,2).is_err());
 if mode==19{rt.thread+=1;rt.bind_fiber(rt.thread).unwrap();}if mode==20{let(_,reference)=rt.module_acquire_result(init,"separate acquired ref",0x500000).unwrap();rt.module_release_result(init,reference,true).unwrap();}
 if mode==21{rt.memory.release(data.cap,data.owner).unwrap();assert!(view.validate(&rt).is_err());continue;}
 if mode==22{let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();assert!(other.process_image(token).is_err());continue;}
 if mode==23{rt.closed=true;assert!(view.validate(&rt).is_err());continue;}
 if mode==24{let old=rt.load(ro,8).unwrap();assert!(rt.map_region(ro.base,ro.size,CrtRegionKind::Module,None).is_err());assert_eq!(rt.load(ro,8).unwrap(),old);}
 if mode==25{b[0x400]=0;assert_eq!(rt.load(ro,8).unwrap(),CrtValue::scalar(91));}
 let stack=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,400).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let v=managed_image_query(&mut rt,&mut cpu,Some(&view)).expect("original query on mapped PE headers");assert_eq!(CrtCpu::bits(v).unwrap().0&255,u32::from(mode==26));assert!(cpu.returned);assert!(rt.bootstrap_pe32(init,&b).is_err());
}
// Exhaustion after mapping the header must roll back only the new image.
for budget in [true,false]{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,if budget{768}else{65536}).unwrap();
 if !budget{for i in 0..62{rt.map_region(0x700000+i*4096,4,CrtRegionKind::Module,Some(&[41;4])).unwrap();}}
 let before=rt.regions.len();assert_eq!(rt.bootstrap_pe32(init,&image()),Err("CRT PE32 mapping contract"));assert!(rt.main_image.is_none());assert_eq!(rt.regions.len(),before);assert!(rt.memory.read(0x500000,1).is_err());if !budget{assert_eq!(rt.memory.read(0x700000,1).unwrap(),[41]);}
}

"#,
        "pe32-process-sections",
    );
    // Optional recorded original input. Reported separately from the authored
    // mapping tests; no fresh Windows result or whole-PE execution is inferred.
    if let Ok(path) = std::env::var("W2L_PE_MAPPING_INPUT") {
        let file = std::fs::read(path).expect("recorded PE mapping input");
        let body = format!(
            r#"let file:&[u8]=&{file:?};
let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,1048576).unwrap();
let token=rt.bootstrap_pe32(init,file).expect("original PE initial mapping");
let view=CrtModuleImage::main(&rt).unwrap();
let code=rt.process_image_pointer(token,0x401d51,66).unwrap();
let cookie=rt.process_image_pointer(token,0x41c000,4).unwrap();let old=rt.load(cookie,32).unwrap();rt.store(cookie,32,CrtValue::scalar(73)).unwrap();assert_eq!(rt.load(cookie,32).unwrap(),CrtValue::scalar(73));rt.store(cookie,32,old).unwrap();assert!(rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&[0;4])).is_err());
assert_eq!(rt.memory.read(code.address(),66).unwrap(),&{:?});
let stack=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,400).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();
let got=managed_image_query(&mut rt,&mut cpu,Some(&view)).expect("original input header query");assert_eq!(CrtCpu::bits(got).unwrap().0&255,0);assert!(cpu.returned);
"#,
            crate::crt_ptd::raw(QUERY)
        );
        crate::crt_stream_callees_tests::native(&extra, &body, "original-pe32-process-sections");
    }
}
