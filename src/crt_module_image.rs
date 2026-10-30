//! Checked image views and original managed-image query. Main-module selection
//! and the API outcome remain explicit component inputs, not loader proof.
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
struct CrtModuleImage{module:CrtModule,root:CrtPointer}
impl CrtModuleImage{
 // An initialization contract supplies the mapped image and executable-module
 // acquisition; matching numbers alone cannot create either capability.
 fn bind(rt:&CrtStreamRuntime,init:CrtInitialization,module:CrtModule,root:CrtPointer)->Result<Self,&'static str>{
  rt.initialization(init)?;rt.module_identity(module)?;
  if root.kind!=CrtRegionKind::Module||root.address()!=module.handle||root.base!=root.address()||root.owner!=guest_memory::Owner::Module(rt.owner)||!rt.regions.iter().any(|r|r.pointer==root){return Err("module image root/owner/extent");}
  rt.valid(root,root.size)?;Ok(Self{module,root})
 }
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{rt.module_identity(self.module)?;rt.valid(self.root,self.root.size)?;Ok(())}
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
