//! Original second FLS initializer and protected-cache resolver composition.
use crate::crt_stream_ir::Target;
pub(crate) fn source() -> Result<String, String> {
    let mut out = String::from(
        r#"
fn startup_fiber_api(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,i:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,iat:u32)->Result<CrtValue,&'static str>{
 i.validate(rt)?;c.validate_active(rt)?;
 if iat==0x415044{let v=rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{bits:0,known:0});c.clobber(v);return c.finish(rt);}
 if iat==0x4150b0{return c.virtual_protect_call(rt,i.image);}
 let p=platform.ok_or("startup second FLS native profile absent")?;
 if iat==0x41509c{let f=p.fls.ok_or("startup second FLS provider absent")?;return p.fls_call(rt,c,i.init,i.image,f);}
 if iat==0x4150a8{return Err("startup FlsFree callback/teardown contract unbound");}
 p.call(rt,c,i.init,iat)
}
fn startup_second_bind(rt:&mut CrtStreamRuntime,c:&CrtCpu,i:&CrtEntropyInputs)->Result<(),&'static str>{
 let sp=CrtCpu::pointer(c.r[4])?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;
 let name=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let begin=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let end=rt.load(rt.offset(sp,16)?,32)?.known_scalar()?;
 let size=end.checked_sub(begin).filter(|n|*n>0&&*n<=128&&*n%4==0).ok_or("second resolver candidate range")?;
 if index>=32||begin%4!=0{return Err("second resolver index/alignment");}
 let list=rt.process_image_pointer(i.image,begin,size)?;rt.process_image_pointer(i.image,name,1)?;
 let bind=|rt:&mut CrtStreamRuntime,address:u32,function:bool|->Result<(),&'static str>{let p=rt.process_image_pointer(i.image,address,4)?;if let Some(&(q,kind))=rt.loader_cells.get(&address){if q!=p||kind!=function{return Err("second resolver cache authority");}rt.loader_cell_value(function,rt.load(p,32)?)?;}else{rt.bind_loader_cell(i.init,p,function)?;}Ok(())};
 rt.store(rt.offset(sp,8)?,32,CrtValue::Pointer(rt.process_image_pointer(i.image,name,1)?))?;rt.store(rt.offset(sp,12)?,32,CrtValue::Pointer(list))?;rt.store(rt.offset(sp,16)?,32,CrtValue::Pointer(rt.offset(list,i64::from(size))?))?;
 bind(rt,0x41e000+index*4,true)?;
 for n in 0..size/4{let module=rt.load(rt.offset(list,i64::from(n)*4)?,32)?.known_scalar()?;if module>=32{return Err("second resolver module index");}bind(rt,0x41cea8+module*4,false)?;}
 Ok(())
}
"#,
    );
    let regions:&[(&str,u32,&str)]=&[
("startup_fiber_init",4236295,"e82addffff6800a14000a230d14100e821dcffffa370c1410083f8ff750332c0c3e805ffffff85c0750950e80600000059ebebb001c3"),
("startup_fiber_selector",4227382,"a10ce0410083f8ff750433c0eb1d85c0751b6824674100681c67410068246741006a03e8e3fcffff83c41085c00f95c0c3"),
("startup_fiber_resolve",4226625,"8bff558bec515356578b7d1083c9ffeb378b078d1c85a8ce41008b339085f6740a3bf10f8590000000eb1aff3485a0614100e8960000008bf05985f6756c83c9ff8bc1870383c7043b7d1475c433f66a0ee8383f0000598d45fcbf80000000506a0457bb00e0410053ff15b050410085c074548b450885f66aff5a8d0c8500e041008bc60f44c287018d45fc506a025753ff15b050410085c0742c6a0ee8343f0000595f8bc65e5bc9c38bc6870385c0740756ff156c504100ff750c56ff15705041008bf0eb88e8f2f8ffff"),
("startup_fiber_load",4226830,"8bff558bec68000800006a00ff7508ff157450410085c07548ff154450410083f857753b6a0768185d4100ff7508e89ff9ffff83c40c85c074256a0768e0664100ff7508e889f9ffff83c40c85c0740f6a006a00ff7508ff15745041005dc333c05dc3"),
("startup_fiber_cleanup",4236349,"a170c1410083f8ff740d50e8fbdbffff830d70c14100ffb001c3"),
];
    for &(name, origin, hex) in regions {
        let bytes = crate::crt_startup_table::raw(hex);
        let g = crate::crt_startup_table::graph(&bytes, origin)?;
        let roles = std::collections::BTreeMap::from_iter(
            [0x41e00c, 0x41e000, 0x41cea8, 0x4161a0, 0x41d130, 0x41c170]
                .map(|a| (a, "CrtRegionKind::Module".into())),
        );
        let exit = if name == "startup_fiber_resolve" {
            Some(0x407f0d)
        } else {
            None
        };
        let mut body = crate::crt_stream_emit::emit_body_with_exit(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                let (callee,pop)=match t{
 Target::Direct(0x408136)=>("startup_fiber_selector",0),Target::Direct(0x407e41)=>("startup_fiber_resolve",0),Target::Direct(0x407f0e)=>("startup_fiber_load",0),Target::Direct(0x40a43d)=>("startup_fiber_cleanup",0),
 Target::Direct(0x40803c)=>return Ok(format!("cpu.call_activation(rt,{next},4,|rt,c|startup_second_thunk(rt,c,inputs,platform,effect,0x40803c,0x41509c))?;")),
 Target::Direct(0x408048)=>return Ok(format!("cpu.call_activation(rt,{next},4,|rt,c|startup_second_thunk(rt,c,inputs,platform,effect,0x408048,0x4150a8))?;")),
 Target::Direct(0x40a332)=>return Ok(format!("let e=epoch.as_deref_mut().ok_or(\"startup registered PTD acquisition context unbound at 0x40a428\")?;let p=platform.ok_or(\"startup PTD native profile absent\")?;cpu.call_activation(rt,{next},0,|rt,c|ptd_get_native_registered_with_lazy(rt,c,e,inputs,p,|rt,c|ucrt_lazy_native(rt,c,inputs,p)))?;")),
 Target::Direct(0x40bdcf)|Target::Direct(0x40be17)=>return Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,{},&mut cache_lease))?;",t==Target::Direct(0x40bdcf))),
 Target::Direct(0x4078e0)=>return Ok("return Err(\"startup second resolver retry comparison unbound\");".into()),
 Target::Direct(0x4077ff)=>return Ok("return Err(\"startup second resolver abort effect unbound\");".into()),
 Target::Import(iat)=>{let (pop,symbol)=match iat{0x415074=>(12,"LoadLibraryExW"),0x415070=>(8,"GetProcAddress"),0x41506c=>(4,"FreeLibrary"),0x415044=>(0,"GetLastError"),0x4150b0=>(16,"VirtualProtect"),_=>return Err("second resolver import".into())};return Ok(format!("rt.process_image_import(inputs.image,{iat},\"kernel32.dll\",\"{symbol}\")?;cpu.call_activation(rt,{next},{pop},|rt,c|effect(rt,c,inputs,platform,{iat}))?;"));},
 _=>return Err("second FLS call binding".into())};
                Ok(format!("cpu.call_activation(rt,{next},{pop},|rt,c|{callee}(rt,c,inputs,platform,effect))?;"))
            },
            &roles,
            4096,
            |_, _| Err("second FLS thread effect".into()),
            |pc, _| {
                Ok(
                    if name == "startup_fiber_resolve"
                        && matches!(pc, 0x407eaa | 0x407ec8 | 0x407ed2 | 0x407ede)
                    {
                        format!("let token=cache_lease.ok_or(\"resolver cache lock missing\")?;rt.check_global(token)?;{}",if pc==0x407ede{"let cache=rt.process_image_pointer(inputs.image,0x41e000,128)?;rt.memory.validate_immutable(cache.cap,cache.owner,cache.address(),128).map_err(|_|\"resolver cache not restored read-only\")?;"}else{""})
                    } else {
                        String::new()
                    },
                )
            },
            |_, _| {
                Ok(if name == "startup_fiber_resolve" {
                    Some("if cache_lease.is_some(){return Err(\"resolver return with live cache lock\");}return cpu.finish(rt);".into())
                } else {
                    None
                })
            },
            exit,
        )?;
        if let Some(exit) = exit {
            let terminal = format!("if pc=={exit}{{return Ok(cpu.r[0]);}}");
            if !body.contains(&terminal) {
                return Err("second resolver terminal binding".into());
            }
            body = body.replace(
                &terminal,
                &format!("if pc=={exit}{{return Err(\"original resolver INT3 reached\");}}"),
            );
        }
        let bind = if name == "startup_fiber_resolve" {
            "startup_second_bind(rt,cpu,inputs)?;let mut cache_lease:Option<CrtGlobalLock>=None;"
        } else if name == "startup_fiber_load" {
            "let sp=CrtCpu::pointer(cpu.r[4])?;let arg=rt.load(rt.offset(sp,4)?,32)?;let p=match arg{CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(inputs.image,bits,2)?,CrtValue::Pointer(p)=>{rt.valid(p,2)?;p},_=>return Err(\"second resolver module name authority\")};rt.store(rt.offset(sp,4)?,32,CrtValue::Pointer(p))?;"
        } else {
            ""
        };
        let params = if name == "startup_fiber_init" {
            ",mut epoch:Option<&mut NormalCallEpoch<'_>>"
        } else {
            ""
        };
        let emitted_name = if name == "startup_fiber_init" {
            "startup_fiber_init_registered"
        } else {
            name
        };
        out.push_str(&format!("fn {emitted_name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>{params},effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,Option<&CrtNativePlatform>,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"second FLS code read\")?!=&{bytes:?}{{return Err(\"second FLS code changed\");}}{bind}{body}}}",bytes.len(),bytes.len()));
    }
    out.push_str(&crate::crt_ucrt_ptd::source()?);
    out.push_str(&crate::crt_ptd::native_registered_source(
        &crate::crt_ptd::raw(crate::crt_ptd::GETTER),
    )?);
    out.push_str("fn startup_fiber_init(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,i:&CrtEntropyInputs,p:Option<&CrtNativePlatform>,effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,Option<&CrtNativePlatform>,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{startup_fiber_init_registered(rt,c,i,p,None,effect)}");
    for (name, origin, iat) in [
        ("startup_second_enter_body", 0x40bdcf, 0x41504cu32),
        ("startup_second_leave_body", 0x40be17, 0x415050),
    ] {
        let mut bytes = vec![0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6b, 0x45, 0x08, 0x18, 0x05];
        bytes.extend(0x41d150u32.to_le_bytes());
        bytes.extend([0x50, 0xff, 0x15]);
        bytes.extend(iat.to_le_bytes());
        bytes.extend([0x5d, 0xc3]);
        out.push_str(
            &crate::crt_global_lock::Proof::prove(&bytes, origin, 0x41d150, iat)?.emit(name)?,
        );
    }
    out.push_str(r#"
fn startup_second_lock(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,i:&CrtEntropyInputs,enter:bool,lease:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{
 i.validate(rt)?;c.validate_active(rt)?;let(origin,iat,symbol)=if enter{(0x40bdcf,0x41504cu32,"EnterCriticalSection")}else{(0x40be17,0x415050u32,"LeaveCriticalSection")};
 let p=rt.process_image_code(i.image,origin,23)?;let mut code=[0x8b,0xff,0x55,0x8b,0xec,0x6b,0x45,0x08,0x18,0x05,0x50,0xd1,0x41,0,0x50,0xff,0x15,0,0,0,0,0x5d,0xc3];code[17..21].copy_from_slice(&iat.to_le_bytes());
 if rt.memory.read(p.address(),23).map_err(|_|"indexed lock helper read")?!=code{return Err("indexed lock helper changed");}rt.process_image_import(i.image,iat,"kernel32.dll",symbol)?;
 if enter{if lease.is_some(){return Err("resolver duplicate lock acquisition");}startup_second_enter_body(rt,c,|rt,slot|{*lease=Some(rt.lock_global(rt.thread,slot)?);Ok(())})}
 else{startup_second_leave_body(rt,c,|rt,slot|{let token=lease.ok_or("resolver release without acquisition")?;if token.index!=slot{return Err("resolver release wrong owned slot");}rt.unlock_global(token)?;*lease=None;Ok(())})}
}
"#);
    out.push_str(r#"
fn startup_second_thunk(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,i:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,Option<&CrtNativePlatform>,u32)->Result<CrtValue,&'static str>,origin:u32,iat:u32)->Result<CrtValue,&'static str>{
 let p=rt.process_image_code(i.image,origin,12)?;let mut expected=[0x8b,0xff,0x55,0x8b,0xec,0x5d,0xff,0x25,0,0,0,0];expected[8..12].copy_from_slice(&iat.to_le_bytes());if rt.memory.read(p.address(),12).map_err(|_|"second thunk read")?!=expected{return Err("second FLS thunk changed");}
 // Original MOV/prolog/POP restores register and flag state. Execute the
 // actual stack push/pop; do not add a protected return for the tail jump.
 c.validate_active(rt)?;c.push(rt,c.r[5])?;c.r[5]=c.r[4];c.r[5]=c.pop(rt)?;
 rt.process_image_import(i.image,iat,"kernel32.dll",if iat==0x41509c{"FlsAlloc"}else{"FlsFree"})?;effect(rt,c,i,platform,iat)
}
"#);
    Ok(out)
}
#[test]
fn original_second_fls_graphs_decode() {
    source().unwrap();
}
