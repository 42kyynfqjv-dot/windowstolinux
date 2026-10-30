//! Original startup lock/FLS control with explicit external effect boundaries.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const REGIONS:&[(&str,u32,&str)]=&[
("modules",4203722,"e8e504000084c0750332c0c3e88804000084c07507e80c050000ebedb001c3"),
("locks",4204980,"5657bfeccc410033f66a0068a00f000057e86302000083c40c85c07415ff0504cd410083c61883c71883fe1872dbb001eb07e80500000032c05f5ec3"),
("destroy",4205040,"568b3504cd410085f674206bc618578db8d4cc410057ff1554504100ff0d04cd410083ef1883ee0175eb5fb0015ec3"),
("fls",4204899,"68a7284000e8d1010000a360c041005983f8ff750332c0c368c4cc410050e869020000595985c07507e805000000ebe5b001c3"),
("release",4204950,"a160c0410083f8ff741150e8d301000059c70560c04100ffffffffb001c3"),
("constructor_prefix",4205613,"558bec56687c5d410068745d4100687c5d41006a04e80cfeffff"),
];
pub(crate) fn source(regions: &[Vec<u8>]) -> Result<String, String> {
    if regions.len() != REGIONS.len() {
        return Err("startup module region count".into());
    }
    let roles = std::collections::BTreeMap::from_iter(
        [0x41c060, 0x41ccc4, 0x41ccec, 0x41cd04].map(|a| (a, "CrtRegionKind::Module".into())),
    );
    let mut out = crate::crt_cxx_lookup::mapped_source()?;
    out.push_str(crate::crt_resident_loader::TYPES);
    out.push_str(&format!(
        "fn resident_load_helper_code()->Vec<u8>{{vec!{:?}}}",
        crate::crt_ptd::raw(crate::crt_cxx_lookup::LOAD_HELPER)
    ));
    for (i, bytes) in regions.iter().enumerate() {
        let (name, origin, literal) = REGIONS[i];
        let expected: Vec<_> = literal
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        if *bytes != expected {
            return Err("startup module original code".into());
        }
        let graph = if name == "constructor_prefix" {
            let mut nodes = std::collections::BTreeMap::new();
            let mut d = iced_x86::Decoder::with_ip(
                32,
                bytes,
                u64::from(origin),
                iced_x86::DecoderOptions::NONE,
            );
            while d.can_decode() {
                let ins = d.decode();
                let at = (ins.ip32() - origin) as usize;
                nodes.insert(
                    ins.ip32(),
                    Graph::decode_instruction(&bytes[at..at + ins.len()], ins.ip32())?,
                );
            }
            Graph {
                origin,
                end: origin + bytes.len() as u32,
                nodes,
            }
        } else {
            Graph::decode(bytes, origin)?
        };
        out.push_str(&format!(
            "fn startup_{name}_code()->Vec<u8>{{vec!{bytes:?}}}"
        ));
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &graph,
            |pc, target| {
                let (Target::Direct(address) | Target::Import(address)) = target;
                let pop = if matches!(target, Target::Import(_)) {
                    4
                } else {
                    0
                };
                Ok(format!(
                    "cpu.call_activation(rt,{}, {pop},|rt,c|effects(rt,c,{pc},{address}))?;",
                    pc + graph.nodes[&pc].length
                ))
            },
            &roles,
            256,
            |_, _| Err("startup module thread effect unbound".into()),
            |_, _| Ok(String::new()),
            |_, _| Ok(None),
            if name == "constructor_prefix" {
                Some(origin + bytes.len() as u32)
            } else {
                None
            },
        )?;
        out.push_str(&format!("fn startup_{name}<F>(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,effects:&mut F)->Result<CrtValue,&'static str> where F:FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32,u32)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"startup module code read\")?!=&{bytes:?}{{return Err(\"startup module live code changed\");}}{body}}}",bytes.len(),bytes.len()));
    }
    out.push_str(r#"
// Resolve only image-owned arguments. Numeric values alone confer no export
// authority. The shared resolver still executes each load, branch and XCHG.
fn startup_resolver(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,inputs:&CrtEntropyInputs,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{
 inputs.validate(rt)?;c.validate_active(rt)?;let sp=CrtCpu::pointer(c.r[4])?;
 let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;
 // This bounded resolver admits the actual table's first five export entries;
 // other indices must establish their table extent before using this adapter.
 if index>=5{return Err("startup resolver function table bound");}
 let symbol_address=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;
 let begin=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let end=rt.load(rt.offset(sp,16)?,32)?.known_scalar()?;
 let size=end.checked_sub(begin).filter(|n|*n>0&&*n<=12&&*n%4==0).ok_or("startup resolver module list bound")?;
 let list=rt.process_image_pointer(inputs.image,begin,size)?;let symbol=rt.process_image_pointer(inputs.image,symbol_address,1)?;
 let mut name=Vec::new();let mut terminated=false;for i in 0..256{let b=rt.load(rt.offset(symbol,i)?,8)?.known_scalar()? as u8;if b==0{terminated=true;break;}name.push(b);}
 if !terminated||name.is_empty()||!name.is_ascii(){return Err("startup resolver symbol bytes");}
 for offset in (0..size).step_by(4){let module_index=rt.load(rt.offset(list,i64::from(offset))?,32)?.known_scalar()?;if module_index>=3{return Err("startup resolver module table bound");}let cell=rt.process_image_pointer(inputs.image,0x41cd08+module_index*4,4)?;startup_loader_cell(rt,inputs,cell,false)?;}
 let cell=rt.process_image_pointer(inputs.image,0x41cd14+index*4,4)?;startup_loader_cell(rt,inputs,cell,true)?;
 // Conversion of proven image addresses preserves the bytes and their owner;
 // unrelated pointers, uninitialized values and cross-section lists reject.
 for(offset,p)in [(8,symbol),(12,list),(16,rt.offset(list,i64::from(size))?)]{rt.store(rt.offset(sp,offset)?,32,CrtValue::Pointer(p))?;}
 let value=cxx_cold_resolver_mapped(rt,c,CrtResolverAccess::Initializing(inputs.init),inputs,api)?;
 if let CrtValue::Function(f)=value{rt.function_identity(f,Some(std::str::from_utf8(&name).map_err(|_|"startup symbol encoding")?))?;}
 Ok(value)
}
fn startup_loader_cell(rt:&mut CrtStreamRuntime,inputs:&CrtEntropyInputs,p:CrtPointer,function:bool)->Result<(),&'static str>{
 if let Some(&(bound,kind))=rt.loader_cells.get(&p.address()){if bound!=p||kind!=function{return Err("startup loader cell owner/kind");}rt.loader_cell_value(function,rt.load(p,32)?)?;Ok(())}
 else{rt.bind_loader_cell(inputs.init,p,function)}
}
fn startup_modules_default(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{
 startup_modules(rt,c,inputs,&mut |rt,c,pc,target|match(pc,target){
 (0x4024ca,0x4029b4)=>startup_locks(rt,c,inputs,&mut |rt,c,pc,target|match(pc,target){
 (0x4029c5,0x402c2d)=>startup_constructor_prefix(rt,c,inputs,&mut |rt,c,pc,target|{if(pc,target)!=(0x402c42,0x402a53){return Err("startup constructor resolver target");}startup_resolver(rt,c,inputs,&mut |_,_,iat|Err(match iat{0x415074=>"startup LoadLibraryExW effects unbound at 0x402b00",_=>"startup loader effects unbound"}))}),
 _=>Err("startup lock effect unbound")}),
 _=>Err("startup module effect unbound")})
}
"#);
    Ok(out)
}
#[test]
fn startup_module_graphs_bind_each_original_byte() {
    let regions: Vec<_> = REGIONS
        .iter()
        .map(|(_, _, s)| crate::crt_ptd::raw(s))
        .collect();
    source(&regions).unwrap();
    for i in 0..regions.len() {
        for j in 0..regions[i].len() {
            let mut m = regions.clone();
            m[i][j] ^= 1;
            assert_eq!(source(&m).unwrap_err(), "startup module original code");
        }
    }
}
