//! Generated arithmetic and typed operand primitives for compiled CRT graphs.
//! No instruction decoder or opcode interpreter is present in generated output.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug)]
struct CrtFlags{cf:Option<bool>,zf:Option<bool>,sf:Option<bool>,of:Option<bool>}
impl CrtFlags{fn unknown()->Self{Self{cf:None,zf:None,sf:None,of:None}}}
/// The constructor admits an explicit 32-bit cdecl function-boundary contract,
/// including DF=0. It is not a capture of unknown Windows thread flags.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtAbi{Cdecl32Forward}
struct CrtCpu{abi:CrtAbi,r:[CrtValue;8],xmm:[[CrtValue;4];8],entry:[CrtValue;8],flags:CrtFlags,return_id:u64,steps:u32,returned:bool,return_pop:u16}
impl CrtCpu{
 fn new(sp:CrtPointer,return_id:u64)->Result<Self,&'static str>{if sp.kind!=CrtRegionKind::Stack||return_id==0{return Err("CRT cpu entry authority");}let mut r=std::array::from_fn(|i|CrtValue::OpaqueSaved(i as u8));r[4]=CrtValue::Pointer(sp);Ok(Self{abi:CrtAbi::Cdecl32Forward,r,xmm:[[CrtValue::Scalar{bits:0,known:0};4];8],entry:r,flags:CrtFlags::unknown(),return_id,steps:0,returned:false,return_pop:0})}
 fn tick(&mut self,budget:u32)->Result<(),&'static str>{self.steps=self.steps.checked_add(1).ok_or("CRT instruction counter overflow")?;if self.steps>budget{return Err("CRT certified instruction bound exceeded");}Ok(())}
 fn bits(v:CrtValue)->Result<(u32,u32),&'static str>{match v{CrtValue::Module(m)=>Ok((m.handle,u32::MAX)),CrtValue::Function(f)=>Ok((f.address,u32::MAX)),CrtValue::Scalar{bits,known}=>Ok((bits,known)),CrtValue::Pointer(p)=>Ok((p.address(),u32::MAX)),CrtValue::Handle(h)=>Ok((h.handle,u32::MAX)),CrtValue::OpaqueSaved(_)=>Ok((0,0)),CrtValue::Heap(_)|CrtValue::Dispatcher(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)=>Err("CRT protected control bits")}}
 fn number(v:CrtValue)->Result<u32,&'static str>{let(b,k)=Self::bits(v)?;if k!=u32::MAX{return Err("CRT unknown scalar bits observed");}Ok(b)}
 fn pointer(v:CrtValue)->Result<CrtPointer,&'static str>{match v{CrtValue::Pointer(p)=>Ok(p),_=>Err("CRT pointer provenance")}}
 fn mask(width:u8)->Result<u32,&'static str>{match width{8=>Ok(255),16=>Ok(65535),32=>Ok(u32::MAX),_=>Err("CRT operand width")}}
 fn get(&self,index:usize,width:u8,shift:u8)->Result<CrtValue,&'static str>{let v=*self.r.get(index).ok_or("CRT register index")?;if width==32&&shift==0{return Ok(v);}let mask=Self::mask(width)?;if shift as u16+width as u16>32{return Err("CRT register slice");}let(b,k)=Self::bits(v)?;Ok(CrtValue::Scalar{bits:(b>>shift)&mask,known:((k>>shift)&mask)|!mask})}
 fn set(&mut self,index:usize,width:u8,shift:u8,v:CrtValue)->Result<(),&'static str>{if index>=8{return Err("CRT register index");}if width==32&&shift==0{self.r[index]=v;return Ok(());}let mask=Self::mask(width)?;if shift as u16+width as u16>32{return Err("CRT register slice");}let(b,k)=Self::bits(v)?;let(old,known)=if matches!(self.r[index],CrtValue::Heap(_)){(0,0)}else{Self::bits(self.r[index])?};let field=mask<<shift;self.r[index]=CrtValue::Scalar{bits:(old&!field)|((b&mask)<<shift),known:(known&!field)|((k&mask)<<shift)};Ok(())}
 /// x86 computes the effective address modulo 2^32. Only an already owned
 /// base (or an explicitly bound image displacement) can supply authority;
 /// wrapping index arithmetic never manufactures a different capability.
 fn address(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtPointer,&'static str>{
  let p=self.form_address(rt,base,index,scale,displacement,absolute)?;rt.identity_range(p,0)?;Ok(p)
 }
 fn form_address(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtPointer,&'static str>{
  if !matches!(scale,1|2|4|8){return Err("CRT address scale");}
  let (p,extra)=if let Some(b)=base{
   match self.r[b]{
    CrtValue::Pointer(p)=>{let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT address adds two pointers");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,displacement.wrapping_add(extra))},
    scalar=>{let b=Self::number(scalar)?;if let Some(kind)=absolute{let p=rt.resolve_absolute(displacement,kind)?;let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT image index adds pointer");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,b.wrapping_add(extra))}
      else if let Some(i)=index{let p=Self::pointer(self.r[i])?;if scale!=1{return Err("CRT scaled pointer index");}(p,b.wrapping_add(displacement))}
      else{return Err("CRT scalar address lacks provenance");}}
   }
  }else{let p=rt.resolve_absolute(displacement,absolute.ok_or("CRT unbound absolute role")?)?;let extra=if let Some(i)=index{if matches!(self.r[i],CrtValue::Pointer(_)){return Err("CRT absolute index adds pointer");}Self::number(self.r[i])?.wrapping_mul(scale)}else{0};(p,extra)};
  let address=p.address().wrapping_add(extra);rt.effective_address(p,address)
 }
 fn push(&mut self,rt:&mut CrtStreamRuntime,v:CrtValue)->Result<(),&'static str>{let p=rt.offset(Self::pointer(self.r[4])?,-4)?;rt.store(p,32,v)?;self.r[4]=CrtValue::Pointer(p);Ok(())}
 fn pop(&mut self,rt:&mut CrtStreamRuntime)->Result<CrtValue,&'static str>{let p=Self::pointer(self.r[4])?;let v=rt.load(p,32)?;rt.consume_stack(p,v)?;self.r[4]=CrtValue::Pointer(rt.offset(p,4)?);Ok(v)}
 fn discard(&mut self,rt:&mut CrtStreamRuntime,bytes:u32)->Result<(),&'static str>{if bytes%4!=0||bytes>256{return Err("CRT cdecl argument cleanup");}let start=Self::pointer(self.r[4])?;for i in 0..bytes/4{let p=rt.offset(start,i64::from(i)*4)?;let v=rt.load(p,32)?;if matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT cleanup crosses protected word");}}for _ in 0..bytes/4{self.pop(rt)?;}Ok(())}
 fn leave(&mut self,rt:&mut CrtStreamRuntime)->Result<(),&'static str>{self.r[4]=CrtValue::Pointer(Self::pointer(self.r[5])?);self.r[5]=self.pop(rt)?;Ok(())}
 /// Check a live interrupted/active call without pretending it has returned.
 fn validate_active(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  let entry=Self::pointer(self.entry[4])?;let sp=Self::pointer(self.r[4])?;
  if self.returned||self.return_id==0||entry.cap!=sp.cap||entry.owner!=sp.owner||sp.address()>entry.address()||rt.load(entry,32)?!=CrtValue::ProtectedReturn(self.return_id)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.return_id)).count()!=1{return Err("CRT active caller lifetime/return authority");}
  rt.valid(sp,entry.address().checked_sub(sp.address()).and_then(|n|n.checked_add(4)).ok_or("CRT active caller range")?)
 }
 fn finish(&mut self,rt:&mut CrtStreamRuntime)->Result<CrtValue,&'static str>{self.finish_pop(rt,0)}
 fn finish_pop(&mut self,rt:&mut CrtStreamRuntime,bytes:u16)->Result<CrtValue,&'static str>{
  if self.returned{return Err("CRT repeated return");}
  if bytes!=self.return_pop||bytes>256||bytes%4!=0{return Err("CRT unbound RET argument cleanup");}
  if self.r[4]!=self.entry[4]{return Err("CRT caller stack identity");}
  if [3,5,6,7].iter().any(|&i|self.r[i]!=self.entry[i]){return Err("CRT callee saved restoration");}
  let p=Self::pointer(self.r[4])?;
  if rt.load(p,32)?!=CrtValue::ProtectedReturn(self.return_id){return Err("CRT original protected return");}
  rt.offset(p,4+i64::from(bytes))?;
  for i in 0..bytes/4{let slot=rt.offset(p,4+i64::from(i)*4)?;if matches!(rt.load(slot,32)?,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT RET cleanup crosses protected word");}}
  self.pop(rt)?;self.discard(rt,u32::from(bytes))?;self.returned=true;Ok(self.r[0])
 }
 /// Execute an already bound native callee with the actual original CALL/RET
 /// state. A fresh identity protects the transient return, not its numeric PC.
 fn call<B:CrtBackend,F>(&mut self,rt:&mut CrtStreamRuntime,lease:CrtLock,backend:&mut B,continuation:u32,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,CrtLock,&mut B)->Result<CrtValue,&'static str>{
  self.call_pop(rt,lease,backend,continuation,0,callee)
 }
 /// Cleanup authority is supplied by the separately validated call binding,
 /// never inferred from whichever RET the callee happens to execute.
 fn call_pop<B:CrtBackend,F>(&mut self,rt:&mut CrtStreamRuntime,lease:CrtLock,backend:&mut B,continuation:u32,return_pop:u16,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,CrtLock,&mut B)->Result<CrtValue,&'static str>{
  rt.check_lock(lease)?;
  self.call_activation(rt,continuation,return_pop,|rt,child|callee(rt,child,lease,backend))
 }
 /// Shared protected CALL/RET mechanism. Lock acquisition and release cannot
 /// require a lock that the original instruction has not yet acquired. Their
 /// independently bound effects validate the exact object and thread instead.
 /// This grants no external-effect or exception-containment certificate.
 fn call_activation<F>(&mut self,rt:&mut CrtStreamRuntime,continuation:u32,return_pop:u16,callee:F)->Result<CrtValue,&'static str>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>{
  if self.returned||continuation==0||return_pop>256||return_pop%4!=0{return Err("CRT call activation/continuation/cleanup");}
  let before=Self::pointer(self.r[4])?;
  if before.kind!=CrtRegionKind::Stack{return Err("CRT call stack role");}
  let expected_after=rt.offset(before,i64::from(return_pop))?;
  for i in 0..return_pop/4{let p=rt.offset(before,i64::from(i)*4)?;if matches!(rt.load(p,32)?,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)){return Err("CRT bound call arguments cross protected word");}}
  let slot=rt.offset(before,-4)?;rt.valid(slot,4)?;
  if rt.overlapping_tags(slot.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("CRT call crosses protected state");}
  let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("CRT call identity exhausted")?;
  let identity=generation|(1u64<<63);
  if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(identity)){return Err("CRT call identity collision");}
  rt.generation=generation;self.push(rt,CrtValue::ProtectedReturn(identity))?;
  let mut child=Self{abi:self.abi,r:self.r,xmm:self.xmm,entry:self.r,flags:self.flags,return_id:identity,steps:self.steps,returned:false,return_pop};
  let result=callee(rt,&mut child);
  self.r=child.r;self.xmm=child.xmm;self.flags=child.flags;self.steps=child.steps;
  let value=result?;
  if !child.returned||self.r[4]!=CrtValue::Pointer(expected_after)||value!=self.r[0]||rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(identity)){return Err("CRT callee missing exact protected RET");}
  Ok(value)
 }
 fn condition(&self,kind:u8)->Result<bool,&'static str>{let z=||self.flags.zf.ok_or("CRT unknown ZF");let c=||self.flags.cf.ok_or("CRT unknown CF");let s=||self.flags.sf.ok_or("CRT unknown SF");let o=||self.flags.of.ok_or("CRT unknown OF");Ok(match kind{0=>z()?,1=>!z()?,2=>c()?,3=>!c()?&&!z()?,4=>c()?||z()?,5=>!c()?,6=>s()?!=o()?,7=>z()?||(s()?!=o()?),8=>!z()?&&(s()?==o()?),9=>s()?==o()?,10=>s()?,11=>!s()?,_=>return Err("CRT condition kind")})}
 fn binary(&mut self,rt:&CrtStreamRuntime,kind:u8,a:CrtValue,b:CrtValue,width:u8)->Result<CrtValue,&'static str>{
  if kind==0{return Ok(b);}for v in [a,b]{match v{CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Function(f)=>rt.function_identity(f,None)?,_=>{}}}let mask=Self::mask(width)?;
  if width==32&&kind==8{if let(CrtValue::Heap(x),CrtValue::Heap(y))=(a,b){if x!=y{return Err("CRT distinct opaque heap comparison");}rt.heap_identity(x)?;self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:Some(false),sf:None};return Ok(CrtValue::Scalar{bits:0,known:0});}}

  if matches!(kind,3|4|5|8){let(x,kx)=Self::bits(a)?;let(y,ky)=Self::bits(b)?;let(bits,known)=match kind{3=>(x^y,kx&ky),4|8=>(x&y,(kx&ky)|(kx&!x)|(ky&!y)),5=>(x|y,(kx&ky)|(kx&x)|(ky&y)),_=>unreachable!()};let bits=bits&mask;let known=(known&mask)|!mask;let sign=1u32<<(width-1);self.flags=CrtFlags{cf:Some(false),of:Some(false),zf:if bits&known&mask!=0{Some(false)}else if known==u32::MAX{Some(true)}else{None},sf:if known&sign!=0{Some(bits&sign!=0)}else{None}};return Ok(CrtValue::Scalar{bits,known});}
  let x=Self::number(a)?&mask;let y=Self::number(b)?&mask;let sign=1u32<<(width-1);
  let (bits,cf,of)=match kind{1=>{let n=u64::from(x)+u64::from(y);let r=n as u32&mask;(r,n>u64::from(mask),(!(x^y)&(x^r)&sign)!=0)},2|7=>{let r=x.wrapping_sub(y)&mask;(r,x<y,((x^y)&(x^r)&sign)!=0)},3=>(x^y,false,false),4|8=>(x&y,false,false),5=>(x|y,false,false),6=>{let borrow=u32::from(self.flags.cf.ok_or("CRT unknown borrow")?);let r=x.wrapping_sub(y).wrapping_sub(borrow)&mask;(r,u64::from(x)<u64::from(y)+u64::from(borrow),((x^y)&(x^r)&sign)!=0)},_=>return Err("CRT binary kind")};
  self.flags=CrtFlags{cf:Some(cf),zf:Some(bits==0),sf:Some(bits&sign!=0),of:Some(of)};
  if width==32&&matches!(kind,1|2){match(a,b){(CrtValue::Pointer(p),CrtValue::Scalar{known:u32::MAX,..})=>return Ok(CrtValue::Pointer(rt.offset(p,if kind==1{i64::from(y as i32)}else{-i64::from(y as i32)})?)),(CrtValue::Scalar{known:u32::MAX,..},CrtValue::Pointer(p))if kind==1=>return Ok(CrtValue::Pointer(rt.offset(p,i64::from(x as i32))?)),(CrtValue::Pointer(p),CrtValue::Pointer(q))if kind==2=>return Ok(CrtValue::scalar(rt.difference(p,q)?)),_=>{}}}
  Ok(CrtValue::scalar(bits))
 }
 /// CDQ changes EDX only; an unknown sign stays unknown, not zero.
 fn sign_dividend(&mut self)->Result<(),&'static str>{let(bits,known)=Self::bits(self.r[0])?;self.r[2]=if known&0x80000000!=0{CrtValue::scalar(if bits&0x80000000!=0{u32::MAX}else{0})}else{CrtValue::Scalar{bits:0,known:0}};Ok(())}
 fn add_carry(&mut self,a:CrtValue,b:CrtValue)->Result<CrtValue,&'static str>{
  let x=Self::number(a)?;let y=Self::number(b)?;let carry=u64::from(self.flags.cf.ok_or("CRT unknown ADC carry")?);
  let full=u64::from(x)+u64::from(y)+carry;let value=full as u32;
  self.flags=CrtFlags{cf:Some(full>u64::from(u32::MAX)),zf:Some(value==0),sf:Some(value&0x80000000!=0),of:Some((!(x^y)&(x^value)&0x80000000)!=0)};Ok(CrtValue::scalar(value))
 }
 /// DIV faults are outside the non-faulting admitted domain. Validate every
 /// operand and both fault conditions before changing registers or flags.
 fn divide_unsigned(&mut self,divisor:CrtValue)->Result<(),&'static str>{
  let divisor=divisor.known_scalar()?;let low=self.r[0].known_scalar()?;let high=self.r[2].known_scalar()?;
  if divisor==0{return Err("CRT unproved DIV zero exception");}
  if high>=divisor{return Err("CRT unproved DIV quotient overflow exception");}
  let dividend=(u64::from(high)<<32)|u64::from(low);let quotient=dividend/u64::from(divisor);let remainder=dividend%u64::from(divisor);
  self.r[0]=CrtValue::scalar(quotient as u32);self.r[2]=CrtValue::scalar(remainder as u32);self.flags=CrtFlags::unknown();Ok(())
 }
 /// Sound per-bit sum for scalar LEA, discarding correlations conservatively.
 fn sum_bits(a:CrtValue,b:CrtValue)->Result<CrtValue,&'static str>{
  let(x,kx)=Self::bits(a)?;let(y,ky)=Self::bits(b)?;let(mut bits,mut known,mut carries)=(0u32,0u32,1u8);
  for bit in 0..32{let mut sums=0u8;let mut next=0u8;for ax in 0..2u32{if kx&(1<<bit)!=0&&ax!=((x>>bit)&1){continue;}for by in 0..2u32{if ky&(1<<bit)!=0&&by!=((y>>bit)&1){continue;}for carry in 0..2u32{if carries&(1<<carry)==0{continue;}let sum=ax+by+carry;sums|=1<<(sum&1);next|=1<<(sum>>1);}}}if sums==1||sums==2{known|=1<<bit;if sums==2{bits|=1<<bit;}}carries=next;}
  Ok(CrtValue::Scalar{bits,known})
 }
 /// LEA with a real capability keeps it. Scalar address bits stay scalar even
 /// if their numeric value coincides with a mapped region: no provenance mint.
 fn lea(&self,rt:&CrtStreamRuntime,base:Option<usize>,index:Option<usize>,scale:u32,displacement:u32,absolute:Option<CrtRegionKind>)->Result<CrtValue,&'static str>{
  if base.is_some_and(|r|matches!(self.r[r],CrtValue::Pointer(_)))||index.is_some_and(|r|matches!(self.r[r],CrtValue::Pointer(_)))||base.is_none()&&absolute.is_some(){return Ok(CrtValue::Pointer(self.form_address(rt,base,index,scale,displacement,absolute)?));}
  if !matches!(scale,1|2|4|8){return Err("CRT LEA scale");}
  let a=base.map(|r|self.r[r]).unwrap_or(CrtValue::scalar(0));
  let b=if let Some(r)=index{let(bits,known)=Self::bits(self.r[r])?;let shift=scale.trailing_zeros();CrtValue::Scalar{bits:bits.wrapping_shl(shift),known:known.wrapping_shl(shift)|(scale-1)}}else{CrtValue::scalar(0)};
  Self::sum_bits(Self::sum_bits(a,b)?,CrtValue::scalar(displacement))
 }
 fn zero(&mut self)->CrtValue{self.flags=CrtFlags{cf:Some(false),zf:Some(true),sf:Some(false),of:Some(false)};CrtValue::scalar(0)}
 /// ROR r32,CL: only five count bits are read; no pointer authority is created.
 fn rotate_right32(&mut self,value:CrtValue,count:CrtValue)->Result<CrtValue,&'static str>{
  let(c,k)=Self::bits(count)?;if k&31!=31{return Err("CRT unknown rotate count");}let n=c&31;
  if n==0{return Ok(value);}
  let(b,k)=Self::bits(value)?;let bits=b.rotate_right(n);let known=k.rotate_right(n);
  self.flags.cf=if known&0x80000000!=0{Some(bits&0x80000000!=0)}else{None};
  self.flags.of=if n==1&&known&0xc0000000==0xc0000000{Some(((bits>>31)^(bits>>30))&1!=0)}else{None};
  Ok(CrtValue::Scalar{bits:bits&known,known})
 }
 fn shift(&mut self,value:CrtValue,count:u8,kind:u8,width:u8)->Result<CrtValue,&'static str>{let mask=Self::mask(width)?;let x=Self::number(value)?&mask;let count=count&31;if count==0{return Ok(value);}let sign=1u32<<(width-1);let result=match kind{0=>x.wrapping_shl(u32::from(count))&mask,1=>x.wrapping_shr(u32::from(count)),2=>((((x<<(32-width))as i32)>>(32-width))>>count)as u32&mask,_=>return Err("CRT shift kind")};
  let cf=if kind==2&&count>=width{Some(x&sign!=0)}else if count<width{Some(if kind==0{x&(1<<(width-count))!=0}else{x&(1<<(count-1))!=0})}else{None};let of=if count==1{match kind{0=>cf.map(|c|(result&sign!=0)^c),1=>Some(x&sign!=0),2=>Some(false),_=>None}}else{None};self.flags=CrtFlags{cf,zf:Some(result==0),sf:Some(result&sign!=0),of};Ok(CrtValue::scalar(result))}
 fn multiply(&mut self,value:CrtValue,factor:u32)->Result<CrtValue,&'static str>{let x=Self::number(value)?;let product=i64::from(x as i32)*i64::from(factor as i32);let result=product as u32;let overflow=product!=i64::from(result as i32);self.flags=CrtFlags{cf:Some(overflow),of:Some(overflow),zf:None,sf:None};Ok(CrtValue::scalar(result))}
 fn clobber(&mut self,result:CrtValue){self.xmm=[[CrtValue::Scalar{bits:0,known:0};4];8];self.r[0]=result;self.r[1]=CrtValue::Scalar{bits:0,known:0};self.r[2]=CrtValue::Scalar{bits:0,known:0};self.flags=CrtFlags::unknown();}
}
"#;
