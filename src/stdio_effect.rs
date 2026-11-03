//! Bounded printf-wrapper proof and owned stream effect at an explicit CRT cut.
//! This proves original argument routing and two leaf accessors. It does NOT
//! prove the linked formatter, startup FILE/locale initialization or exit flush.
//! Contracts: Microsoft Learn printf, printf format specification, data-type
//! ranges, _setmode, fflush and ferror. Windows int and long are both 32 bits.
use super::graph::{self, Binary, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub code: &'a [u8],
    pub origin: u32,
}
pub(crate) struct WrapperProof {
    stdout: u32,
    options: u32,
    formatter: u32,
    temporary_bytes: u32,
}
impl WrapperProof {
    pub fn stdout_address(&self) -> u32 {
        self.stdout
    }
    pub fn options_address(&self) -> u32 {
        self.options
    }
    pub fn formatter_target(&self) -> u32 {
        self.formatter
    }
    /// Decoded wrapper/accessor scratch only; the linked formatter is an
    /// explicit external effect and its guest stack behavior remains unproved.
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
    pub fn body(&self) -> String {
        format!("if stdio.stdout_address!={}u32||stdio.options_address!={}u32{{return Err(\"stdio wrapper owned object binding\");}}stdio.write(owner,format,arguments,sink)",self.stdout,self.options)
    }
    /// These are outstanding contracts, not attestations supplied by a Boolean.
    pub fn required_effects(&self) -> &'static [&'static str] {
        &[
            "linked formatter implements public printf semantics for the admitted integer domain",
            "owned initialized narrow stdout, C locale, text mode and known complete options state",
            "explicit deferred queue or unbuffered projection; normal-exit flush remains independently unproved",
            "no intervening stream/errno observers or unresolved concurrent stream mutation",
        ]
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Saved(u8),
    Stack(i32),
    Return,
    Constant(u32),
    Format,
    Stdout,
    Options,
    OptionWord(u8),
    Result,
}
struct State {
    r: [Value; 8],
    stack: BTreeMap<i32, Value>,
    sp: i32,
    depth: u32,
}
fn full(r: Reg) -> Result<usize, String> {
    if r.width == 32 && r.shift == 0 {
        Ok(r.index as usize)
    } else {
        Err("stdio: partial register".into())
    }
}
fn index(r: Register) -> Result<usize, String> {
    match r {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::EBX => Ok(3),
        Register::ESP => Ok(4),
        Register::EBP => Ok(5),
        Register::ESI => Ok(6),
        Register::EDI => Ok(7),
        _ => Err("stdio: register width".into()),
    }
}
impl State {
    fn new(arg: Value) -> Self {
        let mut r = std::array::from_fn(|i| Value::Saved(i as u8));
        r[4] = Value::Stack(0);
        Self {
            r,
            stack: BTreeMap::from([(0, Value::Return), (4, arg)]),
            sp: 0,
            depth: 0,
        }
    }
    fn address(&self, a: &graph::Address) -> Result<Value, String> {
        if a.index.is_some() {
            return Err("stdio: indexed address".into());
        }
        match a.base.map(|r| &self.r[r as usize]) {
            Some(Value::Stack(n)) => Ok(Value::Stack(
                n.checked_add(a.displacement as i32)
                    .ok_or("stdio: stack address overflow")?,
            )),
            Some(Value::Options) if a.displacement == 0 => Ok(Value::OptionWord(0)),
            Some(Value::Options) if a.displacement == 4 => Ok(Value::OptionWord(1)),
            _ => Err("stdio: unbound pointer/address".into()),
        }
    }
    fn read(&self, o: &Operand) -> Result<Value, String> {
        match o {
            Operand::Immediate(n) => Ok(Value::Constant(*n)),
            Operand::Reg(r) => Ok(self.r[full(*r)?].clone()),
            Operand::Memory(a, 32) => match self.address(a)? {
                Value::Stack(n) => self
                    .stack
                    .get(&n)
                    .filter(|v| **v != Value::Return)
                    .cloned()
                    .ok_or_else(|| "stdio: absent/protected stack read".into()),
                Value::OptionWord(n) => Ok(Value::OptionWord(n)),
                _ => Err("stdio: memory type".into()),
            },
            _ => Err("stdio: unsupported read".into()),
        }
    }
    fn set(&mut self, r: Reg, v: Value) -> Result<(), String> {
        let r = full(r)?;
        if r == 4 {
            return Err("stdio: unproved ESP assignment".into());
        }
        self.r[r] = v;
        Ok(())
    }
    fn step(&mut self, op: Operation) -> Result<(), String> {
        match op {
            Operation::Binary(Binary::Move, Operand::Reg(r), src) => {
                let v = self.read(&src)?;
                self.set(r, v)?;
            }
            Operation::Address(r, a) => {
                let v = self.address(&a)?;
                if !matches!(v, Value::Stack(_)) {
                    return Err("stdio: address capability".into());
                }
                self.set(r, v)?;
            }
            Operation::Push(src) => {
                let v = self.read(&src)?;
                if v == Value::Unknown {
                    return Err("stdio: unknown argument/save".into());
                }
                self.sp = self.sp.checked_sub(4).ok_or("stdio: stack underflow")?;
                if self.sp < -256 {
                    return Err("stdio: stack budget".into());
                }
                self.depth = self.depth.max(self.sp.unsigned_abs());
                self.stack.insert(self.sp, v);
                self.r[4] = Value::Stack(self.sp);
            }
            Operation::Pop(r) => {
                let r = full(r)?;
                if r == 4 {
                    return Err("stdio: POP ESP".into());
                }
                self.r[r] = self
                    .stack
                    .remove(&self.sp)
                    .filter(|v| *v != Value::Return)
                    .ok_or("stdio: protected pop")?;
                self.sp += 4;
                self.r[4] = Value::Stack(self.sp);
            }
            Operation::Binary(Binary::Add, Operand::Reg(r), Operand::Immediate(n))
                if full(r)? == 4 =>
            {
                let n = i32::try_from(n).map_err(|_| "stdio: stack cleanup sign")?;
                let end = self.sp.checked_add(n).ok_or("stdio: cleanup overflow")?;
                if n % 4 != 0 || end > 0 {
                    return Err("stdio: protected cleanup".into());
                }
                for at in (self.sp..end).step_by(4) {
                    self.stack.remove(&at).ok_or("stdio: absent cleanup slot")?;
                }
                self.sp = end;
                self.r[4] = Value::Stack(end);
            }
            Operation::Binary(Binary::Add, Operand::Reg(r), src) => {
                let (Value::Constant(a), Value::Constant(b)) =
                    (self.r[full(r)?].clone(), self.read(&src)?)
                else {
                    return Err("stdio: nonconstant address arithmetic".into());
                };
                self.set(
                    r,
                    Value::Constant(a.checked_add(b).ok_or("stdio: address wrap")?),
                )?;
            }
            Operation::Nop => {}
            _ => return Err("stdio: unsupported wrapper/accessor effect".into()),
        }
        Ok(())
    }
    fn arguments(&self, n: usize) -> Result<Vec<Value>, String> {
        (0..n)
            .map(|i| {
                self.stack
                    .get(&(self.sp + i as i32 * 4))
                    .cloned()
                    .ok_or_else(|| "stdio: incomplete argument list".into())
            })
            .collect()
    }
    fn call(&mut self, result: Value, depth: u32) -> Result<(), String> {
        self.depth = self.depth.max(
            self.sp
                .unsigned_abs()
                .checked_add(4)
                .and_then(|n| n.checked_add(depth))
                .ok_or("stdio: call depth")?,
        );
        self.r[0] = result;
        self.r[1] = Value::Unknown;
        self.r[2] = Value::Unknown;
        Ok(())
    }
    fn finish(&self) -> Result<(), String> {
        if self.sp != 0
            || self.stack.keys().any(|&n| n < 0)
            || [3, 5, 6, 7]
                .into_iter()
                .any(|r| self.r[r] != Value::Saved(r as u8))
        {
            return Err("stdio: original return/saved-register obligation".into());
        }
        Ok(())
    }
}
fn leaf(region: Region<'_>, arg: Value) -> Result<(u32, u32), String> {
    if region.origin == 0 || region.code.is_empty() || region.code.len() > 96 {
        return Err("stdio: accessor extent".into());
    }
    region
        .origin
        .checked_add(region.code.len() as u32)
        .ok_or("stdio: accessor overflow")?;
    let mut d = Decoder::with_ip(
        32,
        region.code,
        u64::from(region.origin),
        DecoderOptions::NONE,
    );
    let no_argument = arg == Value::Unknown;
    let mut s = State::new(arg);
    if no_argument {
        s.stack.remove(&4);
    }
    let mut returned = false;
    while d.can_decode() {
        let i = d.decode();
        if i.is_invalid() || returned {
            return Err("stdio: malformed/trailing accessor".into());
        }
        let at = (i.ip32() - region.origin) as usize;
        let raw = &region.code[at..at + i.len()];
        if i.code() == Code::Imul_r32_rm32_imm8
            && raw[0] == 0x6b
            && i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Memory
            && i.memory_index() == Register::None
        {
            let base = index(i.memory_base())?;
            let Value::Stack(offset) = s.r[base] else {
                return Err("stdio: multiplication source provenance".into());
            };
            let key = offset
                .checked_add(i.memory_displacement32() as i32)
                .ok_or("stdio: multiplication address")?;
            let Some(Value::Constant(a)) = s.stack.get(&key) else {
                return Err("stdio: multiplication argument knowledge".into());
            };
            let n = a.wrapping_mul(i.immediate8to32() as u32);
            let dst = index(i.op0_register())?;
            if dst == 4 {
                return Err("stdio: multiplication ESP".into());
            }
            s.r[dst] = Value::Constant(n);
        } else {
            let op = graph::normalized(&i, raw)?;
            if op == Operation::Return {
                s.finish()?;
                returned = true;
            } else {
                s.step(op)?;
            }
        }
    }
    let Value::Constant(value) = s.r[0] else {
        return Err("stdio: accessor returned unproved address".into());
    };
    if !returned || value == 0 || value % 4 != 0 {
        return Err("stdio: accessor return/alignment".into());
    }
    Ok((value, s.depth))
}
pub(crate) fn prove_wrapper(
    wrapper: Region<'_>,
    iob: Region<'_>,
    options: Region<'_>,
    formatter: u32,
    module: (u32, u32),
) -> Result<WrapperProof, String> {
    let contains = |address: u32, size: u32| {
        address >= module.0 && address.checked_add(size).is_some_and(|end| end <= module.1)
    };
    if module.0 == 0
        || module.0 >= module.1
        || formatter == 0
        || !contains(formatter, 1)
        || wrapper.code.len() > 256
        || wrapper.code.is_empty()
    {
        return Err("stdio: wrapper/module extent".into());
    }
    for r in [wrapper, iob, options] {
        if !contains(r.origin, r.code.len() as u32) {
            return Err("stdio: code outside module".into());
        }
    }
    if [wrapper.origin, iob.origin, options.origin, formatter]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != 4
    {
        return Err("stdio: conflicting callee bindings".into());
    }
    let (stdout, iob_depth) = leaf(iob, Value::Constant(1))?;
    let (option_address, option_depth) = leaf(options, Value::Unknown)?;
    if stdout % 4 != 0
        || option_address % 4 != 0
        || !contains(stdout, 56)
        || !contains(option_address, 8)
        || stdout < option_address + 8 && option_address < stdout + 56
    {
        return Err("stdio: owned stream/options alignment, bounds or alias".into());
    }
    let mut regions = vec![
        (stdout, stdout + 56),
        (option_address, option_address + 8),
        (formatter, formatter + 1),
    ];
    regions.extend(
        [wrapper, iob, options]
            .into_iter()
            .map(|r| (r.origin, r.origin + r.code.len() as u32)),
    );
    regions.sort_unstable();
    if regions.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err("stdio: code and owned object alias".into());
    }
    let mut s = State::new(Value::Format);
    let mut d = Decoder::with_ip(
        32,
        wrapper.code,
        u64::from(wrapper.origin),
        DecoderOptions::NONE,
    );
    let mut calls = 0;
    let mut returned = false;
    while d.can_decode() {
        let i = d.decode();
        if i.is_invalid() || returned {
            return Err("stdio: malformed/trailing wrapper".into());
        }
        let at = (i.ip32() - wrapper.origin) as usize;
        let raw = &wrapper.code[at..at + i.len()];
        if i.code() == Code::Call_rel32_32 && raw.len() == 5 && raw[0] == 0xe8 {
            match (calls, i.near_branch32()) {
                (0, target) if target == iob.origin => {
                    if s.arguments(1)? != [Value::Constant(1)] {
                        return Err("stdio: stdout index/argument".into());
                    }
                    s.call(Value::Stdout, iob_depth)?;
                }
                (1, target) if target == options.origin => s.call(Value::Options, option_depth)?,
                (2, target) if target == formatter => {
                    if s.arguments(6)?
                        != [
                            Value::OptionWord(0),
                            Value::OptionWord(1),
                            Value::Stdout,
                            Value::Format,
                            Value::Constant(0),
                            Value::Stack(8),
                        ]
                    {
                        return Err("stdio: original formatter argument provenance/order".into());
                    }
                    s.call(Value::Result, 0)?;
                }
                _ => return Err("stdio: unresolved or reordered call".into()),
            }
            calls += 1;
        } else {
            let op = graph::normalized(&i, raw)?;
            if op == Operation::Return {
                s.finish()?;
                returned = true;
            } else {
                s.step(op)?;
            }
        }
    }
    if !returned || calls != 3 || s.r[0] != Value::Result {
        return Err("stdio: wrapper completion/result".into());
    }
    Ok(WrapperProof {
        stdout,
        options: option_address,
        formatter,
        temporary_bytes: s.depth,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Piece {
    Literal(Vec<u8>),
    Unsigned,
    Signed,
}
pub(crate) struct FormatProof {
    pieces: Vec<Piece>,
    arguments: usize,
    max_bytes: usize,
}
impl FormatProof {
    pub fn arguments(&self) -> usize {
        self.arguments
    }
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}
pub(crate) fn prove_format(bytes: &[u8]) -> Result<FormatProof, String> {
    if bytes.is_empty() || bytes.len() > 4096 || bytes.last() != Some(&0) {
        return Err("stdio: full NUL-terminated immutable format bounds".into());
    }
    let mut pieces = Vec::new();
    let mut literal = Vec::new();
    let mut arguments = 0;
    let mut max_bytes = 0;
    let mut at = 0;
    while at + 1 < bytes.len() {
        let b = bytes[at];
        at += 1;
        if b == b'%' {
            if !literal.is_empty() {
                pieces.push(Piece::Literal(std::mem::take(&mut literal)));
            }
            let mut ty = *bytes.get(at).ok_or("stdio: incomplete conversion")?;
            at += 1;
            if ty == b'%' {
                literal.push(b'%');
                max_bytes += 1;
                continue;
            }
            if ty == b'l' {
                ty = *bytes.get(at).ok_or("stdio: incomplete size conversion")?;
                at += 1;
            }
            pieces.push(match ty {
                b'u' => Piece::Unsigned,
                b'd' => Piece::Signed,
                _ => return Err("stdio: unsupported format conversion".into()),
            });
            arguments += 1;
            max_bytes += 11;
        } else {
            if !(0x20..=0x7e).contains(&b) && !b"\n\r\t".contains(&b) {
                return Err("stdio: format outside initialized ASCII domain".into());
            }
            literal.push(b);
            max_bytes += if b == b'\n' { 2 } else { 1 };
        }
    }
    if at != bytes.len() - 1 || arguments > 128 || max_bytes > 8192 {
        return Err("stdio: format extent/budget".into());
    }
    if !literal.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    Ok(FormatProof {
        pieces,
        arguments,
        max_bytes,
    })
}

pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum PrintResult {Count(u32),Negative}
impl PrintResult {fn word(self)->Option<u32>{match self{Self::Count(n)=>Some(n),Self::Negative=>None}}}
/// An explicit effect policy; neither variant is inferred from default CRT
/// stdout or an observation made only after process exit.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum OutputPolicy {ImmediateProjection,Deferred}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum FlushResult {Success,Failure}
struct OwnedStdio {owner:u64,stdout_address:u32,options_address:u32,options:[u32;2],stream_error:bool,errno:Option<i32>,policy:OutputPolicy,queued:[u8;8192],pending:usize,written:usize}
impl OwnedStdio {
 /// Explicit initialized owned CRT-state boundary. This does not acquire the
 /// original FILE, close its static formatter code, or implement CRT startup.
 fn new(owner:u64,stdout_address:u32,options_address:u32,options:[u32;2],policy:OutputPolicy)->Result<Self,&'static str>{
  if owner==0||stdout_address==0||options_address==0||stdout_address%4!=0||options_address%4!=0
   ||stdout_address.checked_add(56).is_none()||options_address.checked_add(8).is_none()
   ||stdout_address<options_address+8&&options_address<stdout_address+56||options!=[0x24,0] {return Err("stdio initialized object/options boundary");}
  Ok(Self{owner,stdout_address,options_address,options,stream_error:false,errno:None,policy,queued:[0;8192],pending:0,written:0})
 }
 fn write(&mut self,owner:u64,format:&[u8],arguments:&[u32],sink:impl FnMut(&[u8])->std::io::Result<usize>)->Result<PrintResult,&'static str>{
  if owner!=self.owner||self.options!=[0x24,0]||self.stream_error{return Err("stdio owner/options/initial stream boundary");}
  let(mut bytes,mut physical,mut logical,mut arg)=([0u8;8192],0usize,0u32,0usize);
  if format.is_empty()||format.len()>4096||format.last()!=Some(&0)||arguments.len()>128{return Err("stdio immutable format/argument bounds");}
  let mut put=|b:u8|->Result<(),&'static str>{logical=logical.checked_add(1).ok_or("stdio character count")?;if b==b'\n'{if physical>=bytes.len(){return Err("stdio output budget");}bytes[physical]=b'\r';physical+=1;}if physical>=bytes.len(){return Err("stdio output budget");}bytes[physical]=b;physical+=1;Ok(())};
  let mut at=0;while at+1<format.len(){let b=format[at];at+=1;if b==b'%'{let mut ty=*format.get(at).ok_or("stdio conversion range")?;at+=1;
   if ty==b'%'{put(b'%')?;continue;}if ty==b'l'{ty=*format.get(at).ok_or("stdio conversion size")?;at+=1;}
   if ![b'u',b'd'].contains(&ty){return Err("stdio unsupported conversion");}
   let mut value=*arguments.get(arg).ok_or("stdio incomplete initialized argument")?;arg+=1;
   if ty==b'd'&&(value as i32)<0{put(b'-')?;value=0u32.wrapping_sub(value);}
   let(mut digits,mut count)=([0u8;10],0usize);loop{digits[count]=b'0'+(value%10)as u8;count+=1;value/=10;if value==0{break;}}
   for index in (0..count).rev(){put(digits[index])?;}
  }else{if !(0x20..=0x7e).contains(&b)&&![b'\n',b'\r',b'\t'].contains(&b){return Err("stdio format encoding/control domain");}put(b)?;}}
  if at!=format.len()-1{return Err("stdio trailing/incomplete format");}
  // Formatting validates all input before changing the owned queue or sink.
  // Count precedes CRLF expansion; a queued printf count is not a flush result.
  let end=self.pending.checked_add(physical).filter(|&n|n<=self.queued.len()).ok_or("stdio queue capacity outside effect domain")?;
  self.queued[self.pending..end].copy_from_slice(&bytes[..physical]);self.pending=end;
  match self.policy {OutputPolicy::Deferred=>Ok(PrintResult::Count(logical)),OutputPolicy::ImmediateProjection=>match self.flush(owner,sink)?{FlushResult::Success=>Ok(PrintResult::Count(logical)),FlushResult::Failure=>Ok(PrintResult::Negative)}}
 }
 fn pending_bytes(&self)->&[u8]{&self.queued[..self.pending]}
 fn written_bytes(&self)->usize{self.written}
 /// Explicit component flush, not an implicit normal-exit/CRT-startup claim.
 /// On I/O failure the already written prefix remains observable. The remaining
 /// queued buffer is discarded and recovery/retry is outside this owned domain.
 fn flush(&mut self,owner:u64,mut sink:impl FnMut(&[u8])->std::io::Result<usize>)->Result<FlushResult,&'static str>{
  if owner!=self.owner||self.stream_error{return Err("stdio flush owner/error boundary");}
  self.written.checked_add(self.pending).ok_or("stdio observed byte accounting")?;
  let mut consumed=0;while consumed<self.pending{match sink(&self.queued[consumed..self.pending]){
   Ok(n)if n>0&&n<=self.pending-consumed=>{consumed+=n;self.written+=n;},
   Ok(n)if n>self.pending-consumed=>{self.pending=0;self.stream_error=true;self.errno=None;return Err("stdio sink violated reported byte extent");},
   _=>{self.pending=0;self.stream_error=true;self.errno=None;return Ok(FlushResult::Failure);}
  }}self.pending=0;Ok(FlushResult::Success)
 }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn original_wrapper_argument_route_and_leaf_addresses_are_instruction_derived() {
        let wrapper=raw("568b7424086a01e8ac30000083c4048d4c240c516a005650e833fdffffff7004ff30e8f74e000083c4185ec3");
        let iob = raw("8bff558bec6b4508380580c041005dc3");
        let options = raw("b8e8d24100c3");
        let p = prove_wrapper(
            Region {
                code: &wrapper,
                origin: 0x401520,
            },
            Region {
                code: &iob,
                origin: 0x4045d8,
            },
            Region {
                code: &options,
                origin: 0x401270,
            },
            0x40643e,
            (0x400000, 0x420000),
        )
        .unwrap();
        assert_eq!(
            (
                p.stdout_address(),
                p.options_address(),
                p.formatter_target()
            ),
            (0x41c0b8, 0x41d2e8, 0x40643e)
        );
        assert!(!p.required_effects().is_empty());
        assert!(p.body().contains("stdio.write"));
        for (at, value) in [(6, 2), (0x12, 0x08), (0x1d, 0x08), (0x29, 0x5c)] {
            let mut bad = wrapper.clone();
            bad[at] = value;
            assert!(prove_wrapper(
                Region {
                    code: &bad,
                    origin: 0x401520
                },
                Region {
                    code: &iob,
                    origin: 0x4045d8
                },
                Region {
                    code: &options,
                    origin: 0x401270
                },
                0x40643e,
                (0x400000, 0x420000)
            )
            .is_err());
        }
    }
    #[test]
    fn accessors_cannot_read_unpassed_arguments_or_alias_owned_code() {
        let read_unpassed = raw("8b4c2404b8e8d24100c3");
        assert!(leaf(
            Region {
                code: &read_unpassed,
                origin: 0x401270
            },
            Value::Unknown
        )
        .is_err());
        let wrapper = raw("568b7424086a01e8ac30000083c4048d4c240c516a005650e833fdffffff7004ff30e8f74e000083c4185ec3");
        let alias = raw("b820154000c3");
        let options = raw("b8e8d24100c3");
        assert!(prove_wrapper(
            Region {
                code: &wrapper,
                origin: 0x401520
            },
            Region {
                code: &alias,
                origin: 0x4045d8
            },
            Region {
                code: &options,
                origin: 0x401270
            },
            0x40643e,
            (0x400000, 0x420000)
        )
        .err()
        .unwrap()
        .contains("alias"));
        let iob = raw("8bff558bec6b4508380580c041005dc3");
        for (unaligned_iob, unaligned_options) in [(true, false), (false, true)] {
            let mut iob = iob.clone();
            let mut options = options.clone();
            if unaligned_iob {
                iob[10] += 1;
            }
            if unaligned_options {
                options[1] += 1;
            }
            assert!(prove_wrapper(
                Region {
                    code: &wrapper,
                    origin: 0x401520
                },
                Region {
                    code: &iob,
                    origin: 0x4045d8
                },
                Region {
                    code: &options,
                    origin: 0x401270
                },
                0x40643e,
                (0x400000, 0x420000),
            )
            .err()
            .unwrap()
            .contains("alignment"));
        }
    }
    #[test]
    fn format_gate_is_integer_only_and_complete() {
        let p = prove_format(b"a=%lu b=%ld c=%d %%\n\0").unwrap();
        assert_eq!(p.arguments(), 3);
        assert!(p.max_bytes() > 33);
        assert_eq!(p.pieces.len(), 8);
        for b in [
            b"%s\0".as_slice(),
            b"%n\0",
            b"%08lu\0",
            b"%.2u\0",
            b"%lld\0",
            b"%f\0",
            b"abc",
            b"a\0b\0",
            b"%\0",
            b"%l\0",
            b"\x80\0",
        ] {
            assert!(prove_format(b).is_err(), "{b:?}");
        }
    }
    #[test]
    fn native_integer_text_partial_failure_and_count_are_independent() {
        let source = format!(
            "#![allow(dead_code)]\n{}\n{}",
            EMITTED_TYPES,
            r#"
fn main(){
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::ImmediateProjection).unwrap();let mut output=Vec::new();
 let result=state.write(7,b"%lu,%ld,%d,%%\n\0",&[u32::MAX,i32::MIN as u32,0],|b|{let n=b.len().min(3);output.extend_from_slice(&b[..n]);Ok(n)}).unwrap();
 assert_eq!(output,b"4294967295,-2147483648,0,%\r\n");assert_eq!(result,PrintResult::Count(27));assert_eq!(result.word(),Some(27));
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::ImmediateProjection).unwrap();let mut output=Vec::new();
 let result=state.write(7,b"abc%u\n\0",&[123],|b|{if output.len()<4{let n=(4-output.len()).min(b.len());output.extend_from_slice(&b[..n]);Ok(n)}else{Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))}}).unwrap();
 assert_eq!(output,b"abc1");assert_eq!(result,PrintResult::Negative);assert_eq!(result.word(),None);assert!(state.stream_error);assert_eq!(state.errno,None);
 let final_main_result=if 17u32.wrapping_mul(3)==51{0}else{1};assert_eq!(final_main_result,0);
 for format in [b"%s\0".as_slice(),b"%u%u\0",b"\x80\0",b"abc"]{
  let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::ImmediateProjection).unwrap();let mut called=false;assert!(state.write(7,format,&[7],|_|{called=true;Ok(0)}).is_err());assert!(!called);
 }
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::ImmediateProjection).unwrap();assert!(state.write(8,b"x\0",&[],|_|panic!("foreign owner wrote")).is_err());
 let result=state.write(7,b"x\0",&[],|_|Ok(0)).unwrap();assert_eq!(result,PrintResult::Negative);
 for options in [[0,0],[0x24,1],[0x25,0]]{assert!(OwnedStdio::new(7,0x41c0b8,0x41d2e8,options,OutputPolicy::ImmediateProjection).is_err());}
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::Deferred).unwrap();
 let accepted=state.write(7,b"abc%u\n\0",&[123],|_|panic!("deferred printf must not flush")).unwrap();assert_eq!(accepted,PrintResult::Count(7));assert_eq!(state.pending_bytes(),b"abc123\r\n");assert_eq!(state.written_bytes(),0);
 let main_return=0;let mut output=Vec::new();let flush=state.flush(7,|b|{if output.len()<4{let n=(4-output.len()).min(b.len());output.extend_from_slice(&b[..n]);Ok(n)}else{Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))}}).unwrap();
 assert_eq!(flush,FlushResult::Failure);assert_eq!(output,b"abc1");assert_eq!(state.written_bytes(),4);assert!(state.pending_bytes().is_empty());assert_eq!(accepted,PrintResult::Count(7));assert_eq!(main_return,0);assert!(state.flush(7,|_|panic!("failed stream retried")).is_err());
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::Deferred).unwrap();
 assert_eq!(state.write(7,b"\r\n%lu\0",&[0],|_|panic!()).unwrap(),PrintResult::Count(3));assert_eq!(state.pending_bytes(),b"\r\r\n0");
 assert_eq!(state.write(7,b"%ld\0",&[1],|_|panic!()).unwrap(),PrintResult::Count(1));let mut output=Vec::new();assert_eq!(state.flush(7,|b|{output.push(b[0]);Ok(1)}).unwrap(),FlushResult::Success);assert_eq!(output,b"\r\r\n01");assert_eq!(state.written_bytes(),5);
 assert_eq!(state.flush(7,|_|panic!("empty stream wrote")).unwrap(),FlushResult::Success);
 let mut state=OwnedStdio::new(7,0x41c0b8,0x41d2e8,[0x24,0],OutputPolicy::Deferred).unwrap();state.write(7,b"x\0",&[],|_|panic!()).unwrap();state.written=usize::MAX;assert!(state.flush(7,|_|panic!("overflow reached sink")).is_err());assert_eq!(state.pending_bytes(),b"x");
}
"#
        );
        let dir = std::env::temp_dir().join(format!("w2l-stdio-effect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("check.rs");
        std::fs::write(&path, source).unwrap();
        let exe = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        let built = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = std::process::Command::new(exe).output().unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
    }
}
