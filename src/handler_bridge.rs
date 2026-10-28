//! Original EXCEPTION_POINTERS installation at an explicit handler-entry cut.
//! This proves five MOV/LEA effects, not the preceding cookie/context calls or
//! Windows exception delivery. E/C must carry the containing frame/event proof.
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use std::collections::BTreeSet;

pub(crate) struct InstallerLayout {
    pub handler_start: i32,
    pub handler_end: i32,
    pub owner_start: i32,
    pub owner_end: i32,
    pub writable_handler_words: Vec<i32>,
    pub writable_owner_words: Vec<i32>,
}
pub(crate) struct InstallerProof {
    body: String,
    #[allow(dead_code)] // CRT lowering; other slice examples use the abstract backend.
    live_body: String,
    end: u32,
}
impl InstallerProof {
    #[allow(dead_code)] // CRT lowering; other slice examples use body().
    pub fn live_body(&self) -> &str {
        &self.live_body
    }
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn end(&self) -> u32 {
        self.end
    }
    pub fn owner_pair_offset(&self) -> i32 {
        -20
    }
    pub fn handler_pair_offset(&self) -> i32 {
        -28
    }
}

/// Private generated storage. An opaque identity belongs to one live bridge;
/// its tagged pair cannot be transplanted into another event's memory. Installed
/// views borrow the bridge, so Rust also prevents invalidation while a view lives.
/// This identity is not evidence of a Windows thread or successful prefix calls.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct BridgeIdentity(u64);
static BRIDGE_IDENTITIES:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(1);
#[derive(Clone,Debug,PartialEq,Eq)]
enum BridgeWord {
 Vacant, Scalar(u32), Saved(u8,Option<u32>), Protected,
 Record(BridgeIdentity), Context(BridgeIdentity), Pair(BridgeIdentity,i32),
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum BridgePhase {Fresh,Installing,Installed,Blocked,Revoked}
struct BridgeMemory<E,C> {
 identity:BridgeIdentity, record:E, context:C,
 handler_words:std::collections::BTreeMap<i32,BridgeWord>,
 owner_words:std::collections::BTreeMap<i32,BridgeWord>,
 phase:BridgePhase, eax:BridgeWord,
}
struct InstalledPair<'a,E,C> { memory:&'a BridgeMemory<E,C> }
impl<E,C> BridgeMemory<E,C> {
 fn new(record:E,context:C,handler_words:std::collections::BTreeMap<i32,BridgeWord>,owner_words:std::collections::BTreeMap<i32,BridgeWord>)->Result<Self,&'static str>{
  let mut value=BRIDGE_IDENTITIES.load(std::sync::atomic::Ordering::Relaxed);
  loop {
   let next=value.checked_add(1).ok_or("bridge identity exhausted")?;
   match BRIDGE_IDENTITIES.compare_exchange_weak(value,next,std::sync::atomic::Ordering::Relaxed,std::sync::atomic::Ordering::Relaxed){
    Ok(_)=>break, Err(actual)=>value=actual,
   }
  }
  let identity=BridgeIdentity(value);
  Ok(Self{identity,record,context,handler_words,owner_words,phase:BridgePhase::Fresh,eax:BridgeWord::Record(identity)})
 }
 fn identity(&self)->BridgeIdentity{self.identity}
 fn invalidate(&mut self){self.phase=BridgePhase::Revoked;}
 fn fail<T>(&mut self,message:&'static str)->Result<T,&'static str>{self.phase=BridgePhase::Blocked;Err(message)}
 fn begin_install(&mut self)->Result<(),&'static str>{
  if self.phase!=BridgePhase::Fresh{return self.fail("bridge installation phase");}
  for offset in [-28,-24] {
   if !matches!(self.handler_words.get(&offset),Some(BridgeWord::Vacant|BridgeWord::Scalar(_))){return self.fail("bridge handler word ownership");}
  }
  if !matches!(self.owner_words.get(&-20),Some(BridgeWord::Vacant|BridgeWord::Scalar(_))){return self.fail("bridge owner word ownership");}
  if self.eax!=BridgeWord::Record(self.identity){return self.fail("bridge incoming record identity");}
  self.phase=BridgePhase::Installing;Ok(())
 }
 fn store_handler(&mut self,offset:i32,value:BridgeWord)->Result<(),&'static str>{
  if self.phase!=BridgePhase::Installing{return self.fail("bridge inactive handler write");}
  let required=match offset{-28=>BridgeWord::Record(self.identity),-24=>BridgeWord::Context(self.identity),_=>return self.fail("bridge handler write bounds")};
  if value!=required || !matches!(self.handler_words.get(&offset),Some(BridgeWord::Vacant|BridgeWord::Scalar(_))){return self.fail("bridge handler alias or initialization");}
  self.handler_words.insert(offset,value);Ok(())
 }
 fn context_argument(&mut self)->Result<BridgeWord,&'static str>{
  if self.phase!=BridgePhase::Installing{return self.fail("bridge inactive context read");}
  Ok(BridgeWord::Context(self.identity))
 }
 fn pair_address(&mut self,offset:i32)->Result<BridgeWord,&'static str>{
  if self.phase!=BridgePhase::Installing || offset!=-28{return self.fail("bridge pair address bounds");}
  Ok(BridgeWord::Pair(self.identity,offset))
 }
 fn store_owner(&mut self,offset:i32,value:BridgeWord)->Result<(),&'static str>{
  if self.phase!=BridgePhase::Installing || offset!=-20 || value!=BridgeWord::Pair(self.identity,-28){return self.fail("bridge owner pointer binding");}
  if !matches!(self.owner_words.get(&offset),Some(BridgeWord::Vacant|BridgeWord::Scalar(_))){return self.fail("bridge owner alias or initialization");}
  self.owner_words.insert(offset,value);Ok(())
 }
 fn finish_install(&mut self)->Result<InstalledPair<'_,E,C>,&'static str>{
  if self.phase!=BridgePhase::Installing
   || self.handler_words.get(&-28)!=Some(&BridgeWord::Record(self.identity))
   || self.handler_words.get(&-24)!=Some(&BridgeWord::Context(self.identity))
   || self.owner_words.get(&-20)!=Some(&BridgeWord::Pair(self.identity,-28))
   || self.eax!=BridgeWord::Pair(self.identity,-28) {return self.fail("bridge incomplete original installation");}
  self.phase=BridgePhase::Installed;Ok(InstalledPair{memory:self})
 }
 fn installed(&self,identity:BridgeIdentity)->Result<InstalledPair<'_,E,C>,&'static str>{
  if self.phase!=BridgePhase::Installed || identity!=self.identity{return Err("bridge wrong owner or expired pair");}
  if self.handler_words.get(&-28)!=Some(&BridgeWord::Record(identity))
   || self.handler_words.get(&-24)!=Some(&BridgeWord::Context(identity))
   || self.owner_words.get(&-20)!=Some(&BridgeWord::Pair(identity,-28)) {return Err("bridge stale pointer graph");}
  Ok(InstalledPair{memory:self})
 }
}
impl<E,C> InstalledPair<'_,E,C> {
 fn record(&self,identity:BridgeIdentity)->Result<&E,&'static str>{
  self.memory.installed(identity)?;Ok(&self.memory.record)
 }
 fn context(&self,identity:BridgeIdentity)->Result<&C,&'static str>{
  self.memory.installed(identity)?;Ok(&self.memory.context)
 }
}
"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    Record,
    Context,
    Pair,
}
fn words(start: i32, end: i32, writable: &[i32], required: &[i32]) -> Result<(), String> {
    if start < -4096 || end > 0 || start >= end || writable.len() > 64 {
        return Err("bridge: bounded frame extent".into());
    }
    let mut seen = BTreeSet::new();
    for &offset in writable {
        if offset % 4 != 0
            || offset < start
            || offset.checked_add(4).is_none_or(|last| last > end)
            || !seen.insert(offset)
        {
            return Err("bridge: partial or aliased writable word".into());
        }
    }
    if required.iter().any(|at| !seen.contains(at)) {
        return Err("bridge: missing proved writable word".into());
    }
    Ok(())
}

/// The containing proof provides disjoint live handler/owner frame maps and
/// same-event exception/context objects. EBX is the establisher record and the
/// owner's EBP is record+16. This fragment does not establish those entry facts.
pub(crate) fn prove_installer(
    code: &[u8],
    origin: u32,
    layout: &InstallerLayout,
) -> Result<InstallerProof, String> {
    words(
        layout.handler_start,
        layout.handler_end,
        &layout.writable_handler_words,
        &[-28, -24],
    )?;
    words(
        layout.owner_start,
        layout.owner_end,
        &layout.writable_owner_words,
        &[-20],
    )?;
    if code.is_empty() || code.len() > 128 {
        return Err("bridge: instruction extent".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("bridge: instruction address overflow")?;
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut eax = Value::Record;
    let mut record = false;
    let mut context = false;
    let mut installed = false;
    let mut body = String::from("state.begin_install()?;\n");
    let mut live_body = String::from("pair.validate(frame,cpu)?;\n");
    let mut count = 0;
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        if i.is_invalid()
            || count > 8
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.memory_index() != Register::None
        {
            return Err("bridge: unsupported instruction or address policy".into());
        }
        match i.code() {
            Code::Mov_rm32_r32
                if i.op0_kind() == OpKind::Memory && i.op1_register() == Register::EAX =>
            {
                let offset = i.memory_displacement32() as i32;
                match (i.memory_base(), offset, eax) {
                    (Register::EBP, -28, Value::Record) if !record => {
                        record = true;
                        live_body.push_str("pair.store(frame,cpu,-28,cpu.r[0])?;\n");
                        body.push_str("state.store_handler(-28,state.eax.clone())?;\n");
                    }
                    (Register::EBP, -24, Value::Context) if !context => {
                        context = true;
                        live_body.push_str("pair.store(frame,cpu,-24,cpu.r[0])?;\n");
                        body.push_str("state.store_handler(-24,state.eax.clone())?;\n");
                    }
                    (Register::EBX, -4, Value::Pair) if record && context && !installed => {
                        installed = true;
                        live_body.push_str("pair.install(frame,cpu,cpu.r[0])?;\n");
                        body.push_str("state.store_owner(-20,state.eax.clone())?;\n");
                    }
                    _ => return Err("bridge: unsupported pointer store/ownership/order".into()),
                }
            }
            Code::Mov_r32_rm32
                if i.op0_register() == Register::EAX
                    && i.op1_kind() == OpKind::Memory
                    && i.memory_base() == Register::EBP
                    && i.memory_displacement32() == 16 =>
            {
                eax = Value::Context;
                live_body.push_str("cpu.r[0]=pair.context_argument(frame,cpu)?;\n");
                body.push_str("state.eax=state.context_argument()?;\n");
            }
            Code::Lea_r32_m
                if i.op0_register() == Register::EAX
                    && i.memory_base() == Register::EBP
                    && i.memory_displacement32() as i32 == -28 =>
            {
                eax = Value::Pair;
                live_body.push_str("cpu.r[0]=CrtValue::Pointer(pair.low);\n");
                body.push_str("state.eax=state.pair_address(-28)?;\n");
            }
            _ => return Err("bridge: unproved effect or saved-register write".into()),
        }
    }
    if !record || !context || !installed || eax != Value::Pair {
        return Err("bridge: incomplete pointer graph installation".into());
    }
    body.push_str("state.finish_install()\n");
    live_body.push_str("pair.read(frame,cpu).map(|_|())\n");
    Ok(InstallerProof {
        body,
        live_body,
        end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes() -> Vec<u8> {
        vec![
            0x89, 0x45, 0xe4, 0x8b, 0x45, 0x10, 0x89, 0x45, 0xe8, 0x8d, 0x45, 0xe4, 0x89, 0x43,
            0xfc,
        ]
    }
    fn layout() -> InstallerLayout {
        InstallerLayout {
            handler_start: -28,
            handler_end: 0,
            owner_start: -800,
            owner_end: 0,
            writable_handler_words: vec![-28, -24],
            writable_owner_words: vec![-20],
        }
    }
    #[test]
    fn original_instructions_install_only_owned_typed_pair_and_preserve_other_words() {
        let proof = prove_installer(&bytes(), 0x402263, &layout()).unwrap();
        assert_eq!(proof.end(), 0x402272);
        assert_eq!(proof.handler_pair_offset(), -28);
        assert_eq!(proof.owner_pair_offset(), -20);
        assert_eq!(
            proof.body(),
            prove_installer(&bytes(), 0x402263, &layout())
                .unwrap()
                .body()
        );
        let source = format!(
            r#"#![allow(dead_code)]
{EMITTED_TYPES}
fn install<E,C>(state:&mut BridgeMemory<E,C>)->Result<InstalledPair<'_,E,C>,&'static str>{{{}}}
fn fresh(event:u32)->BridgeMemory<u32,[u32;3]>{{
 BridgeMemory::new(event,[101,202,303],std::collections::BTreeMap::from([(-28,BridgeWord::Vacant),(-24,BridgeWord::Scalar(999)),(-12,BridgeWord::Saved(3,Some(777)))]),std::collections::BTreeMap::from([(-20,BridgeWord::Vacant),(-8,BridgeWord::Protected)])).unwrap()
}}
fn main(){{
 let mut state=fresh(0xe0424242);let id=state.identity();
 {{let pair=install(&mut state).unwrap();assert_eq!(*pair.record(id).unwrap(),0xe0424242);assert_eq!(*pair.context(id).unwrap(),[101,202,303]);}}
 assert_eq!(state.handler_words[&-12],BridgeWord::Saved(3,Some(777)));assert_eq!(state.owner_words[&-8],BridgeWord::Protected);
 let other=fresh(88);assert!(state.installed(other.identity()).is_err());
 let snapshot=state.handler_words.clone();assert!(install(&mut state).is_err());assert_eq!(state.handler_words,snapshot);assert!(state.installed(id).is_err());
 let mut expired=fresh(19);let stale=expired.identity();install(&mut expired).unwrap();expired.invalidate();assert!(expired.installed(stale).is_err());
 let mut missing=fresh(99);missing.handler_words.remove(&-24);assert!(install(&mut missing).is_err());assert_eq!(missing.owner_words[&-20],BridgeWord::Vacant);
 let mut protected=fresh(99);protected.owner_words.insert(-20,BridgeWord::Saved(5,Some(99)));assert!(install(&mut protected).is_err());assert_eq!(protected.handler_words[&-28],BridgeWord::Vacant);
 let mut transplanted=fresh(5);transplanted.eax=BridgeWord::Record(id);assert!(install(&mut transplanted).is_err());
 let mut corrupt=fresh(8);let identity=corrupt.identity();install(&mut corrupt).unwrap();corrupt.handler_words.insert(-24,BridgeWord::Context(id));assert!(corrupt.installed(identity).is_err());
}}
"#,
            proof.body()
        );
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("w2l-handler-bridge-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("test.rs");
        let binary = dir.join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::write(&path, source).unwrap();
        let result = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&path)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result = std::process::Command::new(&binary).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn independently_mutated_pointer_offsets_saved_registers_and_incomplete_code_reject() {
        for (offset, value) in [
            (2, 0xe0),
            (5, 12),
            (8, 0xe4),
            (11, 0xe8),
            (14, 0xf8),
            (1, 0x4d),
            (4, 0x5d),
            (10, 0x4d),
        ] {
            let mut code = bytes();
            code[offset] = value;
            assert!(
                prove_installer(&code, 0x1000, &layout()).is_err(),
                "accepted byte {offset}"
            );
        }
        for prefix in [0x66, 0x67, 0x64, 0xf0, 0xf2, 0xf3] {
            let mut code = vec![prefix];
            code.extend(bytes());
            assert!(prove_installer(&code, 0x1000, &layout()).is_err());
        }
        for end in 0..bytes().len() {
            assert!(prove_installer(&bytes()[..end], 0x1000, &layout()).is_err());
        }
        let mut extra = bytes();
        extra.push(0xc3);
        assert!(prove_installer(&extra, 0x1000, &layout()).is_err());
        assert!(prove_installer(&bytes(), u32::MAX - 2, &layout()).is_err());
    }
    #[test]
    fn complete_word_bounds_and_nonaliased_writable_regions_are_required() {
        let mut l = layout();
        l.handler_start = -27;
        assert!(prove_installer(&bytes(), 1, &l).is_err());
        let mut l = layout();
        l.owner_end = -18;
        assert!(prove_installer(&bytes(), 1, &l).is_err());
        let mut l = layout();
        l.writable_handler_words.push(-28);
        assert!(prove_installer(&bytes(), 1, &l).is_err());
        let mut l = layout();
        l.writable_owner_words.clear();
        assert!(prove_installer(&bytes(), 1, &l).is_err());
        let mut l = layout();
        l.writable_handler_words.push(-2);
        assert!(prove_installer(&bytes(), 1, &l).is_err());
    }
}
