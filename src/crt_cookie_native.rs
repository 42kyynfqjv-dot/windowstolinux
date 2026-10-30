//! Native acquisition for the bounded single-host-process cookie domain.
//! This is not general Windows process identity or a general QPC implementation.
pub(crate) const TYPES: &str = r#"
struct CrtNativeEntropy{anchor:guest_memory::Capability,owner:u64,thread:u64,pid:u32,tid:u32,host_thread:std::thread::ThreadId,origin:std::time::Instant}
fn entropy_filetime_duration(d:std::time::Duration)->Result<u64,&'static str>{
 let seconds=d.as_secs().checked_add(11_644_473_600).ok_or("native FILETIME epoch overflow")?;
 seconds.checked_mul(10_000_000).and_then(|n|n.checked_add(u64::from(d.subsec_nanos()/100))).ok_or("native FILETIME range")
}
fn entropy_counter_duration(d:std::time::Duration)->Result<u64,&'static str>{u64::try_from(d.as_nanos()).map_err(|_|"native counter range")}
fn entropy_proc_identity(pid:u32,path:&std::path::Path)->Result<u32,&'static str>{
 let text=path.to_str().filter(|s|s.len()<=64).ok_or("native procfs thread identity")?;
 let parts:Vec<_>=text.split('/').collect();
 if parts.len()!=3||parts[0]!=pid.to_string()||parts[1]!="task"||parts[2].is_empty()||!parts[2].bytes().all(|b|b.is_ascii_digit()){return Err("native procfs thread identity");}
 let tid=parts[2].parse::<u32>().ok().filter(|n|*n!=0).ok_or("native procfs thread identity")?;
 if parts[2]!=tid.to_string(){return Err("native procfs thread identity");}Ok(tid)
}
fn entropy_host_identity()->Result<(u32,u32),&'static str>{
 #[cfg(target_os="linux")] {
  let pid=std::process::id();if pid==0{return Err("native process identity");}
  let link=std::fs::read_link("/proc/thread-self").map_err(|_|"native procfs unavailable")?;
  Ok((pid,entropy_proc_identity(pid,&link)?))
 }
 #[cfg(not(target_os="linux"))] {Err("native entropy host unsupported")}
}
impl CrtNativeEntropy{
 fn acquire(rt:&CrtStreamRuntime,init:CrtInitialization)->Result<(CrtEntropyInputs,Self),&'static str>{
  rt.initialization(init)?;let(pid,tid)=entropy_host_identity()?;
  let inputs=CrtEntropyInputs::bind(rt,init,pid,tid)?;
  static ORIGIN:std::sync::OnceLock<std::time::Instant>=std::sync::OnceLock::new();
  let origin=*ORIGIN.get_or_init(std::time::Instant::now);
  Ok((inputs,Self{anchor:rt.anchor,owner:rt.owner,thread:rt.thread,pid,tid,host_thread:std::thread::current().id(),origin}))
 }
 fn host(&self)->Result<(),&'static str>{
  if std::thread::current().id()!=self.host_thread||entropy_host_identity()?!=(self.pid,self.tid){return Err("native entropy host lifetime/thread");}Ok(())
 }
}
impl CrtEntropyBackend for CrtNativeEntropy{
 fn validate(&self,rt:&CrtStreamRuntime,inputs:&CrtEntropyInputs)->Result<(),&'static str>{
  inputs.validate(rt)?;
  if self.anchor!=rt.anchor||self.owner!=rt.owner||self.thread!=rt.thread||inputs.process_id!=self.pid||inputs.thread_id!=self.tid{return Err("native entropy runtime binding");}self.host()
 }
 fn filetime(&mut self)->Result<u64,&'static str>{
  self.host()?;let d=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|"native time before Unix epoch unsupported")?;entropy_filetime_duration(d)
 }
 fn counter(&mut self)->Result<u64,&'static str>{
  self.host()?;let d=std::time::Instant::now().checked_duration_since(self.origin).ok_or("native monotonic clock reversed")?;entropy_counter_duration(d)
 }
}
"#;

#[test]
fn native_clock_units_bounds_and_procfs_identity_are_independent() {
    let code = crate::crt_ptd::raw(crate::crt_cookie_init::ENTROPY_CODE);
    let imports = crate::crt_cookie_init::IMPORTS
        .iter()
        .map(|(a, n)| (*a, "kernel32.dll".into(), (*n).into()))
        .collect::<Vec<_>>();
    let source = crate::crt_cookie_init::entropy_source(&code, &imports).unwrap();
    crate::crt_stream_callees_tests::native(
        &source,
        r#"
assert_eq!(entropy_filetime_duration(std::time::Duration::ZERO).unwrap(),116444736000000000);
assert_eq!(entropy_filetime_duration(std::time::Duration::new(1,199)).unwrap(),116444736010000001);
assert_eq!(entropy_filetime_duration(std::time::Duration::new(0,99)).unwrap(),116444736000000000);
assert!(entropy_filetime_duration(std::time::Duration::new(u64::MAX,0)).is_err());
assert_eq!(entropy_counter_duration(std::time::Duration::new(3,17)).unwrap(),3000000017);
assert!(entropy_counter_duration(std::time::Duration::new(u64::MAX,0)).is_err());
for text in ["12/task/0","12/task/-1","12/task/01","12/task/4294967296","13/task/4","12/no/4","/12/task/4","12/task/4/more"]{assert_eq!(entropy_proc_identity(12,std::path::Path::new(text)),Err("native procfs thread identity"));}
assert_eq!(entropy_proc_identity(12,std::path::Path::new("12/task/34")),Ok(34));
#[cfg(target_os="linux")] {
 let(pid,tid)=entropy_host_identity().expect("supported procfs host");assert_eq!(pid,std::process::id());assert_ne!(tid,0);
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();assert!(CrtNativeEntropy::acquire(&rt,CrtInitialization{anchor:rt.anchor,thread:rt.thread,serial:1}).is_err());

}
"#,
        "native-cookie-clock",
    );
}
