//! Native registry lifecycle tests. No Windows loader or API result is inferred.
use crate::crt_stream_callees_tests::native;

#[test]
fn native_provider_publication_is_owned_and_initialization_failure_is_atomic() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();
let before=r.serial;assert!(r.provider_begin(i,"Alpha",0x700000,0).is_err());assert_eq!(r.serial,before);assert!(r.providers.is_empty());
let t=r.provider_begin(i,"Alpha",0x700000,2).unwrap();assert!(r.modules.is_empty());assert!(r.module_acquire_result(i,"Alpha",0x700000).is_err());
assert!(r.provider_begin(i,"aLPHa",0x710000,1).is_err());assert!(r.provider_begin(i,"Beta",0x700000,1).is_err());
let(mut other,oi)=CrtStreamRuntime::new_initializing(17,23,0x8000,65536).unwrap();assert!(other.provider_publish(oi,&t).is_err());assert!(other.providers.is_empty());
// A real intervening namespace mutation must make publication reject, retaining it.
let(collision,cr)=r.module_acquire_result(i,"ALPHA",0x720000).unwrap();let n=r.module_references.len();
assert_eq!(r.provider_publish(i,&t),Err("CRT provider publication identity collision"));assert_eq!(r.module_references.len(),n);r.module_identity(collision).unwrap();assert!(r.providers[&0x700000].root.is_none());
r.module_release_result(i,cr,true).unwrap();let m=r.provider_publish(i,&t).unwrap();assert!(r.provider_publish(i,&t).is_err());assert!(r.provider_abort(i,&t).is_err());
let root=r.providers[&m.handle].root.unwrap();assert_eq!(r.module_release_result(i,root,true),Err("CRT process provider root is not a load reference"));
let (_,load)=r.module_acquire_result(i,"Alpha",m.handle).unwrap();assert_eq!(r.module_references.len(),2);assert_eq!(r.provider_destroy(i,m),Err("CRT provider still acquired/borrowed"));
r.module_release_result(i,load,true).unwrap();r.provider_destroy(i,m).unwrap();assert!(r.module_identity(m).is_err());assert!(r.provider_destroy(i,m).is_err());
let new=r.provider_begin(i,"Alpha",0x700000,1).unwrap();assert!(r.provider_publish(i,&t).is_err());r.provider_abort(i,&new).unwrap();assert!(r.provider_abort(i,&new).is_err());assert!(r.providers.is_empty());
"#,
        "provider-publication",
    );
}

#[test]
fn native_provider_forwarded_exports_borrow_the_actual_target_until_source_retirement() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
let a=r.provider_begin(i,"IndependentFrontend",0x700000,3).unwrap();let a=r.provider_publish(i,&a).unwrap();
let b=r.provider_begin(i,"IndependentBackend",0x720000,3).unwrap();let b=r.provider_publish(i,&b).unwrap();
let f=r.provider_export(i,a,b,"ForwardedOperation",0x721000).unwrap();assert_eq!(f.record.module,a);assert_eq!(r.provider_target(f).unwrap(),b);assert_eq!(r.module_references.len(),2);
assert_eq!(r.provider_destroy(i,b),Err("CRT provider still acquired/borrowed"));assert_eq!(r.provider_target(f).unwrap(),b);assert_eq!(r.function_identity(f.record,Some("ForwardedOperation")),Err("CRT native provider export implementation unbound"));
let count=r.exports.len();assert_eq!(r.provider_export(i,b,a,"BackEdge",0x701000),Err("CRT provider dependency cycle"));assert_eq!(r.exports.len(),count);
assert!(r.provider_export(i,a,b,"ForwardedOperation",0x722000).is_err());assert!(r.module_export_result(i,a,"Bypass",0x702000).is_err());
let self_fn=r.provider_export(i,b,b,"LocalOperation",0x722000).unwrap();assert_eq!(r.provider_target(self_fn).unwrap(),b);
let mut forged=f;forged.record.module=b;assert!(r.provider_target(forged).is_err());
r.provider_destroy(i,a).unwrap();assert!(r.provider_target(f).is_err());r.provider_target(self_fn).unwrap();r.provider_destroy(i,b).unwrap();assert!(r.provider_target(self_fn).is_err());
let b2=r.provider_begin(i,"IndependentBackend",b.handle,1).unwrap();let b2=r.provider_publish(i,&b2).unwrap();assert_ne!(b,b2);assert!(r.provider_target(f).is_err());assert!(r.provider_export(i,b2,b,"StaleTarget",0x721000).is_err());
"#,
        "provider-forwarding",
    );
}

#[test]
fn native_provider_export_and_publication_limits_preserve_prior_effects() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let data=r.map_region(0x9000,4,CrtRegionKind::Module,None).unwrap();r.store(data,32,CrtValue::scalar(73)).unwrap();
let t=r.provider_begin(i,"Bounded",0x700000,1).unwrap();let saved=r.serial;r.serial=u64::MAX;
assert_eq!(r.provider_publish(i,&t),Err("CRT provider serial"));assert!(r.modules.is_empty());assert!(r.module_references.is_empty());assert_eq!(r.load(data,32).unwrap(),CrtValue::scalar(73));r.serial=saved;
let m=r.provider_publish(i,&t).unwrap();let f=r.provider_export(i,m,m,"One",0x701000).unwrap();let serial=r.serial;
assert!(r.provider_export(i,m,m,"Two",0x701100).is_err());assert_eq!(r.serial,serial);assert_eq!(r.providers[&m.handle].exports,vec![f.record.serial]);r.provider_target(f).unwrap();
let(_,reference)=r.module_acquire_result(i,"Bounded",m.handle).unwrap();assert_eq!(r.module_release_result(i,reference,false),Err("CRT failed release effects unclosed"));assert!(r.provider_target(f).is_err());assert!(r.provider_destroy(i,m).is_err());assert_eq!(r.load(data,32).unwrap(),CrtValue::scalar(73));
"#,
        "provider-failure-order",
    );
}

#[test]
fn native_provider_builds_cannot_outlive_their_thread_or_initialization_phase() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let t=r.provider_begin(i,"Owner",0x700000,1).unwrap();
r.thread=4;assert!(r.provider_publish(i,&t).is_err());assert!(r.provider_abort(i,&t).is_err());r.thread=3;
assert!(r.end_initialization(i).is_err());r.provider_abort(i,&t).unwrap();r.end_initialization(i).unwrap();assert!(r.provider_publish(i,&t).is_err());
"#,
        "provider-initialization-lifetime",
    );
}

#[test]
fn native_provider_descriptors_cannot_be_transportable_call_authority() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
let t=r.provider_begin(i,"UnimplementedProvider",0x700000,2).unwrap();let m=r.provider_publish(i,&t).unwrap();
let descriptor=r.provider_export(i,m,m,"FlsGetValue",0x701000).unwrap();
let cell=r.map_region(0x9000,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();r.bind_loader_cell(i,cell,true).unwrap();
assert_eq!(r.function_identity(descriptor.record,Some("FlsGetValue")),Err("CRT native provider export implementation unbound"));
assert_eq!(r.store(cell,32,CrtValue::Function(descriptor.record)),Err("CRT native provider export implementation unbound"));
assert_eq!(r.exchange_module_word(cell,CrtValue::Function(descriptor.record)),Err("CRT native provider export implementation unbound"));
assert_eq!(r.load(cell,32).unwrap(),CrtValue::scalar(0));assert_eq!(r.provider_target(descriptor).unwrap(),m);
r.provider_destroy(i,m).unwrap();assert!(r.provider_target(descriptor).is_err());
"#,
        "provider-call-authority",
    );
}

#[test]
fn native_provider_failed_target_release_does_not_borrow_source_authority() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
let a=r.provider_begin(i,"Source",0x700000,1).unwrap();let a=r.provider_publish(i,&a).unwrap();
let b=r.provider_begin(i,"Target",0x720000,1).unwrap();let b=r.provider_publish(i,&b).unwrap();
let f=r.provider_export(i,a,b,"Operation",0x721000).unwrap();let(_,reference)=r.module_acquire_result(i,"Target",b.handle).unwrap();
assert_eq!(r.module_release_result(i,reference,false),Err("CRT failed release effects unclosed"));
r.module_identity(a).unwrap();assert!(r.module_identity(b).is_err());assert!(r.provider_target(f).is_err());
assert_eq!(r.exports.len(),1);assert_eq!(r.module_references.len(),3);assert!(r.provider_export(i,a,a,"Replacement",0x701000).is_err());
assert!(r.provider_destroy(i,b).is_err());
"#,
        "provider-stale-target",
    );
}

#[test]
fn native_sync_binding_initializes_real_opaque_recursive_lock_and_preserves_failures() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
let t=r.provider_begin(i,"IndependentSynchronization",0x700000,2).unwrap();let m=r.provider_publish(i,&t).unwrap();
let wrong=r.provider_export(i,m,m,"DifferentOperation",0x701000).unwrap();assert!(r.bind_native_sync(i,wrong).is_err());
let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x702000).unwrap();let f=r.bind_native_sync(i,d).unwrap();assert!(r.bind_native_sync(i,d).is_err());r.native_sync_identity(f).unwrap();
let p=r.map_region(0x9000,48,CrtRegionKind::Module,Some(&[73;48])).unwrap();
assert!(r.native_sync_initialize(i,f,7,p,4000,1).is_err());assert_eq!(r.load(p,8).unwrap(),CrtValue::scalar(73));assert!(r.native_sync.is_empty());
assert_eq!(r.native_sync_initialize(i,f,7,p,4000,0),Ok(1));assert!(r.load(p,8).is_err());assert!(r.store(r.offset(p,4).unwrap(),32,CrtValue::scalar(0)).is_err());
assert_eq!(r.load(r.offset(p,24).unwrap(),8).unwrap(),CrtValue::scalar(73));assert!(r.native_sync_initialize(i,f,8,r.offset(p,4).unwrap(),0,0).is_err());
assert!(r.native_sync_initialize(i,f,7,p,0,0).is_err());assert!(r.provider_destroy(i,m).is_err());
let a=r.lock_global(3,7).unwrap();let b=r.lock_global(3,7).unwrap();assert!(r.lock_global(4,7).is_err());assert!(r.native_sync_delete(i,f,7,p).is_err());
r.unlock_global(b).unwrap();r.unlock_global(a).unwrap();r.native_sync_delete(i,f,7,p).unwrap();assert!(r.lock_global(3,7).is_err());assert!(r.native_sync_delete(i,f,7,p).is_err());
assert_eq!(r.native_sync_initialize(i,f,7,p,0,0),Ok(1));r.thread=4;assert!(r.native_sync_delete(i,f,7,p).is_err());r.thread=3;r.native_sync_delete(i,f,7,p).unwrap();r.provider_destroy(i,m).unwrap();assert!(r.native_sync_identity(f).is_err());
"#,
        "native-sync-semantics",
    );
}

#[test]
fn native_sync_rejects_observed_symbol_wrong_runtime_and_protected_alias() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let p=r.map_region(0x9000,24,CrtRegionKind::Module,Some(&[19;24])).unwrap();
let(m,_)=r.module_acquire_result(i,"ObservedOnly",0x700000).unwrap();let f=r.module_export_result(i,m,"InitializeCriticalSectionEx",0x701000).unwrap();assert!(r.native_sync_initialize(i,f,0,p,0,0).is_err());
let t=r.provider_begin(i,"Native",0x720000,1).unwrap();let m=r.provider_publish(i,&t).unwrap();let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x721000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
let(mut other,oi)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();assert!(other.native_sync_initialize(oi,f,0,p,0,0).is_err());
r.store(p,32,CrtValue::Pointer(r.file())).unwrap();assert!(r.native_sync_initialize(i,f,0,p,0,0).is_err());assert_eq!(r.load(p,32).unwrap(),CrtValue::Pointer(r.file()));assert!(r.native_sync.is_empty());
let short=r.subrange(r.offset(p,4).unwrap(),16).unwrap();assert!(r.native_sync_initialize(i,f,0,short,0,0).is_err());assert!(r.global_objects.is_empty());
"#,
        "native-sync-rejections",
    );
}

#[test]
fn native_sync_stdcall_checks_protected_return_before_effect_and_cleans_three_arguments() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let p=r.map_region(0x9000,24,CrtRegionKind::Module,Some(&[71;24])).unwrap();
let t=r.provider_begin(i,"Synchronization",0x700000,1).unwrap();let m=r.provider_publish(i,&t).unwrap();let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x701000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
let sp=r.map_region(0xa000,64,CrtRegionKind::Stack,None).unwrap();r.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();r.store(r.offset(sp,4).unwrap(),32,CrtValue::Pointer(p)).unwrap();r.store(r.offset(sp,8).unwrap(),32,CrtValue::scalar(4000)).unwrap();r.store(r.offset(sp,12).unwrap(),32,CrtValue::scalar(0)).unwrap();
let mut c=CrtCpu::new(sp,77).unwrap();c.return_pop=12;c.return_id=78;assert!(c.native_sync_call(&mut r,i,f,3).is_err());assert!(r.global_objects.is_empty());assert_eq!(r.load(p,8).unwrap(),CrtValue::scalar(71));
c.return_id=77;assert_eq!(c.native_sync_call(&mut r,i,f,3),Ok(CrtValue::scalar(1)));assert!(c.returned);assert_eq!(CrtCpu::pointer(c.r[4]).unwrap().address(),0xa010);assert!(c.native_sync_call(&mut r,i,f,3).is_err());
r.native_sync_delete(i,f,3,p).unwrap();r.provider_destroy(i,m).unwrap();
"#,
        "native-sync-stdcall",
    );
}

#[test]
fn native_sync_conformance_spins() {
    native(
        "",
        r#"
for spin in [0u32,4000] {
 let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
 let t=r.provider_begin(i,"ConformanceSynchronization",0x700000,1).unwrap();let m=r.provider_publish(i,&t).unwrap();let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x701000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
 let region=r.map_region(0x9000,32,CrtRegionKind::Module,Some(&[0;32])).unwrap();let lock=r.offset(region,4).unwrap();r.store(region,32,CrtValue::scalar(0x13579bdf)).unwrap();let tail=r.offset(region,28).unwrap();r.store(tail,32,CrtValue::scalar(0x2468ace0)).unwrap();
 let mut events=Vec::new();assert_ne!(r.native_sync_initialize(i,f,3,lock,spin,0).unwrap(),0);events.push(1);
 let a=r.lock_global(3,3).unwrap();events.push(2);let b=r.lock_global(3,3).unwrap();events.push(2);let c=r.lock_global(3,3).unwrap();events.push(3);
 r.unlock_global(c).unwrap();events.push(4);r.unlock_global(b).unwrap();events.push(4);r.unlock_global(a).unwrap();events.push(4);r.native_sync_delete(i,f,3,lock).unwrap();events.push(5);
 assert_ne!(r.native_sync_initialize(i,f,3,lock,spin,0).unwrap(),0);events.push(1);r.native_sync_delete(i,f,3,lock).unwrap();events.push(5);
 let canaries=r.load(region,32).unwrap()==CrtValue::scalar(0x13579bdf)&&r.load(tail,32).unwrap()==CrtValue::scalar(0x2468ace0);assert!(canaries);assert_eq!(events,vec![1,2,2,3,4,4,4,5,1,5]);
 if let Ok(out)=std::env::var("W2L_SYNC_OUTPUT"){std::fs::write(std::path::Path::new(&out).join(format!("native-{spin}.json")),format!("{{\"initialized\":true,\"events\":{events:?},\"reinitialized\":true,\"canaries\":{canaries}}}")).unwrap();}
 r.provider_destroy(i,m).unwrap();
}
"#,
        "native-sync-conformance",
    );
}

#[test]
fn native_sync_fixed_storage_survives_allocator_denial_and_full_capacity() {
    native(
        r#"
struct RejectingAllocator;
static DENY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static ATTEMPTS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for RejectingAllocator {
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){ATTEMPTS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::ptr::null_mut()}else{std::alloc::System.alloc(l)}}
 unsafe fn alloc_zeroed(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){ATTEMPTS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::ptr::null_mut()}else{std::alloc::System.alloc_zeroed(l)}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){ATTEMPTS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);std::ptr::null_mut()}else{std::alloc::System.realloc(p,l,n)}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){std::alloc::System.dealloc(p,l)}
}
#[global_allocator] static ALLOCATOR:RejectingAllocator=RejectingAllocator;
"#,
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();
let t=r.provider_begin(i,"FixedResource",0x700000,1).unwrap();let m=r.provider_publish(i,&t).unwrap();let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x701000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
let p=r.map_region(0x9000,33*24,CrtRegionKind::Module,Some(&[73;33*24])).unwrap();
let alias=r.map_region(0xa000,24,CrtRegionKind::Module,None).unwrap();r.store(alias,32,CrtValue::Pointer(r.file())).unwrap();
let collision=r.map_region(0xb000,24,CrtRegionKind::Module,None).unwrap();r.store(collision,32,CrtValue::Pointer(r.file())).unwrap();r.tags.insert(collision.address()+1,CrtValue::Pointer(r.file()));
let sp=r.map_region(0xc000,64,CrtRegionKind::Stack,None).unwrap();r.store(sp,32,CrtValue::ProtectedReturn(717)).unwrap();r.store(r.offset(sp,4).unwrap(),32,CrtValue::Pointer(p)).unwrap();r.store(r.offset(sp,8).unwrap(),32,CrtValue::scalar(0)).unwrap();r.store(r.offset(sp,12).unwrap(),32,CrtValue::scalar(0)).unwrap();let mut cpu=CrtCpu::new(sp,717).unwrap();cpu.return_pop=12;
DENY.store(true,std::sync::atomic::Ordering::SeqCst);
let result=(||->Result<(),&'static str>{
 // The same allocation-denied harness verifies the independent FLS producer.
 for n in 0..64{let id=r.native_fls_allocate(i,None)?;assert_eq!(id.index,n);}
 let saved=r.serial;r.last_os_error=Some(87);
 assert_eq!(r.native_fls_allocate(i,None),Err("CRT native FLS index capacity"));
 assert_eq!(r.serial,saved);assert_eq!(r.last_os_error,Some(87));assert_eq!(r.fls_indices.len(),64);assert!(r.fls.is_empty());
 let old=r.fls_indices.get(&11).unwrap().id;r.fls_free_index_result(i,old,true)?;
 let next=r.native_fls_allocate(i,None)?;assert_eq!(next.index,11);assert_ne!(old,next);assert!(r.fls_index(old).is_err());
 // A typed-alias rejection must also avoid allocating an overlap vector.
 assert_eq!(r.native_sync_initialize(i,f,0,alias,0,0),Err("CRT synchronization flags/object domain"));
 assert_eq!(r.load(alias,8),Err("CRT partial typed-word read"));assert_eq!(r.load(r.offset(alias,1)?,32),Err("CRT partial typed-word read"));assert_eq!(r.load(collision,32),Err("CRT partial typed-word read"));
 for index in 0..32 {let q=r.offset(p,i64::from(index)*24)?;assert_eq!(r.native_sync_initialize(i,f,index,q,0,0)?,1);}
 assert_eq!(r.global_objects.values().count(),32);assert_eq!(r.native_sync.values().count(),32);
 let extra=r.offset(p,32*24)?;r.last_os_error=Some(1234);
 assert_eq!(r.native_sync_initialize(i,f,32,extra,0,0),Err("CRT synchronization flags/object domain"));assert_eq!(r.last_os_error,Some(1234));
 let mut leases=[None;32];for lease in &mut leases{*lease=Some(r.lock_global(3,17)?);}
 let serial=r.serial;assert_eq!(r.lock_global(3,17),Err("CRT global lock thread/budget"));assert_eq!(r.serial,serial);
 assert_eq!(r.native_sync_delete(i,f,17,r.offset(p,17*24)?),Err("CRT live global lock destruction"));
 for lease in leases.into_iter().rev(){r.unlock_global(lease.unwrap())?;}
 // Sparse removal/reuse must preserve the other 31 source/target borrows.
 r.native_sync_delete(i,f,17,r.offset(p,17*24)?)?;assert_eq!(r.native_sync.values().count(),31);
 assert_eq!(r.native_sync_initialize(i,f,17,r.offset(p,17*24)?,4000,0)?,1);
 for index in (0..32).rev(){r.native_sync_delete(i,f,index,r.offset(p,i64::from(index)*24)?)?;}
 assert_eq!(cpu.native_sync_call(&mut r,i,f,0)?,CrtValue::scalar(1));assert!(cpu.returned);assert_eq!(CrtCpu::pointer(cpu.r[4])?.address(),0xc010);
 assert!(cpu.native_sync_call(&mut r,i,f,0).is_err());r.native_sync_delete(i,f,0,p)?;
 Ok(())})();
DENY.store(false,std::sync::atomic::Ordering::SeqCst);
result.unwrap();assert_eq!(ATTEMPTS.load(std::sync::atomic::Ordering::SeqCst),0);assert!(r.global_objects.is_empty());assert!(r.native_sync.is_empty());assert!(r.global_locks.is_empty());
assert_eq!(r.load(r.offset(p,32*24).unwrap(),8).unwrap(),CrtValue::scalar(73));assert_eq!(r.load(alias,32).unwrap(),CrtValue::Pointer(r.file()));r.provider_destroy(i,m).unwrap();
"#,
        "native-sync-fixed-resource",
    );
}

#[test]
fn native_sync_partial_construction_preserves_prior_objects_and_error_order() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let t=r.provider_begin(i,"PartialResource",0x700000,1).unwrap();let m=r.provider_publish(i,&t).unwrap();let d=r.provider_export(i,m,m,"InitializeCriticalSectionEx",0x701000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
let first=r.map_region(0x9000,24,CrtRegionKind::Module,Some(&[61;24])).unwrap();let second=r.map_region(0xa000,24,CrtRegionKind::Module,Some(&[62;24])).unwrap();
assert_eq!(r.native_sync_initialize(i,f,4,first,0,0),Ok(1));let token=r.lock_global(3,4).unwrap();
r.last_os_error=Some(91);let short=r.subrange(second,20).unwrap();assert!(r.native_sync_initialize(i,f,5,short,0,0).is_err());assert_eq!(r.last_os_error,Some(91));assert_eq!(r.load(second,8).unwrap(),CrtValue::scalar(62));r.check_global(token).unwrap();assert_eq!(r.global_objects.values().count(),1);assert_eq!(r.native_sync.values().count(),1);
// Permissions fail before forgetting bytes, publishing tracking or changing error knowledge.
let cap=r.memory.map_image(0xb000,24,r.owner,guest_memory::Permissions::READ,&[63;24]).unwrap();let readonly=CrtPointer{cap,owner:guest_memory::Owner::Module(r.owner),base:0xb000,size:24,address:0xb000,kind:CrtRegionKind::Module};r.regions.push(CrtRegion{pointer:readonly,heap:false,file_owner:None});assert_eq!(r.native_sync_initialize(i,f,5,readonly,0,0),Err("CRT synchronization writable range"));assert_eq!(r.last_os_error,Some(91));assert_eq!(r.load(second,8).unwrap(),CrtValue::scalar(62));
r.unlock_global(token).unwrap();r.native_sync_delete(i,f,4,first).unwrap();assert!(r.check_global(token).is_err());assert_eq!(r.native_sync_initialize(i,f,4,first,0,0),Ok(1));assert!(r.check_global(token).is_err());
// Mapping retirement cannot silently free the borrow or make a stale object callable.
r.memory.release(first.cap,first.owner).unwrap();assert!(r.native_sync_delete(i,f,4,first).is_err());assert!(r.provider_destroy(i,m).is_err());assert_eq!(r.native_sync.values().count(),1);assert_eq!(r.global_objects.values().count(),1);
"#,
        "native-sync-partial-resource",
    );
}

#[test]
fn native_provider_initializer_rolls_back_only_owned_pending_state() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let data=r.map_region(0x9000,4,CrtRegionKind::Module,None).unwrap();r.store(data,32,CrtValue::scalar(73)).unwrap();r.last_os_error=Some(1114);
let old=r.provider_begin(i,"Unrelated",0x710000,1).unwrap();let old=r.provider_publish(i,&old).unwrap();
for address in [0,u32::MAX]{let ticket=r.provider_begin(i,"Failed",0x700000,1).unwrap();let serial=r.serial;assert_eq!(r.provider_initialize_sync(i,&ticket,address),Err("CRT native provider initialization bounds"));assert_eq!(r.serial,serial);assert!(!r.providers.contains_key(&0x700000));assert!(!r.modules.contains_key(&0x700000));assert!(r.exports.is_empty());assert!(r.provider_publish(i,&ticket).is_err());assert_eq!(r.last_os_error,Some(1114));r.module_identity(old).unwrap();assert_eq!(r.load(data,32).unwrap(),CrtValue::scalar(73));}
// Reject a corrupted construction limit after root publication, then retire
// only this attempt; monotonic serials must not revive the failed ticket.
let partial=r.provider_begin(i,"Partial",0x730000,1).unwrap();r.providers.get_mut(&partial.handle).unwrap().limit=0;let before=r.serial;assert_eq!(r.provider_initialize_sync(i,&partial,0x731000),Err("CRT provider export bounds/duplicate"));assert!(r.serial>before);assert!(!r.modules.contains_key(&partial.handle));assert!(!r.providers.contains_key(&partial.handle));assert!(!r.module_references.values().any(|x|x.module.handle==partial.handle));assert!(r.exports.is_empty());assert_eq!(r.last_os_error,Some(1114));assert_eq!(r.load(data,32).unwrap(),CrtValue::scalar(73));r.module_identity(old).unwrap();
// Intervening identity collision is not this transaction's property to undo.
let t=r.provider_begin(i,"Collision",0x700000,1).unwrap();let (foreign,reference)=r.module_acquire_result(i,"COLLISION",0x720000).unwrap();assert_eq!(r.provider_initialize_sync(i,&t,0x701000),Err("CRT provider publication identity collision"));r.module_identity(foreign).unwrap();assert_eq!(r.module_references.get(&reference.serial),Some(&reference));assert!(!r.providers.contains_key(&t.handle));
let t=r.provider_begin(i,"Retry",0x700000,1).unwrap();r.thread=4;assert!(r.provider_initialize_sync(i,&t,0x701000).is_err());assert!(r.providers.contains_key(&t.handle));r.thread=3;let(m,f)=r.provider_initialize_sync(i,&t,0x701000).unwrap();r.native_sync_identity(f).unwrap();assert_eq!(f.module,m);assert!(r.provider_initialize_sync(i,&t,0x701000).is_err());
"#,
        "native-provider-initialization",
    );
}

#[test]
fn native_provider_references_bind_implemented_calls_and_teardown_lifetime() {
    native(
        "",
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();let t=r.provider_begin(i,"OwnedNative",0x700000,2).unwrap();let(m,f)=r.provider_initialize_sync(i,&t,0x701000).unwrap();
let unimplemented=r.provider_export(i,m,m,"Unimplemented",0x702000).unwrap();assert!(r.native_provider_acquire(i,unimplemented.record).is_err());
let serial=r.serial;r.serial=u64::MAX;assert_eq!(r.native_provider_acquire(i,f),Err("CRT native provider reference serial"));assert_eq!(r.module_references.len(),1);r.serial=serial;
let a=r.native_provider_acquire(i,f).unwrap();let b=r.native_provider_acquire(i,f).unwrap();assert_eq!(r.module_references.len(),3);
let(mut other,oi)=CrtStreamRuntime::new_initializing(2,3,0x8000,65536).unwrap();assert!(other.native_provider_acquire(oi,f).is_err());assert!(other.native_provider_release(oi,a).is_err());r.thread=4;assert!(r.native_provider_release(i,a).is_err());r.thread=3;assert_eq!(r.module_references.len(),3);assert!(r.provider_destroy(i,m).is_err());
let mut forged=a;forged.reference=r.providers[&m.handle].root.unwrap();assert!(r.native_provider_release(i,forged).is_err());assert_eq!(r.module_references.len(),3);
let p=r.map_region(0x9000,24,CrtRegionKind::Module,Some(&[0;24])).unwrap();assert_eq!(r.native_sync_initialize(i,f,0,p,0,0),Ok(1));r.native_provider_release(i,a).unwrap();assert!(r.native_provider_release(i,a).is_err());r.native_sync_identity(f).unwrap();r.native_provider_release(i,b).unwrap();assert_eq!(r.module_references.len(),1);assert!(r.provider_destroy(i,m).is_err());
r.native_sync_delete(i,f,0,p).unwrap();r.provider_destroy(i,m).unwrap();assert!(r.native_provider_acquire(i,f).is_err());assert!(r.native_provider_release(i,b).is_err());
let t2=r.provider_begin(i,"OwnedNative",0x700000,1).unwrap();let(m2,f2)=r.provider_initialize_sync(i,&t2,0x701000).unwrap();assert_ne!(m,m2);assert!(r.native_provider_acquire(i,f).is_err());r.native_provider_acquire(i,f2).unwrap();
"#,
        "native-provider-references",
    );
}

#[test]
fn native_reference_capacity_and_sparse_reuse_require_no_allocation() {
    native(
        r#"
struct Guard;static DENY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
unsafe impl std::alloc::GlobalAlloc for Guard{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{std::alloc::System.alloc(l)}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{std::alloc::System.realloc(p,l,n)}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){std::alloc::System.dealloc(p,l)}
}
#[global_allocator]static ALLOC:Guard=Guard;
"#,
        r#"
let(mut r,i)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let t=r.provider_begin(i,"ReferenceCapacity",0x700000,1).unwrap();let(m,f)=r.provider_initialize_sync(i,&t,0x701000).unwrap();let mut refs=[None;255];
DENY.store(true,std::sync::atomic::Ordering::SeqCst);
let result=(||->Result<(),&'static str>{
 for x in &mut refs{*x=Some(r.native_provider_acquire(i,f)?);}
 let serial=r.serial;assert_eq!(r.module_references.len(),256);assert_eq!(r.native_provider_acquire(i,f),Err("CRT native provider reference budget"));assert_eq!(r.serial,serial);
 let before=r.module_references.clone();assert_eq!(before.len(),256);
 for index in (0..255).step_by(2){r.native_provider_release(i,refs[index].unwrap())?;}
 for index in (0..255).step_by(2){let old=refs[index].unwrap();refs[index]=Some(r.native_provider_acquire(i,f)?);assert!(r.native_provider_release(i,old).is_err());}
 assert_eq!(r.module_references.len(),256);assert_eq!(before.iter().filter(|(k,_)|!r.module_references.contains_key(k)).count(),128);
 for x in refs{r.native_provider_release(i,x.unwrap())?;}assert_eq!(r.module_references.len(),1);r.module_identity(m)?;Ok(())})();
DENY.store(false,std::sync::atomic::Ordering::SeqCst);result.unwrap();r.provider_destroy(i,m).unwrap();assert!(r.module_references.is_empty());
"#,
        "native-reference-capacity",
    );
}

#[test]
fn named_native_export_requires_unique_live_implemented_source_and_target() {
    native(
        "",
        r#"
for mode in 0..12{
 let(mut r,i)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
 let a=r.provider_begin(i,"UnrelatedFrontend",0x700000,3).unwrap();let a=r.provider_publish(i,&a).unwrap();
 let b=r.provider_begin(i,"UnrelatedBackend",0x720000,3).unwrap();let b=r.provider_publish(i,&b).unwrap();
 let d=r.provider_export(i,a,b,"InitializeCriticalSectionEx",0x721000).unwrap();let f=r.bind_native_sync(i,d).unwrap();
 let prior=r.serial;r.last_os_error=Some(87);
 if mode==1{r.exports.get_mut(&f.serial).unwrap().callable=false;}
 if mode==2{r.exports.get_mut(&f.serial).unwrap().api=None;}
 if mode==3{r.modules.get_mut(&b.handle).unwrap().certain=false;}
 if mode==4{r.modules.get_mut(&a.handle).unwrap().certain=false;}
 if mode==5{let mut duplicate=CrtExport{function:f,symbol:"InitializeCriticalSectionEx".into(),target:b,callable:true,api:Some(CrtNativeApi::InitializeGlobalCriticalSectionEx)};duplicate.function.serial+=1;r.exports.insert(duplicate.function.serial,duplicate);}
 if mode==6{r.exports.remove(&f.serial);}
 if mode==7{r.thread+=1;}
 if mode==11{r.providers.get_mut(&a.handle).unwrap().exports.clear();}
 let name=match mode{8=>"initializecriticalsectionex",9=>"InitializeCriticalSectionEx\0",_=>"InitializeCriticalSectionEx"};
 let got=r.native_named_export(i,a,name);
 assert_eq!(r.serial,prior);assert_eq!(r.last_os_error,Some(87));
 if mode==0||mode==10{assert_eq!(got,Ok(f));let p=r.map_region(0x9000,24,CrtRegionKind::Module,Some(&[0;24])).unwrap();assert_eq!(r.native_sync_initialize(i,f,0,p,0,0),Ok(1));r.native_sync_delete(i,f,0,p).unwrap();}
 else{assert_eq!(got,Err(match mode{1=>"CRT native provider export implementation unbound",2=>"CRT native named export implementation unbound",3|4=>"CRT module owner/generation/lifetime",5=>"CRT native named export ambiguous",6|8=>"CRT native named export unsupported",7=>"CRT initialization owner/lifetime",9=>"CRT native named export encoding/bounds",11=>"CRT native named export publication incomplete",_=>unreachable!()}));}
 if mode==10{assert_eq!(r.provider_destroy(i,b),Err("CRT provider still acquired/borrowed"));r.provider_destroy(i,a).unwrap();assert!(r.native_named_export(i,a,name).is_err());r.provider_destroy(i,b).unwrap();let t=r.provider_begin(i,"UnrelatedFrontend",a.handle,1).unwrap();let new=r.provider_publish(i,&t).unwrap();assert_ne!(new,a);assert!(r.function_identity(f,None).is_err());}
}
"#,
        "native-named-export",
    );
}
