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
