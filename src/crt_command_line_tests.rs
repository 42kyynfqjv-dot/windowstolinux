//! Independent command-line contract tests; kept out of shared runtime examples.
#[test]
fn command_line_codec_matches_independent_unicode_quote_and_boundary_vectors() {
    let extra = include_str!("../research/process/startup/command-line-vectors.rs");
    crate::crt_stream_callees_tests::native(
        extra,
        r#"
for(args,a,w)in command_line_vectors(){assert_eq!(CrtStreamRuntime::encode_native_command_line(&args),Ok((a,w)));}
for args in [vec![],vec!["".into()],vec!["bad\"name".into()],vec!["p".into(),"a\0b".into()]]{assert!(CrtStreamRuntime::encode_native_command_line(&args).is_err());}
for (argument,narrow_len)in [("a".repeat(32760),32767),("😀".repeat(16380),65527)]{let(a,w)=CrtStreamRuntime::encode_native_command_line(&["p".into(),argument]).expect("exact UTF16 boundary must encode");assert_eq!(a.len(),narrow_len);assert_eq!(w.len(),65534);}
assert_eq!(CrtStreamRuntime::encode_native_command_line(&["p".into(),"a".repeat(32761)]),Err("native command-line UTF16 limit"));assert_eq!(CrtStreamRuntime::encode_native_command_line(&["p".into(),"😀".repeat(16381)]),Err("native command-line UTF16 limit"));
"#,
        "command-line-codec",
    );
}
#[test]
fn command_line_process_lifetime_readonly_mapping_and_transaction_failures() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
let args=vec!["p".into(),"Ω\"\\".into()];
for mode in 0..12{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,if mode==3{80}else{65536}).unwrap();
 let before=rt.regions.len();let serial=rt.serial;
 if mode==1||mode==2{rt.map_region(if mode==1{0x20000}else{0x21000},4,CrtRegionKind::Module,Some(&[0x55;4])).unwrap();}
 let count=rt.regions.len();let result=rt.publish_command_line(init,0x20000,if mode==0{1252}else{65001},&args);
 if mode<=3{assert!(result.is_err(),"publication failure mode {mode}");assert!(rt.command_line.is_none());assert_eq!(rt.regions.len(),count);assert_eq!(rt.serial,serial);if mode!=1{assert!(rt.memory.read(0x20000,1).is_err());}if mode==1||mode==2{assert_eq!(rt.memory.read(if mode==1{0x20000}else{0x21000},4).unwrap(),&[0x55;4]);}continue;}
 let token=result.expect("owned command-line publication");assert_eq!(rt.regions.len(),before+2);let a=rt.command_line_pointer(token,false).unwrap();let w=rt.command_line_pointer(token,true).unwrap();assert_ne!(a.cap,w.cap);
 let(na,nw)=CrtStreamRuntime::encode_native_command_line(&args).unwrap();assert_eq!(rt.memory.read(a.address(),a.size).unwrap(),na);assert_eq!(rt.memory.read(w.address(),w.size).unwrap(),nw);
 assert!(rt.store(a,8,CrtValue::scalar(0)).is_err());assert!(rt.memory.write(a.address(),b"x").is_err());assert!(rt.free_initialization(init,a).is_err());assert!(rt.retire_region(a).is_err());assert!(rt.map_region(0x30000,4,CrtRegionKind::ProcessData,Some(&[0;4])).is_err());assert!(rt.valid(CrtPointer{kind:CrtRegionKind::Input,..a},1).is_err());
 if mode==4{rt.memory.release(a.cap,a.owner).unwrap();assert!(rt.command_line_pointer(token,false).is_err());assert_eq!(rt.command_line_pointer(token,true),Ok(w));}
 if mode==5{rt.memory.release(w.cap,w.owner).unwrap();assert_eq!(rt.command_line_pointer(token,false),Ok(a));assert!(rt.command_line_pointer(token,true).is_err());}
 if mode==6{let(other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();assert!(other.command_line_pointer(token,false).is_err());}
 if mode==7{rt.closed=true;assert!(rt.command_line_pointer(token,false).is_err());}
 if mode==8{let mut wrong=token;wrong.pid=wrong.pid.wrapping_add(1);assert!(rt.command_line_pointer(wrong,false).is_err());}
 if mode==9{rt.end_initialization(init).unwrap();assert_eq!(rt.command_line_pointer(token,false),Ok(a));assert_eq!(rt.command_line_pointer(token,true),Ok(w));}
 if mode==10{let output=rt.map_region(0x30000,4,CrtRegionKind::Stack,Some(&[0;4])).unwrap();rt.memory.protect_data_with_old((w.cap,w.owner,w.address(),w.size),4,(output.cap,output.owner,output.address())).unwrap();rt.memory.forget(w.address(),2).unwrap();rt.memory.protect_data_with_old((w.cap,w.owner,w.address(),w.size),2,(output.cap,output.owner,output.address())).unwrap();assert!(rt.command_line_pointer(token,true).is_err());assert_eq!(rt.command_line_pointer(token,false),Ok(a));}
 if mode==11{assert!(rt.publish_command_line(init,0x30000,65001,&args).is_err());assert_eq!(rt.command_line_pointer(token,false),Ok(a));assert_eq!(rt.command_line_pointer(token,true),Ok(w));}
}
"#,
        "command-line-process-storage",
    );
}
#[cfg(target_os = "linux")]
#[test]
fn native_command_line_acquires_actual_argv_and_rejects_invalid_utf8() {
    let extra = include_str!("../research/process/startup/command-line-vectors.rs");
    crate::crt_stream_callees_tests::native(
        extra,
        r#"
use std::os::unix::process::CommandExt;use std::os::unix::ffi::OsStringExt;
if let Ok(mode)=std::env::var("W2L_CMD_CHILD"){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,262144).unwrap();let result=rt.acquire_native_command_line(init,0x20000,65001);
 if mode=="invalid"{assert_eq!(result,Err("native command-line non-UTF8 argument"));assert!(rt.command_line.is_none());assert_eq!(rt.regions.len(),1);return;}
 let token=result.unwrap();let p=rt.command_line_pointer(token,false).unwrap();std::io::Write::write_all(&mut std::io::stdout(),rt.memory.read(p.address(),p.size).unwrap()).unwrap();return;
}
for(args,a,_)in command_line_vectors(){let output=std::process::Command::new(std::env::current_exe().unwrap()).arg0(&args[0]).args(&args[1..]).env("W2L_CMD_CHILD","observe").output().unwrap();assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));assert_eq!(output.stdout,a);}
let output=std::process::Command::new(std::env::current_exe().unwrap()).arg0("p").arg(std::ffi::OsString::from_vec(vec![0xff])).env("W2L_CMD_CHILD","invalid").output().unwrap();assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
"#,
        "command-line-native-argv",
    );
}
