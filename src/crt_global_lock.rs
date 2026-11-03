//! Original indexed critical-section helpers. Integer address formation is
//! certified separately from the owned module object supplied to the API.
use super::{
    crt_stream_emit,
    crt_stream_ir::{Graph, Target},
};

pub(crate) struct Proof {
    graph: Graph,
    table: u32,
    iat: u32,
}
impl Proof {
    pub fn prove(bytes: &[u8], origin: u32, table: u32, iat: u32) -> Result<Self, String> {
        if table == 0
            || !table.is_multiple_of(4)
            || table.checked_add(32 * 24).is_none()
            || iat == 0
            || !iat.is_multiple_of(4)
        {
            return Err("global lock table/import range".into());
        }
        let overlaps = |a: u32, n: u32, b: u32, m: u32| {
            u64::from(a) < u64::from(b) + u64::from(m) && u64::from(b) < u64::from(a) + u64::from(n)
        };
        if overlaps(table, 32 * 24, origin, 23)
            || overlaps(iat, 4, origin, 23)
            || overlaps(table, 32 * 24, iat, 4)
        {
            return Err("global lock code/table/import alias".into());
        }
        // Full cdecl helper, including volatile IMUL/ADD effects and exact RET.
        let mut expected = vec![0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6b, 0x45, 0x08, 0x18, 0x05];
        expected.extend(table.to_le_bytes());
        expected.extend([0x50, 0xff, 0x15]);
        expected.extend(iat.to_le_bytes());
        expected.extend([0x5d, 0xc3]);
        if bytes != expected {
            return Err("global lock complete indexed helper protocol".into());
        }
        Ok(Self {
            graph: Graph::decode(bytes, origin)?,
            table,
            iat,
        })
    }
    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("global lock helper name".into());
        }
        let body = crt_stream_emit::emit_body(
            &self.graph,
            |pc, target| {
                if target != Target::Import(self.iat) {
                    return Err("global lock import disagreement".into());
                }
                let next = pc + self.graph.nodes[&pc].length;
                Ok(format!("cpu.call_activation(rt,{next},4,|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;let bp=CrtCpu::pointer(child.r[5])?;let index=rt.load(rt.offset(bp,8)?,32)?.known_scalar()?;let argument=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let owned_slot=rt.check_global_address(index,{},argument)?;effect(rt,owned_slot)?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish_pop(rt,4)}})?;",self.table))
            },
            &Default::default(),
            32,
        )?;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,mut effect:impl FnMut(&mut CrtStreamRuntime,u32)->Result<(),&'static str>)->Result<CrtValue,&'static str>{{{body}}}"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(table: u32, iat: u32) -> Vec<u8> {
        let mut b = vec![0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6b, 0x45, 8, 24, 5];
        b.extend(table.to_le_bytes());
        b.extend([0x50, 0xff, 0x15]);
        b.extend(iat.to_le_bytes());
        b.extend([0x5d, 0xc3]);
        b
    }
    #[test]
    fn complete_helper_identity_rejects_changed_stride_argument_import_and_return() {
        assert!(Proof::prove(&bytes(0x4000, 0x8000), 0x4000, 0x4000, 0x8000).is_err());
        assert!(Proof::prove(&bytes(0x8000, 0x8004), 0x4000, 0x8000, 0x8004).is_err());
        for (table, iat) in [(0x41d150, 0x41504c), (0x720000, 0x710020)] {
            let b = bytes(table, iat);
            let p = Proof::prove(&b, 0x4000, table, iat).unwrap();
            assert!(p.emit("indexed_lock").is_ok());
            for at in [0, 7, 8, 14, 15, 21, 22] {
                let mut changed = b.clone();
                changed[at] ^= 1;
                assert!(Proof::prove(&changed, 0x4000, table, iat).is_err());
            }
            assert!(Proof::prove(&b[..22], 0x4000, table, iat).is_err());
            assert!(Proof::prove(&b, 0x4000, table, iat + 4).is_err());
        }
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    #[test]
    fn indexed_helpers_keep_module_ownership_and_failure_effects() {
        for table in [0x41d150u32, 0x720000] {
            let mut bytes = vec![0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6b, 0x45, 8, 24, 5];
            bytes.extend(table.to_le_bytes());
            bytes.extend([0x50, 0xff, 0x15]);
            bytes.extend(0x41504cu32.to_le_bytes());
            bytes.extend([0x5d, 0xc3]);
            let extra = Proof::prove(&bytes, 0x4000, table, 0x41504c)
                .unwrap()
                .emit("helper")
                .unwrap();
            super::super::crt_stream_callees_tests::native(
                &extra,
                &format!(
                    r#"
for index in [0,7,31,32,u32::MAX]{{for fault in 0..4{{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let p=rt.map_region({table},768,CrtRegionKind::Module,None).unwrap();for i in [0,7,31]{{rt.construct_global_lock(init,i,rt.offset(p,i64::from(i)*24).unwrap(),1).unwrap();}}
 let stack=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,384).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,if fault==1{{CrtValue::Scalar{{bits:0,known:0}}}}else{{CrtValue::scalar(index)}}).unwrap();let mut cpu=CrtCpu::new(sp,77).unwrap();let saved=cpu.r;let mut effects=0;
 if fault==2&&index<32{{rt.global_objects.remove(&index);}}
 let result=helper(&mut rt,&mut cpu,|rt,seen|{{effects+=1;assert_eq!(seen,index);let lease=rt.lock_global(2,seen)?;if fault==3{{return Err("failure after observable acquisition");}}rt.unlock_global(lease)}});
 if index>=32||fault==1||fault==2{{assert!(result.is_err());assert_eq!(effects,0);assert!(!cpu.returned);assert!(rt.global_locks.is_empty());}}else if fault==3{{assert!(result.is_err());assert_eq!(effects,1);assert_eq!(rt.global_locks.len(),1);assert!(!cpu.returned);}}else{{result.unwrap();assert!(cpu.returned);assert_eq!(effects,1);for r in[3,5,6,7]{{assert_eq!(cpu.r[r],saved[r]);}}assert_eq!(cpu.r[4],CrtValue::Pointer(rt.offset(sp,4).unwrap()));assert!(cpu.r[0].known_scalar().is_err());}}
}}}}
// The owned object must agree with the certified table, even when an alternate
// live lock has the same index and permissions.
let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let other=rt.map_region({table}+0x1000,24,CrtRegionKind::Module,None).unwrap();rt.construct_global_lock(init,0,other,1).unwrap();assert!(rt.check_global_address(0,{table},{table}).is_err());
"#
                ),
                &format!("indexed-global-{table}"),
            );
        }
    }
}
