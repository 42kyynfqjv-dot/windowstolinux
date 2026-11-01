//! A bounded compiler frame idiom, independent of application address or data.
//! The complete prefix is decoded and bound before its one return-bit copy is
//! lowered. All other instructions retain ordinary shared lowering and effects.
use crate::crt_stream_ir::Graph;

const SHAPE: &str = "8bff538bdc515183e4f883c404558b6b04896c24048bec81ec380200005657ff7314ff7310";

pub(crate) fn prefix(bytes: &[u8], address: u32) -> Result<String, String> {
    let mut shape = crate::crt_ptd::raw(SHAPE);
    if bytes.len() != shape.len() || address.checked_add(bytes.len() as u32).is_none() {
        return Err("aligned prefix extent".into());
    }
    // Only the local allocation varies in this bounded compiler idiom.
    let allocation = u32::from_le_bytes(bytes[25..29].try_into().unwrap());
    if allocation == 0 || allocation > 1024 * 1024 || allocation % 4 != 0 {
        return Err("aligned prefix local extent".into());
    }
    shape[25..29].copy_from_slice(&allocation.to_le_bytes());
    if bytes != shape {
        return Err("aligned prefix instruction shape".into());
    }
    let graph = Graph::decode_linear_fragment(bytes, address)?;
    crate::crt_stream_emit::emit_body_with_store(
        &graph,
        |_, _| Err("aligned prefix unexpected call".into()),
        &Default::default(),
        32,
        |_, _| Err("aligned prefix thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("aligned prefix unexpected return".into()),
        Some(graph.end),
        |pc, operand, width| {
            if pc != address + 17 || width != 32 {
                return Err("aligned prefix unexpected store".into());
            }
            let destination = crate::crt_stream_emit::address(operand, &Default::default())?;
            Ok(Some(format!(
                "aligned.copy_return(rt,cpu,{destination},v)?;"
            )))
        },
    )
}

#[test]
fn aligned_prefix_proof_rejects_changed_operations_and_extents() {
    let bytes = crate::crt_ptd::raw(SHAPE);
    for address in [0x1000, 0x40b235, 0x10000000] {
        prefix(&bytes, address).unwrap();
        for size in [4u32, 32, 1024, 1024 * 1024] {
            let mut other = bytes.clone();
            other[25..29].copy_from_slice(&size.to_le_bytes());
            prefix(&other, address).unwrap();
        }
    }
    for at in 0..bytes.len() {
        if (25..29).contains(&at) {
            continue;
        }
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert!(prefix(&changed, 0x1000).is_err(), "mutation {at}");
    }
    for size in [0u32, 3, 1024 * 1024 + 4, u32::MAX] {
        let mut changed = bytes.clone();
        changed[25..29].copy_from_slice(&size.to_le_bytes());
        assert!(prefix(&changed, 0x1000).is_err());
    }
    assert!(prefix(&bytes[..bytes.len() - 1], 0x1000).is_err());
    assert!(prefix(&bytes, u32::MAX - 4).is_err());
}
