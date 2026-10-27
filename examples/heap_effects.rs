//! Native component conformance; NOT mechanically translated from either PE.
//! Original implementation MIT OR Apache-2.0.
#[allow(dead_code)]
#[path = "../src/guest_memory.rs"]
mod guest_memory;
use guest_memory::{Availability, Space};
use std::io::{Read, Write};
fn effect(name: &str, a: u8, b: u8) -> Vec<u8> {
    let mut memory = Space::new(1024, 16).unwrap();
    let heap = memory.process_heap();
    let n = 1 + u32::from(a & 31);
    let yes = Availability::Available;
    let result = match name {
        "grow" => {
            let p = memory.heap_alloc(heap, 0, n, yes).unwrap().unwrap();
            for i in 0..n {
                memory
                    .write(p + i, &[(i as u8).wrapping_mul(17).wrapping_add(a)])
                    .unwrap();
            }
            let total = n + 1 + u32::from(b & 15);
            let q = memory
                .heap_realloc(heap, 8, p, total, yes)
                .unwrap()
                .unwrap();
            let bytes = memory.read(q, total).unwrap().to_vec();
            memory.heap_free(heap, 0, q).unwrap();
            bytes
        }
        "shrink" => {
            let k = n / 2 + 1;
            let p = memory.heap_alloc(heap, 8, n, yes).unwrap().unwrap();
            let q = memory.heap_alloc(heap, 0, k, yes).unwrap().unwrap();
            assert!(memory.read(p, n).unwrap().iter().all(|&v| v == 0));
            for i in 0..n {
                memory
                    .write(p + i, &[b.wrapping_add((i as u8).wrapping_mul(3))])
                    .unwrap();
            }
            let r = memory.heap_realloc(heap, 0, p, k, yes).unwrap().unwrap();
            for i in 0..k {
                let v = memory.read(r + k - i - 1, 1).unwrap()[0];
                memory.write(q + i, &[v]).unwrap();
            }
            memory.heap_free(heap, 0, r).unwrap();
            let bytes = memory.read(q, k).unwrap().to_vec();
            memory.heap_free(heap, 0, q).unwrap();
            bytes
        }
        _ => panic!("unknown conformance algorithm"),
    };
    result
}
fn main() {
    let name = std::env::args().nth(1).expect("grow or shrink");
    let mut input = [0; 2];
    if std::io::stdin().read_exact(&mut input).is_err() {
        std::process::exit(11);
    }
    let output = effect(&name, input[0], input[1]);
    let mut destination = std::io::stdout().lock();
    if destination
        .write_all(&output)
        .and_then(|_| destination.flush())
        .is_err()
    {
        std::process::exit(14);
    }
}
