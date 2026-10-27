//! Structural decoder inventory only; cannot emit or grant PE execution eligibility.
#[path = "../src/stream/graph.rs"]
pub mod graph;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let code = std::fs::read(&args[1]).expect("code file");
    let origin = args[2].parse::<u32>().expect("origin");
    let entry = args[3].parse::<u32>().expect("entry");
    match graph::decode(&code, origin, entry) {
        Ok(g) => {
            println!(
                "STRUCTURAL ONLY: {} nodes; {} cyclic components; emission_eligible=false",
                g.nodes.len(),
                g.cyclic_components.len()
            );
            for (p, n) in g.nodes {
                println!("{p:08x} {n:?}");
            }
            println!("cycles={:?}", g.cyclic_components);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
