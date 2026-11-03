//! Experimental slice compiler; does not grant whole-image startup eligibility.
#[path = "../src/handler.rs"]
pub mod handler;
fn run() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 6 {
        return Err("handler_slice CODE ORIGIN FAULT_IP CONTINUATION_IP OUTPUT.rs".into());
    }
    let number = |i: usize| a[i].parse::<u32>().map_err(|e| e.to_string());
    let code = std::fs::read(&a[1]).map_err(|e| e.to_string())?;
    let proved = handler::prove(&code, number(2)?, number(3)?, number(4)?, true)?;
    std::fs::write(&a[5], proved.emit()).map_err(|e| e.to_string())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
