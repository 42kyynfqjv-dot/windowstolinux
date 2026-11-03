//! Experimental event/handler/continuation slice compiler; not whole-PE admission.
#[path = "../src/handler.rs"]
pub mod handler;
fn run() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 6 {
        return Err("handler_event HANDLER HANDLER_ORIGIN EVENT EVENT_ORIGIN OUTPUT.rs".into());
    }
    let h = std::fs::read(&a[1]).map_err(|e| e.to_string())?;
    let event = std::fs::read(&a[3]).map_err(|e| e.to_string())?;
    let proof = handler::prove_event(
        &h,
        a[2].parse::<u32>().map_err(|e| e.to_string())?,
        &event,
        a[4].parse::<u32>().map_err(|e| e.to_string())?,
    )?;
    std::fs::write(&a[5], proof.emit()).map_err(|e| e.to_string())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
