//! Experimental original cleanup/restore compiler with explicit orchestration cut.
#[path = "../src/unwind.rs"]
pub mod unwind;
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err(
            "unwind_slice DIRECTORY BASE TABLE_RVA RESTORE_RVA TARGET_RVA OUTPUT.rs".into(),
        );
    }
    let root = std::path::Path::new(&args[1]);
    let read = |name: &str| std::fs::read(root.join(name)).map_err(|e| e.to_string());
    let number = |index: usize| args[index].parse::<u32>().map_err(|e| e.to_string());
    let mut blocks = Vec::new();
    for line in String::from_utf8(read("cleanup.list")?)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2 || parts[1].contains('/') || parts[1].contains('\\') {
            return Err("invalid cleanup list".into());
        }
        blocks.push((
            parts[0].parse::<u32>().map_err(|e| e.to_string())?,
            read(parts[1])?,
        ));
    }
    let active = String::from_utf8(read("active.txt")?)
        .map_err(|e| e.to_string())?
        .split_whitespace()
        .map(|n| n.parse::<i32>().map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if root.join("dispatch.bin").exists() != root.join("dispatch.bind").exists() {
        return Err("dispatcher bytes and binding must be supplied together".into());
    }
    let dispatch_code = if root.join("dispatch.bind").exists() {
        Some(read("dispatch.bin")?)
    } else {
        None
    };
    let dispatch_binding = if dispatch_code.is_some() {
        let text = String::from_utf8(read("dispatch.bind")?).map_err(|e| e.to_string())?;
        let values = text
            .split_whitespace()
            .map(|n| n.parse::<u32>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if values.len() != 2 {
            return Err("invalid dispatcher binding".into());
        }
        Some((values[0], values[1]))
    } else {
        None
    };
    let dispatcher =
        dispatch_code
            .as_deref()
            .zip(dispatch_binding)
            .map(|(code, (rva, trace_rva))| unwind::Dispatcher {
                code,
                rva,
                trace_rva,
            });
    let proof = unwind::prove_with_dispatch(
        &read("scope.bin")?,
        number(2)?,
        number(3)?,
        &blocks,
        &read("restore.bin")?,
        number(4)?,
        number(5)?,
        &read("target.bin")?,
        &active,
        0,
        dispatcher,
    )?;
    std::fs::write(&args[6], proof.emit()).map_err(|e| e.to_string())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
