//! Bounded local compiler dependency; no network or generated-runtime use.
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
fn invoke(
    exe: &std::ffi::OsStr,
    args: &[&str],
    input: Vec<u8>,
    budget: Duration,
) -> Result<String, String> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("stream solver unavailable: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let reader = thread::spawn(move || {
        let mut b = Vec::new();
        stdout.take(8193).read_to_end(&mut b).map(|_| b)
    });
    let errors = thread::spawn(move || {
        let mut b = Vec::new();
        stderr.take(8193).read_to_end(&mut b).map(|_| b)
    });
    let start = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) => {}
            Err(e) => break Err(format!("stream solver wait: {e}")),
        }
        if start.elapsed() >= budget {
            break Err("stream solver wall-time budget exhausted".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let wrote = writer.join().map_err(|_| "stream solver writer thread")?;
    let out = reader
        .join()
        .map_err(|_| "stream solver stdout thread")?
        .map_err(|e| e.to_string())?;
    let err = errors
        .join()
        .map_err(|_| "stream solver stderr thread")?
        .map_err(|e| e.to_string())?;
    let status = result?;
    wrote.map_err(|e| format!("stream solver input: {e}"))?;
    if !status.success() || out.len() > 8192 || !err.is_empty() {
        return Err("stream solver failed/output outside policy".into());
    }
    String::from_utf8(out).map_err(|_| "stream solver output encoding".into())
}
fn accepted(text: &str, queries: usize) -> bool {
    queries > 0 && text.lines().count() == queries && text.lines().all(|line| line == "unsat")
}
pub(super) fn prove(logic: &super::logic::Logic) -> Result<(), String> {
    let exe = std::env::var_os("W2L_Z3").unwrap_or_else(|| "z3".into());
    let version = invoke(&exe, &["-version"], vec![], Duration::from_secs(3))?;
    if version.trim() != "Z3 version 4.15.4 - 64 bit" {
        return Err("stream solver requires Z3 4.15.4 (64 bit)".into());
    }
    let output = invoke(
        &exe,
        &["-in", "-smt2"],
        logic.text.as_bytes().to_vec(),
        Duration::from_secs(25),
    )?;
    if !accepted(&output, logic.queries) {
        return Err(format!(
            "stream proof rejected: expected {} UNSAT results, received {:?}",
            logic.queries,
            output
                .lines()
                .enumerate()
                .filter(|(_, v)| *v != "unsat")
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_property_must_be_unsat() {
        assert!(accepted("unsat\nunsat\n", 2));
        for bad in [
            "unsat\nunknown\n",
            "unsat\nsat\n",
            "unsat\n",
            "unsat\nunsat\nextra\n",
            "(error)\nunsat\n",
            "unsat\n\n",
        ] {
            assert!(!accepted(bad, 2));
        }
        assert!(!accepted("", 0));
    }
}
