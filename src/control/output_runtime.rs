fn write_output(writer: &mut impl std::io::Write, bytes: &[u8]) -> Result<u32, &'static str> {
    if !(1..=64).contains(&bytes.len()) || !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err("output byte domain");
    }
    match writer.write(bytes) {
        Ok(n) if n == bytes.len() => Ok(n as u32),
        _ => Err("short or failed output write"),
    }
}
fn native_output(bytes: &[u8]) -> u32 {
    use std::os::fd::AsFd;
    let result = (|| {
        let stdout = std::io::stdout();
        let mut file = std::fs::File::from(
            stdout
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| "stdout duplication")?,
        );
        if !file.metadata().map_err(|_| "stdout metadata")?.is_file() {
            return Err("stdout must be a regular file");
        }
        write_output(&mut file, bytes)
    })();
    match result {
        Ok(n) => n,
        Err(e) => {
            eprintln!("w2l: unsupported output environment: {e}");
            std::process::exit(125)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Writer {
        outcome: Result<usize, std::io::ErrorKind>,
        calls: usize,
        observed: Vec<u8>,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if let Ok(n) = self.outcome {
                self.observed.extend_from_slice(&bytes[..n]);
            }
            self.outcome.map_err(std::io::Error::from)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("no buffered flush")
        }
    }
    #[test]
    fn production_output_failure_contract() {
        for outcome in [
            Ok(0),
            Ok(1),
            Ok(4),
            Err(std::io::ErrorKind::BrokenPipe),
            Err(std::io::ErrorKind::Interrupted),
            Err(std::io::ErrorKind::WriteZero),
        ] {
            let mut writer = Writer {
                outcome,
                calls: 0,
                observed: vec![],
            };
            assert!(write_output(&mut writer, b"Hello").is_err());
            assert_eq!(writer.calls, 1);
            assert_eq!(writer.observed, &b"Hello"[..outcome.unwrap_or(0)]);
        }
        let mut writer = Writer {
            outcome: Ok(5),
            calls: 0,
            observed: vec![],
        };
        assert_eq!(write_output(&mut writer, b"Hello"), Ok(5));
        for bytes in [&b""[..], &b"\n"[..], &b"\x1a"[..], &[b'A'; 65][..]] {
            assert!(write_output(&mut writer, bytes).is_err());
        }
        assert_eq!(writer.calls, 1);
    }
}
