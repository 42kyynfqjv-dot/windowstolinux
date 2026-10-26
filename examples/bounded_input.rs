// Standalone comparison only. Production shares acquisition, never program_exit.
include!("../src/linker/input/acquisition.rs");
impl ApiResult {
    fn program_exit(&self) -> i32 {
        if self.returned == 0 {
            return 200;
        }
        if self.returned > 2 {
            return 201;
        }
        let mut number = 0;
        for i in 0..self.returned as usize {
            let word = u16::from_le_bytes([
                self.bytes[2 * i].expect("private success initialization"),
                self.bytes[2 * i + 1].expect("private success initialization"),
            ]);
            if !(48..=57).contains(&word) {
                return 202;
            }
            number = number * 10 + i32::from(word - 48);
        }
        number
    }
}
fn main() {
    let exit = match acquire() {
        Ok(value) => value.project().program_exit(),
        Err(_) => 203,
    };
    std::process::exit(exit);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(s: &str) -> Value {
        parse(format!("W2L_INPUT={s}\0").as_bytes()).unwrap()
    }
    #[test]
    fn capacity_five_utf16_boundaries_and_unknown_bytes() {
        let r = value("A€😀").project_capacity(5).unwrap();
        assert_eq!(r.returned, 4);
        assert_eq!(
            r.bytes,
            [
                Some(65),
                Some(0),
                Some(0xac),
                Some(0x20),
                Some(0x3d),
                Some(0xd8),
                Some(0),
                Some(0xde),
                Some(0),
                Some(0)
            ]
        );
        for text in ["", "12345", "😀😀😀"] {
            let r = value(text).project_capacity(5).unwrap();
            assert_eq!(
                r.returned,
                if text.is_empty() {
                    0
                } else {
                    text.encode_utf16().count() as u32 + 1
                }
            );
            assert_eq!(r.bytes, [None; 10]);
        }
        assert_eq!(
            value("123").project_capacity(5).unwrap().bytes[8..],
            [None, None]
        );
        for capacity in [0, 1, 2, 4, 6, u32::MAX] {
            assert_eq!(value("7").project_capacity(capacity), Err(Error::Capacity));
        }
    }
    #[test]
    fn missing_empty_and_initialized_ranges() {
        assert_eq!(
            parse(b"").unwrap().project(),
            ApiResult {
                returned: 0,
                bytes: [None; 6]
            }
        );
        assert_eq!(value("").project().returned, 0);
        assert_eq!(
            value("7").project().bytes,
            [Some(55), Some(0), Some(0), Some(0), None, None]
        );
        assert_eq!(
            value("42").project().bytes,
            [Some(52), Some(0), Some(50), Some(0), Some(0), Some(0)]
        );
    }
    #[test]
    fn utf16_and_required_capacity() {
        assert_eq!(value("😀").project().returned, 2);
        assert_eq!(value("😀").project().program_exit(), 202);
        assert_eq!(
            value("😀7").project(),
            ApiResult {
                returned: 4,
                bytes: [None; 6]
            }
        );
        assert_eq!(value(&"é".repeat(64)).project().returned, 65);
        assert_eq!(
            parse(format!("W2L_INPUT={}\0", "7".repeat(65)).as_bytes()),
            Err(Error::ValueLimit)
        );
    }
    #[test]
    fn encoding_and_alias_failures() {
        for raw in [&b"W2L_INPUT=\xff\0"[..], &b"W2L_INPUT=\xed\xa0\x80\0"[..]] {
            assert_eq!(parse(raw), Err(Error::Encoding));
        }
        assert_eq!(parse("W2L_ıNPUT=7\0".as_bytes()), Err(Error::Malformed));
        assert_eq!(parse(b"w2l_input=7\0"), Err(Error::Alias));
        assert_eq!(parse(b"W2L_INPUT=7\0W2L_INPUT=7\0"), Err(Error::Duplicate));
        assert_eq!(parse(b"W2L_INPUT=7\0w2l_input=7\0"), Err(Error::Alias));
    }
    #[test]
    fn complete_snapshot_validation() {
        assert_eq!(parse(b"W2L_INPUT=7"), Err(Error::Unterminated));
        assert_eq!(parse(b"W2L_INPUT=7\0bad\0"), Err(Error::Malformed));
        assert_eq!(parse(b"=7\0"), Err(Error::Malformed));
        assert_eq!(parse(b"\0"), Err(Error::Malformed));
        assert_eq!(
            parse(b"OTHER=\xff\0W2L_INPUT=42\0")
                .unwrap()
                .project()
                .program_exit(),
            42
        );
    }
    #[test]
    fn entry_and_total_caps() {
        assert!(parse(&b"A=\0".repeat(256)).is_ok());
        assert_eq!(parse(&b"A=\0".repeat(257)), Err(Error::EntryLimit));
        let entry = format!("A={}\0", "x".repeat(4094));
        assert!(parse(entry.as_bytes()).is_ok());
        assert_eq!(
            parse(format!("A={}\0", "x".repeat(4095)).as_bytes()),
            Err(Error::EntryLimit)
        );
        let exact = format!("A={}\0", "x".repeat(4093)).repeat(16);
        assert_eq!(exact.len(), MAX_BYTES);
        assert!(read_snapshot(exact.as_bytes()).is_ok());
        assert_eq!(
            read_snapshot([exact.as_bytes(), b"x"].concat().as_slice()),
            Err(Error::SnapshotLimit)
        );
    }
    #[test]
    fn short_reads_and_errors() {
        struct Small<'a>(&'a [u8]);
        impl Read for Small<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(&mut b[..1])
            }
        }
        assert_eq!(
            read_snapshot(Small(b"W2L_INPUT=7\0"))
                .unwrap()
                .project()
                .program_exit(),
            7
        );
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(read_snapshot(Failed), Err(Error::Io));
    }
    #[test]
    fn interrupted_budget_and_bad_reader() {
        struct Interrupted;
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        assert_eq!(read_snapshot(Interrupted), Err(Error::ReadBudget));
        struct Invalid;
        impl Read for Invalid {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                Ok(b.len() + 1)
            }
        }
        assert_eq!(read_snapshot(Invalid), Err(Error::Io));
    }
    #[test]
    fn owned_result_survives_source_and_projection() {
        let mut bytes = b"W2L_INPUT=42\0".to_vec();
        let result = parse(&bytes).unwrap();
        bytes.fill(0);
        assert_eq!(result.project().program_exit(), 42);
        assert_eq!(value("99").project().program_exit(), 99);
        assert_eq!(value(" 7").project().program_exit(), 202);
    }
}
