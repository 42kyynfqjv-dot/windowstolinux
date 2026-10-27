//! Narrow synchronous file/byte-pipe effects. No raw handles or guest API admission.
use super::memory::{Error, Memory, Pointer};
use std::io::{Read, Write};
pub const BROKEN_PIPE: u32 = 109;
pub const IO_ERROR: u32 = 1117;
pub const INVALID_HANDLE: u32 = 6;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Pipe,
}
pub trait Backend {
    fn read(&mut self, b: &mut [u8]) -> Result<usize, u32>;
    fn write(&mut self, b: &[u8]) -> Result<usize, u32>;
}
/// Supplied, already-owned endpoints. Standard-handle discovery remains a separate
/// admission/runtime obligation; no unsafe construction from guessed host fds.
pub struct Native<R, W> {
    pub input: R,
    pub output: W,
}
impl<R: Read, W: Write> Backend for Native<R, W> {
    fn read(&mut self, b: &mut [u8]) -> Result<usize, u32> {
        loop {
            match self.input.read(b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                r => return r.map_err(|_| IO_ERROR),
            }
        }
    }
    fn write(&mut self, b: &[u8]) -> Result<usize, u32> {
        loop {
            match self.output.write(b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                r => return r.map_err(|_| IO_ERROR),
            }
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Effect {
    pub success: bool,
    pub last_error: Option<u32>,
}
impl Effect {
    fn ok() -> Self {
        Self {
            success: true,
            last_error: None,
        }
    }
    fn fail(e: u32) -> Self {
        Self {
            success: false,
            last_error: Some(e),
        }
    }
}
pub fn read_file<B: Backend>(
    m: &mut Memory,
    b: &mut B,
    kind: Kind,
    valid: bool,
    p: Pointer,
    n: usize,
    count: Pointer,
) -> Result<Effect, Error> {
    // Validate all ranges/aliases before any external side effect.
    m.pair(p, n, count)?;
    m.put_word(count, 0)?;
    if !valid {
        return Ok(Effect::fail(INVALID_HANDLE));
    }
    // A zero-byte request is successful, not evidence of EOF.
    if n == 0 {
        return Ok(Effect::ok());
    }
    match m.receive(p, n, |dst| b.read(dst))? {
        Ok(0) if kind == Kind::Pipe => Ok(Effect::fail(BROKEN_PIPE)),
        Ok(k) => {
            m.put_word(count, k as u32)?;
            Ok(Effect::ok())
        }
        Err(e) => Ok(Effect::fail(e)),
    }
}
pub fn write_file<B: Backend>(
    m: &mut Memory,
    b: &mut B,
    valid: bool,
    p: Pointer,
    n: usize,
    count: Pointer,
) -> Result<Effect, Error> {
    m.pair(p, n, count)?;
    // Check initialized source before resetting count or performing host I/O.
    m.read(p, n)?;
    m.put_word(count, 0)?;
    if !valid {
        return Ok(Effect::fail(INVALID_HANDLE));
    }
    if n == 0 {
        return Ok(Effect::ok());
    }
    match b.write(m.read(p, n)?) {
        Ok(k) if k <= n => {
            m.put_word(count, k as u32)?;
            Ok(Effect::ok())
        }
        Ok(_) => Err(Error::BackendCount),
        Err(e) => Ok(Effect::fail(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    struct Script {
        calls: usize,
        result: Result<usize, u32>,
    }
    impl Backend for Script {
        fn read(&mut self, b: &mut [u8]) -> Result<usize, u32> {
            self.calls += 1;
            if !b.is_empty() {
                b[0] = 65;
            }
            self.result
        }
        fn write(&mut self, _: &[u8]) -> Result<usize, u32> {
            self.calls += 1;
            self.result
        }
    }
    fn setup() -> (Memory, Pointer, Pointer) {
        let mut m = Memory::default();
        let p = m.allocate(8, false).unwrap();
        let c = m.allocate(4, false).unwrap();
        (m, p, c)
    }
    #[test]
    fn file_and_pipe_eof_are_different_and_zero_request_is_not_eof() {
        let (mut m, p, c) = setup();
        let mut b = Script {
            calls: 0,
            result: Ok(0),
        };
        assert_eq!(
            read_file(&mut m, &mut b, Kind::File, true, p, 8, c),
            Ok(Effect::ok())
        );
        assert_eq!(m.word(c), Ok(0));
        assert_eq!(m.read(p, 1), Err(Error::Uninitialized));
        assert_eq!(
            read_file(&mut m, &mut b, Kind::Pipe, true, p, 8, c),
            Ok(Effect::fail(109))
        );
        assert_eq!(
            read_file(&mut m, &mut b, Kind::Pipe, true, p, 0, c),
            Ok(Effect::ok())
        );
        assert_eq!(b.calls, 2);
    }
    #[test]
    fn alias_and_protected_reject_before_external_effect_and_count_write() {
        let (mut m, p, c) = setup();
        let mut b = Script {
            calls: 0,
            result: Ok(1),
        };
        m.put_word(c, 99).unwrap();
        assert_eq!(
            read_file(&mut m, &mut b, Kind::File, true, c, 4, c),
            Err(Error::Alias)
        );
        assert_eq!(m.word(c), Ok(99));
        let protected = m.allocate(4, true).unwrap();
        assert_eq!(
            read_file(&mut m, &mut b, Kind::File, true, p, 8, protected),
            Err(Error::Protected)
        );
        assert_eq!(b.calls, 0);
    }
    #[test]
    fn partial_io_count_failure_and_unknown_source() {
        let (mut m, p, c) = setup();
        let mut b = Script {
            calls: 0,
            result: Ok(1),
        };
        read_file(&mut m, &mut b, Kind::File, true, p, 8, c).unwrap();
        assert_eq!(m.word(c), Ok(1));
        assert_eq!(m.read(p, 1), Ok(&[65][..]));
        assert_eq!(
            write_file(&mut m, &mut b, true, p, 2, c),
            Err(Error::Uninitialized)
        );
        assert_eq!(b.calls, 1);
        write_file(&mut m, &mut b, true, p, 1, c).unwrap();
        assert_eq!(m.word(c), Ok(1));
        b.result = Err(5);
        assert_eq!(
            write_file(&mut m, &mut b, true, p, 1, c),
            Ok(Effect::fail(5))
        );
        assert_eq!(m.word(c), Ok(0));
        assert_eq!(
            read_file(&mut m, &mut b, Kind::File, false, p, 8, c),
            Ok(Effect::fail(6))
        );
        assert_eq!(b.calls, 3);
    }
    #[test]
    fn excessive_backend_progress_rejects_not_clamps() {
        let (mut m, p, c) = setup();
        let mut b = Script {
            calls: 0,
            result: Ok(9),
        };
        assert_eq!(
            read_file(&mut m, &mut b, Kind::File, true, p, 8, c),
            Err(Error::BackendCount)
        );
        assert_eq!(m.word(c), Ok(0));
        assert_eq!(m.read(p, 1), Err(Error::Uninitialized));
        m.write(p, &[0; 8]).unwrap();
        assert_eq!(
            write_file(&mut m, &mut b, true, p, 8, c),
            Err(Error::BackendCount)
        );
    }
    #[test]
    fn native_backend_keeps_binary_bytes_and_actual_partial_reads() {
        let (mut m, p, c) = setup();
        let mut b = Native {
            input: Cursor::new([0, 255, 10, 13]),
            output: Vec::new(),
        };
        read_file(&mut m, &mut b, Kind::File, true, p, 8, c).unwrap();
        assert_eq!(m.word(c), Ok(4));
        write_file(&mut m, &mut b, true, p, 4, c).unwrap();
        assert_eq!(b.output, [0, 255, 10, 13]);
    }
}
