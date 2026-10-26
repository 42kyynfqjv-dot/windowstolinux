//! Isolated research state, no host-pointer dereference or production eligibility.
#[allow(dead_code)]
#[path = "crt_sentinel.rs"]
mod image_binding;
use std::{
    cell::{Cell, RefCell},
    env, fs,
};
type Result<T> = std::result::Result<T, &'static str>;
struct Image {
    bytes: Vec<u8>,
}
impl Image {
    fn new(bytes: Vec<u8>) -> Result<Self> {
        image_binding::validate_external_caller(&bytes)?;
        Ok(Self { bytes })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    process: u64,
    instance: u64,
    generation: u64,
}
impl Owner {
    fn new(process: u64, instance: u64, generation: u64) -> Result<Self> {
        if [process, instance, generation].contains(&0) {
            return Err("zero identity");
        }
        Ok(Self {
            process,
            instance,
            generation,
        })
    }
}
#[derive(Clone, Copy)]
struct Region {
    writable: bool,
    address: u32,
    start: u32,
    size: u32,
    stack_start: u32,
    stack_size: u32,
}
fn overlap(a: u32, n: u32, b: u32, m: u32) -> bool {
    u64::from(a) < u64::from(b) + u64::from(m) && u64::from(b) < u64::from(a) + u64::from(n)
}
impl Region {
    fn validate(self) -> Result<()> {
        let end = self.address.checked_add(4).ok_or("word overflow")?;
        let limit = self
            .start
            .checked_add(self.size)
            .ok_or("mapping overflow")?;
        self.stack_start
            .checked_add(self.stack_size)
            .ok_or("stack range overflow")?;
        if !self.writable
            || self.address == 0
            || !self.address.is_multiple_of(4)
            || self.size < 4
            || self.stack_size == 0
            || self.address < self.start
            || end > limit
        {
            return Err("full aligned word");
        }
        if overlap(self.address, 4, 0x400000, 0x5000)
            || overlap(self.address, 4, self.stack_start, self.stack_size)
        {
            return Err("protected image/stack");
        }
        Ok(())
    }
}
struct Session<'a> {
    image: &'a Image,
    owner: Owner,
    region: Region,
    value: RefCell<Option<u32>>,
    live: Cell<bool>,
    blocked: Cell<bool>,
}
#[derive(Clone, Copy)]
struct Capability<'s, 'i> {
    session: &'s Session<'i>,
}
impl<'a> Session<'a> {
    // Explicit hypothetical frame ONLY. The real accessor cannot call this issuer.
    fn isolated(
        image: &'a Image,
        owner: Owner,
        region: Region,
        value: Option<u32>,
    ) -> Result<Self> {
        region.validate()?;
        Ok(Self {
            image,
            owner,
            region,
            value: RefCell::new(value),
            live: Cell::new(true),
            blocked: Cell::new(false),
        })
    }
    fn capability(&self, owner: Owner) -> Result<Capability<'_, 'a>> {
        if owner != self.owner {
            return Err("wrong owner/generation");
        }
        if !self.live.get() || self.blocked.get() {
            return Err("revoked");
        }
        Ok(Capability { session: self })
    }
    fn unresolved_accessor(&self) {
        self.blocked.set(true);
        *self.value.borrow_mut() = None;
    }
    fn expire(&self) {
        self.live.set(false);
        *self.value.borrow_mut() = None;
    }
}
impl Capability<'_, '_> {
    fn aliases(&self, other: &Self) -> bool {
        std::ptr::eq(self.session, other.session)
    }
    fn store_zero(&self) -> Result<[u8; 4]> {
        let s = self.session;
        if !s.live.get() || s.blocked.get() {
            return Err("revoked");
        }
        s.region.validate()?;
        *s.value.borrow_mut() = Some(0);
        Ok([0, 0, 0, 0])
    }
}
fn integer(s: &str) -> Result<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unsigned integer");
    }
    s.parse().map_err(|_| "integer width")
}
fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    if !(a.len() == 2 || a.len() == 4 && a[2] == "--isolated") {
        return Err("usage: crt_external_cell PE [--isolated U32-or-unknown]");
    }
    let image = Image::new(fs::read(&a[1]).map_err(|_| "read image")?)?;
    let before = if a.len() == 4 && a[3] != "unknown" {
        Some(integer(&a[3])?)
    } else {
        None
    };
    // Synthetic virtual addresses are labels only: never mapped or dereferenced.
    let s = Session::isolated(
        &image,
        Owner::new(1, 1, 1)?,
        Region {
            writable: true,
            address: 0x70001000,
            start: 0x70000000,
            size: 0x2000,
            stack_start: 0x100000,
            stack_size: 0x10000,
        },
        before,
    )?;
    let _pinned_image_len = s.image.bytes.len();
    let (stored, aliases) = if a.len() == 4 {
        let c = s.capability(s.owner)?;
        let alias = s.capability(s.owner)?;
        c.store_zero()?;
        (true, c.aliases(&alias))
    } else {
        s.unresolved_accessor();
        (false, false)
    };
    // Exercise lifetime revocation after reporting the effect, without restoring authority.
    let output = if stored { "0" } else { "null" };
    let eax_kind = if stored {
        "owned-external-pointer"
    } else {
        "unknown"
    };
    println!("{{\"stored\":{stored},\"cell_after\":{output},\"same_owner_alias\":{aliases},\"esi\":0,\"ecx\":null,\"edx\":null,\"arithmetic_flags\":null,\"eax_kind\":\"{eax_kind}\",\"hypothetical_frame\":{stored},\"accessor_effects_closed\":false,\"complete_startup_proof\":false,\"emission_allowed\":false}}");
    s.expire();
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("external-cell rejected: {e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // State tests intentionally use an inert image marker, not a forged PE binding.
    fn image() -> Image {
        Image {
            bytes: vec![1, 2, 3],
        }
    }
    fn owner() -> Owner {
        Owner::new(1, 2, 3).unwrap()
    }
    fn region() -> Region {
        Region {
            writable: true,
            address: 0x70001000,
            start: 0x70000000,
            size: 8192,
            stack_start: 0x100000,
            stack_size: 4096,
        }
    }
    #[test]
    fn literal_overwrites_and_aliases() {
        let i = image();
        for v in [None, Some(0), Some(64), Some(u32::MAX)] {
            let s = Session::isolated(&i, owner(), region(), v).unwrap();
            let a = s.capability(owner()).unwrap();
            let b = s.capability(owner()).unwrap();
            assert!(a.aliases(&b));
            assert_eq!(a.store_zero(), Ok([0, 0, 0, 0]));
            assert_eq!(*b.session.value.borrow(), Some(0));
            assert_eq!(i.bytes, [1, 2, 3]);
        }
    }
    #[test]
    fn equal_numeric_id_different_objects_not_aliases() {
        let i = image();
        let a = Session::isolated(&i, owner(), region(), Some(64)).unwrap();
        let b = Session::isolated(&i, owner(), region(), Some(99)).unwrap();
        let p = a.capability(owner()).unwrap();
        let q = b.capability(owner()).unwrap();
        assert!(!p.aliases(&q));
        p.store_zero().unwrap();
        assert_eq!(*b.value.borrow(), Some(99));
    }
    #[test]
    fn wrong_owners_atomic() {
        let i = image();
        let s = Session::isolated(&i, owner(), region(), Some(64)).unwrap();
        for o in [
            Owner::new(9, 2, 3).unwrap(),
            Owner::new(1, 9, 3).unwrap(),
            Owner::new(1, 2, 9).unwrap(),
        ] {
            assert!(s.capability(o).is_err());
            assert_eq!(*s.value.borrow(), Some(64));
        }
    }
    #[test]
    fn expired_aliases_reject() {
        let i = image();
        let s = Session::isolated(&i, owner(), region(), Some(64)).unwrap();
        let p = s.capability(owner()).unwrap();
        let q = p;
        s.expire();
        assert!(p.store_zero().is_err());
        assert!(q.store_zero().is_err());
        assert!(s.capability(owner()).is_err());
        assert_eq!(*s.value.borrow(), None);
    }
    #[test]
    fn unknown_effect_stays_blocked() {
        let i = image();
        let s = Session::isolated(&i, owner(), region(), Some(64)).unwrap();
        let p = s.capability(owner()).unwrap();
        s.unresolved_accessor();
        assert!(p.store_zero().is_err());
        assert!(s.capability(owner()).is_err());
        assert_eq!(*s.value.borrow(), None);
    }
    #[test]
    fn complete_ranges_and_protected_slots() {
        for address in [
            0, 1, 0x400000, 0x4030ac, 0x403040, 0x100000, 0x70001ffd, 0xfffffffc, 0xffffffff,
        ] {
            let mut r = region();
            r.address = address;
            assert!(r.validate().is_err());
        }
        for address in [0x400000, 0x4030ac, 0x100000] {
            let mut r = region();
            r.address = address;
            r.start = address;
            assert_eq!(r.validate(), Err("protected image/stack"));
        }
        let mut read_only = region();
        read_only.writable = false;
        assert!(read_only.validate().is_err());
        for size in [0, 1, 3, 4099, u32::MAX] {
            let mut r = region();
            r.size = size;
            assert!(r.validate().is_err());
        }
        let mut r = region();
        r.stack_start = 0x70001002;
        assert!(r.validate().is_err());
    }
    #[test]
    fn malformed_integer_boundaries() {
        for s in ["-1", "0.5", "1.0", "true", "4294967296", "", "+1"] {
            assert!(integer(s).is_err());
        }
        assert_eq!(integer("4294967295"), Ok(u32::MAX));
        assert!(Owner::new(0, 1, 1).is_err());
    }
}
