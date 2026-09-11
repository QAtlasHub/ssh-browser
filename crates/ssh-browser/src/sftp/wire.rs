//! SFTP v3 wire format.

pub const INIT: u8 = 1;
pub const VERSION: u8 = 2;
pub const OPEN: u8 = 3;
pub const CLOSE: u8 = 4;
pub const READ: u8 = 5;
pub const LSTAT: u8 = 7;
pub const OPENDIR: u8 = 11;
pub const READDIR: u8 = 12;
pub const REALPATH: u8 = 16;
pub const STATUS: u8 = 101;
pub const HANDLE: u8 = 102;
pub const DATA: u8 = 103;
pub const NAME: u8 = 104;
pub const ATTRS: u8 = 105;

pub const FXF_READ: u32 = 0x0000_0001;

const A_SIZE: u32 = 0x0000_0001;
const A_UIDGID: u32 = 0x0000_0002;
const A_PERM: u32 = 0x0000_0004;
const A_TIME: u32 = 0x0000_0008;
const A_EXT: u32 = 0x8000_0000;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// Big-endian encoder, chained by value so one request is one expression.
#[derive(Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn str(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(&(v.len() as u32).to_be_bytes());
        self.0.extend_from_slice(v);
        self
    }

    pub fn done(self) -> Vec<u8> {
        self.0
    }
}

/// Bounds-checked reader. Every accessor returns None rather than panicking so a
/// malformed reply from the remote cannot take the daemon down.
pub struct Dec<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let end = self.i.checked_add(4)?;
        let v = u32::from_be_bytes(self.b.get(self.i..end)?.try_into().ok()?);
        self.i = end;
        Some(v)
    }

    pub fn u64(&mut self) -> Option<u64> {
        let end = self.i.checked_add(8)?;
        let v = u64::from_be_bytes(self.b.get(self.i..end)?.try_into().ok()?);
        self.i = end;
        Some(v)
    }

    pub fn str(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let end = self.i.checked_add(n)?;
        let v = self.b.get(self.i..end)?;
        self.i = end;
        Some(v)
    }
}

/// The subset of SSH_FXP_ATTRS the origin layer needs.
///
/// `size` and `mtime` form the cache key, which is why a single READDIR can
/// replace a per-file STAT and keep the round trips flat. `uid` is what lets us
/// check an annotation log's declared author against the file's real owner.
#[derive(Debug, Clone, Copy, Default)]
pub struct Attrs {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl Attrs {
    pub fn decode(d: &mut Dec<'_>) -> Option<Self> {
        let flags = d.u32()?;
        let mut a = Self::default();
        if flags & A_SIZE != 0 {
            a.size = Some(d.u64()?);
        }
        if flags & A_UIDGID != 0 {
            a.uid = Some(d.u32()?);
            a.gid = Some(d.u32()?);
        }
        if flags & A_PERM != 0 {
            a.permissions = Some(d.u32()?);
        }
        if flags & A_TIME != 0 {
            a.atime = Some(d.u32()?);
            a.mtime = Some(d.u32()?);
        }
        if flags & A_EXT != 0 {
            for _ in 0..d.u32()? {
                d.str()?;
                d.str()?;
            }
        }
        Some(a)
    }

    pub fn is_dir(&self) -> bool {
        self.permissions.is_some_and(|p| p & S_IFMT == S_IFDIR)
    }

    pub fn is_symlink(&self) -> bool {
        self.permissions.is_some_and(|p| p & S_IFMT == S_IFLNK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_primitives() {
        let bytes = Enc::new().u32(7).u64(1 << 40).str(b"hi").done();
        let mut d = Dec::new(&bytes);
        assert_eq!(d.u32(), Some(7));
        assert_eq!(d.u64(), Some(1 << 40));
        assert_eq!(d.str(), Some(&b"hi"[..]));
        assert_eq!(d.u32(), None);
    }

    #[test]
    fn truncated_input_returns_none_instead_of_panicking() {
        let mut d = Dec::new(&[0, 0, 0, 9, 1, 2]);
        assert_eq!(d.str(), None);
    }

    #[test]
    fn decodes_attrs_and_classifies_a_directory() {
        let bytes = Enc::new()
            .u32(A_SIZE | A_UIDGID | A_PERM | A_TIME)
            .u64(4096)
            .u32(1000)
            .u32(1000)
            .u32(0o040755)
            .u32(111)
            .u32(222)
            .done();
        let a = Attrs::decode(&mut Dec::new(&bytes)).expect("attrs");
        assert_eq!(a.size, Some(4096));
        assert_eq!(a.uid, Some(1000));
        assert_eq!(a.mtime, Some(222));
        assert!(a.is_dir());
        assert!(!a.is_symlink());
    }

    #[test]
    fn skips_extended_attr_pairs() {
        let bytes = Enc::new()
            .u32(A_SIZE | A_EXT)
            .u64(1)
            .u32(1)
            .str(b"k")
            .str(b"v")
            .done();
        let a = Attrs::decode(&mut Dec::new(&bytes)).expect("attrs");
        assert_eq!(a.size, Some(1));
    }
}
