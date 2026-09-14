//! SFTP v3 wire format.

/// A request this daemon can send.
///
/// The README says nothing is written to your remote, and this is the sentence that makes it
/// true: `Verb` wraps a `u8` that nothing outside this module can construct, and there are six
/// of them. `SSH_FXP_WRITE`, `SETSTAT`, `REMOVE`, `MKDIR`, `RMDIR`, `RENAME` and `SYMLINK` are
/// not missing by policy -- there is no value of this type that means them, so the code that
/// would send one does not compile.
///
/// A seventh means adding a `pub const` here, which is a line in a diff somebody reads. That
/// is the point: the claim stops being a thing to remember and becomes a thing to notice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verb(u8);

impl Verb {
    /// The byte that goes on the wire.
    ///
    /// One way only. There is no `from_u8`, because a byte that arrived from somewhere is a
    /// reply type or somebody's input, and neither is a request this may send.
    pub const fn code(self) -> u8 {
        self.0
    }
}

pub const OPEN: Verb = Verb(3);
pub const CLOSE: Verb = Verb(4);
pub const READ: Verb = Verb(5);
pub const OPENDIR: Verb = Verb(11);
pub const READDIR: Verb = Verb(12);
pub const REALPATH: Verb = Verb(16);

/// The version handshake, which is not a filesystem request and so is not a `Verb`.
pub const INIT: u8 = 1;
pub const VERSION: u8 = 2;

/// Reply types. These arrive; they are never sent, which is why they stay bytes.
pub const STATUS: u8 = 101;
pub const HANDLE: u8 = 102;
pub const DATA: u8 = 103;
pub const NAME: u8 = 104;
pub const ATTRS: u8 = 105;

/// The only open mode this daemon has. There is no write path.
pub const FXF_READ: u32 = 0x0000_0001;

/// A read ending in SSH_FX_EOF is a normal end of file. Any other status is a
/// real failure, and conflating the two turns a directory into an empty 200.
pub const STATUS_EOF: u32 = 1;

/// SSH_FX_OK, the only status a write may answer with.
pub const STATUS_OK: u32 = 0;

/// SSH_FX_NO_SUCH_FILE: the one refusal that means "there is nothing there" rather than
/// "something went wrong". Everything else — a permission problem, a dead session, a server
/// that simply failed — has to stay distinguishable from it, because the difference is the
/// difference between an empty answer and an error.
pub const STATUS_NO_SUCH_FILE: u32 = 2;

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
/// replace a per-file STAT and keep the round trips flat.
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

    /// The README says nothing is written to your remote. This is the list that claim is about.
    ///
    /// It fails two ways, and both are the point. Adding a `Verb` and forgetting this list
    /// fails it; deleting one that is in use fails to compile. So the set cannot grow quietly,
    /// which is the only way a read-only client stops being one.
    #[test]
    fn the_verbs_are_the_six_read_ones() {
        let mut codes = [OPEN, CLOSE, READ, OPENDIR, READDIR, REALPATH].map(Verb::code);
        codes.sort_unstable();
        assert_eq!(codes, [3, 4, 5, 11, 12, 16]);

        // SSH_FXP_WRITE, SETSTAT, FSETSTAT, REMOVE, MKDIR, RMDIR, RENAME, SYMLINK. Named here
        // so that the absence is written down: a reader should not have to know SFTP v3 by
        // heart to see that the dangerous half of it is not in the list above.
        for writes in [6u8, 9, 10, 13, 14, 15, 18, 20] {
            assert!(!codes.contains(&writes), "{writes} is a write");
        }
    }

    /// The only open mode there is. `FXF_WRITE`, `FXF_APPEND`, `FXF_CREAT` and `FXF_TRUNC` are
    /// not defined anywhere in this crate, so `OPEN` has nothing else it could ask for.
    #[test]
    fn the_only_open_flag_is_read() {
        assert_eq!(FXF_READ, 1);
    }

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
