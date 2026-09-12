//! SFTP v3 wire format.

pub const INIT: u8 = 1;
pub const VERSION: u8 = 2;
pub const OPEN: u8 = 3;
pub const CLOSE: u8 = 4;
pub const READ: u8 = 5;
pub const WRITE: u8 = 6;
pub const LSTAT: u8 = 7;
pub const OPENDIR: u8 = 11;
pub const READDIR: u8 = 12;
pub const MKDIR: u8 = 14;
pub const REALPATH: u8 = 16;
pub const STATUS: u8 = 101;
pub const HANDLE: u8 = 102;
pub const DATA: u8 = 103;
pub const NAME: u8 = 104;
pub const ATTRS: u8 = 105;

pub const FXF_READ: u32 = 0x0000_0001;
pub const FXF_WRITE: u32 = 0x0000_0002;
/// In append mode the offset in each WRITE is ignored and the server places the data at
/// the end. That is what makes a single-writer log safe without any locking.
pub const FXF_APPEND: u32 = 0x0000_0004;
pub const FXF_CREAT: u32 = 0x0000_0008;

/// A read ending in SSH_FX_EOF is a normal end of file. Any other status is a
/// real failure, and conflating the two turns a directory into an empty 200.
pub const STATUS_EOF: u32 = 1;

/// SSH_FX_OK, the only status a write may answer with.
pub const STATUS_OK: u32 = 0;

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
///
/// `uid` deliberately does not answer "does this log belong to the account it
/// names": it is a number, an author is a name, and turning one into the other
/// needs a passwd lookup there is no way to perform over the sftp subsystem.
/// [`owner_of_longname`] is what answers that.
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

/// The owner's account name out of an SFTP v3 `longname`, if one can be read with
/// confidence.
///
/// Version 3 says only that the field looks like `ls -l` output, so this parses a
/// convention rather than a grammar, and it is written to decline rather than to
/// guess. That direction is the whole point. The one thing this feeds is the check
/// that an annotation log belongs to the account its filename names, and a wrongly
/// parsed owner would accuse a real person of writing somebody else's log — strictly
/// worse than having no check at all. So the leading fields are all validated, and
/// anything unfamiliar yields `None`, which the caller reports as "not checked"
/// rather than as agreement.
///
/// Nothing past the size is looked at. The name at the end may contain spaces, and
/// the date is the `ls -l` mixture of `Mon DD HH:MM` and `Mon DD  YYYY` depending on
/// the file's age — neither is needed here, so neither is interpreted.
pub fn owner_of_longname(longname: &str) -> Option<&str> {
    let mut fields = longname.split_ascii_whitespace();
    if !is_mode_string(fields.next()?) {
        return None;
    }
    // Link count and size are parsed only to be discarded: they are what distinguishes
    // a real listing line from a string that merely opens like one.
    fields.next()?.parse::<u64>().ok()?;
    let owner = fields.next()?;
    let _group = fields.next()?;
    fields.next()?.parse::<u64>().ok()?;
    Some(owner)
}

/// Does this look like the ten-character mode column of a listing?
fn is_mode_string(s: &str) -> bool {
    // A trailing `+` or `.` marks an ACL or a security context on some systems, which
    // says nothing about the owner either way.
    let b = s
        .strip_suffix('+')
        .or_else(|| s.strip_suffix('.'))
        .unwrap_or(s)
        .as_bytes();
    b.len() == 10
        && matches!(b[0], b'-' | b'd' | b'l' | b'b' | b'c' | b'p' | b's')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'r' | b'w' | b'x' | b's' | b't' | b'S' | b'T' | b'-'))
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

    /// The shape OpenSSH's sftp-server produces, which is the one that matters in
    /// practice, plus the variations other servers are known to add.
    #[test]
    fn reads_the_owner_out_of_a_listing_line() {
        for line in [
            "-rw-r--r--    1 souta    devs         1234 Sep 12 01:00 souta.jsonl",
            // An older file: the time column becomes a year, which is not looked at.
            "-rw-r--r--    1 souta    devs         1234 Sep 12  2024 souta.jsonl",
            "drwxrwsr-x    2 souta    devs         4096 Sep 12 01:00 ann",
            // An ACL marker, and a setuid bit in the mode.
            "-rwsr-xr-x+   1 souta    devs         1234 Sep 12 01:00 x",
            // A filename with spaces in it, which is why nothing past the size is read.
            "-rw-r--r--    1 souta    devs         1234 Sep 12 01:00 two words.jsonl",
        ] {
            assert_eq!(owner_of_longname(line), Some("souta"), "parsing {line:?}");
        }
    }

    /// Declining is the load-bearing behaviour: a guessed owner would accuse somebody
    /// of writing a log that is not theirs, which is worse than reporting no check.
    #[test]
    fn anything_unfamiliar_yields_no_owner() {
        for line in [
            "",
            // What a listing carries when a server reports only the filename.
            "souta.jsonl",
            // Mode column the wrong length, or with characters that do not belong.
            "-rw-r--r-   1 souta devs 1234 Sep 12 01:00 x",
            "-rw-r--r--x 1 souta devs 1234 Sep 12 01:00 x",
            "?rw-r--r--  1 souta devs 1234 Sep 12 01:00 x",
            // Right shape up front, but the numeric columns are not numbers, so this is
            // some other format that happens to start with ten plausible characters.
            "-rw-r--r-- one souta devs 1234 Sep 12 01:00 x",
            "-rw-r--r--   1 souta devs size Sep 12 01:00 x",
            // Truncated before the owner can be established.
            "-rw-r--r--   1 souta",
        ] {
            assert_eq!(owner_of_longname(line), None, "parsing {line:?}");
        }
    }

    /// Ten bytes are not always ten characters. This is why the mode column is examined
    /// as bytes: slicing the `str` would panic on a character boundary instead of
    /// declining, and the remote chooses this string.
    #[test]
    fn a_ten_byte_mode_column_that_is_not_ten_characters_declines() {
        let mode = "-\u{e9}-r--r--";
        assert_eq!(mode.len(), 10, "ten bytes");
        assert_eq!(mode.chars().count(), 9, "but nine characters");
        assert_eq!(
            owner_of_longname(&format!("{mode} 1 souta devs 1 Sep 12 01:00 x")),
            None
        );
    }
}
