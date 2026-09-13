//! An in-memory remote, for tests that need a filesystem rather than a protocol.
//!
//! Distinct from the fake server inside `fs::sftp`'s tests, which exists to make a
//! read *fail* and holds no tree at all. This one holds directories and file bodies
//! so the origin layer can be driven end to end. It counts nothing itself: round
//! trips are counted by `SftpFs` exactly as they are in production, which is the
//! only way an assertion about them means anything.

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::fs::Entry;
use crate::fs::sftp::SftpFs;
use crate::sftp::wire::{
    Attrs, CLOSE, DATA, Dec, Enc, FXF_CREAT, HANDLE, INIT, MKDIR, NAME, OPEN, OPENDIR, READ,
    READDIR, REALPATH, STATUS, VERSION, WRITE,
};
use crate::sftp::{read_frame, write_frame};

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;

pub fn file_attrs(size: u64, mtime: u32) -> Attrs {
    Attrs {
        size: Some(size),
        permissions: Some(0o100644),
        mtime: Some(mtime),
        ..Attrs::default()
    }
}

pub fn dir_attrs() -> Attrs {
    Attrs {
        size: Some(4096),
        permissions: Some(0o040755),
        mtime: Some(1),
        ..Attrs::default()
    }
}

pub fn symlink_attrs() -> Attrs {
    Attrs {
        size: Some(11),
        permissions: Some(0o120777),
        mtime: Some(1),
        ..Attrs::default()
    }
}

#[derive(Default)]
pub struct FakeRemote {
    dirs: HashMap<String, Vec<Entry>>,
    files: HashMap<String, Vec<u8>>,
    /// The account this remote is reached as, when it reports owners at all.
    ///
    /// A file a WRITE creates is owned by this account. That is what makes a daemon
    /// configured with an author name the remote does not actually write as visible in a
    /// test, which is the one situation `SECURITY.md` could not previously claim to catch.
    reached_as: Option<String>,
    /// Directories this remote refuses to open, and the status it refuses with.
    ///
    /// Without this the only refusal a test could produce was "no such file" — the one
    /// refusal a caller is entitled to read as an ordinary empty answer. The whole class of
    /// failures that must *not* read as empty therefore had no way to be exercised at all.
    refuses: HashMap<String, u32>,
    /// What REALPATH of "." answers, if this remote has been told.
    ///
    /// Unset is a refusal rather than a plausible-looking default, so a test that
    /// depends on the home directory has to say what it is. A default would let a test
    /// pass while asserting nothing about the value it was handed.
    home: Option<String>,
}

impl FakeRemote {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare what REALPATH of "." answers — the account's home directory.
    pub fn home(mut self, path: &str) -> Self {
        self.home = Some(path.to_string());
        self
    }

    /// Refuse to open a directory, for a reason that is not absence.
    pub fn refuses_listing(mut self, path: &str, status: u32) -> Self {
        self.refuses.insert(path.to_string(), status);
        self
    }

    /// Declare a directory and what a listing of it returns.
    ///
    /// Entries start with no owner, which is a remote reporting nothing legible rather than
    /// one reporting nobody. Use [`FakeRemote::owner`] to say otherwise: a default owner
    /// would make the ownership check pass without any test having chosen that.
    pub fn dir(mut self, path: &str, entries: Vec<(&str, Attrs)>) -> Self {
        self.dirs.insert(
            path.to_string(),
            entries
                .into_iter()
                .map(|(name, attrs)| Entry {
                    name: name.to_string(),
                    attrs,
                    owner: None,
                })
                .collect(),
        );
        self
    }

    /// The account this remote is reached as, so a WRITE creates a file owned by it.
    pub fn reached_as(mut self, who: &str) -> Self {
        self.reached_as = Some(who.to_string());
        self
    }

    /// Declare who a listing reports as the owner of one already-declared path.
    ///
    /// Panics if the path has no listing entry yet. Doing nothing instead would let a test
    /// believe it had arranged a mismatch when it had arranged nothing at all.
    pub fn owner(mut self, path: &str, who: &str) -> Self {
        let (parent, name) = path.rsplit_once('/').expect("an owner needs a full path");
        let entry = self
            .dirs
            .get_mut(parent)
            .and_then(|entries| entries.iter_mut().find(|e| e.name == name))
            .unwrap_or_else(|| panic!("no listing entry for {path}; declare it with dir() first"));
        entry.owner = Some(who.to_string());
        self
    }

    /// Declare a file body. The listing entry is declared separately on purpose: a
    /// listing that promises a file the remote then refuses is a real situation, and
    /// the origin layer has to survive it.
    pub fn file(mut self, path: &str, body: &[u8]) -> Self {
        self.files.insert(path.to_string(), body.to_vec());
        self
    }

    /// Start serving, and hand back a client driving it through the real `SftpFs`,
    /// including its writer coalescing and its round-trip counter.
    pub async fn spawn(self) -> SftpFs {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (cr, cw) = tokio::io::split(client);
        let (sr, sw) = tokio::io::split(server);
        tokio::spawn(serve(self, sr, sw));
        SftpFs::over(cw, cr)
            .await
            .expect("handshake with the in-memory remote")
    }
}

/// Handles are opaque to the client, so they carry what the server needs: a kind, a
/// serial to keep a reopened path distinct, and the path.
fn handle_for(kind: char, serial: u32, path: &str) -> Vec<u8> {
    format!("{kind}{serial}:{path}").into_bytes()
}

fn path_of(handle: &[u8]) -> Option<String> {
    let s = String::from_utf8(handle.to_vec()).ok()?;
    let (_kind_and_serial, path) = s.split_once(':')?;
    Some(path.to_string())
}

async fn serve<R, W>(mut remote: FakeRemote, mut r: R, mut w: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (kind, _) = read_frame(&mut r).await.expect("init frame");
    assert_eq!(kind, INIT, "first frame must be SSH_FXP_INIT");
    write_frame(&mut w, VERSION, &Enc::new().u32(3).done())
        .await
        .expect("version");
    w.flush().await.expect("flush version");

    let mut serial = 0u32;
    // Which readdir handles have already returned their single page.
    let mut drained: Vec<Vec<u8>> = Vec::new();

    while let Ok((kind, payload)) = read_frame(&mut r).await {
        let mut d = Dec::new(&payload);
        let id = d.u32().expect("request id");

        let (out_kind, body) = match kind {
            OPENDIR => {
                let path = utf8(d.str().expect("opendir path"));
                // A declared refusal wins over the tree, so a directory can be made to exist
                // and still be refused — which is what a permission problem looks like.
                if let Some(&code) = remote.refuses.get(&path) {
                    (STATUS, status(id, code, "refused"))
                } else if remote.dirs.contains_key(&path) {
                    serial += 1;
                    (
                        HANDLE,
                        Enc::new()
                            .u32(id)
                            .str(&handle_for('D', serial, &path))
                            .done(),
                    )
                } else {
                    (STATUS, status(id, SSH_FX_NO_SUCH_FILE, "no such directory"))
                }
            }
            READDIR => {
                let handle = d.str().expect("readdir handle").to_vec();
                let path = path_of(&handle).expect("readdir handle shape");
                if drained.contains(&handle) {
                    (STATUS, status(id, SSH_FX_EOF, "eof"))
                } else {
                    drained.push(handle);
                    let entries = remote.dirs.get(&path).expect("listed dir exists");
                    (NAME, names(id, entries))
                }
            }
            OPEN => {
                let path = utf8(d.str().expect("open path"));
                let flags = d.u32().expect("open flags");
                // A create flag makes the file exist, as it does on a real server. Without
                // this an append could never write a log that did not already exist.
                let creating = flags & FXF_CREAT != 0;
                if creating {
                    remote.files.entry(path.clone()).or_default();
                }
                if remote.files.contains_key(&path) {
                    serial += 1;
                    (
                        HANDLE,
                        Enc::new()
                            .u32(id)
                            .str(&handle_for('F', serial, &path))
                            .done(),
                    )
                } else {
                    (STATUS, status(id, SSH_FX_NO_SUCH_FILE, "no such file"))
                }
            }
            READ => {
                let handle = d.str().expect("read handle").to_vec();
                let path = path_of(&handle).expect("read handle shape");
                let offset = d.u64().expect("read offset") as usize;
                // The requested length is honoured, as a real server does. Returning
                // everything from the offset would hide a caller that asked for the
                // wrong amount.
                let want = d.u32().expect("read length") as usize;
                let body = remote.files.get(&path).expect("opened file exists");
                if offset >= body.len() {
                    (STATUS, status(id, SSH_FX_EOF, "eof"))
                } else {
                    let end = offset.saturating_add(want).min(body.len());
                    (DATA, Enc::new().u32(id).str(&body[offset..end]).done())
                }
            }
            WRITE => {
                let handle = d.str().expect("write handle").to_vec();
                let path = path_of(&handle).expect("write handle shape");
                // The offset is read and ignored: the client opened in append mode, and a
                // real server places the data at the end regardless of what it says.
                d.u64().expect("write offset");
                let data = d.str().expect("write data").to_vec();
                remote
                    .files
                    .entry(path.clone())
                    .or_default()
                    .extend_from_slice(&data);

                // Made visible to a listing too, because a listing is how the reader finds
                // the file at all. A fake that wrote without listing would let a broken
                // reader pass.
                if let Some((parent, name)) = path.rsplit_once('/') {
                    let size = remote.files.get(&path).map_or(0, Vec::len) as u64;
                    let entries = remote.dirs.entry(parent.to_string()).or_default();
                    match entries.iter_mut().find(|e| e.name == name) {
                        Some(e) => e.attrs.size = Some(size),
                        // A file this remote creates belongs to the account it is reached
                        // as, whatever the writer decided to call the file.
                        None => entries.push(Entry {
                            name: name.to_string(),
                            attrs: file_attrs(size, 1),
                            owner: remote.reached_as.clone(),
                        }),
                    }
                }
                (STATUS, status(id, SSH_FX_OK, "ok"))
            }
            REALPATH => {
                d.str().expect("realpath path");
                match &remote.home {
                    // A one-entry NAME page, built by the same encoder a listing uses.
                    // That is what v3 puts on the wire for this, and going through the
                    // same encoder is what stops the client's decoder from being tested
                    // against a shape only this file produces.
                    Some(home) => (
                        NAME,
                        names(
                            id,
                            &[Entry {
                                name: home.clone(),
                                attrs: dir_attrs(),
                                owner: remote.reached_as.clone(),
                            }],
                        ),
                    ),
                    None => (
                        STATUS,
                        status(id, 4, "this remote was not given a home directory"),
                    ),
                }
            }
            MKDIR => {
                let path = utf8(d.str().expect("mkdir path"));
                remote.dirs.entry(path).or_default();
                (STATUS, status(id, SSH_FX_OK, "ok"))
            }
            CLOSE => {
                d.str().expect("close handle");
                (STATUS, status(id, SSH_FX_OK, "ok"))
            }
            other => panic!("in-memory remote got unexpected request type {other}"),
        };

        write_frame(&mut w, out_kind, &body).await.expect("reply");
        w.flush().await.expect("flush reply");
    }
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn status(id: u32, code: u32, message: &str) -> Vec<u8> {
    Enc::new()
        .u32(id)
        .u32(code)
        .str(message.as_bytes())
        .str(b"")
        .done()
}

/// SIZE | PERMISSIONS | ACMODTIME, in the order the fields are written below.
const WRITTEN_ATTRS: u32 = 0x0000_0001 | 0x0000_0004 | 0x0000_0008;

/// The `ls -l`-shaped longname a real server sends, so that the client's owner parse is
/// exercised rather than bypassed.
///
/// An entry with no owner gets the bare filename instead. That is what a server reporting
/// nothing useful looks like on the wire, and it is what the client has to decline to parse
/// rather than read an owner out of.
///
/// The date is a fixed string. A real one would suggest the client reads it, and it does
/// not: the column is ambiguous between a time and a year depending on the file's age.
fn longname(e: &Entry) -> String {
    match &e.owner {
        Some(who) => format!(
            "{} 1 {who} {who} {:>8} Jan  1 00:00 {}",
            mode_column(&e.attrs),
            e.attrs.size.unwrap_or(0),
            e.name
        ),
        None => e.name.clone(),
    }
}

fn mode_column(attrs: &Attrs) -> &'static str {
    if attrs.is_dir() {
        "drwxr-xr-x"
    } else if attrs.is_symlink() {
        "lrwxrwxrwx"
    } else {
        "-rw-r--r--"
    }
}

fn names(id: u32, entries: &[Entry]) -> Vec<u8> {
    let mut enc = Enc::new().u32(id).u32(entries.len() as u32);
    for e in entries {
        enc = enc
            .str(e.name.as_bytes())
            .str(longname(e).as_bytes())
            .u32(WRITTEN_ATTRS)
            .u64(e.attrs.size.unwrap_or(0))
            .u32(e.attrs.permissions.unwrap_or(0o100644))
            .u32(e.attrs.atime.unwrap_or(0))
            .u32(e.attrs.mtime.unwrap_or(0));
    }
    enc.done()
}
