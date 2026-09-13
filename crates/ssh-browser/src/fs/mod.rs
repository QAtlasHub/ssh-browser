//! Filesystem access shaped so that latency optimisation survives a backend swap.
//!
//! The operations are batch-first on purpose. A per-path interface — `stat(p)`,
//! `read(p)` — forces O(N) round trips no matter which backend implements it, so
//! the abstraction would defeat the invariant it sits beneath. A single read is
//! the n=1 case of `read_batch`, not the other way round.

use anyhow::{Result, anyhow};

use crate::sftp::wire::{Attrs, STATUS_NO_SUCH_FILE};

pub mod sftp;

/// A refusal from the remote, carrying the reason it gave.
///
/// The reason has to survive the trip. Without it every failed listing looks alike, and a
/// caller that wants to treat "there is no such directory" as an ordinary empty answer ends
/// up treating a dead session and a permission problem that way too — which is how a remote
/// that has stopped answering comes to render as a directory with nothing in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub status: u32,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.status {
            1 => "end of file",
            2 => "no such file",
            3 => "permission denied",
            4 => "failure",
            5 => "bad message",
            6 => "no connection",
            7 => "connection lost",
            8 => "operation unsupported",
            _ => "unrecognised status",
        };
        write!(f, "the remote refused: {name} ({})", self.status)
    }
}

impl std::error::Error for Refused {}

/// Did this failure mean "there is nothing there", as opposed to anything else at all?
///
/// Anything that cannot be established as absence is not treated as absence. Guessing the
/// other way turns every transport problem into an empty answer, which is the failure this
/// project has already shipped once.
pub fn is_absent(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<Refused>())
        .any(|r| r.status == STATUS_NO_SUCH_FILE)
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub attrs: Attrs,
}

/// One byte range of one file.
#[derive(Debug, Clone)]
pub struct RangeReq {
    pub path: String,
    pub offset: u64,
    /// Bytes wanted. Fewer may come back at end of file, which is not an error.
    pub len: u64,
}

#[allow(async_fn_in_trait)]
pub trait RemoteFs {
    /// Read whole files. Implementations must issue every request before awaiting
    /// any reply; doing otherwise silently reintroduces O(N) round trips.
    async fn read_batch(&self, paths: &[String]) -> Vec<Result<Vec<u8>>>;

    /// Read byte ranges. Chunking is the implementation's business; what matters
    /// here is that the whole set is issued together, so a one-megabyte range costs
    /// one round trip rather than the thirty-two its chunks would suggest.
    async fn read_ranges(&self, reqs: &[RangeReq]) -> Vec<Result<Vec<u8>>>;

    /// List several directories at once. One listing carries every entry's attrs,
    /// which is what removes per-file stat from the page path; batching the
    /// listings is what holds a symlink check over a deep path at one round trip
    /// rather than one per path component.
    async fn list_dirs(&self, paths: &[String]) -> Vec<Result<Vec<Entry>>>;

    /// The n=1 case, defined in terms of the batch so that no implementation can
    /// quietly make the single listing the cheap path and the batch a loop.
    async fn list_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let one = [path.to_string()];
        self.list_dirs(&one)
            .await
            .into_iter()
            .next()
            .unwrap_or_else(|| Err(anyhow!("list_dirs returned no result for {path}")))
    }

    /// The absolute path a fresh session starts in — the account's home directory.
    ///
    /// The one question about the remote that cannot be answered from a path, and the
    /// reason an alias can be written without a base at all. `~` is shell syntax and
    /// the transport never runs a shell, so expanding it locally would produce this
    /// machine's home rather than the remote one.
    ///
    /// Asked once per alias at startup, never on a page path, so it costs no round trip
    /// that a reader waits for.
    async fn home(&self) -> Result<String>;

    /// Flushes issued so far. One flush is one remote round trip, so this is the
    /// invariant made observable.
    ///
    /// Reported by `GET /_control/hosts` per open alias, not only asserted in tests. A
    /// claim about round trips that can only be checked against a fake remote is a claim
    /// about the fake.
    fn round_trips(&self) -> u64;
}
