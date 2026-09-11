//! Filesystem access shaped so that latency optimisation survives a backend swap.
//!
//! The operations are batch-first on purpose. A per-path interface — `stat(p)`,
//! `read(p)` — forces O(N) round trips no matter which backend implements it, so
//! the abstraction would defeat the invariant it sits beneath. A single read is
//! the n=1 case of `read_batch`, not the other way round.

use anyhow::Result;

use crate::sftp::wire::Attrs;

pub mod sftp;

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub attrs: Attrs,
}

#[allow(async_fn_in_trait)]
pub trait RemoteFs {
    /// Read whole files. Implementations must issue every request before awaiting
    /// any reply; doing otherwise silently reintroduces O(N) round trips.
    async fn read_batch(&self, paths: &[String]) -> Vec<Result<Vec<u8>>>;

    /// One listing carries every entry's attrs, which is what removes per-file
    /// stat from the page path entirely.
    async fn list_dir(&self, path: &str) -> Result<Vec<Entry>>;

    /// Flushes issued so far. One flush is one remote round trip, so this is the
    /// invariant made observable, and assertable in tests.
    fn round_trips(&self) -> u64;
}
