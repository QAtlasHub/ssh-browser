//! What makes a revisit cost nothing.
//!
//! Two caches with different jobs. The listing cache holds one directory's entries
//! with their attrs, which is what lets a request answer "does this exist, and is
//! it the same version the browser already has?" without going near the remote.
//! The body cache holds file contents keyed by identity rather than by path, so it
//! cannot serve a stale page: a rebuilt file has a different mtime or size and
//! therefore a different key.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::fs::Entry;
use crate::sftp::wire::Attrs;

/// How long a listing is trusted. Short, because a directory's contents are exactly
/// what changes when a site is rebuilt, and a stale listing turns a new file into a
/// 404.
pub const DEFAULT_TTL: Duration = Duration::from_secs(2);

/// Bytes of file content held at once.
pub const DEFAULT_BODY_CAP: usize = 64 * 1024 * 1024;

struct Listing {
    /// Attrs and owner per name.
    ///
    /// The owner is kept even though nothing reads it from here yet, because
    /// `listing_entries` hands back an `Entry`, and an `Entry` with no owner asserts that
    /// the remote did not report one. Dropping it here would make the cache quietly say
    /// something false about the remote rather than something incomplete about itself.
    entries: HashMap<String, (Attrs, Option<String>)>,
    fetched: Instant,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct BodyKey {
    path: String,
    mtime: u32,
    size: u64,
}

/// Insertion-ordered, not least-recently-used.
///
/// A true LRU has to touch the ordering on every hit, and the access pattern here
/// does not reward it: a page's subresources arrive together and are used together,
/// so evicting the oldest whole page is the right thing anyway. Under a 64 MB
/// budget the distinction is hard to even provoke.
struct Bodies {
    map: HashMap<BodyKey, Bytes>,
    order: VecDeque<BodyKey>,
    bytes: usize,
    cap: usize,
}

impl Bodies {
    fn insert(&mut self, key: BodyKey, body: Bytes) {
        // A file larger than the whole budget would evict everything else to cache
        // something that cannot be kept. Decline instead.
        if body.len() > self.cap || self.map.contains_key(&key) {
            return;
        }
        self.bytes += body.len();
        self.order.push_back(key.clone());
        self.map.insert(key, body);

        while self.bytes > self.cap {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(dropped) = self.map.remove(&oldest) {
                self.bytes -= dropped.len();
            }
        }
    }
}

pub struct Cache {
    listings: Mutex<HashMap<String, Listing>>,
    bodies: Mutex<Bodies>,
    ttl: Duration,
}

impl Cache {
    pub fn new(ttl: Duration, body_cap: usize) -> Self {
        Self {
            listings: Mutex::new(HashMap::new()),
            bodies: Mutex::new(Bodies {
                map: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
                cap: body_cap,
            }),
            ttl,
        }
    }

    /// Is there a listing for this directory that is still inside its TTL?
    ///
    /// Distinct from `attrs_of` returning None, which cannot tell "no listing" from
    /// "listed, and the name is not in it". The origin layer needs that difference:
    /// the second is a 404 it can answer locally, the first is a fetch.
    pub fn has_listing(&self, dir: &str) -> bool {
        self.listings
            .lock()
            .expect("listing cache poisoned")
            .get(dir)
            .is_some_and(|l| l.fetched.elapsed() < self.ttl)
    }

    /// Attrs for one entry of a fresh listing. `Attrs` is `Copy`, so this does not
    /// clone the map.
    pub fn attrs_of(&self, dir: &str, name: &str) -> Option<Attrs> {
        let listings = self.listings.lock().expect("listing cache poisoned");
        let listing = listings.get(dir)?;
        if listing.fetched.elapsed() >= self.ttl {
            return None;
        }
        listing.entries.get(name).map(|(attrs, _)| *attrs)
    }

    /// A fresh listing as entries, for rendering a directory index.
    ///
    /// Unlike `attrs_of` this clones, because an autoindex needs every name anyway
    /// and holding the lock across the render would block every other request.
    pub fn listing_entries(&self, dir: &str) -> Option<Vec<Entry>> {
        let listings = self.listings.lock().expect("listing cache poisoned");
        let listing = listings.get(dir)?;
        if listing.fetched.elapsed() >= self.ttl {
            return None;
        }
        Some(
            listing
                .entries
                .iter()
                .map(|(name, (attrs, owner))| Entry {
                    name: name.clone(),
                    attrs: *attrs,
                    owner: owner.clone(),
                })
                .collect(),
        )
    }

    pub fn put_listing(&self, dir: &str, entries: &[Entry]) {
        let map = entries
            .iter()
            .map(|e| (e.name.clone(), (e.attrs, e.owner.clone())))
            .collect::<HashMap<_, _>>();
        self.listings
            .lock()
            .expect("listing cache poisoned")
            .insert(
                dir.to_string(),
                Listing {
                    entries: map,
                    fetched: Instant::now(),
                },
            );
    }

    /// Forget a listing so the next request refetches it.
    ///
    /// Called when a fetch contradicts the listing: a file the listing promised, and
    /// the remote refused. Keeping a listing that has been proven wrong would serve
    /// the same wrong answer for a whole TTL.
    pub fn forget_listing(&self, dir: &str) {
        self.listings
            .lock()
            .expect("listing cache poisoned")
            .remove(dir);
    }

    pub fn body(&self, path: &str, attrs: &Attrs) -> Option<Bytes> {
        let key = body_key(path, attrs)?;
        self.bodies
            .lock()
            .expect("body cache poisoned")
            .map
            .get(&key)
            .cloned()
    }

    pub fn put_body(&self, path: &str, attrs: &Attrs, body: Bytes) {
        // No key means the remote reported neither mtime nor size, so there is
        // nothing to invalidate against. Caching that would be caching a guess.
        let Some(key) = body_key(path, attrs) else {
            return;
        };
        self.bodies
            .lock()
            .expect("body cache poisoned")
            .insert(key, body);
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_BODY_CAP)
    }
}

fn body_key(path: &str, attrs: &Attrs) -> Option<BodyKey> {
    Some(BodyKey {
        path: path.to_string(),
        mtime: attrs.mtime?,
        size: attrs.size?,
    })
}

/// A validator the browser can send back.
///
/// Weak on purpose. SFTP v3 reports mtime in whole seconds, so two writes inside
/// one second that land on the same size are indistinguishable here. Publishing
/// that as a strong ETag would be a lie, and a strong validator is precisely what
/// `If-Range` is permitted to trust.
pub fn etag(attrs: &Attrs) -> Option<String> {
    let mtime = attrs.mtime?;
    let size = attrs.size?;
    Some(format!("W/\"{mtime:x}-{size:x}\""))
}

/// Weak comparison per RFC 9110: the weakness marker is stripped from both sides,
/// and `*` matches whatever the client holds.
pub fn etag_matches(header: &str, tag: &str) -> bool {
    let want = normalise(tag);
    header
        .split(',')
        .any(|candidate| candidate.trim() == "*" || normalise(candidate) == want)
}

fn normalise(tag: &str) -> &str {
    tag.trim().trim_start_matches("W/").trim_matches('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(mtime: u32, size: u64) -> Attrs {
        Attrs {
            mtime: Some(mtime),
            size: Some(size),
            ..Attrs::default()
        }
    }

    fn entry(name: &str, a: Attrs) -> Entry {
        Entry {
            name: name.to_string(),
            attrs: a,
            owner: Some("souta".to_string()),
        }
    }

    #[test]
    fn a_fresh_listing_answers_without_the_remote() {
        let c = Cache::default();
        c.put_listing("/srv", &[entry("a.html", attrs(100, 7))]);
        assert!(c.has_listing("/srv"));
        assert_eq!(c.attrs_of("/srv", "a.html").and_then(|a| a.size), Some(7));
        // Listed, but no such name: a 404 the origin can answer locally.
        assert!(c.attrs_of("/srv", "missing.html").is_none());
    }

    #[test]
    fn a_stale_listing_is_not_used() {
        let c = Cache::new(Duration::ZERO, DEFAULT_BODY_CAP);
        c.put_listing("/srv", &[entry("a.html", attrs(100, 7))]);
        assert!(!c.has_listing("/srv"));
        assert!(c.attrs_of("/srv", "a.html").is_none());
    }

    #[test]
    fn forgetting_a_listing_forces_a_refetch() {
        let c = Cache::default();
        c.put_listing("/srv", &[entry("a.html", attrs(100, 7))]);
        c.forget_listing("/srv");
        assert!(!c.has_listing("/srv"));
    }

    /// The point of keying on identity: a rebuilt file must not be served out of the
    /// cache entry belonging to the old one.
    #[test]
    fn a_changed_file_misses_the_cache() {
        let c = Cache::default();
        let old = attrs(100, 7);
        c.put_body("/srv/a.html", &old, Bytes::from_static(b"old"));
        assert_eq!(
            c.body("/srv/a.html", &old).as_deref(),
            Some(&b"old"[..]),
            "the version that was cached is served"
        );

        let rebuilt_same_size = attrs(200, 7);
        assert!(
            c.body("/srv/a.html", &rebuilt_same_size).is_none(),
            "a new mtime must miss even when the size is unchanged"
        );
        let rebuilt_same_mtime = attrs(100, 9);
        assert!(
            c.body("/srv/a.html", &rebuilt_same_mtime).is_none(),
            "a new size must miss even when the mtime is unchanged"
        );
    }

    #[test]
    fn a_body_without_mtime_or_size_is_not_cached() {
        let c = Cache::default();
        let bare = Attrs::default();
        c.put_body("/srv/a.html", &bare, Bytes::from_static(b"x"));
        assert!(c.body("/srv/a.html", &bare).is_none());
    }

    #[test]
    fn the_body_cache_respects_its_budget() {
        let c = Cache::new(DEFAULT_TTL, 10);
        for i in 0..5u32 {
            c.put_body(&format!("/f{i}"), &attrs(i, 4), Bytes::from_static(b"1234"));
        }
        let held = c.bodies.lock().expect("body cache").bytes;
        assert!(held <= 10, "cache holds {held} bytes over a 10 byte budget");
        // The newest survives; the oldest went first.
        assert!(c.body("/f4", &attrs(4, 4)).is_some());
        assert!(c.body("/f0", &attrs(0, 4)).is_none());
    }

    #[test]
    fn a_file_bigger_than_the_budget_is_declined_rather_than_flushing_everything() {
        let c = Cache::new(DEFAULT_TTL, 4);
        c.put_body("/small", &attrs(1, 2), Bytes::from_static(b"ab"));
        c.put_body("/huge", &attrs(2, 99), Bytes::from_static(b"0123456789"));
        assert!(c.body("/huge", &attrs(2, 99)).is_none());
        assert!(
            c.body("/small", &attrs(1, 2)).is_some(),
            "an oversized insert must not flush the cache"
        );
    }

    #[test]
    fn etags_compare_weakly() {
        let a = attrs(0x64, 0x7);
        let tag = etag(&a).expect("attrs carry mtime and size");
        assert_eq!(tag, "W/\"64-7\"");
        assert!(etag_matches(&tag, &tag));
        // A client that drops the weakness marker still matches.
        assert!(etag_matches("\"64-7\"", &tag));
        assert!(etag_matches("*", &tag));
        assert!(etag_matches("\"deadbeef\", W/\"64-7\"", &tag));
        assert!(!etag_matches("W/\"64-8\"", &tag));
        assert!(!etag_matches("", &tag));
    }

    #[test]
    fn an_etag_needs_both_halves() {
        assert!(etag(&Attrs::default()).is_none());
        assert!(
            etag(&Attrs {
                mtime: Some(1),
                ..Attrs::default()
            })
            .is_none()
        );
    }
}
