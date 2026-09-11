//! Annotations as per-author append-only logs.
//!
//! There is no central authority here, so the three things one would normally provide —
//! a total order, an identity, and a notification — are replaced rather than reproduced.
//!
//! The order is not reproduced at all: it is made unnecessary. Every log has exactly one
//! writer, so merging is a set union of lines, which is commutative, idempotent and
//! associative. The order the logs are read in cannot change the result, and nobody has
//! to agree on anything.
//!
//! The identity is the SSH account, which is what the log's filename says. A record's id
//! carries its author too, so a log that tries to touch someone else's record is ignored
//! rather than obeyed — and "you cannot delete someone else's annotation" stops being a
//! rule anyone has to enforce and becomes a fact about the shape of the data.
//!
//! Notification is not this module's problem; it is a `readdir` of one directory, which
//! returns every log's mtime and size in a single round trip.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::fs::RemoteFs;

/// The directory that holds a document's sidecar data.
///
/// Beside the document rather than in one central place, so that copying a tree copies
/// its annotations along with it.
pub const SIDECAR: &str = ".ssh-browser";

const ID_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Add,
    Update,
    Delete,
}

/// One line of one author's log.
///
/// No `author` field, deliberately. The author is the log's filename, which is a fact the
/// filesystem owns; a field would be a second source for the same thing and the two could
/// disagree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub op: Op,
    pub id: String,
    /// Unix epoch seconds.
    ///
    /// A number rather than an RFC 3339 string: rendering one needs a calendar, and a
    /// number cannot be ambiguous about its timezone. It is also not what orders the log —
    /// position in the file does that, because the file is append-only and a clock is not
    /// trustworthy.
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Carried through without interpretation.
    ///
    /// Anchoring belongs to the extension, because the extension is what has a DOM.
    /// Storing selectors opaquely means a new selector type needs no daemon release, which
    /// matters when the two halves ship through different channels at different speeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

/// What a reader sees after the logs are folded together.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Annotation {
    pub id: String,
    pub author: String,
    pub at: u64,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selectors: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

pub struct AuthorLog {
    pub author: String,
    pub records: Vec<Record>,
}

/// What `load` found, including what it could not read.
pub struct Loaded {
    pub annotations: Vec<Annotation>,
    /// Lines that did not parse.
    ///
    /// Counted and reported rather than hidden. One line written by some future version
    /// must not make every other annotation quietly invisible, and a caller that knows how
    /// many were skipped can say so.
    pub skipped: usize,
}

/// Mint an id for a new record.
///
/// The author is part of the id, which is what makes ownership checkable without a
/// registry: any reader can tell whose record it is by looking at it.
pub fn new_id(author: &str) -> Result<String> {
    ensure!(is_safe_name(author), "author {author:?} is not a safe name");
    let mut bytes = [0u8; ID_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("reading OS entropy for an id: {e}"))?;
    let mut hex = String::with_capacity(ID_BYTES * 2);
    for b in bytes {
        hex.push(nibble(b >> 4));
        hex.push(nibble(b & 0x0f));
    }
    Ok(format!("{author}:{hex}"))
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

/// Does this id belong to this author?
fn owns(author: &str, id: &str) -> bool {
    id.split_once(':').is_some_and(|(owner, _)| owner == author)
}

/// Safe as a single path component.
///
/// An author name becomes a filename, so a name that could climb out of its directory is
/// a path traversal with extra steps.
fn is_safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Where a document's annotation logs live.
///
/// `/srv/docs/index.html` becomes `/srv/docs/.ssh-browser/index.html/ann`.
pub fn ann_dir(doc: &str) -> String {
    let (parent, name) = match doc.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", doc),
    };
    format!("{parent}/{SIDECAR}/{name}/ann")
}

/// Fold every author's log into the annotations that survive.
///
/// Within one log, later lines win over earlier ones, and position in the file is the
/// ordering. Across logs there is nothing to order: an id belongs to exactly one author, so
/// two logs never describe the same record, which is why the union is commutative and why
/// no lock is needed anywhere in this design.
pub fn merge(logs: &[AuthorLog]) -> Vec<Annotation> {
    let mut live: HashMap<String, Annotation> = HashMap::new();

    for log in logs {
        for record in &log.records {
            // An id names its author, and a log naming someone else's record is ignored.
            // File permissions should already have prevented it, but a shared account has
            // no permissions to rely on and this check costs nothing.
            if !owns(&log.author, &record.id) {
                continue;
            }

            match record.op {
                Op::Delete => {
                    live.remove(&record.id);
                }
                Op::Add | Op::Update => {
                    let entry = live.entry(record.id.clone()).or_insert_with(|| Annotation {
                        id: record.id.clone(),
                        author: log.author.clone(),
                        at: record.at,
                        body: String::new(),
                        selectors: None,
                        reply_to: None,
                    });
                    entry.at = record.at;
                    if let Some(body) = &record.body {
                        entry.body = body.clone();
                    }
                    if record.selectors.is_some() {
                        entry.selectors = record.selectors.clone();
                    }
                    if record.reply_to.is_some() {
                        entry.reply_to = record.reply_to.clone();
                    }
                }
            }
        }
    }

    let mut out: Vec<Annotation> = live.into_values().collect();
    // Sorted so the same logs always produce the same order however the files were read.
    // Without this the union would be commutative in content but not in presentation,
    // which is a difference a caller would notice and come to depend on.
    out.sort_by(|a, b| (a.at, &a.id).cmp(&(b.at, &b.id)));
    out
}

/// Parse a log, reporting how many lines could not be read.
///
/// A malformed line is skipped rather than failing the load. One bad line — from a future
/// version of the format, or a partial write — must not make every other annotation
/// invisible.
pub fn parse(body: &[u8]) -> (Vec<Record>, usize) {
    let mut records = Vec::new();
    let mut skipped = 0;
    for line in body.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Record>(line) {
            Ok(r) => records.push(r),
            Err(_) => skipped += 1,
        }
    }
    (records, skipped)
}

/// The author a log belongs to, taken from its filename.
fn author_of(path: &str) -> Result<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let author = name
        .strip_suffix(".jsonl")
        .with_context(|| format!("log file {name:?} does not end in .jsonl"))?;
    ensure!(
        is_safe_name(author),
        "log file {name:?} is not a safe author name"
    );
    Ok(author.to_string())
}

pub struct Store<'a, F> {
    fs: &'a F,
}

impl<'a, F: RemoteFs> Store<'a, F> {
    pub fn new(fs: &'a F) -> Self {
        Self { fs }
    }

    /// Read every author's annotations for one document.
    pub async fn load(&self, doc: &str) -> Result<Loaded> {
        let dir = ann_dir(doc);
        let Ok(entries) = self.fs.list_dir(&dir).await else {
            // No annotation directory means no annotations. That is the ordinary case for
            // every document nobody has annotated, so it is not an error.
            return Ok(Loaded {
                annotations: Vec::new(),
                skipped: 0,
            });
        };

        let paths: Vec<String> = entries
            .iter()
            .filter(|e| !e.attrs.is_dir() && e.name.ends_with(".jsonl"))
            .map(|e| format!("{dir}/{}", e.name))
            .collect();
        if paths.is_empty() {
            return Ok(Loaded {
                annotations: Vec::new(),
                skipped: 0,
            });
        }

        // Every author's log in one batch, so the cost does not grow with the number of
        // people annotating.
        let bodies = self.fs.read_batch(&paths).await;

        let mut logs = Vec::new();
        let mut skipped = 0;
        for (path, body) in paths.iter().zip(bodies) {
            let author = author_of(path)?;
            let body = body.with_context(|| format!("reading {path}"))?;
            let (records, bad) = parse(&body);
            skipped += bad;
            logs.push(AuthorLog { author, records });
        }

        Ok(Loaded {
            annotations: merge(&logs),
            skipped,
        })
    }

    /// Append one record to one author's log.
    pub async fn append(&self, doc: &str, author: &str, record: &Record) -> Result<()> {
        ensure!(is_safe_name(author), "author {author:?} is not a safe name");
        // Refused here as well as ignored at merge time. Writing a record that would then
        // be discarded on read is a silent no-op, and a caller deserves to be told.
        ensure!(
            owns(author, &record.id),
            "record {} does not belong to {author}",
            record.id
        );

        let dir = ann_dir(doc);
        self.fs
            .mkdirs(&dir)
            .await
            .with_context(|| format!("creating {dir}"))?;

        let mut line = serde_json::to_vec(record).context("serialising the record")?;
        line.push(b'\n');
        let path = format!("{dir}/{author}.jsonl");
        self.fs
            .append(&path, &line)
            .await
            .with_context(|| format!("appending to {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeRemote;

    const DOC: &str = "/srv/index.html";

    async fn store_over_empty_tree() -> crate::fs::sftp::SftpFs {
        FakeRemote::new().dir("/srv", vec![]).spawn().await
    }

    fn rec(op: Op, id: &str, at: u64, body: Option<&str>) -> Record {
        Record {
            op,
            id: id.to_string(),
            at,
            body: body.map(str::to_string),
            selectors: None,
            reply_to: None,
        }
    }

    fn log(author: &str, records: Vec<Record>) -> AuthorLog {
        AuthorLog {
            author: author.to_string(),
            records,
        }
    }

    #[test]
    fn annotations_live_beside_their_document() {
        assert_eq!(
            ann_dir("/srv/docs/index.html"),
            "/srv/docs/.ssh-browser/index.html/ann"
        );
        assert_eq!(ann_dir("/a.html"), "/.ssh-browser/a.html/ann");
    }

    #[test]
    fn an_id_carries_its_author() {
        let id = new_id("souta").expect("entropy");
        assert!(id.starts_with("souta:"));
        assert!(owns("souta", &id));
        assert!(!owns("alice", &id));
        assert!(new_id("../etc").is_err());
    }

    /// The whole reason the format is per-author logs: the order they are read in cannot
    /// matter, so no lock and no agreement is needed.
    #[test]
    fn merging_is_commutative() {
        let a = || {
            log(
                "alice",
                vec![rec(Op::Add, "alice:1", 10, Some("from alice"))],
            )
        };
        let b = || log("bob", vec![rec(Op::Add, "bob:1", 20, Some("from bob"))]);

        let forward = merge(&[a(), b()]);
        let backward = merge(&[b(), a()]);
        assert_eq!(forward, backward);
        assert_eq!(forward.len(), 2);
    }

    #[test]
    fn merging_is_idempotent() {
        let once = merge(&[log(
            "alice",
            vec![rec(Op::Add, "alice:1", 10, Some("hello"))],
        )]);
        let twice = merge(&[
            log("alice", vec![rec(Op::Add, "alice:1", 10, Some("hello"))]),
            log("alice", vec![rec(Op::Add, "alice:1", 10, Some("hello"))]),
        ]);
        assert_eq!(once, twice);
    }

    /// Position in the file is the ordering, not the clock: the second line wins even
    /// though its timestamp is older.
    #[test]
    fn later_lines_win_over_earlier_ones_regardless_of_timestamp() {
        let merged = merge(&[log(
            "alice",
            vec![
                rec(Op::Add, "alice:1", 100, Some("first")),
                rec(Op::Update, "alice:1", 50, Some("second")),
            ],
        )]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].body, "second");
        assert_eq!(merged[0].at, 50, "the later line's timestamp is kept");
    }

    #[test]
    fn a_delete_removes_the_annotation() {
        let merged = merge(&[log(
            "alice",
            vec![
                rec(Op::Add, "alice:1", 10, Some("hello")),
                rec(Op::Delete, "alice:1", 20, None),
            ],
        )]);
        assert!(merged.is_empty());
    }

    /// Authorisation falling out of the shape of the data rather than out of a rule
    /// someone has to remember to check.
    #[test]
    fn a_log_cannot_touch_another_authors_record() {
        let merged = merge(&[
            log("alice", vec![rec(Op::Add, "alice:1", 10, Some("mine"))]),
            // Bob's log trying to delete Alice's annotation, and to edit it.
            log(
                "bob",
                vec![
                    rec(Op::Delete, "alice:1", 20, None),
                    rec(Op::Update, "alice:1", 30, Some("vandalised")),
                ],
            ),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].body, "mine");
        assert_eq!(merged[0].author, "alice");
    }

    #[test]
    fn the_author_comes_from_the_filename() {
        assert_eq!(
            author_of("/srv/.ssh-browser/a.html/ann/souta.jsonl").unwrap(),
            "souta"
        );
        assert!(author_of("/srv/ann/souta.txt").is_err());
        assert!(author_of("/srv/ann/...jsonl").is_err());
    }

    #[test]
    fn unsafe_author_names_are_refused() {
        assert!(!is_safe_name(""));
        assert!(!is_safe_name("../etc"));
        assert!(!is_safe_name("a/b"));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name(&"x".repeat(65)));
        assert!(is_safe_name("souta"));
        assert!(is_safe_name("first.last"));
        assert!(is_safe_name("user_1-2"));
    }

    /// One unreadable line must not hide the rest, and the count must be reported rather
    /// than swallowed.
    #[test]
    fn a_malformed_line_is_skipped_and_counted() {
        let body = b"{\"op\":\"add\",\"id\":\"alice:1\",\"at\":10,\"body\":\"ok\"}\nnot json\n{\"op\":\"add\",\"id\":\"alice:2\",\"at\":20}\n";
        let (records, skipped) = parse(body);
        assert_eq!(records.len(), 2);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn blank_lines_are_not_counted_as_damage() {
        let (records, skipped) = parse(b"\n\n  \n");
        assert!(records.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn a_record_round_trips_through_json() {
        let record = Record {
            op: Op::Add,
            id: "souta:a1b2c3d4e5f6a7b8".to_string(),
            at: 1_757_600_000,
            body: Some("a note".to_string()),
            selectors: Some(serde_json::json!([{"type": "TextQuoteSelector"}])),
            reply_to: Some("alice:1".to_string()),
        };
        let line = serde_json::to_vec(&record).expect("serialises");
        let (back, skipped) = parse(&line);
        assert_eq!(skipped, 0);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].id, record.id);
        assert_eq!(back[0].at, record.at);
        assert_eq!(back[0].reply_to.as_deref(), Some("alice:1"));
        assert!(back[0].selectors.is_some(), "selectors survive untouched");
    }

    /// A reply is an ordinary record in the replier's own log, which is what makes a thread
    /// work without anyone writing to anyone else's file.
    #[test]
    fn a_reply_to_another_authors_annotation_is_just_a_record() {
        let mut reply = rec(Op::Add, "bob:1", 20, Some("agreed"));
        reply.reply_to = Some("alice:1".to_string());
        let merged = merge(&[
            log("alice", vec![rec(Op::Add, "alice:1", 10, Some("a claim"))]),
            log("bob", vec![reply]),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].reply_to.as_deref(), Some("alice:1"));
        assert_eq!(merged[1].author, "bob");
    }

    #[tokio::test]
    async fn a_record_written_comes_back_out() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let id = new_id("souta").expect("entropy");

        store
            .append(DOC, "souta", &rec(Op::Add, &id, 100, Some("a note")))
            .await
            .expect("append");

        let loaded = store.load(DOC).await.expect("load");
        assert_eq!(loaded.skipped, 0);
        assert_eq!(loaded.annotations.len(), 1);
        assert_eq!(loaded.annotations[0].body, "a note");
        assert_eq!(
            loaded.annotations[0].author, "souta",
            "the author comes from the filename the daemon chose, not from the record"
        );
    }

    /// Two people annotating one document touch different files, so neither can lose the
    /// other's work. This is the property the whole format exists for.
    #[tokio::test]
    async fn two_authors_do_not_overwrite_each_other() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let souta = new_id("souta").expect("entropy");
        let alice = new_id("alice").expect("entropy");

        store
            .append(DOC, "souta", &rec(Op::Add, &souta, 100, Some("from souta")))
            .await
            .expect("souta appends");
        store
            .append(DOC, "alice", &rec(Op::Add, &alice, 200, Some("from alice")))
            .await
            .expect("alice appends");

        let loaded = store.load(DOC).await.expect("load");
        assert_eq!(loaded.annotations.len(), 2);
        let bodies: Vec<&str> = loaded.annotations.iter().map(|a| a.body.as_str()).collect();
        assert!(bodies.contains(&"from souta"));
        assert!(bodies.contains(&"from alice"));
    }

    /// An edit is another line, not a rewrite of the file. That is what makes it safe
    /// without a lock.
    #[tokio::test]
    async fn an_update_appends_rather_than_rewriting() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let id = new_id("souta").expect("entropy");

        store
            .append(DOC, "souta", &rec(Op::Add, &id, 100, Some("first")))
            .await
            .expect("add");
        store
            .append(DOC, "souta", &rec(Op::Update, &id, 200, Some("edited")))
            .await
            .expect("update");

        let loaded = store.load(DOC).await.expect("load");
        assert_eq!(
            loaded.annotations.len(),
            1,
            "an update is not a second record"
        );
        assert_eq!(loaded.annotations[0].body, "edited");
    }

    #[tokio::test]
    async fn a_delete_survives_a_round_trip() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let id = new_id("souta").expect("entropy");

        store
            .append(DOC, "souta", &rec(Op::Add, &id, 100, Some("doomed")))
            .await
            .expect("add");
        store
            .append(DOC, "souta", &rec(Op::Delete, &id, 200, None))
            .await
            .expect("delete");

        assert!(store.load(DOC).await.expect("load").annotations.is_empty());
    }

    /// The ordinary case for every document nobody has annotated: no directory, no error.
    #[tokio::test]
    async fn a_document_with_no_annotations_loads_empty() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let loaded = store.load(DOC).await.expect("load");
        assert!(loaded.annotations.is_empty());
        assert_eq!(loaded.skipped, 0);
    }

    /// Refused at write time as well as ignored at merge time. Writing a record that would
    /// be silently discarded on read is worse than an error.
    #[tokio::test]
    async fn appending_someone_elses_record_is_refused() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let alice = new_id("alice").expect("entropy");

        let result = store
            .append(DOC, "souta", &rec(Op::Add, &alice, 100, Some("vandalism")))
            .await;
        assert!(
            result.is_err(),
            "souta must not be able to write a record owned by alice"
        );
    }

    #[tokio::test]
    async fn an_unsafe_author_name_never_reaches_the_filesystem() {
        let fs = store_over_empty_tree().await;
        let store = Store::new(&fs);
        let result = store
            .append(DOC, "../etc", &rec(Op::Add, "../etc:1", 100, Some("x")))
            .await;
        assert!(result.is_err());
    }
}
