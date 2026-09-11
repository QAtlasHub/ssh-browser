//! Range requests, and the two directions in which they are declined.

/// What to serve for a given `Range` header.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    /// Serve the whole representation. Either nothing was asked for, or the request
    /// is one we are permitted to answer in full.
    Whole,
    /// Serve bytes `start..=end`, inclusive at both ends as HTTP counts them.
    Part { start: u64, end: u64 },
    /// The range names nothing inside the representation.
    Unsatisfiable,
}

/// Resolve a `Range` header against a known size.
///
/// Declines in two directions, both deliberate and both permitted.
///
/// A multi-range request is answered whole. Honouring it means emitting
/// `multipart/byteranges`, which is a lot of surface for something no browser needs in
/// order to seek in a video or a PDF, and RFC 9110 allows answering with the whole
/// representation instead.
///
/// An `If-Range` is never honoured. The spec permits `If-Range` only with a strong
/// validator, and the only validator this daemon offers is weak, because SFTP reports
/// mtime in whole seconds. The specified outcome of that condition evaluating false is
/// the whole representation, not a `412`.
pub fn resolve(header: &str, if_range: Option<&str>, size: u64) -> Resolved {
    if if_range.is_some() {
        return Resolved::Whole;
    }

    // An unrecognised unit is a request we are free to ignore: `Range` asks, it does
    // not instruct.
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Resolved::Whole;
    };
    if spec.contains(',') {
        return Resolved::Whole;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return Resolved::Whole;
    };
    let (first, last) = (first.trim(), last.trim());

    // A zero-length representation satisfies no range at all, including `-0`.
    if size == 0 {
        return Resolved::Unsatisfiable;
    }
    let final_byte = size - 1;

    match (first.is_empty(), last.is_empty()) {
        // `-N`: the last N bytes. An N larger than the file means the whole file,
        // which is what the spec asks for rather than an error.
        (true, false) => {
            let Ok(suffix) = last.parse::<u64>() else {
                return Resolved::Whole;
            };
            if suffix == 0 {
                return Resolved::Unsatisfiable;
            }
            Resolved::Part {
                start: size.saturating_sub(suffix),
                end: final_byte,
            }
        }
        // `N-`: from N to the end.
        (false, true) => {
            let Ok(start) = first.parse::<u64>() else {
                return Resolved::Whole;
            };
            if start > final_byte {
                return Resolved::Unsatisfiable;
            }
            Resolved::Part {
                start,
                end: final_byte,
            }
        }
        // `N-M`: both ends named. An M past the end is clamped, not refused.
        (false, false) => {
            let (Ok(start), Ok(end)) = (first.parse::<u64>(), last.parse::<u64>()) else {
                return Resolved::Whole;
            };
            if start > end || start > final_byte {
                return Resolved::Unsatisfiable;
            }
            Resolved::Part {
                start,
                end: end.min(final_byte),
            }
        }
        // A bare `-` names nothing.
        (true, true) => Resolved::Whole,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(start: u64, end: u64) -> Resolved {
        Resolved::Part { start, end }
    }

    #[test]
    fn both_ends_given() {
        assert_eq!(resolve("bytes=0-9", None, 100), part(0, 9));
        assert_eq!(resolve("bytes=10-19", None, 100), part(10, 19));
        // The last byte is size-1, not size.
        assert_eq!(resolve("bytes=99-99", None, 100), part(99, 99));
    }

    #[test]
    fn an_end_past_the_file_is_clamped_rather_than_refused() {
        assert_eq!(resolve("bytes=0-1000", None, 100), part(0, 99));
        assert_eq!(resolve("bytes=50-1000", None, 100), part(50, 99));
    }

    #[test]
    fn an_open_ended_range_runs_to_the_last_byte() {
        assert_eq!(resolve("bytes=90-", None, 100), part(90, 99));
        assert_eq!(resolve("bytes=0-", None, 100), part(0, 99));
    }

    #[test]
    fn a_suffix_range_counts_back_from_the_end() {
        assert_eq!(resolve("bytes=-10", None, 100), part(90, 99));
        // Asking for more than exists yields the whole file, per the spec.
        assert_eq!(resolve("bytes=-500", None, 100), part(0, 99));
    }

    #[test]
    fn ranges_outside_the_file_are_unsatisfiable() {
        assert_eq!(resolve("bytes=100-", None, 100), Resolved::Unsatisfiable);
        assert_eq!(resolve("bytes=100-200", None, 100), Resolved::Unsatisfiable);
        // A backwards range is not a range.
        assert_eq!(resolve("bytes=5-3", None, 100), Resolved::Unsatisfiable);
        // `-0` asks for the last zero bytes, which no representation has.
        assert_eq!(resolve("bytes=-0", None, 100), Resolved::Unsatisfiable);
    }

    #[test]
    fn an_empty_file_satisfies_nothing() {
        assert_eq!(resolve("bytes=0-0", None, 0), Resolved::Unsatisfiable);
        assert_eq!(resolve("bytes=0-", None, 0), Resolved::Unsatisfiable);
        assert_eq!(resolve("bytes=-1", None, 0), Resolved::Unsatisfiable);
    }

    /// Declining to do multipart is a choice, and it has to be the safe one:
    /// answering whole is always correct, answering one part of several would be a
    /// lie about what was sent.
    #[test]
    fn a_multi_range_request_is_answered_whole() {
        assert_eq!(resolve("bytes=0-9,20-29", None, 100), Resolved::Whole);
    }

    #[test]
    fn an_unknown_unit_or_malformed_spec_is_answered_whole() {
        assert_eq!(resolve("items=0-9", None, 100), Resolved::Whole);
        assert_eq!(resolve("bytes=abc-def", None, 100), Resolved::Whole);
        assert_eq!(resolve("bytes=-", None, 100), Resolved::Whole);
        assert_eq!(resolve("nonsense", None, 100), Resolved::Whole);
        assert_eq!(resolve("", None, 100), Resolved::Whole);
    }

    /// The validator on offer is weak, so `If-Range` can never be honoured. The whole
    /// representation is the specified answer, not a 412.
    #[test]
    fn if_range_is_never_honoured_because_the_validator_is_weak() {
        assert_eq!(
            resolve("bytes=0-9", Some("W/\"64-7\""), 100),
            Resolved::Whole
        );
        // Even a strong-looking one: no strong validator was ever issued, so anything
        // a client sends here is something we cannot have promised.
        assert_eq!(resolve("bytes=0-9", Some("\"64-7\""), 100), Resolved::Whole);
    }

    #[test]
    fn whitespace_around_the_spec_is_tolerated() {
        assert_eq!(resolve("  bytes=0-9  ", None, 100), part(0, 9));
        assert_eq!(resolve("bytes= 10 - 19 ", None, 100), part(10, 19));
    }
}
