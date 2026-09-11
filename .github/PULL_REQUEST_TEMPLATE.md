<!--
Thanks for opening a PR against ssh-browser. Please fill out each section
below — delete a section only if it genuinely does not apply.

Background reading:
  * CONTRIBUTING.md  — local dev loop, commit style, sign-off
  * SECURITY.md      — the guarantees this daemon does and does not make

If your change moves a round-trip count or relaxes a guard, say so explicitly:
those are the two things this project is actually about.
-->

## Summary

<!--
1–3 bullets focused on WHY this change exists, not what the diff is.
The diff already shows what; the description should answer "why now,
why this shape, what does it unlock or fix?"
-->

-

## Invariants

<!--
Does this change the remote round trips for a page, the round trips on a
revisit, the single-writer rule, or any guard? If yes, say which way and why.
If no, say "no invariant touched".
-->

## Changes

<!--
High-level list of files added / modified / removed. Group by area
(crate, doc, workflow). Don't paste the diff — just the shape.
-->

## Test plan

- [ ] CI green on this branch
- [ ] If a workflow file is added/modified, all third-party Actions are SHA-pinned
- [ ] If Cargo.toml/Cargo.lock changed, dep churn reviewed
- [ ] Every commit is signed off (`git commit -s`) — enforced by the `dco` job
- [ ] Reviewer checklist: maintainer auto-assigned via CODEOWNERS

## Posture checks

<!--
This daemon holds a view of someone else's filesystem. Confirm both, or call out
the exception explicitly.
-->

- [ ] No telemetry / phone-home / self-update added (`deny.toml` enforces the crate list)
- [ ] Round trips for a page did not grow, and the `roundtrips` job still passes

## Notes for the reviewer

<!--
Free-form: anything reviewers should look at first, known follow-ups,
flaky-CI caveats, or context that didn't fit above.
-->

<!--
If this PR was authored with AI assistance (Claude Code, Copilot, etc.),
please add a trailer to your commit(s) so attribution lands in `git log`:

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

(Substitute the appropriate co-author identity for the assistant you used.)
-->
