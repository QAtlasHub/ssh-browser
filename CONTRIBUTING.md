# Contributing

## Local loop

`just` mirrors what CI runs, so a green `just ci` predicts a green PR.

```
just            # list recipes
just ci         # fmt-check + lint + test
just roundtrips <ssh-host>
```

On a Windows host without the MSVC linker, prefix cargo with the gnu toolchain:

```
cargo +stable-x86_64-pc-windows-gnu test
```

On Git Bash, prefix any command that passes a remote path with
`MSYS_NO_PATHCONV=1`, or the path is rewritten into a Windows path before the
program ever sees it.

## Sign-off

Every commit needs a `Signed-off-by` trailer:

```
git commit -s
```

The `dco` job checks this on every PR. Merge commits and bot authors are exempt;
nothing else is. If you forgot:

```
git rebase --signoff origin/main
git push --force-with-lease
```

## What matters in review

Two things, above ordinary code quality.

**The round-trip invariants.** A page must cost O(1) remote round trips however
many subresources it has, and a revisit must cost zero. A change that leaves every
test green while turning one batched request back into N sequential ones is the
failure this project is most exposed to, which is why `read_batch` is deliberately
awkward: it issues every request before awaiting any reply. Please do not
"simplify" that into a loop. The `roundtrips` job and
`forty_reads_cost_a_constant_number_of_round_trips` both exist to catch it.

**Silent success.** A remote failure must never surface as an empty `200`, an
empty listing, or a hang. That has already happened once here: SFTP `OPEN`
succeeds on a directory and `READ` then fails, and treating every `STATUS` as EOF
returned an empty body with a `200`. If you add a match arm over a reply type, be
explicit about which statuses count as success.

## Security

Do not open a public issue for a vulnerability; see `SECURITY.md`.

Two guards are load-bearing and easy to drop by accident. The `Host` check,
without which a DNS-rebinding site can read the remote through the loopback
listener. And the path normalisation that runs *after* percent-decoding, without
which `%2e%2e` walks straight out of the alias base.

## Commit messages

Say why, not what; the diff already shows what. Conventional-commit prefixes are
used for changelog drafting (`cliff.toml`) but are not enforced.

## Releasing

One tag ships both halves: the crate to crates.io, and the extension as a zip on
the GitHub release. One version on purpose — with two, "which extension goes with
which daemon" is a question somebody has to answer by hand every time.

1. Merge to `main` as usual.
2. `release-plz` opens or updates a pull request titled `chore: release`. It bumps
   `Cargo.toml` and says what would go out. `cargo-semver-checks` decides the size
   of the bump when the commits do not, which is most of the time here: subjects
   in this repository are prose, not conventional-commit prefixes.
3. **Edit that pull request.** Two things it will not do for you:
   - rename `## [Unreleased]` in `CHANGELOG.md` to `## [x.y.z] - YYYY-MM-DD`.
     `changelog_update = false`, because that file is written by hand and a
     generated one would be worse;
   - bump `"version"` in `extension/manifest.json` to match. CI's `versions agree`
     job fails until it does.
4. Merge it. `release-plz` publishes, tags, and creates the release;
   `release-assets.yml` attaches `ssh-browser-x.y.z.zip` and its `.sha256`.
5. Upload that zip to the Chrome Web Store by hand. There is a review behind it
   anyway.

**One-time setup.** Nothing here holds a `CARGO_REGISTRY_TOKEN`: `release-plz`
exchanges GitHub's OIDC identity for a token that lives thirty minutes. That needs
a trusted publisher registered once on crates.io, against this repository and the
workflow filename `release-plz.yml`. Until it is, publishing fails — which is the
right failure, rather than falling back to something longer-lived.

**The release pull request shows no checks until somebody touches it.** Events
raised by the built-in `GITHUB_TOKEN` do not start workflows, so the pull request
arrives without any. Pushing the two edits above is itself a push by a person, and
CI runs from then on — which is the moment the checks are worth having anyway.

The same rule is why `release-assets.yml` is *called* from `release-plz.yml`
rather than triggered by `release: published`: the release is created with
`GITHUB_TOKEN`, so that event starts nothing. The first version of it never ran
once. Being called keeps it inside the same run, where the restriction does not
apply.

It also takes a tag through `workflow_dispatch`, so a zip can be rebuilt and
reattached without cutting a version again. It is byte-identical between runs by
construction, so a rebuild that differs is a signal.
