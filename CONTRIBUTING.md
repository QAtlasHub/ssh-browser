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
