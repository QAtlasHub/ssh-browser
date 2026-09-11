# Changelog

All notable changes to ssh-browser will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Nothing is released yet: the version in `Cargo.toml` is `0.0.1` and no surface is
stable.

## [Unreleased]

### Added

- SFTP transport over `ssh <host> -s sftp`, so ssh_config, ProxyJump,
  non-standard ports, agent keys and certificates all work without
  reimplementation.
- A batch-first `RemoteFs` and a demultiplexing SFTP backend: any number of
  concurrent callers share one stream and their requests coalesce into one flush.
- `measure-roundtrips`, which times one round trip and reports each batch as a
  multiple of it, failing on a serial verdict.
- An HTTP origin at `http://<alias>.<suffix>/`, reached through a PAC the daemon
  serves itself. Host validation, traversal guard, MIME types, `index.html`,
  directory listings, and a `301` for a directory missing its trailing slash.
- Development environment ported from doiget: CI with SHA-pinned actions,
  `cargo deny` / `cargo audit`, CodeQL, coverage, typos, MSRV drift, sign-off
  enforcement, issue and PR templates.
- A listing cache and a body cache, which together make a revisit cost no remote
  round trips and let a conditional `GET` be answered inside the process. 184 ms
  cold, 1.6 ms warm against a host at 18 ms RTT.
- `RemoteFs::list_dirs`, the batch form of a listing, with `list_dir` defined as its
  n=1 case.
- A request whose final path component is a symlink is refused, decided from the
  cached listing rather than from a REALPATH per request.

### Fixed

- A directory read came back as an empty `200`. SFTP `OPEN` succeeds on a
  directory and `READ` then fails, and every `STATUS` was being treated as EOF.
- The same fault in `readdir`: any `STATUS` ended the listing, so a directory we
  were refused read as an empty directory.
- The `roundtrips` verdict judged reads as well as opens. A read carries the file, so
  under injected per-packet latency it reported transfer time as round trips, and the
  gate failed on how much data the chosen directory happened to hold.
