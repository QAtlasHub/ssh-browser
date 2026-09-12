# justfile -- dev shortcuts that mirror what CI runs.
#
# Cargo invocations need no shell, so this file works on bash and PowerShell
# without a `set shell` directive. The toolchain is intentionally unpinned here;
# rust-toolchain.toml is the single source of truth.
#
# On a Windows host without the MSVC linker, prefix with the gnu toolchain:
#   cargo +stable-x86_64-pc-windows-gnu ...

# Default: list available recipes.
default:
    @just --list

# Format in place (local only; CI runs fmt-check instead).
fmt:
    cargo fmt --all

# Mirrors CI `rustfmt`.
fmt-check:
    cargo fmt --all -- --check

# Mirrors CI `clippy`.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Mirrors CI `test`.
test:
    cargo test --workspace --all-targets

# Mirrors CI `msrv` (a plain build of the whole workspace).
build:
    cargo build --workspace

# Mirrors CI `rustdoc`.
doc:
    cargo doc --workspace --no-deps

# Mirrors `cargo audit` in .github/workflows/audit.yml.
audit:
    cargo audit

# Mirrors `cargo deny` in .github/workflows/audit.yml.
deny:
    cargo deny check

# Measure the round-trip invariant against a real host. CI runs the same binary
# against a local sshd with 10 ms of injected latency.
roundtrips host dir="/usr/include":
    cargo run --release --example measure-roundtrips -- {{host}} {{dir}}

# Serve one alias, e.g. `just serve docs myhost /srv/docs`.
serve alias host base:
    cargo run --bin ssh-browser -- serve {{alias}}={{host}}:{{base}}

# Composite local pre-push gate.
ci: fmt-check lint test
