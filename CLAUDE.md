# CLAUDE.md

Guidance for agents that work on this crate.

## What this crate is

`autumn-plugin-topcoat` is an Autumn plugin. Autumn (`autumn-web` 0.7, axum 0.8.9) serves the backend. Topcoat (`topcoat` 0.9) renders the frontend. Read `docs/adr/0001-mount-topcoat-with-typed-routes.md` before a design change.

## Commands

The toolchain is pinned to Rust 1.98.1 (`rust-toolchain.toml`). Topcoat 0.9 needs 1.98.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --lib
cargo test --all-targets --all-features
cargo test --doc
cargo llvm-cov --all-features --fail-under-lines 90
AUTUMN_DUMP_ROUTES=1 cargo run -q --example host
```

## Architecture

| Module | Kind | Job |
|--------|------|-----|
| `plugin` | glue | `TopcoatPlugin` builder and `Plugin::build` |
| `plan` | pure | Validates the options and makes the route templates |
| `routes` | glue | Makes the typed `ANY` routes |
| `finalize` | glue | State initializer: builds the router, reads config, checks the CSP |
| `handler` | glue | Forwards a request to Topcoat |
| `ingress` | glue | The CSRF bridge layer in front of Autumn CSRF |
| `tagger` | glue | Pathless Topcoat layer that marks unmatched paths |
| `csrf` | pure | The bridge decision and the cookie parser |
| `origin` | pure | `Origin` and `Host` parsing and the same-origin check |
| `csp` | pure | CSP analysis and the additive patch |
| `path` | pure | `PathPrefix` and `MountPath` |
| `fallthrough` | pure | Autumn 404 and favicon 204 |
| `autumn` | public | Helpers for Topcoat pages |

Each pure module has a `# Contract` doc section and property tests. Change the contract first, then the tests, then the code.

## Rules that the design depends on

- Never use `AppBuilder::merge`, `nest` or `fallback`. Autumn replaces a plugin fallback, and `autumn routes audit` fails for merged routers.
- Never strip a prefix. Topcoat writes absolute URLs.
- Put data that each render needs in the Topcoat app context. WebSocket renders lose the request extensions.
- The bridge must fail closed. A rule that cannot decide skips the request, and Autumn CSRF decides.
- Production code has no `unwrap`, `expect` or `panic`. Clippy denies them outside tests.

## Test notes

- Topcoat route macros make a unit struct with the function name. Do not give a local variable the same name.
- `/live`, `/ready`, `/health` and `/startup` are Autumn probe paths. Do not use them for test pages.
- `tracing` caches callsite interest for all threads. Tests that capture events hold `common::serial()`.
- The `tests/axum_guards.rs` tests pin axum behavior. If one fails after an upgrade, review the ADR.
- Verus is not available here. Property tests stand in for proofs.

## Documentation style

Write docs and comments in ASD-STE100 style: short sentences, active voice, simple present tense, one instruction per sentence. Keep instructions at 20 words or fewer and descriptions at 25 words or fewer.
