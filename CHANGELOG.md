# Changelog

All notable changes to this crate are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The crate needs `autumn-web` 0.8 (`>=0.8, <0.9`). It no longer accepts 0.7.

## [0.1.0] - 2026-09-27

### Added

- `TopcoatPlugin`: mounts one Topcoat router in an Autumn app with typed, public `ANY` routes.
- Root mount (`/`, `/{*path}`, also `mount_at("/")`) and prefix mount (`mount_at`), with full-path forwarding.
- `TopcoatPlugin::validate`: returns each configuration problem as a `ConfigErrors` value.
- `autumn::state`, `autumn::config` and `autumn::extension` for app data in each render.
- `autumn::session` and `autumn::csrf_token` for request data in HTTP renders.
- The CSRF bridge for same-origin Topcoat runtime requests (`CsrfBridge`).
- The CSP check at startup (`CspCheck`), `csp::analyze` and `csp::recommended_csp`.
- The Autumn 404 for unknown paths (`NotFoundOwner`) and excluded prefixes (`exclude`).
- `RemoteAddr` from `ConnectInfo` for Topcoat `remote_addr` and `client_ip`.
- `TopcoatDiagnostics` (with `serves_http` and `startup_error`), one `info` event after a good startup, and an `error` event for each startup error.
- Worker processes and one-off task runs serve no HTTP, so they do not build the Topcoat router and do not check the CSP.
- ADR 0001, a README in ASD-STE100 style, and the example apps `host` (root mount) and `prefix_host` (prefix mount).

[0.1.0]: https://github.com/autumn-foundation/autumn-plugin-topcoat/releases/tag/v0.1.0
