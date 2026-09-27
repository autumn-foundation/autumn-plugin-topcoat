# Changelog

All notable changes to this crate are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The crate uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-27

### Added

- `TopcoatPlugin`: mounts one Topcoat router in an Autumn app with typed, public `ANY` routes.
- Root mount (`/`, `/{*path}`) and prefix mount (`mount_at`), with full-path forwarding.
- `autumn::state`, `autumn::config` and `autumn::extension` for app data in each render.
- `autumn::session` and `autumn::csrf_token` for request data in HTTP renders.
- The CSRF bridge for same-origin Topcoat runtime requests (`CsrfBridge`).
- The CSP check at startup (`CspCheck`), `csp::analyze` and `csp::recommended_csp`.
- The Autumn 404 for unknown paths (`NotFoundOwner`) and excluded prefixes (`exclude`).
- `RemoteAddr` from `ConnectInfo` for Topcoat `remote_addr` and `client_ip`.
- `TopcoatDiagnostics` and one startup `info` event.
- ADR 0001, a README in ASD-STE100 style and an example host app.
