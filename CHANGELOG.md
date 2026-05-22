# Changelog

All notable changes to Tardus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub organization structure: CODEOWNERS, issue templates, PR template
- Security audit workflow (`audit.yml`) — RustSec, cargo-deny, npm audit, clippy security lints
- Release workflow (`release.yml`) — cross-platform CLI binaries, cosign keyless signing
- Root `SECURITY.md` with responsible disclosure policy
- `audit/findings/` directory for security audit artifacts
- `deploy/INFRA_REPO.md` — instructions for splitting sensitive infra into private repo

### Changed

### Fixed

### Security

---

## [0.1.0] — TBD

> Initial public release. Protocol specification, formal proofs, and reference implementation.

### Added
- `tardus-core`: Blind Schnorr signature scheme, VSS, DKG primitives
- `tardus-mint`: Threshold mint protocol with key rotation
- `tardus-client`: Client library for token issuance and redemption
- `tardus-wallet` / `tardus-wallet-gui`: Desktop wallet with mnemonic backup
- `tardus-program`: Solana on-chain program for double-spend prevention
- `tardus-relay`: Relay server for client-mint communication
- `tardus-validator`: Validator node implementation
- `tardus-refresh`: Token refresh protocol
- `tardus-cli`: Command-line interface
- `ts-sdk`: TypeScript SDK with Rust cross-language compatibility vectors
- `web`: Web frontend
- `spec/`: Full protocol specification (LaTeX + EasyCrypt)
- `paper/`: Academic paper (PDF)
- `proofs/`: EasyCrypt formal proofs (blindness, unforgeability, double-spend, state integrity)
- `audit/`: Security audit documentation and threat model

[Unreleased]: https://github.com/tardus-protocol/tardus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tardus-protocol/tardus/releases/tag/v0.1.0