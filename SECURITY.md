# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Active |
| Previous releases | ⚠️ Critical fixes only |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Tardus handles cryptographic key material and digital cash tokens. A vulnerability could result in loss of funds or privacy. Please follow responsible disclosure.

### How to Report

Send an encrypted report to the security team:

**Email:** `security@tardus.dev` *(replace with actual address)*

**PGP Key:** *(publish your PGP fingerprint here)*

Include in your report:
- Description of the vulnerability
- Affected component(s): `tardus-core`, `tardus-mint`, `tardus-program`, `ts-sdk`, etc.
- Steps to reproduce
- Potential impact (funds at risk, privacy leak, DoS, etc.)
- Suggested fix (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| **48 hours** | Acknowledgement of your report |
| **7 days** | Initial severity assessment |
| **30 days** | Target for patch (critical issues) |
| **90 days** | Public disclosure (coordinated) |

We follow [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). We will credit researchers in the release notes unless anonymity is requested.

## Scope

### In Scope

- **`crates/tardus-core/`** — Blind Schnorr signatures, VSS, DKG, hash functions
- **`crates/tardus-mint/`** — Mint protocol, key rotation, signing
- **`crates/tardus-program/`** — Solana on-chain program (PDA logic, ed25519 verification)
- **`crates/tardus-client/`** — Client-side token handling, invoice/coin store
- **`crates/tardus-wallet/`** / **`crates/tardus-wallet-gui/`** — Key storage, mnemonic handling
- **`crates/tardus-relay/`** / **`crates/tardus-validator/`** — Network-facing services
- **`ts-sdk/`** — TypeScript cryptographic operations, sealed-box, mnemonic
- **`web/`** — Web frontend (XSS, key exposure, CSP)
- Protocol-level attacks: double-spend, blindness violations, unforgeability breaks

### Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Issues requiring physical access to HSM hardware
- Social engineering attacks
- Theoretical attacks without a practical exploit path
- Issues in `deploy/` runbooks (operational, not code)

## Security Architecture

Tardus is a **threshold blind-signature e-cash protocol** on Solana. Key security properties:

- **Blindness** — the mint cannot link a token to its issuance request
- **Unforgeability** — tokens cannot be created without mint participation
- **Double-spend prevention** — enforced on-chain via the Solana program
- **Threshold security** — DKG/VSS ensures no single mint node holds the full key

Formal proofs for these properties are in `proofs/` (EasyCrypt) and `spec/easycrypt/`.

## Known Limitations

See `audit/ASSUMPTIONS.md` for the explicit trust assumptions of the current protocol version.

## Bug Bounty

A formal bug bounty program is planned. Until announced, we offer public acknowledgement and our sincere gratitude for responsible disclosures.