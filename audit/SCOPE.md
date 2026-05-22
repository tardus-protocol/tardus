# TARDUS Audit Scope — In vs Out

Cross-reference for the audit engagement to anchor the firm's
attention and prevent scope drift.

License: TARDUS-PROPRIETARY-1.0.

---

## IN SCOPE

### Protocol design + cryptographic reductions

- `spec/SPEC.pdf` §2-9 (47 pages).
- All 7 theorems (T1-T7) and their associated reductions.
- EasyCrypt skeletons in `spec/easycrypt/` for T1, T2, T4, T7.
- Failure-mode catalogue F1-F18 + R1-R7 + F3a-F3d.
- Assumption catalogue A1-A8 (this folder's `ASSUMPTIONS.md`).

### Reference implementation (in-house Rust)

Every line of code under the project's own copyright:

```
crates/tardus-core/        Schnorr primitives, hash-to-scalar
crates/tardus-mint/        DKG, threshold sign, transcript, reshare
crates/tardus-refresh/     6-round κ-fold cut-and-choose refresh
crates/tardus-program/     Solana SBF program (6 instructions)
crates/tardus-client/      SDK: coin store, invoice URI, backup
crates/tardus-cli/         operator CLI (12 subcommands)
crates/tardus-validator/   validator daemon (HTTP, mTLS, transparency log)
crates/tardus-wallet/      user CLI (16 subcommands, sealed-box, BIP-39)
crates/tardus-relay/       relay daemon (TTL inbox, TLS, SQLite)
```

### Operational layer

- `deploy/systemd/*.service` — systemd unit hardening.
- `deploy/monitoring/health-probe.sh` — health-check script logic.
- `deploy/runbooks/*.md` — operator procedures (especially
  key-rotation taxonomy in `key-rotation.md`).

### HSM integration

- v2.11 `Pkcs11ShareStore` (AES-256-GCM wrap-key custody).
- v2.12 `reopen_session` (F3d auto-recovery).
- v2.13 (in progress) native EDDSA path (`C_UnwrapKey` import +
  `C_Sign / CKM_EDDSA`).
- Validation against softhsm2 2.6.1 (audit notes the limitations
  per A7).

### Live demo path

`crates/tardus-wallet/examples/demo_private_transfer.rs`
— the end-to-end private-transfer demonstration. The audit firm
should run this against fresh mnemonics to validate the empirical
"relay-side audit failure" claim (Step 6 of the demo output).

### On-chain devnet program

Program ID `AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u`. The
audit firm may submit transactions against this program ID for
runtime validation (program is upgradeable but only by the
project's authority; audit submissions cannot brick the program
or extract value).

---

## OUT OF SCOPE

### External cryptographic dependencies

Treat these as trusted; do NOT audit their internals:

- `curve25519-dalek 4` — Curve25519 + Ed25519 group operations
- `chacha20poly1305 0.10` — ChaCha20-Poly1305 AEAD
- `sha2 0.10` — SHA-256, SHA-512
- `hkdf 0.12` — HKDF
- `rand 0.8` + `OsRng` — operating-system RNG
- `rustls 0.23` (ring backend) — TLS 1.3 stack
- `rusqlite 0.31` — SQLite bindings
- `cryptoki 0.7` — PKCS#11 bindings
- `solana-program 2.x` — Solana program-side runtime
- `borsh 1` — canonical serialization
- `bip39 2` — BIP-39 mnemonic codec
- `rcgen 0.13` — self-signed cert generation (test-only)

If a finding of the audit relies on a vulnerability in one of
these crates, raise it as an out-of-scope advisory (we will
upstream to the dependency maintainer rather than patch locally).

### Production HSM hardware integration

The reference implementation is validated against softhsm2 2.6.1.
Cloud HSM, YubiHSM 2, Thales Luna, Utimaco SecurityServer
vendor-specific PKCS#11 quirks are a Phase 5 operator concern
and out of scope. The cryptographic correctness of the
`Pkcs11ShareStore` interface is in scope; specific vendor SDKs
are not.

### Solana network internals

The audit does not include a review of Solana's runtime, consensus,
SVM, or token program. Assumption A6 captures the trust we place
in Solana's finality.

### User wallet host security

Operating-system security, browser security, keylogger detection,
mnemonic-entry UX — out of scope. The wallet binary's
correctness in handling secret material once entered IS in scope.

### Future protocol versions

This audit covers v1 + v2 + v5.6 as documented in `spec/SPEC.pdf`
v1.5 Phase 1 revision (47 pages, content-complete). The roadmap
items in `spec/SPEC.tex` marked "deferred to v..." (multi-keyset
routing v1.5, federation v5.7, etc.) are explicitly out of scope.

### Documentation accuracy beyond the spec

`README.md`, `CHANGELOG.md`, and miscellaneous docs are NOT
authoritative. The spec PDF is the single source of truth; any
discrepancy between spec and docs is a doc bug, not a protocol
bug, and may be filed as a low-severity finding.

---

## Severity rubric

| Severity | Definition |
|---|---|
| **Critical** | Allows forgery (T1 violation), double-spend (T3 violation), or extraction of `≥ t` shares without operator action. Mainnet deployment must be blocked until resolved. |
| **High** | Allows extraction of a single share (no threshold violation), key-material recovery from non-key-bearing component, or T2/T7 distinguishing attack. Must be resolved before mainnet. |
| **Medium** | Operational impact only: confused-deputy, DoS at a single component, mis-handling of error path that does not leak key material. Resolved per the audit firm's recommendation timeline. |
| **Low** | Documentation drift, suboptimal but secure parameter choices, missing audit-trail entry. Triaged after mainnet. |
| **Informational** | Code style, naming, dead-code, that-but-not-quite — for the project team's awareness only, no remediation expected. |

---

## Engagement boundaries

- The audit firm receives the codebase + spec via a private
  channel; the public GitHub mirror is identical but accessing
  it does not constitute an audit engagement.
- The firm may publish a redacted audit letter after engagement
  conclusion, with project approval on the redaction set.
- Findings remediated within the engagement timeline appear in
  the audit letter as "resolved during engagement"; unresolved
  findings are categorised by severity with the project's
  written response.
