# TARDUS Audit Package

Materials for a Phase 4 independent security audit of the TARDUS
protocol and reference implementation.

License: TARDUS-PROPRIETARY-1.0. Audit firm receives an audit-only
license addendum granting read + reproduce-findings rights for the
duration of the engagement.

---

## What is TARDUS

TARDUS is a fully-private bearer-coin payment protocol on Solana,
built from threshold blind Schnorr signatures, κ-fold cut-and-choose
refresh, and a sealed-box encrypted off-chain delivery layer. It
hides sender, receiver, and amount without any zero-knowledge
proof, pairing-based cryptography, or per-circuit trusted setup.

For full design rationale see `spec/SPEC.pdf` (47 pages, Phase 1
revision).

---

## Audit-package layout

```
audit/
├── README.md                this file
├── THREAT_MODEL.md          adversary classes, attack surfaces, assumptions
├── ASSUMPTIONS.md           A1-A8 cryptographic + operational assumptions
├── SCOPE.md                 in-scope vs out-of-scope cut for the engagement
├── ONBOARDING.md            day-1 read order, where to start, how to reproduce
├── REPRODUCE.md             how to rebuild the spec, run the test suite,
│                            run the live demo
└── FINDINGS_TEMPLATE.md     suggested finding-report format

spec/                        47-page protocol spec (Phase 1, content-complete)
spec/easycrypt/              proof-skeleton .ec files for T1, T2, T4, T7
crates/                      10-crate Rust workspace (~18800 LoC)
deploy/                      operator runbooks + systemd units
```

---

## Engagement classes

We expect the audit to cover three classes of issue, with relative
weights:

| Class | What | Weight |
|---|---|---|
| **Cryptographic** | Reductions in §7 + §9, EasyCrypt skeleton soundness, primitive choices, parameter selection (κ = 32, hash function domains, HKDF salts) | 50% |
| **Implementation** | Rust workspace adherence to spec, side-channel resistance, key-handling discipline, AEAD usage, randomness sources, no `unsafe` violations | 35% |
| **Operational** | Validator/relay daemon runtime behaviour, HSM integration (v2.11 + v2.12), systemd hardening, key-rotation procedures, F-mode coverage | 15% |

---

## What this package contains for the auditor

1. **Spec** (`spec/SPEC.pdf`) — 47-page LaTeX-built specification
   covering primitives, mint protocol, refresh protocol, on-chain
   program, wallet, security theorems, failure modes, relay layer.
2. **EasyCrypt skeletons** (`spec/easycrypt/`) — proof shape for
   T1 (Schnorr unforgeability), T2 (issuance blindness), T4
   (cut-and-choose soundness), T7 (sealed-box confidentiality).
   Bodies are `admit`; the auditor or their formal-methods
   subcontractor fills in tactics.
3. **Reference implementation** (`crates/`) — 10-crate Rust
   workspace, ~18800 LoC, 186/186 default tests pass + 4 ignored
   (devnet + HSM). Pure Rust, no Anchor, MSRV 1.85.
4. **Live demo** (`crates/tardus-wallet/examples/demo_private_transfer.rs`)
   — reproducible end-to-end private-transfer demonstration that
   the auditor can run against fresh mnemonics.
5. **Operator deployment kit** (`deploy/`) — systemd units,
   monitoring scripts, 4 runbooks (validator, relay, key-rotation,
   index). Provides the operational threat surface for the
   "operational" class of findings.

---

## What this package does NOT contain

- **Mainnet deployment artefacts.** TARDUS is currently deployed
  only to Solana devnet (program ID
  `AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u`). Mainnet
  deployment is gated on this audit's findings + a fresh DKG +
  audit-approved bootstrap.
- **Production HSM hardware tests.** The current HSM integration
  is validated against softhsm2 2.6.1. CloudHSM / YubiHSM 2 /
  Thales Luna 7 integration is a Phase 5 operator concern;
  vendor-specific PKCS#11 quirks are out of scope for protocol
  audit.
- **GUI wallet.** The reference implementation is CLI-only. A
  GUI wallet's UX security review would be a separate engagement.
- **External cryptographic primitives.** Audit firm is expected
  to take, e.g., `dalek-cryptography/curve25519-dalek 4` and
  `RustCrypto/chacha20poly1305 0.10` as trusted dependencies
  rather than re-auditing those crates. List of trusted deps
  is enumerated in `SCOPE.md`.

---

## Engagement deliverables expected from the audit firm

1. **Findings report**, with each finding using the format in
   `FINDINGS_TEMPLATE.md` (severity, location, exploitability,
   recommendation, response). Findings are tracked in
   `audit/findings/<finding-id>.md`.
2. **Mechanized proof completion** for at least T1 and T7 (the
   load-bearing reductions) via EasyCrypt or equivalent. T2 and
   T4 may remain in skeleton form if the audit firm judges the
   informal arguments sufficient.
3. **Audit letter** (PDF), signed, referencing the spec build
   hash, the workspace git SHA, and the EasyCrypt build hash if
   applicable. Suitable for public attestation when TARDUS
   ships to mainnet.

---

## Contact

`zkdaofun@gmail.com` (project lead nzengi).
GitHub issues are NOT used for audit-engagement coordination;
all communication via signed email + a shared private channel
TBD per engagement.
