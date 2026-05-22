# Audit Firm Onboarding — Day 1 Read Order

For an engineer or cryptographer joining the audit engagement.
Estimated time: 1-2 working days for thorough first-pass
familiarity.

License: TARDUS-PROPRIETARY-1.0.

---

## Read order

### Day 1 morning — protocol understanding (~3h)

1. `spec/SPEC.pdf` §1 (Introduction, 2 pages) — what TARDUS is
   and why.
2. `spec/SPEC.pdf` §2 (Cryptographic Primitives, ~3 pages) —
   notation, group operations, hash-to-scalar definition.
3. `spec/SPEC.pdf` §3 (Mint Protocol, ~7 pages) — DKG, threshold
   sign, reshare. The validator-daemon endpoint table at
   §3 "Validator Daemon Reference Surface" is the implementation
   anchor.
4. `spec/SPEC.pdf` §4 (Refresh Protocol, ~3 pages) — 6-round
   cut-and-choose.

### Day 1 afternoon — implementation tour (~3h)

5. Build the workspace and run the test suite:
   ```
   cd ~/audit/tardus
   cargo build --release
   cargo test --release
   # Optional: HSM tests (needs softhsm2)
   sudo apt install softhsm2
   cargo test -p tardus-validator --features hsm \
       --test hsm_pkcs11 -- --ignored --test-threads=1
   ```
   Expected: `186 passed; 0 failed` for default,
   `3 passed; 0 failed` for HSM.
6. Read `crates/tardus-core/src/schnorr.rs` (the foundational
   Schnorr+blind implementation).
7. Read `crates/tardus-mint/src/dkg.rs` (the DKG; the spec
   discoveries #1-#3 in §2.3, §3.4, §3.7 are anchored here).
8. Read `crates/tardus-refresh/src/lib.rs` (the cut-and-choose
   refresh; the 6-round canonical ordering of spec discovery #4
   in §4.5 lives here).

### Day 2 morning — security argument (~3h)

9. `spec/SPEC.pdf` §7 (Security Theorems, ~6 pages) — T1-T6 and
   the composition corollary.
10. `spec/SPEC.pdf` §9 (Relay Layer, ~5 pages) — T7 sealed-box
    confidentiality.
11. `audit/ASSUMPTIONS.md` (A1-A8) — the conditional security
    base.
12. `audit/THREAT_MODEL.md` — adversary classes A.NET, A.RELAY,
    A.VAL.k, A.VAL.t, A.HSM, A.WALLET, A.SOLANA, A.SUPPLY.
13. `spec/easycrypt/*.ec` — proof skeletons for T1, T2, T4, T7.

### Day 2 afternoon — live demo + ops (~2h)

14. Run the live demo:
    ```
    cargo run --release -p tardus-wallet --example demo_private_transfer
    ```
    Observe Step 6 (relay-side audit failure): 5 attack vectors,
    all NO ✓. Re-run with different mnemonics; verify
    non-determinism.
15. Read `deploy/runbooks/validator-operator.md` (validator
    operations).
16. Read `deploy/runbooks/key-rotation.md` (the 4-scenario
    rotation taxonomy, especially Scenario D for catastrophic
    response).
17. Read `spec/SPEC.pdf` §8 (Failure Modes F1-F18 + R1-R7 + F3a-F3d).

---

## Key files for cryptographic review

| File | Cryptographic content |
|---|---|
| `crates/tardus-core/src/schnorr.rs` | Schnorr sign + verify, hash-to-scalar |
| `crates/tardus-core/src/blind.rs` | Blind Schnorr blinding factor algebra |
| `crates/tardus-mint/src/dkg.rs` | Pedersen-VSS DKG with dual commitments |
| `crates/tardus-mint/src/sign.rs` | Threshold blind sign (Stinson-Strobl 2001) |
| `crates/tardus-mint/src/reshare.rs` | Proactive zero-poly reshare (Gennaro et al. 1999) |
| `crates/tardus-refresh/src/lib.rs` | κ-fold cut-and-choose |
| `crates/tardus-wallet/src/sealed_box.rs` | T7 sealed-box AEAD |
| `crates/tardus-wallet/src/mnemonic.rs` | BIP-39 → master_seed + recv-identity derivation |
| `crates/tardus-validator/src/pkcs11_store.rs` | v2.11 HSM-mediated share storage |

---

## Key files for implementation review

| File | Implementation surface |
|---|---|
| `crates/tardus-program/src/processor.rs` | On-chain instruction dispatch |
| `crates/tardus-program/src/state.rs` | KeysetRegistry, NullifierSet, Vault state |
| `crates/tardus-program/src/ed25519_verifier.rs` | Solana ed25519_program precompile bridge |
| `crates/tardus-validator/src/api.rs` | HTTP endpoint handlers |
| `crates/tardus-validator/src/dkg_sessions.rs` | DKG session state machine |
| `crates/tardus-validator/src/sign_sessions.rs` | Threshold sign session state machine |
| `crates/tardus-validator/src/transparency_log.rs` | Hash-chained event log |
| `crates/tardus-relay/src/inbox.rs` | TTL-bounded inbox + dual backend (Memory / SQLite) |
| `crates/tardus-wallet/src/wallet_db.rs` | AEAD-sealed wallet persistence |
| `crates/tardus-wallet/src/bin/wallet.rs` | User CLI surface (16 subcommands) |

---

## Reproducing findings

For any finding the audit firm produces, the reproduction should
be deterministic:

- Cryptographic: a minimal-counterexample Rust test in
  `crates/<affected>/tests/audit_<finding-id>.rs` that fails
  against the current implementation and passes against the
  recommended fix.
- Implementation: a curl-able HTTP request sequence + expected
  vs observed response, recorded in
  `audit/findings/<finding-id>.md`.
- Operational: a `deploy/runbooks/`-driven procedure that
  produces a divergence from the documented behaviour.

See `audit/FINDINGS_TEMPLATE.md` for the report format.

---

## Communication discipline

- **Findings.** File one Markdown file per finding under
  `audit/findings/<finding-id>.md`. Severity per `SCOPE.md`'s
  rubric.
- **Direct messaging.** Signed-email + dedicated audit-engagement
  channel TBD per engagement contract. No GitHub-issue-based
  coordination.
- **Public disclosure.** Audit firm may publish a redacted audit
  letter on conclusion, with project approval on the redaction
  set. Findings with `Critical` or `High` severity remain
  embargoed until remediation lands AND a coordinated disclosure
  window has passed.

---

## What to expect from the project team

- Authoritative answer on any spec ambiguity within 1 business
  day (via the audit channel).
- Reproducibility help: if a test or the live demo doesn't
  reproduce against a fresh clone, the project team owns the
  rebuild before the audit clock continues.
- Code freezes: no `main`-branch merges to in-scope code during
  the active audit window, except for findings remediation.

---

Welcome to the engagement. The spec is the source of truth; the
code's job is to faithfully implement it; the audit's job is to
verify both.
