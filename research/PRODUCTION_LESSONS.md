# TARDUS — Production Lessons from Cashu + GNU Taler

_Synthesis date: 2026-05-20. Source detail: `cashu/findings.md`, `taler/findings.md`._

This document is the output of Phase B (research) and the input of Phase A (spec + proof). Everything that actually broke in Cashu and everything that actually works in Taler is captured here as a TARDUS spec action.

---

## Executive summary — what changes

Post-round-4 TARDUS architecture gets a **strong update** in the following points:

1. **Migrate to a refresh-protocol model.** The earlier "swap" concept was insufficient. Adopt Taler's κ-fold cut-and-choose refresh model — partial spend + anonymous change fold into one atomic protocol.
2. **Reject deterministic seed derivation.** The Cashu NUT-13 attack makes this an evidence-based call. Coin secrets are signature-based + non-deterministic.
3. **256-bit keyset ID from v1.** Never open Cashu's 31-bit residue collision attack surface.
4. **Mandatory client keyset validation.** Cashu's "SHOULD" becomes TARDUS's "MUST" — no client accepts a keyset without recomputing.
5. **On-chain audit, not off-chain auditor.** Taler's single-auditor weakness is structurally resolved; make this explicit in the spec.
6. **Mandatory HSMs.** Taler left this open; we formalize Bjørnar's round 4 R3.
7. **Income transparency v2 door open, v1 closed.** Dold's asymmetric-privacy contribution is a regulatory axis; keep v1 lean.
8. **`/recoup`-style compromise response API is mandatory.** A threshold-key revocation procedure.
9. **Failure-mode documentation is mandatory.** Don't repeat Cashu's rug-pull discourse gap; explicit section.

---

## Category 1: Cryptographic protocol

### L1 — Refresh protocol = κ-fold cut-and-choose

**Source:** Taler DD-62, Dold 2019.

**Decision:** TARDUS's swap operation is renamed **refresh** and runs as a cut-and-choose. κ=3 by default.

- The client produces κ sets of blinded planchets.
- The threshold mint picks γ ∈ [1, κ] at random.
- The client opens all κ-1 sets except the γ-th → the mint verifies honesty.
- Fresh coin secret = `s = SignUnique(cs, t)`, `t = Hash1a("Refresh", Cp, r)`.
- `x = Hash1b(s)` → new coin secret.

**Spec impact:** `Protocol.Refresh` (new section); the prior name `Protocol.Swap` is retired.

### L2 — Deterministic seed derivation FORBIDDEN

**Source:** Cashu NUT-13 conduition.io disclosure (July 2025).

**Decision:** TARDUS coin secrets are **not** derived deterministically from a seed via BIP32 / HKDF. Signature-based (refresh) or pure random nonce only.

**Rationale:** Cashu NUT-13's attack surface was rooted in 31-bit reduction during BIP32 path derivation. Do not repeat the pattern.

**Spec impact:** "No deterministic derivation from seed" requirement in `Crypto.Derivation`.

### L3 — 256-bit keyset ID, version byte 0x02

**Source:** Cashu NUT-02 v2 (33-byte, version byte 0x01).

**Decision:** TARDUS keyset ID v1 = 33 bytes, version byte `0x02` (distinct from Cashu v2), SHA-256 hash of:
- Public keys sorted by denomination (ascending)
- Concatenated `denom:pk_hex` pairs, comma-separated
- Appended `|unit:tardus-sol|`
- Appended `|epoch:N|`
- SHA-256 → prefix 0x02

No reduction to 31 bits anywhere. Not used as a BIP32 path index.

**Spec impact:** `Crypto.KeysetID` section, version-byte allocation.

### L4 — Client keyset validation MUST

**Source:** Cashu NUT-02 violation pattern.

**Decision:** A TARDUS client recomputes any keyset ID locally with SHA-256 before accepting it. Mismatch → spec error, transaction rejected. Global uniqueness constraint over both active and inactive keysets.

**Spec impact:** `Client.Validation.Keyset` section, with explicit MUST.

### L5 — Blind Schnorr + Threshold (round 4 approved, unchanged)

**Source:** Stinson-Strobl 2001 + Komlo-Goldberg 2020.

Approved in round 4. No change.

---

## Category 2: Operational security

### L6 — Three-tier key architecture + threshold

**Source:** Taler exchange manual.

**Decision:** Each TARDUS mint operator's validator has three tiers analogous to Taler's:
- Tier 1: Offline master signing key (in HSM, validator identity).
- Tier 2: Online threshold helper (FROST signing, signs with HSM).
- Tier 3: Public-facing API server (no key access).

**Additionally**: These three tiers exist _per validator_; N=30 validators in total, threshold t=14 (round 4).

**Spec impact:** `Mint.KeyArchitecture` section.

### L7 — HSM FIPS 140-2 Level 3 MANDATORY

**Source:** Taler exchange manual gap ("does not yet support HSM"), Bjørnar round 4 R3.

**Decision:** Each TARDUS mint validator holds its FROST share inside a FIPS L3 HSM. The spec records this as a requirement, not a soft recommendation.

**Spec impact:** `Mint.HardwareReqs`, with a compliance-certificate requirement.

### L8 — Key rotation — proactive secret sharing

**Source:** Taler `DURATION_*` parameters + Bjørnar round 4 R4.

**Decision:** TARDUS denomination keys:
- `epoch = 1 day` proactive secret-sharing rotation.
- `LOOKAHEAD = 30 epochs` of DKG ahead (the committee maintains a 30-day buffer).
- `OVERLAP_DURATION = 2 epochs` (transition window).
- Signed rotation transcripts, on-chain audit log.

**Spec impact:** `Mint.Rotation` section, schedule parameters fixed.

### L9 — Compromise response → on-chain revoke

**Source:** Taler `/recoup` API.

**Decision:** In TARDUS, denomination revoke = a threshold-signed on-chain transaction. A `/recoup`-style API lets wallets return unspent coins onto a new keyset. Because it is threshold-signed, no single operator can force a revoke (forced-revoke protection).

**Spec impact:** `Protocol.Revoke` and `Client.Recoup` sections.

---

## Category 3: Audit and proof-of-liabilities

### L10 — On-chain Solana vault = anyone-as-auditor system

**Source:** Taler single-auditor weakness + Cashu PoL gap.

**Decision:** TARDUS's vault collateral _and_ the sum of issued-commitment denominations are readable on-chain. The equality constraint: `vault_collateral == sum_active_commitments`. Anyone can verify this in a single Solana RPC query.

**Spec impact:** `OnChain.Vault.AuditInvariant` section; the mathematical equality is stated formally.

### L11 — Slow-rug / inflation impossibility

**Source:** Cashu slow-rug risk.

**Decision:** The vault collateral can never be less than the issued-commitment sum → enforced on-chain. The threshold mint cannot violate this invariant even under t-1 collusion, because each issuance is an on-chain TX and vault bookkeeping is atomic.

**Spec impact:** `Security.SlowRug` theorem (tied to EasyCrypt theorem T4 — state integrity).

---

## Category 4: Wallet UX

### L12 — Bearer-instrument hygiene + mandatory backup

**Source:** Cashu local-storage wipe → fund loss; Habibi round 4 R9.

**Decision:** TARDUS wallet onboarding makes encrypted seed backup a _mandatory_ step. Deterministic coin regeneration from the seed is _forbidden_ (per L2); the backup is only an encrypted snapshot of the coin store.

**Spec impact:** `Wallet.Backup` section; compatible with the CRDT multi-device sync (round 4 R10).

### L13 — Multi-device sync — don't repeat Cashu's mistake

**Source:** Inconsistent counter tracking across Cashu wallets.

**Decision:** TARDUS multi-device sync uses CRDTs (G-Set + LWW-Register), with conflict resolution logged in a local ledger. A double-spend attempt is reported via a specific error code.

**Spec impact:** `Wallet.MultiDeviceSync` section.

### L14 — Hardware-wallet roadmap (round 4 R8)

Taler has no hardware-wallet support; neither does Cashu. TARDUS targets Tangem/Trezor custom apps in Phase 2-3, with a Ledger firmware contribution in Phase 3.

**Spec impact:** `Roadmap.HardwareWallet`.

---

## Category 5: Regulation and governance

### L15 — Failure-mode disclosure — explicit section

**Source:** Cashu FAQ's rug-pull gap; ECB rulebook with 2,000 comments.

**Decision:** A `Security.FailureModes` section is mandatory in the TARDUS spec. Each failure mode lists:
- Definition
- Trigger condition
- User-facing consequence
- System recovery steps
- Vault state outcome

Nothing unexpected — everything is written down.

**Spec impact:** `Security.FailureModes` section; minimum 8 modes (validator down, threshold collusion, vault drain attempt, keyset compromise, refresh abort, relay outage, client device loss, network partition).

### L16 — Income-transparency v2 door

**Source:** Dold thesis, asymmetric privacy.

**Decision:** Not in v1. In a v2 spec extension, combine Stadler-Piveteau-Camenisch 1995 fair blind signatures with Taler's merchant-visible income model.

**Spec impact:** `Protocol.v2.ComplianceExtension` — placeholder section.

---

## Category 6: PQ roadmap

### L17 — PQ refresh (DD-62 parallel)

**Source:** Taler DD-62.

**Decision:** In Phase 2-3, adopt a lattice-based blind signature (Zhou's round 3 proposal, Ducas-Lyubashevsky lineage). PQ-hardened refresh + hash-based derivation. Placeholder only in Phase 0.

**Spec impact:** `Protocol.PostQuantum` draft.

---

## Open questions for the spec phase

1. **Is refresh κ=3, or can interaction with the threshold mint push κ down to 2?** Need soundness/round-trade-off math.
2. **How is the coin-secret nonce derived?** Pure random (hard to back up), or HKDF over a random salt (stays away from the NUT-13 trap but is partly deterministic)?
3. **How does a revoke TX affect vault collateral?** Does the BTC equivalent of recouped coins stay in the vault or get burned?
4. **For the auditor invariant: a special instruction, or an anyone-callable view function?**
5. **Failure mode 5 (refresh abort) — does it need Taler-style protocol-abort recovery?**

These five answer themselves as the first sections of `spec/SPEC.tex` are written.

---

## Direct mathematical formalities for the spec

**Refresh protocol formal:**

```
RefreshSession := {
  m_old: Coin,         // melted coin
  κ: 3,                // cut-and-choose parameter
  planchets: [κ × n],  // n = output coins
  challenge: γ ∈ [1,κ],
  reveals: planchets \ {planchets[γ]},
  fresh_secret: SignUnique(cs_old, Hash1a("Refresh", Cp, r)),
  new_coins: [n × Coin]
}
```

**Vault invariant:**

```
∀ epoch e:
  vault_collateral_sol(e) = Σ_{cm ∈ active_commitments(e)} denom(cm)
```

**Keyset ID v1 derivation:**

```
KeysetID_v1(denoms, pks, unit, epoch) :=
  0x02 || SHA256(sorted_pairs(denoms, pks) || "|unit:" || unit || "|epoch:" || epoch)
```

These three are the central mathematical formalities in the first draft of `spec/SPEC.tex`.

---

## Sources

- `cashu/findings.md` — Cashu detail
- `taler/findings.md` — Taler detail
- conduition.io disclosure (Jan 2026)
- Taler DD-62 PQ Refresh Protocol
- Dold (2019) thesis, Université de Rennes
- ECB Digital Euro Closing Report (Oct 2025)
