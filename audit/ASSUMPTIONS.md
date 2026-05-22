# TARDUS Security Assumptions (A1-A8)

These are the explicit cryptographic and operational assumptions
the security theorems T1-T7 rely on. An audit firm verifies that
the assumptions are correctly identified, individually plausible,
and that the theorems' conditional security depends on no other
unstated assumption.

Cross-reference: spec §7.1, §9.6.

License: TARDUS-PROPRIETARY-1.0.

---

## A1 — Computational ECDLP hardness on Curve25519

For any PPT adversary `B` and security parameter `λ`:
```
Adv^{ECDLP}_{Curve25519}(B, λ) ≤ negl(λ).
```

**Status:** Standard cryptographic assumption (Bernstein 2006).
Best-known attack complexity is `≥ 2^125`.

**Used by:** T1, T7.

---

## A2 — Honest threshold majority

Strictly fewer than `t` of the `n` mint-committee validators are
adversary-controlled at any single point in time.

**Status:** Operational; cannot be reduced to a cryptographic
assumption. Enforced by:
- Geographic / jurisdictional diversification of validators.
- Independent HSM hardware per validator.
- Operator background-check + multi-party governance.
- Proactive reshare (spec §3.7) bounds historical-window damage.

**Used by:** T1 (threshold corollary), T2 (committee blindness),
T5 (reshare).

---

## A3 — Random Oracle Model for SHA-512 hash-to-scalar

The `H : (group × msg) → scalar` map defined as
`SHA-512(domain || R || msg) mod ℓ` is modelled as a random
oracle in security reductions.

**Status:** Standard ROM assumption (Bellare-Rogaway 1993).

**Used by:** T1 (Pointcheval-Stern forking), T7 (HKDF as PRF).

---

## A4 — IND-CCA security of ChaCha20-Poly1305

For any PPT adversary `B`:
```
Adv^{IND-CCA}_{ChaCha20-Poly1305}(B, λ) ≤ negl(λ).
```

**Status:** Standard AEAD assumption (RFC 8439, NIST SP 800-185).
Foundational to multiple deployed protocols (TLS 1.3, WireGuard,
SSH).

**Used by:** T7 (sealed-box confidentiality).

---

## A5 — HKDF-SHA-256 PRF security

For any PPT adversary `B`:
```
Adv^{PRF}_{HKDF-SHA-256}(B, λ) ≤ negl(λ).
```

In the analysis we treat HKDF as a Random Oracle for the purposes
of the T7 reduction; the standard-model PRF assumption is the
weaker form sufficient for practical security.

**Status:** Standard (Krawczyk 2010, RFC 5869).

**Used by:** T7.

---

## A6 — Solana finality safety boundary

Solana blocks at finality depth ≥ 32 do not reorganize.

**Status:** Operational property of the Solana network; matches
the supermajority-vote model. Has not been violated in production
since Solana's mainnet launch.

**Used by:** T3 (double-spend prevention), T6 (vault collateral
invariant).

**Risk:** A catastrophic Solana consensus event (≥ ⅓ Byzantine
validators colluding) would violate A6. F16 (spec §8) covers the
response.

---

## A7 — HSM tamper-resistance (PKCS#11 CKA_EXTRACTABLE=false)

A correctly-provisioned HSM cryptographic key with
`CKA_EXTRACTABLE=false` cannot be extracted via the PKCS#11 API,
including under any sequence of legitimate `C_*` calls. Physical
or firmware compromise of the HSM hardware itself is OUT of
scope for the cryptographic argument.

**Status:** Vendor-stated property; verified per-HSM by the
operator at deployment time (FIPS 140-2 Level 3 typically
required by TARDUS operator policy).

**Used by:** v2.11+ wrap-key custody, v2.13 native-share custody.

**Test gap:** softhsm2 is a software HSM and does NOT physically
enforce `CKA_EXTRACTABLE=false`. Production deployments require
real HSM hardware (Thales Luna 7, CloudHSM, YubiHSM 2,
Utimaco SecurityServer) for the A7 guarantee to hold.

---

## A8 — Mnemonic operational security

The user's BIP-39 mnemonic is correctly transcribed and stored
offline (paper backup, metal etcher) per BIP-39's user-experience
guidance, and is not exposed to a malicious party between
generation (via `tardus-wallet mnemonic generate`) and the user's
secure offline storage.

**Status:** Operational; cannot be reduced to a cryptographic
assumption.

**Used by:** All wallet-side properties (R6 mitigation,
receiving-identity privacy).

---

## Assumption-to-theorem matrix

| Theorem | Spec § | Assumptions used |
|---|---|---|
| T1 — Coin Unforgeability | §7.3 | A1, A3 (+ A2 for threshold corollary) |
| T2 — Issuance Blindness | §7.4 | A2 (information-theoretic; no cryptographic assumption) |
| T3 — Double-Spend Prevention | §7.5 | A6 |
| T4 — Cut-and-Choose Soundness | §7.6 | (combinatorial; no cryptographic assumption) |
| T5 — Reshare Correctness | §7.7 | A2 |
| T6 — Vault Collateral Invariant | §7.8 | A6 |
| T7 — Sealed-box Confidentiality | §9.6 | A1, A4, A5 |
| All operational v2.11+ HSM properties | §3, §8 | A7, A8 |
