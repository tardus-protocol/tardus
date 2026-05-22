# TARDUS Threat Model

Last updated: tied to spec v1.5 (47-page Phase 1 revision).

License: TARDUS-PROPRIETARY-1.0.

---

## Adversary classes

### A.NET — Network observer

Sees TLS-protected traffic between users, validators, and relays.
Cannot decrypt TLS (assumed). May learn:

- Connection metadata (source/dest IPs, timing, payload sizes).
- Solana on-chain TX ordering and content (`Refresh`, `Withdraw`
  instructions land in cleartext per spec §5.3).

Cannot:
- Read TARDUS coin secrets or signatures from any encrypted channel.
- Forge or replay coins (T1, T3).

**TARDUS resists:** content recovery, double-spend.
**TARDUS does NOT resist:** traffic-pattern analysis at IP level;
deploy under Tor/I2P to address.

### A.RELAY — Relay operator (single, full audit access)

Runs `tardus-relayd`. Has full read access to:

- Inbox ciphertexts (the `payload_hex` blob).
- Recipient pubkeys (URL path).
- Timestamps, TTLs, payload sizes.

Cannot:
- Decrypt sealed-box payloads (T7) without the recipient's
  ed25519 sk.
- Participate in mint or refresh (no key material).

**TARDUS resists:** coin-material recovery, forgery participation,
double-spend.
**TARDUS does NOT resist:** denial of service for users polling
that relay; correlation by recipient pubkey for users who reuse
their pubkey across many payments. Mitigation: pubkey rotation +
multi-relay federation (v5.7).

### A.VAL.k — `k` colluding validators, `k < t`

Each runs `tardus-validator`, holds one share. By assumption A2 the
adversary controls strictly fewer than `t` shares.

Cannot:
- Forge coins (T1 plus threshold simulator argument).
- Recover any user's coin secret across mint or refresh (T2 +
  refresh-blindness).
- Read any user's wallet state (no access to wallet).

Can:
- Stall ceremonies if their participation is required to make a
  quorum-of-`t` work. (Mitigated by validator overprovisioning;
  spec §3.1 recommends `n ≥ 2t`.)
- Run their own `Withdraw` against coins they hold (this is not
  an attack — they are valid users with valid coins).

**TARDUS resists:** under-quorum cryptographic compromise.
**TARDUS does NOT resist:** quorum-exceeding collusion — see
A.VAL.t.

### A.VAL.t — `t` or more colluding validators (CATASTROPHIC)

Adversary controls a full threshold. By A2's failure:

- Can sign arbitrary coins under `joint_pk` (forge).
- Can run refresh without honouring nullifier discipline
  (double-spend if combined with chain reorg or RPC delay).
- Can extract shares from each other and reconstruct the joint
  secret offline.

**Response is not cryptographic; it is governance** — F5/F6 in
spec §8: `Revoke` the affected keyset, run a fresh DKG with new
committee, transition users to the new keyset via recoup. The
proactive-reshare cadence (spec §3.7, weekly) bounds the
historical-window damage but does not prevent the forward attack.

### A.HSM — HSM-resident wrap key compromise

Adversary breaks `CKA_EXTRACTABLE=false` on a specific HSM (e.g.
via firmware vulnerability + physical access). Recovers the AES
wrap key for one validator.

- Can decrypt the on-disk share file of that validator (under
  v2.11) and read the share scalar.
- Reduces A.VAL.k → A.VAL.{k+1} for the attacker.

**TARDUS resists:** single-HSM compromise via the threshold (T1,
T2 hold for `k < t`).
**TARDUS does NOT resist:** mass-HSM compromise across the
committee.

Mitigation for v2.12+ with native EDDSA HSMs (CKM_EDDSA path):
the share is generated inside or imported into the HSM via
`C_UnwrapKey` and signs via `C_Sign / CKM_EDDSA`, eliminating the
plaintext-share-in-memory window entirely. The HSM is then the
only repository of share material; CKA_EXTRACTABLE=false on the
SHARE key itself directly hardens A.HSM.

### A.WALLET — User wallet compromise

Adversary obtains the user's BIP-39 mnemonic, or root access to
the user's wallet host while it's unlocked.

- Recovers all of the user's coin material (full A.WALLET → full
  recovery).
- Can spend all coins in flight or held.
- Can decrypt all past + future sealed-box deliveries to the
  user's receiving identity (R6 in spec §8).

**TARDUS does NOT resist:** the BIP-39 mnemonic is the security
root. Users are responsible for offline mnemonic storage. Spec
§6 documents this trust boundary explicitly.

**Partial mitigation** (v3.4): the on-disk `wallet.bin` is
AEAD-sealed under HKDF-derived key from mnemonic; OS-level
file-permission compromise alone (without the mnemonic) does
not recover wallet contents.

### A.SOLANA — Solana network adversary

Validator-set adversary or RPC adversary on Solana itself.

- Can stall transaction inclusion (delay, not deny).
- Cannot violate Solana finality (assumed A6).
- Can lie via RPC (F18); users should multi-RPC verify.

**TARDUS resists:** chain liveness failures via off-chain
issuance (mint protocol does not need the chain). On-chain
proofs (T3, T6) inherit Solana's finality.

### A.SUPPLY — Supply-chain adversary

Compromises a dependency or build environment. Adds a malicious
patch to `curve25519-dalek`, `chacha20poly1305`, `rusqlite`, etc.

- Could leak any in-process key material via stenographic
  channels.

**TARDUS resists:** none directly. Mitigation is standard
supply-chain hygiene: pinned dependencies, `cargo audit` in CI,
reproducible builds (cargo-vet, in roadmap), and validator-side
HSM key residency (v2.13 native HSM path closes the residency
window even if a dependency is compromised).

---

## Attack-surface summary table

| Surface | Adversary class | Mitigation | Residual risk |
|---|---|---|---|
| TLS network | A.NET | Standard TLS (rustls + ring) | IP-level traffic analysis |
| Relay inbox | A.RELAY | T7 sealed-box | Pubkey reuse correlation |
| Validator peer mTLS | A.NET, A.VAL.k | mTLS with peer-CA pinning | Cross-validator collusion not detected by TLS |
| Validator HSM | A.HSM | CKA_EXTRACTABLE=false + v2.13 native sign | Firmware/physical HSM attack |
| Validator process memory | A.HSM, A.SUPPLY | v2.13 closes window for native-EDDSA HSMs | Pre-v2.13 share residency during sign |
| Wallet on-disk file | A.WALLET (partial) | AEAD-sealed wallet.bin under BIP-39 | Mnemonic compromise = total loss |
| BIP-39 mnemonic | A.WALLET | None (it IS the root) | Mnemonic loss = unrecoverable; mnemonic theft = full compromise |
| Solana program | A.SOLANA, A.SUPPLY | PDA validation + canonical-deserialization (§5.5) | Solana runtime bug |
| Operator boot config | A.SUPPLY | systemd hardening (deploy/systemd/) | Compromised /etc/tardus secrets |

---

## Non-goals

TARDUS does NOT attempt to address:

- **Quantum adversary.** All security reductions are
  classical-ECDLP-based. Post-quantum migration is a future
  protocol (likely a hash-based bearer scheme; not v1).
- **User-side malware on the wallet host.** A keylogger that
  captures the mnemonic at first-entry defeats every wallet's
  threat model.
- **Coercion / rubber-hose attacks** against the user.
  Plausible-deniability or duress wallets are an explicit
  non-goal for v1.
- **Universal sender anonymity at the IP layer.** Deploy under
  Tor/I2P if you need IP-level unlinkability between sender and
  recipient.

---

## Audit firm focus

The most productive audit attention is on:

1. **T1 reduction completeness** — does the EasyCrypt
   `schnorr.ec` skeleton correctly capture the Pointcheval-Stern
   forking lemma applied to *threshold* Schnorr (not just
   single-party)?
2. **T7 reduction completeness** — does `sealed_box.ec` correctly
   compose X25519 ECDH, HKDF, and ChaCha20-Poly1305 IND-CCA?
3. **Refresh protocol nullifier discipline (T3 + T4)** — does the
   implementation in `crates/tardus-refresh` faithfully implement
   the κ-fold cut-and-choose with no early-exit or
   side-channel-friendly branches?
4. **HSM session lifecycle** — does the v2.12 `reopen_session`
   path handle every PKCS#11 error class that softhsm or
   production HSMs can return?
5. **Operator runbook gaps** — would an operator following only
   `deploy/runbooks/validator-operator.md` produce a secure
   deployment, or are there implicit assumptions not written
   down?
