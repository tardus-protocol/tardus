# TARDUS

A fully private bearer-payment protocol on Solana. **Chaum 1982 + 44 years of cryptographic hygiene**, wired into a native SBF on-chain program — no ZK, no pairings, no per-circuit trusted setup.

[![License: TARDUS-PROPRIETARY-1.0](https://img.shields.io/badge/license-TARDUS--PROPRIETARY--1.0-red)](LICENSE)
**Devnet program:** [`AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u`](https://explorer.solana.com/address/AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u?cluster=devnet) (v1.4.14, 9 instructions)
**Status:** Phase 4 audit-ready. Real economic loop validated on devnet — Bob received real SOL via a TARDUS Withdraw.

---

## Why TARDUS

Existing privacy layers on Solana (Token-2022 Confidential Transfer, Light Protocol compressed accounts) only provide *amount privacy*. The sender, the receiver, and the transaction graph remain transparent. Stacking ZK SNARKs on top (Light + Groth16, the Aztec/Aleo pattern) brings trusted-setup-ceremony dependency, a ~960k+ CU budget, and composability headaches.

TARDUS takes a different route: David Chaum's 1982 blind-signature-based bearer cash, layered with 44 years of academic hygiene (Brands 1993, Okamoto 1995, Pointcheval-Stern 1996, Stinson-Strobl 2001, Camenisch-Hohenberger-Lysyanskaya 2005, Dold 2019, Komlo-Goldberg 2020), wired into a Solana-native harness with a Bitcoin-style sealed-box P2P payload layer.

| | TARDUS | Light + Groth16 | Token-2022 Confidential |
|---|---|---|---|
| Sender privacy | ✓ | ✓ (commitment-hidden) | ✗ |
| Receiver privacy | ✓ (off-chain delivery) | ✓ | ✗ |
| Amount privacy | per-denom (set anonymity) | full | full (ElGamal) |
| Trusted setup | none | universal SRS (Plonk/Halo2) | none |
| Per-TX CU (measured) | 7–77 k | ~960 k | ~150 k |
| Auditor key required | no | no | optional |

---

## Architecture in brief

**Off-chain threshold mint.** An `n`-of-`n` committee of validator daemons holds the mint key as Stinson-Strobl 2001 + Komlo-Goldberg 2020 DKG-derived shares. Each share is HSM-resident (PKCS#11, `softhsm2` validated; production CloudHSM / YubiHSM via Path A v2.13.1 — wrap-key AES custody + `CKM_EDDSA_RAW` Path B v2.14 deferred). Proactive secret-sharing reshare per epoch.

**κ-fold cut-and-choose refresh.** Dold 2019 style; κ=32 default. Cheating bound `1/(κ+1) ≈ 3%` per attempt. Partial spend + anonymous change fold into one atomic protocol. Coin secrets are signature-derived (not BIP-32 seed-derived — avoids Cashu's NUT-13 attack surface).

**Bearer on-chain model.** Solana native Rust program (`tardus-program`, ~233 KiB SBF ELF on devnet). 9 instructions: `Bootstrap`, `RegisterKeyset`, `Deposit`, `Refresh`, `Withdraw`, `Revoke`, `SponsorDeposit`, `SponsorPayout`, `ResizeAccount`. Nullifier is `null(Cp)` not `null(x)` — bearer model fixes the SBF 4 KB stack budget and the double-spend predicate in one shot. Ed25519 verification via the `ed25519_program` precompile bridge.

**Fee-payer privacy stack (Layers 1–4).** Ephemeral payer per TX + multi-sponsor pool rotation + on-chain `SponsorPool` commingled faucet + pool caller rotation. Decouples the spend-class TX signer from any specific funding source. See spec §3.10.1.

**Sealed-box AEAD.** `tardus://` invoice URIs deliver coin material via an encrypted relay mesh: X25519 ECDH + HKDF-SHA-256 + ChaCha20-Poly1305. Recipient identity is BIP-39 + HKDF-SHA-512 derived (deterministic, recv-only privacy domain separate from per-coin secret HKDF domain). Relay operator sees only opaque ciphertext.

---

## Repository layout

```
~/Desktop/tardus/
├── Cargo.toml                workspace (12 Rust crates, MSRV 1.85)
├── LICENSE                   TARDUS-PROPRIETARY-1.0
├── README.md                 this file
│
├── crates/                   12 Rust crates
│   ├── tardus-core           Schnorr + blind sign primitives
│   ├── tardus-mint           DKG + threshold sign + reshare
│   ├── tardus-refresh        κ-fold cut-and-choose protocol
│   ├── tardus-program        Solana SBF program (devnet LIVE)
│   ├── tardus-client         coin store + invoice + AEAD backup
│   ├── tardus-cli            operator CLI (20+ devnet subcommands)
│   ├── tardus-validator      mint daemon (18 endpoints, mTLS, HSM)
│   ├── tardus-wallet         user CLI + BIP-39 + sealed-box
│   ├── tardus-relay          relay daemon (SQLite-backed inbox)
│   └── tardus-wallet-gui     desktop GUI v1 (eframe + tokio + 7 tabs)
│
├── ts-sdk/                   @tardus/sdk v0.2 (Phantom/Solflare baseline)
│   ├── src/                  v0.1 X25519-clamped + v0.2 Rust-compat
│   └── test/                 32 tests + CI cross-language drift detector
│
├── spec/                     v1.7, 53-page LaTeX
│   ├── SPEC.tex
│   ├── sections/             9 sections + reference vectors appendix
│   └── easycrypt/            T1, T2, T4, T7 mechanization skeletons
│
├── audit/                    Phase 4 hand-off kit (7 docs, ~1140 LoC)
│
├── deploy/                   production deployment kit
│   ├── runbooks/             validator-operator, relay-operator,
│   │                         key-rotation, HSM v2.13 roadmap,
│   │                         Light Protocol design,
│   │                         Token-2022 ConfidentialMint design,
│   │                         HSM vendor capability matrix,
│   │                         mainnet ship gate checklist
│   ├── systemd/              tardus-validator.service + tardus-relayd.service
│   └── monitoring/           Prometheus exporter + health probe
│
├── .github/workflows/        6 CI workflows
│   ├── workspace-tests       cargo test + clippy -D warnings
│   ├── spec-build            LaTeX 0-warning gate + EasyCrypt structural
│   ├── gui-build             X11/Wayland headers + tardus-wallet-gui
│   ├── ts-sdk-tests          Node 24 typecheck + 32 tests
│   ├── hsm-tests             weekly cron softhsm2 integration
│   └── cross-language-compat Rust example → TS decrypt (drift detector)
│
└── research/                 PRODUCTION_LESSONS.md L1-L17 (Phase 0 inputs)
```

---

## Phase status

| Phase | Scope | Status |
|---|---|---|
| **0** | Spec & proof skeleton | ✓ |
| **1** | Reference implementation (Rust) | ✓ devnet v1.4.14 LIVE |
| **2** | Mint ops & DKG | ✓ HSM Path A shipped |
| **3** | Wallet & SDK | ✓ |
| **4** | Audit baseline | ✓ external firm engagement pending |
| **5** | Relay + sealed-box P2P | ✓ |
| **6** | Spec v1.7 revision | ✓ T1–T8, reference vectors appendix |
| **7** | Deployment kit | ✓ |
| **8** | GUI v1 (desktop) | ✓ 7 tabs, direct devnet integration |
| **9** | Fee-payer privacy Layer 1–4 | ✓ ephemeral + sponsor pool + commingled |
| **E (mini)** | Real economic loop | ✓ Bob received real SOL on devnet |
| **G (mini)** | Registry / nullifier scaling | ✓ multi-tx ResizeAccount |
| **TS SDK v0.2** | Rust-compat Montgomery ladder | ✓ wire-format byte-equal proven |
| **CI/CD** | 6 GitHub Actions workflows | ✓ clippy strict + cross-language drift |

**81 crown jewels** (each runtime-evidenced). Mainnet ship gate has 4 MUST blockers: external audit firm engagement, HSM v2.14 Path B (CloudHSM), mainnet on-chain deployment, operator runbook fire drill. See `deploy/runbooks/mainnet-ship-gate-checklist.md`.

---

## Download

**TARDUS Wallet — Linux x86_64 AppImage** (v0.1.0, 6.2 MB stripped):

```bash
# 1. Download
curl -LO https://<host>/TARDUS-Wallet-0.1.0-x86_64.AppImage
curl -LO https://<host>/TARDUS-Wallet-0.1.0-x86_64.AppImage.sha256

# 2. Verify integrity
echo 'c99c0e8102320e275cc4ca70fba908a89263bf2f97805d3ea9b85d93c302a085  TARDUS-Wallet-0.1.0-x86_64.AppImage' | sha256sum -c

# 3. Verify authenticity (minisign — public key in paper appendix once signed)
# minisign -Vm TARDUS-Wallet-0.1.0-x86_64.AppImage -P "$(cat tardus-wallet.pub | tail -1)"

# 4. Run
chmod +x TARDUS-Wallet-0.1.0-x86_64.AppImage
./TARDUS-Wallet-0.1.0-x86_64.AppImage
```

The AppImage bundles the wallet binary, `.desktop` integration metadata,
and an icon — no install, no package manager, no sudo. Linux desktop with
glibc 2.31+ (Ubuntu 20.04+, Debian 11+, Fedora 34+, Arch current) is
supported. macOS and Windows builds are not yet available.

Build artefacts and signing procedure live in
[`deploy/wallet-release/`](deploy/wallet-release/).

---

## Live demos (devnet)

The CLI exercises every component end-to-end on Solana devnet:

```bash
# Build the workspace (one-time).
cargo build --release --workspace

# Show current on-chain capacity (registry / nullifier-tree / SponsorPool).
cargo run --release -p tardus-cli -- devnet capacity

# Demo 1: pure off-chain (DKG + mint + refresh, no devnet TX).
cargo run --release -p tardus-cli -- devnet private-tx-demo

# Demo 2: Alice mints, Bob receives via relay, Bob refreshes
# (DKG + sealed-box delivery + on-chain Refresh TX).
cargo run --release -p tardus-cli -- devnet alice-pays-bob-on-devnet

# Demo 3: full economic loop — Bob withdraws to a fresh Solana
# wallet and gets REAL SOL.
cargo run --release -p tardus-cli -- devnet alice-pays-bob-and-bob-withdraws \
    --denom 1000000 \
    --use-ephemeral-payer \
    --use-onchain-pool
```

Demo 3 lands a real Withdraw TX signed by an ephemeral keypair funded from the on-chain SponsorPool (Faz 9.1 + 9.4 privacy stack). A representative live run on 2026-05-22 transferred 0.005550000 SOL to a fresh Bob wallet — TX [`3UVkfK5tt671FDJ…`](https://explorer.solana.com/tx/3UVkfK5tt671FDJichxezdviVubnkiZrGS1GBFRMHrTXLTBf49Xyg8w4MaHKeXyPmqodcABvntRE7faxBkePcysV?cluster=devnet).

---

## Quick start (developer)

```bash
# Workspace tests (51 default test groups, default features).
cargo test --workspace --release

# Strict clippy gate (CI mirror).
cargo clippy --workspace --all-targets -- -D warnings

# Spec PDF build (53 pages, zero-warning gate).
cd spec && make
pdfinfo SPEC.pdf | grep Pages    # → 53

# TS SDK (Phantom/Solflare baseline + Rust-compat path).
cd ts-sdk
npm install
npm run typecheck
npm test                          # → 32 tests pass (34 with CI fixture)

# Optional: HSM tests (requires softhsm2 system package).
cargo test --release -p tardus-validator --features hsm \
    --test hsm_pkcs11 -- --ignored --test-threads=1   # → 6 tests pass

# Optional: GUI (requires X11/Wayland + libxkbcommon-dev).
cargo run --release -p tardus-wallet-gui
```

---

## Documentation

| Document | Purpose |
|---|---|
| `spec/SPEC.pdf` | Authoritative protocol specification (v1.7, 53 pages, 8 theorems T1–T8) |
| `audit/` | Phase 4 audit firm onboarding kit (7 docs) |
| `deploy/runbooks/mainnet-ship-gate-checklist.md` | M1–M4 MUST blockers + S1–S4 SHOULD + Y1–Y6 MAY |
| `deploy/runbooks/hsm-vendor-capability-matrix.md` | 8 vendor × 5 mechanism support matrix |
| `deploy/runbooks/light-protocol-integration-design.md` | v1.5+ nullifier-tree replacement (13 weeks) |
| `deploy/runbooks/token-2022-confidential-mint-design.md` | v1.5+ vault confidential-balance migration (19 weeks) |
| `deploy/runbooks/v2.13-hsm-resident-share-roadmap.md` | HSM Path A v2.13.1 + Path B v2.14 roadmap |
| `research/PRODUCTION_LESSONS.md` | L1–L17 lessons from prior privacy-payment systems |

---

## Historical lineage

- **Chaum, D. (1982).** Blind signatures for untraceable payments. *Crypto '82.*
- **Pointcheval, D. & Stern, J. (1996).** Provably secure blind signature schemes. *Asiacrypt '96.*
- **Stinson, D. & Strobl, R. (2001).** Provably secure distributed Schnorr signatures. *ACISP.*
- **Camenisch, J., Hohenberger, S. & Lysyanskaya, A. (2005).** Compact e-cash. *Eurocrypt.*
- **Dold, F. (2019).** *The GNU Taler system: practical and provably secure electronic payments.* Université de Rennes.
- **Komlo, C. & Goldberg, I. (2020).** FROST: Flexible round-optimized Schnorr threshold signatures. *SAC.*

Full bibliography: `spec/refs.bib`.

---

## License

**TARDUS-PROPRIETARY-1.0** — the repository is visible for reference only. Copying, derivation, redistribution, commercial use, and AI training/inference are prohibited. See `LICENSE`.
