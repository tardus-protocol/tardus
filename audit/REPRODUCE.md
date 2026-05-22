# Reproducing the TARDUS Audit Baseline

How to rebuild every audit artefact from a fresh `git clone`.
Times are wall-clock on a modern Linux laptop.

License: TARDUS-PROPRIETARY-1.0.

---

## Prerequisites

```bash
# Rust toolchain (MSRV 1.85)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable
rustup default stable

# LaTeX (for spec build)
sudo apt install texlive-full   # heavy; or just: texlive-latex-extra texlive-fonts-extra

# softhsm2 (for HSM tests)
sudo apt install softhsm2 pkcs11-tool

# EasyCrypt (optional, for .ec skeleton type-check)
opam install easycrypt
```

---

## 1. Build the workspace (~3 min)

```bash
cd ~/audit/tardus
cargo build --release
# Builds 10 crates, ~18800 LoC, no errors expected.
```

Verify:
```bash
ls target/release/ | grep -E 'tardus-(validator|relayd|wallet|cli)'
# tardus-validator
# tardus-relayd
# tardus-wallet
# tardus  (the CLI binary)
```

---

## 2. Run the default test suite (~30 s)

```bash
cargo test --release --workspace
```

Expected:
```
test result: ok. 186 passed; 0 failed; ... 
```
(across 49 test groups). One devnet-ignored test
(`devnet_e2e::ignored`) is gated behind `--ignored` and not run
by default.

---

## 3. Run the HSM tests (~10 s)

```bash
cargo test -p tardus-validator --features hsm --test hsm_pkcs11 \
    --release -- --ignored --test-threads=1
```

Expected:
```
test pkcs11_store_roundtrip_with_softhsm ... ok
test pkcs11_session_auto_reopen_recovers ... ok
test ckm_eddsa_native_sign_capability ... ok

test result: ok. 3 passed; 0 failed; ...
```

The third test additionally proves softhsm2 supports CKM_EDDSA
natively; an audit firm using a different HSM (e.g. CloudHSM)
should re-run with the vendor module path swapped.

---

## 4. Run the live private-transfer demo (~5 s after build)

```bash
cargo run --release -p tardus-wallet --example demo_private_transfer
```

Expected: the 8-step output capturing DKG, mint, sealed-box,
relay-audit, decrypt, refresh, all with cryptographic
verifications. The key audit observation is **Step 6**:

```
Step 6  ▸  Relay operator audit — try to extract coin material
  Try parse payload as JSON                        FAILED (opaque) ✓
  Try parse payload as UTF-8 text                  FAILED (binary) ✓
  Bytes contain 'coin_secret' substring?           NO ✓
  Bytes contain Coin A's pubkey?                   NO ✓
  Bytes contain Coin A's signature?                NO ✓
```

All 5 attack vectors MUST return ✓ NO / FAILED.

Re-run with `RUST_LOG=debug` to see daemon-side telemetry.

Note: each run uses fresh OS randomness, so joint_pk, coin
pubkeys, ephemeral X25519 keys, etc. differ every time.

---

## 5. Build the specification PDF (~30 s)

```bash
cd spec
make
# Output: SPEC.pdf (47 pages)
pdfinfo SPEC.pdf | grep Pages
# Pages: 47
```

Verify zero LaTeX warnings:
```bash
grep -cE "Warning|undefined" SPEC.log
# 0
```

---

## 6. Type-check the EasyCrypt skeletons (optional, ~1 min)

```bash
cd spec/easycrypt
easycrypt schnorr.ec
easycrypt blind.ec
easycrypt cut_choose.ec
easycrypt sealed_box.ec
```

Each should exit 0 with "X admits" reported. The audit firm is
expected to replace these `admit` placeholders with real
EasyCrypt tactics for T1 and T7 (the load-bearing reductions).

---

## 7. Verify devnet program is live (optional)

```bash
solana program show AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u \
    --url https://api.devnet.solana.com
# Program Id: AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u
# Owner: BPFLoaderUpgradeab1e11111111111111111111111
# ProgramData Address: ...
# Authority: 5EiLNkpp3QiH1wzBEHnCdWSpxREFH2q5jje9S2gVmaMz
# Last Deployed In Slot: ...
# Data Length: ~200 KiB
# Balance: ~1.40 SOL
```

Audit firm may submit transactions against this program for
runtime validation; the program is upgradeable but only by the
project's authority key — your submissions cannot brick the
program.

---

## 8. Workspace size + line counts

```bash
find crates -name '*.rs' | xargs wc -l | tail -1
# ~18800 total
find deploy -type f | xargs wc -l | tail -1
# ~918 total
ls spec/sections/*.tex | wc -l
# 9 sections
```

These are the absolute numbers the audit firm should match
against the engagement scope. Drift from these numbers between
engagement-start clone and engagement-end re-clone indicates
post-engagement code changes.

---

## Issue triage during audit

Findings from the above reproductions should land under
`audit/findings/`. The project team commits to:

- Reproduce + acknowledge within 1 business day.
- Rebuild + commit a fix branch within 5 business days for
  Critical / High severity.
- Medium / Low severity per engagement-agreed timeline.

For findings that DON'T reproduce against the audit firm's
artefacts, request a re-clone + repro session via the
engagement channel before filing.
