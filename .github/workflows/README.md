# TARDUS CI Workflows

GitHub Actions configuration for the TARDUS workspace. Covers the
**S2 SHOULD** mainnet-ship-gate item from
`deploy/runbooks/mainnet-ship-gate-checklist.md`.

| Workflow | Trigger | What it does |
|---|---|---|
| `workspace-tests.yml` | push / PR on Rust paths | `cargo build --release` + `cargo test --workspace --release` + `cargo clippy -D warnings` (default features + `--features hsm` separately) |
| `spec-build.yml` | push / PR on `spec/**` | `texlive` install + `cd spec && make`; **zero-LaTeX-warning gate**; uploads PDF artifact + EasyCrypt skeleton structural check |
| `gui-build.yml` | push on GUI-touching paths | X11/Wayland headers install + `cargo build -p tardus-wallet-gui --release` + GUI tests |
| `ts-sdk-tests.yml` | push / PR on `ts-sdk/**` | Node 24 + `npm install` + `npm run typecheck` + `npm test` (21 tests) |
| `hsm-tests.yml` | manual + weekly cron Sunday 04 UTC | `softhsm2` install + `cargo test --features hsm -- --ignored --test-threads=1` |

## Deferred / not-yet-shipped CI

### `nightly-devnet-smoke.yml` (not in this commit)

A nightly workflow that runs `tardus devnet private-tx-demo` or
`alice-pays-bob-on-devnet` would prove the deployed Solana
program still responds correctly. It needs:

1. A funded Solana devnet wallet (≥ 1 SOL).
2. The wallet's keypair JSON stored as a GitHub repository
   secret (e.g. `DEVNET_PAYER_KEYPAIR`).
3. CI workflow that fetches the secret, writes it to
   `~/.config/solana/id.json`, and runs the demo.

This is **not shipped here** because:
- Requires per-org SOL custody for the CI runner.
- Live demo runs publicly visible TXs on devnet; cadence + cost
  must be agreed by the operator team.
- v9.6 GUI direct integration already covers manual smoke from
  developer workstations.

Once the operator team approves a CI-owned devnet wallet, add:

```yaml
name: nightly-devnet-smoke
on:
  schedule: [{cron: '0 3 * * *'}]   # daily 03:00 UTC
  workflow_dispatch:
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release --workspace
      - name: write devnet wallet
        run: |
          mkdir -p ~/.config/solana
          echo '${{ secrets.DEVNET_PAYER_KEYPAIR }}' > ~/.config/solana/id.json
      - run: cargo run --release -p tardus-cli -- devnet private-tx-demo --denom 999
```

### Release / publish workflows (Faz 10+)

Mainnet release artifact publishing (signed binaries, deb / rpm
packages, OCI images for validator/relay daemons) is part of the
Faz 10 mainnet ship gate. Not in S2 scope.

## Local CI mirror

To run the same checks locally before pushing:

```bash
# workspace-tests.yml mirror:
cargo build --release --workspace
cargo test --workspace --release
cargo clippy --workspace --all-targets -- -D warnings

# spec-build.yml mirror:
cd spec && make && grep -cE 'Warning|undefined' SPEC.log
# expect 0

# ts-sdk-tests.yml mirror:
cd ts-sdk && npm install && npm run typecheck && npm test

# gui-build.yml mirror:
cargo build --release -p tardus-wallet-gui

# hsm-tests.yml mirror (needs softhsm2 installed):
cargo test --release -p tardus-validator --features hsm \
  --test hsm_pkcs11 -- --ignored --test-threads=1
```
