# Tardus

**Privacy-preserving digital cash on Solana.**

Tardus is an open-source, threshold blind-signature e-cash protocol built on Solana. It enables private, unlinkable payments while leveraging Solana's on-chain double-spend prevention.

---

## What We Build

| Repository | Visibility | Description |
|------------|-----------|-------------|
| [`tardus`](https://github.com/tardus-protocol/tardus) | 🌐 Public | Core protocol, Rust crates, TypeScript SDK, web frontend, formal spec & proofs |
| `tardus-infra` | 🔒 Private | Deployment runbooks, HSM configuration, operator guides |
| `tardus-audit` | 🔒 Private | Security audit findings (public after audit completion) |

---

## Protocol Properties

- **Blindness** — the mint cannot link a token to its issuance request
- **Unforgeability** — tokens cannot be created without mint participation
- **Double-spend prevention** — enforced on-chain via Solana program
- **Threshold security** — DKG/VSS: no single node holds the full signing key
- **Formal proofs** — EasyCrypt machine-checked proofs for core security properties

---

## Repository Structure (`tardus`)

```
crates/
├── tardus-core/        # Blind Schnorr, VSS, DKG primitives
├── tardus-mint/        # Threshold mint protocol & key rotation
├── tardus-client/      # Client library
├── tardus-wallet/      # Wallet logic
├── tardus-wallet-gui/  # Desktop wallet (GUI)
├── tardus-program/     # Solana on-chain program
├── tardus-relay/       # Relay server
├── tardus-validator/   # Validator node
├── tardus-refresh/     # Token refresh protocol
└── tardus-cli/         # Command-line interface
ts-sdk/                 # TypeScript SDK
web/                    # Web frontend
spec/                   # Protocol specification (LaTeX + EasyCrypt)
paper/                  # Academic paper
proofs/                 # EasyCrypt formal proofs
audit/                  # Security audit documentation
```

---

## Expert Review Teams

We actively seek review from specialists in:

- **Cryptography & Formal Verification** — blind signatures, VSS/DKG, EasyCrypt proofs
- **Solana Program Security** — on-chain program audit (Neodyme, OtterSec, Sec3)
- **Rust Security** — memory safety, supply chain (cargo-audit, cargo-deny)
- **HSM & Key Management** — hardware security module integration
- **TypeScript / Web Security** — client-side cryptography, XSS, CSP

If you have expertise in any of these areas and want to contribute, open a [Cryptographic Review Request](https://github.com/tardus-protocol/tardus/issues/new?template=crypto_review.md) or email `security@tardus.dev`.

---

## Security

Found a vulnerability? **Do not open a public issue.**
See [`SECURITY.md`](https://github.com/tardus-protocol/tardus/blob/main/SECURITY.md) for responsible disclosure.

---

## License

[MIT](https://github.com/tardus-protocol/tardus/blob/main/LICENSE) — Tardus Organization