# TARDUS EasyCrypt mechanization skeleton

EasyCrypt 2024.x proof-file skeletons for the security theorems of
`spec/SPEC.pdf` §7 + §9.

License: TARDUS-PROPRIETARY-1.0.

## Status

These are **proof skeletons** (theory + module + lemma signatures,
proof bodies marked `admit`). Filling in the proof tactics requires
an EasyCrypt expert; the skeletons exist so a Phase 4 auditor or
formal methods consultant can step in without re-deriving the
protocol structure.

## File map

| File | Theorem | Spec source |
|---|---|---|
| `schnorr.ec` | T1 — Coin Unforgeability (EUF-CMA / ECDLP + ROM) | §7.3 |
| `blind.ec` | T2 — Issuance Blindness (info-theoretic) | §7.4 |
| `cut_choose.ec` | T4 — Cut-and-Choose Soundness, bound $1/(\kappa+1)$ | §7.6 |
| `sealed_box.ec` | T7 — Sealed-box Payload Confidentiality (IND-CCA + ECDLP) | §9.6 |

Not mechanized in this phase:
- T3 (Double-Spend Prevention) — argued at the on-chain nullifier-set
  layer; the proof is a state-machine invariant, more naturally
  modelled in TLA+ or Coq rather than EasyCrypt.
- T5 (Reshare Correctness) — algebraic identity over polynomial shares;
  proof is one paragraph of arithmetic, mechanization would not change
  conviction.
- T6 (Vault Collateral Invariant) — on-chain accounting invariant,
  same class as T3.

## Layout

```
spec/easycrypt/
├── README.md            this file
├── schnorr.ec           T1 — EUF-CMA reduction to ECDLP
├── blind.ec             T2 — issuance blindness (perfect)
├── cut_choose.ec        T4 — κ-fold cut-and-choose soundness
└── sealed_box.ec        T7 — sealed-box AEAD IND-CCA
```

## Build prerequisites

EasyCrypt installation per
<https://github.com/EasyCrypt/easycrypt> is required to type-check
these files:

```
opam install easycrypt
easycrypt config --check
```

Type-check the skeletons (admits are accepted; the goal here is
syntactic validity + reduction structure):

```
cd spec/easycrypt/
easycrypt schnorr.ec
easycrypt blind.ec
easycrypt cut_choose.ec
easycrypt sealed_box.ec
```

A non-zero exit code means the skeleton has drifted from the spec
or has a syntax error — file an issue.

## Phase 4 work

A formal methods consultant takes these skeletons, replaces each
`admit` with a real proof using EasyCrypt tactics (`smt`, `auto`,
`call`, `wp`, `rnd`, `byequiv`, `byphoare`, etc.), then submits
the verified proofs + an audit letter referencing the EC build
hash.

The proof obligation is "show that the reductions in the spec
hold to within the indicated negligible bounds, given the
explicitly stated assumptions". The skeletons fix the reductions'
shape; the consultant fills in the algebraic work.
