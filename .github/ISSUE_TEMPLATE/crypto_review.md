---
name: Cryptographic Review Request
about: Request a review of a cryptographic design, proof, or protocol change
title: "[CRYPTO] "
labels: ["cryptography", "needs-expert-review"]
assignees: []
---

## Summary
<!-- What cryptographic component or protocol change needs review? -->

## Affected Files
<!-- List the relevant files: proofs/*.ec, spec/sections/*.tex, crates/tardus-core/, etc. -->

## Security Claim / Property
<!-- What security property is being claimed or changed?
     e.g. blindness, unforgeability, double-spend prevention, state integrity -->

## Formal Proof Status
- [ ] No formal proof yet
- [ ] EasyCrypt proof draft (see `proofs/` or `spec/easycrypt/`)
- [ ] EasyCrypt proof complete
- [ ] Proof needs update due to this change

## Review Checklist
- [ ] Blind signature scheme correctness
- [ ] VSS / DKG security assumptions
- [ ] Schnorr signature soundness
- [ ] Key rotation security
- [ ] Cross-language (Rust ↔ TypeScript) compatibility vectors

## References
<!-- Links to relevant papers, IACR ePrint, prior art, or related issues -->

## Suggested Reviewers
<!-- Tag the GitHub usernames of anyone you'd like to review this -->
- @nzengi
