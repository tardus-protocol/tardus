# Pull Request

## Summary
<!-- What does this PR do? One paragraph max. -->

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (protocol / API / on-chain)
- [ ] Refactor / cleanup
- [ ] Documentation / spec update
- [ ] CI / tooling change
- [ ] Security fix

## Related Issues
<!-- Closes #___ -->

## Component(s) Affected
- [ ] `tardus-core`
- [ ] `tardus-mint`
- [ ] `tardus-client`
- [ ] `tardus-wallet` / `tardus-wallet-gui`
- [ ] `tardus-program` (Solana on-chain)
- [ ] `tardus-relay`
- [ ] `tardus-validator`
- [ ] `tardus-refresh`
- [ ] `tardus-cli`
- [ ] `ts-sdk`
- [ ] `web`
- [ ] `spec` / `paper` / `proofs`
- [ ] CI / deploy

## Testing
- [ ] Existing tests pass (`cargo test --workspace`)
- [ ] New unit tests added
- [ ] Integration tests pass
- [ ] Cross-language compat vectors updated (if crypto change)
- [ ] Manual testing performed — describe: ___

## Protocol / Security Impact
- [ ] No protocol change
- [ ] Protocol change — spec section updated: ___
- [ ] Cryptographic change — EasyCrypt proof updated / review requested
- [ ] Solana program change — requires audit review
- [ ] HSM / key management change

## Checklist
- [ ] Code follows project style (`cargo fmt`, `cargo clippy`)
- [ ] `cargo deny check` passes
- [ ] No new `unsafe` blocks without justification comment
- [ ] CHANGELOG.md updated (for user-visible changes)
- [ ] Documentation updated (rustdoc / README)
- [ ] Relevant reviewers tagged (see CODEOWNERS for who owns each path)

## Notes for Reviewers
<!-- Anything specific reviewers should focus on -->