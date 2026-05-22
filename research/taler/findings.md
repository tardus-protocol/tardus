# GNU Taler — Production Findings and TARDUS Implications

_Research date: 2026-05-20. Sources in footnotes._

## 1. System status

Taler has been live since 2014. There were informal contacts with the ECB, but **the digital euro did not select Taler** — the ECB's October 2025 closing report does not mention Taler at all. The ECB chose a centralized ledger + secure element (eSE/eSIM) approach, with privacy delivered via _segregated processing_ rather than cryptographic primitives.

Lesson: Taler's cryptographic superiority was insufficient at the institutional level; a system that wants to ship must also be _operationally_ mature. TARDUS closes that gap by parasitizing Solana's institutional plumbing + on-chain auditability.

## 2. Refresh protocol — Taler's beating heart (DD-62)

The solution to a problem Cashu does not solve.

**Mechanism:** κ-fold cut-and-choose (κ=3 by default):

1. **Commitment:** The client produces κ sets of blinded coin planchets `m[i][j]` derived from nonces `r_1...r_κ`.
2. **Challenge:** The exchange (mint) picks γ ∈ [1, κ] uniformly at random.
3. **Reveal:** The client opens all κ-1 signatures except the γ-th one — the exchange verifies honesty without learning the _fresh coin secret_.

**How unlinkability is preserved:**
- The master seed `r` is _public_ and acts as a commitment.
- The actual secret is `s = SignUnique(cs, t)` where `t = Hash1a("Refresh", Cp, r)`, disclosed only in the reveal phase.
- The fresh coin secret is `x = Hash1b(s)` — no one but the owner can link.

**Primitives used:**
- Hash functions (`Hash1a`, `Hash1b`, `Hash2`)
- Unique signatures (`SignUnique(cs, t)`)
- Blind signatures (`Blind(C2_p, b, pkD)`)
- `KeyGen(x)` — derived material → keypair

**Critical contrast with Cashu:** Taler uses **non-deterministic, signature-based derivation**. Cashu's NUT-13 deterministic-seed approach allowed the 31-bit residue collision — in Taler this is impossible because the secret is derived from the _signature_, not the seed.

**PQ property:** No DH operations in refresh derivation. No quantum-vulnerable computational hardness assumption, only hash-collision resistance.

## 3. Exchange operational security model (taler-exchange-manual)

In Taler's production deployment, the key architecture has three tiers:

**Tier 1 — Offline master signing key:**
- A long-term root key on an air-gapped system.
- Authenticates the exchange's identity, bank account, and online keys.
- Manual usage.

**Tier 2 — Online signing helpers:**
- `taler-exchange-secmod-rsa`, `taler-exchange-secmod-cs`, `taler-exchange-secmod-eddsa`.
- Separate UNIX users with restricted permissions.
- Communicate with the HTTP daemon via UNIX domain sockets (mode 0620).
- The HTTP daemon requests signatures; it cannot directly access the keys.

**Tier 3 — HTTP daemon:**
- The public web service.
- If compromised, keys are not exposed; only the ability to generate signatures while the attacker holds control.

**Key rotation:**
- `DURATION_WITHDRAW`, `DURATION_SPEND` limits per denomination.
- `LOOKAHEAD_SIGN` generates at least one year of future keys.
- Offline signing in six-month cycles.
- `OVERLAP_DURATION` for the transition window.

**Compromise response:**
- `taler-exchange-offline revoke-denomination` revokes a denomination.
- The `/recoup` API → wallets return unspent coins.
- Single-operator security scope.

**Gap: no HSM support.** The manual explicitly states: _"does not yet support the use of a hardware security module."_ Operators interested in HSM integration are invited to contact the developers. **TARDUS already filled this gap in round 4 with the FIPS L3 HSM requirement.**

## 4. Auditor role — Taler's proof-of-liabilities answer

Taler's audit mechanism:
- An external auditor receives an up-to-date copy of the exchange database.
- Verifies signatures, totals amounts, and alerts on inconsistency.
- Computes expected bank balance, revenue, and risk exposure.

**Limitation:** Single auditor. Not threshold. Auditor compromise → all guarantees gone. Auditor offline → fraud detection delayed.

**TARDUS contrast:** The on-chain Solana vault is a system in which _anyone can be an auditor_. The vault collateral is public state, the issued-commitment set is public state, and the equality between the two is verified on-chain mathematically. This is a structural improvement on Taler's single-auditor model.

## 5. Income transparency — Dold's unique contribution

Dold's thesis (2019, Université de Rennes):
- The refresh protocol makes _customer spending anonymous_ but _merchant income visible_.
- "The merchant can receive a payment from an untrusted payer reliably _only when_ their income is visible to the tax authority."
- Asymmetric privacy — closes the tax-evasion loophole.
- The refresh protocol is also used for "Camenisch-style atomic swaps" and "anonymity in the presence of protocol aborts."

**TARDUS implication:** Income transparency is not in v1 but is _attractive for v2_. For regulatory acceptance, Taler's asymmetric design (parallel to Stadler-Piveteau-Camenisch 1995 fair blind signatures) is a guiding pattern.

## 6. ECB digital euro pilot — _not Taler_, but parallel lessons

The ECB closing report (October 2025), in context for TARDUS:

- **Centralized ledger:** The ECB did not pick threshold; only "geographical distribution across multiple independent sites" — not distributed validation logic.
- **Privacy mechanism:** Architectural segregation, not a cryptographic primitive.
- **Offline payments:** Secure elements (eSE/eSIM), _not_ a Cashu/Taler-style bearer instrument.
- **Governance overhead:** The rulebook development gathered 2,000+ comments, with multi-stakeholder delay slowing the system.

**Takeaway:** Institutional/regulatory sides are not persuaded by _cryptographic superiority_ alone. Shipping requires maturity in operations + governance + ecosystem together. TARDUS's parasitization of Solana plays in our favor here — the institutional incentive is already there.

## 7. TARDUS implications (each finding → spec action)

| Taler finding | TARDUS spec action | Spec section |
|---|---|---|
| κ-fold cut-and-choose refresh | **TARDUS refresh = κ=3 cut-and-choose**, not deterministic seed | Protocol.Refresh |
| Signature-based key derivation | **Fresh coin secret = unique-signature based**, no BIP32/HKDF | Crypto.Derivation |
| Refresh enables partial spend + change | **Denomination split/merge via refresh** in TARDUS — stronger than a Cashu swap | Protocol.Swap |
| Three-tier key arch (offline master + helpers) | **Same compartmentalization plus threshold N=30, t=14** | Mint.KeyArchitecture |
| No HSM (Taler gap) | **FIPS L3 HSM mandatory in TARDUS** (round 4 R3) | Mint.HardwareReqs |
| Offline master key rotation | **Proactive secret-sharing rotation, epoch=1 day** | Mint.Rotation |
| `/recoup` API for revoke | **TARDUS denomination revoke = on-chain TX with threshold signature** | Protocol.Revoke |
| Single-auditor weakness | **On-chain Solana vault = anyone-as-auditor**, threshold collusion the structural answer | OnChain.Audit |
| Income transparency (asymmetric privacy) | **v2 consideration**; the Stadler-Piveteau-Camenisch 1995 line remains open | Protocol.v2.Compliance |
| Refresh protocol PQ-resistant derivation | **PQ migration in Phase 2-3**, Zhou's lattice-blind line | Protocol.PostQuantum |
| ECB-style institutional drag | **Production-ready spec + reference implementation in Phase 0-2** | Project.Roadmap |

## 8. Open questions

- κ=3 for TARDUS refresh, or higher? κ=3 is standard, but interactive rounds grow with the threshold mint; the optimization is open.
- Is income transparency in v2 _optional_ or _mandatory_? Regulatory pressure decides.
- The auditor role is fully on-chain, so how do we mirror Taler's "expected bank balance" bookkeeping? — via the `vault_collateral == sum(commitments)` constraint.
- Taler pre-generates keysets with `LOOKAHEAD_SIGN`; how does TARDUS do this in the threshold setting? Does the committee perform DKG several epochs in advance?

## Sources

1. Taler DD-62 PQ Refresh Protocol: <https://docs.taler.net/design-documents/062-pq-refresh.html>
2. Taler Exchange Operator Manual: <https://docs.taler.net/taler-exchange-manual.html>
3. Florian Dold (2019), "The GNU Taler system: practical and provably secure electronic payments", Université de Rennes: <https://theses.hal.science/tel-02138082v1/file/DOLD_Florian.pdf>
4. Schnorr's Blind Signature in Taler: <https://www.taler.net/papers/cs-thesis.pdf>
5. ECB Digital Euro Preparation Phase Closing Report (Oct 2025): <https://www.ecb.europa.eu/euro/digital_euro/progress/html/ecb.deprp202510.en.html>
6. Taler Refresh API: <https://docs.taler.net/core/api-exchange.html>
