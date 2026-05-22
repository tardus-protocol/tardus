# Cashu — Production Findings and TARDUS Implications

_Research date: 2026-05-20. Sources in footnotes._

## 1. Incident map

To date there are **no documented operator-level fund-theft incidents** for Cashu. The risk remains theoretical and protocol-level. This is an important nuance — Cashu's custodial risk is "rug-pull expected," not "rug-pull occurred." TARDUS resolves this structurally via the threshold mint + on-chain vault transparency described in our architecture.

Documented protocol-level incidents:

### 1.1 NUT-13 Keyset Collision (July 2025, conduition.io disclosure)

**Affected:** Minibits, Cashu.me, Nutstash wallets.

**Mechanism:**
1. The attacker deliberately crafts a keyset whose 31-bit keyset-ID residue collides with the target mint's.
2. The attacker airdrops tokens from their own mint.
3. The victim wallet automatically swaps the airdropped proofs and derives _identical_ blinding factors and preimages (because NUT-13's BIP32 derivation is reduced to a 31-bit residue).
4. The attacker queries the target mint's `/v1/restore` endpoint (NUT-09) and recovers the victim's prior blind signatures.
5. The attacker multiplies the recovered signatures by their own secret scalar and returns them to the victim.
6. The victim unblinds → seemingly valid proofs are produced, but the attacker can spend them too.
7. When the victim spends, the attacker presents the proofs to the target mint and collects the money.

**Root cause:** In NUT-13, `keyset_id_int = parse_int(keyset_id_hex, base=16) % (2**31 - 1)` — a 31-bit residue for the BIP32 path index. Within ~2 billion possibilities, a collision can be brute-forced on commodity CPU in hours.

**Long-term fix:** Replace BIP32 with a single-shot HMAC-SHA512:
```
hash = hmac_sha512(seed, keyset_id || counter.to_bytes())
x = hash[:32]; r = hash[32:]
```
Transition to a 256-bit keyset ID v2 + cryptographic compartmentalization per keyset.

**Short-term fix:** Wallet-side detection of 31-bit collisions across all keyset IDs (active and inactive) with explicit trusted-mint confirmation from the user.

### 1.2 NUT-02 Keyset-ID Validation Missing

The Cashu spec (NUT-02) requires keyset IDs to be derived from a hash of the keyset, **yet no Cashu client actually validated this**. Mints could pick whatever keyset ID they wanted. This was the precondition for the NUT-13 attack.

### 1.3 Nutshell HTLC Preimage DoS

The Nutshell mint implementation validated HTLC preimages without checking the spec-required 32-byte size, opening a DoS bug. Calle disclosed it, a fast patch followed. Low blast radius but a discipline lesson.

## 2. Officially acknowledged risks (docs.cashu.space/faq)

- "Funds might be lost forever due to bugs" — explicit early-stage warning.
- Wiping browser local storage → fund loss.
- Mint operator trust is mandatory.
- **Rug-pull scenarios are not addressed in the FAQ at all** — a telling gap, which TARDUS's on-chain vault answers directly.

## 3. Structural gaps

- **No proof-of-liabilities:** Mint reserves cannot be verified. A Cashu user cannot compare the total ecash issued by a mint against the BTC it has backing it.
- **Slow-rug risk:** Custody key and ecash-signing key live in the same hands → the mint can mint unbacked ecash indefinitely and then exit.
- **Identity opacity:** Mint operators are pseudonymous, with no recourse.

## 4. TARDUS implications (each finding → spec action)

| Cashu finding | TARDUS spec action | Spec section |
|---|---|---|
| 31-bit residue collision (BIP32) | **Use one-shot HMAC-SHA512 derivation, 256-bit keyset ID from v1**; do not use BIP32 anywhere | Crypto.Derivation |
| NUT-02 validation missing | **Client MUST recompute keyset ID**, reject on mismatch | Client.Validation |
| No keyset-collision detection | **Global uniqueness constraint across all keyset IDs** (active + inactive), enforced on-chain in the threshold-mint registry | OnChain.KeysetRegistry |
| Restore endpoint as deanonymization vector | **Restore protocol revisited in round 4**; threshold-mint setting changes the collusion model | Mint.Recovery |
| Mint single point of failure | **N=30, t=14 threshold + FIPS L3 HSM + proactive rotation** — the structural answer to Cashu's single-operator model | Mint.Threshold |
| No proof-of-liabilities | **On-chain Solana vault**: collateral = sum of issued commitments, verifiable by anyone | OnChain.Vault |
| Slow-rug | Impossible under threshold-collusion < t + on-chain audit | Security.SlowRug |
| Local-storage wipe | **Mandatory encrypted seed-based backup (cloud + local)** at onboarding | Wallet.Backup |
| Rug-pull discourse gap | TARDUS spec includes an **explicit failure-mode section**: what, when, what to do | Security.FailureModes |

## 5. Open questions

- Does TARDUS's restore protocol reproduce Cashu's NUT-09 attack vector? Under threshold signatures, the mechanism must be re-examined.
- Does HTLC support (Cashu NUT-14) enter TARDUS? Not needed in v1, but composability discussion will surface it.
- Cashu wallets derive secrets deterministically from a seed — restore is possible, but it created the collision surface. Does TARDUS bear the same trade-off, or does it use a pure random nonce + backup?

## Sources

1. Conduition (Jan 2026), "Vulnerabilities in the Cashu ECash Protocol": <https://conduition.io/code/cashu-disclosure/>
2. Cashu FAQ: <https://docs.cashu.space/faq>
3. NUT-02 spec: <https://cashubtc.github.io/nuts/02/>
4. NUT-12 DLEQ spec: <https://cashubtc.github.io/nuts/12/>
5. Calle (callebtc) Nutshell DoS post-mortem: <https://x.com/callebtc/status/1986749416338837630>
6. Cashu vision article: <https://bitcoinmagazine.com/technical/cashu-a-vision-for-a-bitcoin-powered-ecash-ecosystem>
