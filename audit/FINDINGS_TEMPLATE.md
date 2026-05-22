# TARDUS Audit Finding — `<finding-id>`

Filename: `audit/findings/<finding-id>.md`
(e.g. `audit/findings/TARDUS-001-refresh-early-exit.md`)

License: TARDUS-PROPRIETARY-1.0.

---

## Header

```yaml
id:        TARDUS-NNN-<short-slug>
severity:  Critical | High | Medium | Low | Informational
status:    open | acknowledged | resolved | won't-fix | duplicate
filed-by:  <audit firm engineer name>
filed-at:  YYYY-MM-DDTHH:MM±TZ
target:    spec | code | ops | docs
affects:   <list of files, spec sections, or runbook IDs>
spec-refs: <e.g. §7.3, §9.6 T7, §8 F3c>
```

---

## Summary

One paragraph stating the issue. Audience: a senior engineer
skimming the audit letter who needs to decide whether to read
the rest. Be concrete — name the function, the parameter, the
attack vector.

Example (good): *"The `tardus-refresh` Round 5 handler returns
the validator's blind signature before verifying that the
user-submitted `c_γ` is actually a κ-fold cut-and-choose
challenge response (it only checks length). An adversary who
submits a forged response with matching length receives a free
blind signature on arbitrary coin material, defeating T4."*

Example (bad): *"Refresh has a vulnerability."*

---

## Reproduction

Step-by-step procedure that produces the issue from a fresh
`cargo build --release` workspace. For cryptographic findings,
include a runnable Rust test (filed under
`crates/<affected>/tests/audit_<finding-id>.rs`) and reference
its name here.

```bash
# Example reproduction
cd ~/audit/tardus
cargo test -p tardus-refresh --release -- audit_TARDUS_NNN
# Expected:
#   test audit_TARDUS_NNN_demonstrates_early_exit ... FAILED
```

For HTTP findings, include the exact `curl` invocation and the
unexpected response.

---

## Exploitability

What an adversary gains. Map to the threat-model class in
`audit/THREAT_MODEL.md`:

- Adversary required: <A.NET | A.RELAY | A.VAL.k | A.HSM | A.WALLET | A.SOLANA | A.SUPPLY>
- Pre-conditions: <list>
- Adversary cost: <O(1) | O(n) | O(2^k) for k = ...>
- Resulting capability: <forge coin / extract share / DoS / read
  metadata / etc.>

If exploitability requires multiple adversary classes to chain
(e.g. A.NET + A.WALLET), enumerate the chain.

---

## Root cause

Where in the code or spec does the issue originate, and why.
Distinguish:

- **Spec gap**: the spec doesn't say what the code should do; the
  code's behaviour is unaudited.
- **Spec-code drift**: the spec specifies behaviour X, the code
  implements X' ≠ X.
- **Code bug**: the spec is correct, the code's implementation
  has a logic error in a function or module.
- **Operational bug**: spec + code are correct, but a runbook
  procedure produces an insecure deployment.

---

## Recommended fix

Concrete patch direction. Include:

- File(s) to modify.
- Function or block to change.
- Suggested test that catches the regression.
- Spec update (if the fix changes documented behaviour).
- Migration concern (if existing deployments need re-provisioning).

If multiple fix shapes are plausible, list them with trade-offs.

---

## Project response

(Filled by the project team after acknowledgement.)

- Acknowledged at: `YYYY-MM-DDTHH:MM±TZ`
- Acknowledged by: <project team member>
- Decision: <fix-as-recommended | fix-differently | won't-fix>
- Justification (if won't-fix): <reasoning>
- Fix commit (if resolved): `<git-sha>`
- Spec update (if applicable): `<spec PR / commit>`
- Verified by re-running: <yes / no / N/A>

---

## Disclosure

- Audit-letter inclusion: <yes-public | yes-redacted | no>
- Embargo period (if Critical/High): <days from resolution>
- CVE assignment (if applicable): <CVE-YYYY-NNNN or "not applicable">
- Post-mortem publication (if Critical): <link to write-up>

---

## Cross-references

- Related findings: <list>
- Linked spec section: §<N>
- Linked PR (project team): <link>
