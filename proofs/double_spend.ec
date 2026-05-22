(* ============================================================
 * TARDUS — Formal Proofs
 * Theorem T3: Double-Spend Detection Soundness
 * ============================================================
 *
 * Informal statement:
 *   Any attempt to submit two valid (proof, signature) pairs
 *   referencing the same serial number to the on-chain nullifier
 *   set will be rejected with probability 1 by an honest verifier
 *   following the protocol.
 *
 * Underlying argument:
 *   Nullifier insertion is atomic and uniqueness-checked at the
 *   Light Protocol compressed tree level. Re-presentation triggers
 *   a deterministic rejection at the on-chain program boundary.
 *
 * Status: PLACEHOLDER (Phase 0 signature-only)
 * Full mechanization: Phase 4
 * ============================================================
 *)

require import AllCore.

abstract theory TARDUS_DoubleSpend.

  type serial.
  type proof.
  type signature.
  type spend = serial * proof * signature.

  (* On-chain nullifier set state *)
  type nullifier_set.

  (* Verifier operation *)
  op verify_spend : nullifier_set -> spend -> bool.

  (* After accepting a spend, the serial is committed *)
  op insert_nullifier : nullifier_set -> serial -> nullifier_set.

  (* Soundness: a serial cannot be accepted twice *)
  axiom no_double_spend :
    forall (s : serial) (p1 p2 : proof) (sig1 sig2 : signature) (ns : nullifier_set),
      verify_spend ns (s, p1, sig1) =>
      ! verify_spend (insert_nullifier ns s) (s, p2, sig2).

  axiom double_spend_holds : True.

end TARDUS_DoubleSpend.

(* ============================================================
 * Phase 4 to-do:
 *   - Formalize Light Protocol compressed tree as nullifier_set
 *   - State insert_nullifier semantics with uniqueness invariant
 *   - Prove no_double_spend by structural induction on tree state
 *   - Handle concurrent insertion (forester batching)
 * ============================================================
 *)
