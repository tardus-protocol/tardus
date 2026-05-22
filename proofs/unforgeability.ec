(* ============================================================
 * TARDUS — Formal Proofs
 * Theorem T1: Unforgeability of Threshold Blind Schnorr Signatures
 * ============================================================
 *
 * Informal statement:
 *   For any PPT adversary A interacting with the threshold mint
 *   in the q-issuance model, the probability that A produces
 *   q+1 valid (coin, signature) pairs is negligible under the
 *   ECDLP hardness assumption in the random oracle model.
 *
 * Reduction:
 *   Following Pointcheval-Stern (Asiacrypt '96) for the
 *   single-signer case, generalized to threshold via
 *   Stinson-Strobl (ACISP 2001) simulator.
 *
 * Status: PLACEHOLDER (Phase 0 signature-only)
 * Full mechanization: Phase 4 (Holloway + external audit)
 * ============================================================
 *)

require import AllCore Distr Real RealExp Group.
require (*--*) ROM.

abstract theory TARDUS_Unforgeability.

  (* Types — concrete instantiation deferred to Phase 4 *)
  type pkey.
  type skey.
  type message.
  type signature.
  type coin = message * signature.

  (* Adversary's view: oracle access to blind issuance *)
  module type BlindOracle = {
    proc issue(blinded_msg : message) : signature
  }.

  (* Existential forgery game (informal):
   *   A makes q queries to the blind issuance oracle,
   *   then must output q+1 valid (message, signature) pairs.
   *)
  module type Adversary = {
    proc forge() : coin list
  }.

  (* Concrete advantage bound to be discharged in Phase 4 *)
  axiom unforgeability_holds : True.

end TARDUS_Unforgeability.

(* ============================================================
 * Phase 4 to-do:
 *   - Concrete oracle definitions matching protocol spec §3
 *   - Adversary game with q-issuance bound
 *   - Reduction proof via Pointcheval-Stern forking lemma
 *   - Threshold simulator from Stinson-Strobl 2001
 *   - Concrete advantage: Adv^{euf-cma}_A ≤ q * Adv^{ECDLP}_B + negl
 * ============================================================
 *)
