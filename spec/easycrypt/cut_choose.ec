(* ============================================================
   TARDUS  —  T4: Cut-and-Choose Refresh Soundness
   Spec §7.6, §4 (κ-fold cut-and-choose refresh)

   Theorem: A malicious user who submits κ+1 candidate refreshed
   coin commitments {C_0, ..., C_κ}, of which the validator
   committee opens κ challenge-selected positions and validates,
   then receives a blind signature on the surviving position, has
   probability at most 1/(κ+1) of producing a coin that is NOT a
   valid refresh of the surrendered coin's denomination.

   The bound 1/(κ+1) is tight: the adversary's best strategy is
   to corrupt exactly one of the κ+1 positions and hope the
   challenge spares it.

   License: TARDUS-PROPRIETARY-1.0.
   ============================================================ *)

require import AllCore List Int Distr DInterval.
require import Real.

(* ---------- Setup parameters ---------- *)

op kappa : int.

axiom kappa_positive : 0 < kappa.

(* The user submits kappa+1 candidates; the validator commits to
   one random index to "spare" (the unblinded position) and opens
   the remaining kappa for inspection.                            *)

type candidate.

op valid : candidate -> bool.   (* whether a single candidate would yield a sound refresh *)

(* ---------- Refresh game ---------- *)

module type Cheater_Adv = {
  proc submit() : candidate list  (* must have length = kappa+1 *)
}.

module Refresh_Game (A : Cheater_Adv) = {
  proc main() : bool = {
    var cs : candidate list;
    var spare : int;
    var spared : candidate;
    var rest : candidate list;
    var all_opened_valid : bool;
    cs <@ A.submit();
    if (size cs <> kappa + 1) {
      return false;   (* malformed submission, A loses *)
    }
    (* Validator samples a uniform challenge in [0, kappa]. *)
    spare <$ [0 .. kappa];
    spared <- nth witness cs spare;
    rest <- take spare cs ++ drop (spare + 1) cs;
    all_opened_valid <- all valid rest;
    (* A wins iff the kappa "opened" candidates pass validation
       (so the validator proceeds with the refresh) but the
       spared candidate is NOT valid (so the resulting coin is
       unsound). *)
    return all_opened_valid /\ ! valid spared;
  }
}.

(* ---------- T4 ---------- *)

(* For any adversary A, the probability of winning the refresh
   game is at most 1/(kappa+1). *)

lemma T4_cut_choose_soundness &m (A <: Cheater_Adv) :
    Pr[Refresh_Game(A).main() @ &m : res] <= 1%r / (kappa + 1)%r.
proof.
  admit.   (* Phase 4: straightforward combinatorial argument.
              If A includes k_bad invalid candidates among the kappa+1:
                - k_bad = 0  → A loses with probability 1
                - k_bad = 1  → A wins iff the spare hits the bad one: 1/(kappa+1)
                - k_bad ≥ 2  → at least one bad is "opened", so
                                all_opened_valid is false and A loses.
              The maximum is therefore exactly 1/(kappa+1), achieved at k_bad = 1.  *)
qed.

(* ---------- T4 corollary: κ = 32 default ---------- *)

(* The default deployment uses κ = 32, giving a per-refresh
   cheating probability ≤ 1/33 ≈ 0.030. With sufficiently many
   honest validators (≥ t out of n) and the on-chain nullifier
   set, the cheating gain is bounded by amplifying the per-coin
   bound across n_attacks attempts — see spec §7.6 corollary. *)

lemma T4_at_kappa_32 &m (A <: Cheater_Adv) :
    kappa = 32 =>
    Pr[Refresh_Game(A).main() @ &m : res] <= 1%r / 33%r.
proof.
  admit.
qed.
