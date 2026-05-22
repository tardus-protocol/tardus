(* ============================================================
   TARDUS  —  T1: Coin Unforgeability
   Spec §7.3, §2.4 (Schnorr on Curve25519), §3 (threshold mint)

   Theorem: For any PPT adversary A having ROM-query access to
   H and signing-oracle access to the threshold mint (with at
   most t-1 corrupted shares), the probability A produces a
   forged (m, sigma) pair such that Schnorr_Verify(joint_pk, m,
   sigma) = 1 and m was never queried to the signing oracle is
   bounded by:

     Adv^{euf-cma}_{TARDUS-mint}(A) ≤ q_H · Adv^{ECDLP}_{Curve25519}(B)
                                       + q_S / |Group|
                                       + negl(λ).

   The reduction B uses A's forging signature to extract a
   discrete log via the standard Pointcheval-Stern forking
   lemma.

   License: TARDUS-PROPRIETARY-1.0.
   ============================================================ *)

require import AllCore List Int Distr DBool.
require import FSet SmtMap.
require (*--*) DiffieHellman ROM.

(* ---------- Group theory: Curve25519 prime-order subgroup ---------- *)

type group.
type exp.

op g : group.                        (* generator *)
op ( * ) : group -> group -> group.  (* group op *)
op ( ^ ) : group -> exp -> group.    (* scalar mul *)
op order : int.                      (* group order ℓ *)

axiom group_order_prime : prime order.
axiom scalar_mul_unit  : forall g, g ^ 0 = g.
axiom group_inversion  : forall g x, (g ^ x) ^ (-1) = g ^ (-x).

(* ---------- Random oracle H : (group * msg) → exp ---------- *)

type msg.

clone import ROM as HashOracle with
  type from <- group * msg,
  type to   <- exp.

(* ---------- Schnorr scheme ---------- *)

module SchnorrSig = {
  proc keygen() : exp * group = {
    var sk : exp;
    sk <$ duniform exp;     (* uniform secret *)
    return (sk, g ^ sk);
  }

  proc sign(sk : exp, m : msg) : group * exp = {
    var k, R, c, s;
    k <$ duniform exp;
    R <- g ^ k;
    c <@ HashOracle.o(R, m);
    s <- k + c * sk;
    return (R, s);
  }

  proc verify(pk : group, m : msg, sig : group * exp) : bool = {
    var R, s, c;
    (R, s) <- sig;
    c <@ HashOracle.o(R, m);
    return (g ^ s = R * pk ^ c);
  }
}.

(* ---------- EUF-CMA game ---------- *)

module type EUF_Adv = {
  proc forge(pk : group) : msg * (group * exp)
}.

module EUF_CMA (A : EUF_Adv) = {
  var queried : msg fset

  proc sign(m : msg, sk : exp) : group * exp = {
    var sig;
    queried <- queried `|` fset1 m;
    sig <@ SchnorrSig.sign(sk, m);
    return sig;
  }

  proc main() : bool = {
    var sk, pk, m, sig, ok;
    HashOracle.init();
    queried <- fset0;
    (sk, pk) <@ SchnorrSig.keygen();
    (m, sig) <@ A.forge(pk);
    ok <@ SchnorrSig.verify(pk, m, sig);
    return ok /\ ! m \in queried;
  }
}.

(* ---------- ECDLP game ---------- *)

module type ECDLP_Adv = {
  proc solve(g : group, h : group) : exp
}.

module ECDLP_Game (B : ECDLP_Adv) = {
  proc main() : bool = {
    var x, h, x';
    x  <$ duniform exp;
    h  <- g ^ x;
    x' <@ B.solve(g, h);
    return x = x';
  }
}.

(* ---------- T1 reduction (Pointcheval-Stern forking) ---------- *)

(* The reduction B simulates A's signing oracle by programming the
   random oracle (chosen-c-then-find-R technique). On A producing a
   forgery, B rewinds and reruns A with the same coins but a fresh
   H response at the forking index; the two transcripts let B
   extract the discrete log. *)

module Reduction (A : EUF_Adv) : ECDLP_Adv = {
  proc solve(g : group, h : group) : exp = {
    var sk_extracted;
    (* TODO Phase 4: full Pointcheval-Stern forking lemma application. *)
    sk_extracted <$ duniform exp;
    return sk_extracted;
  }
}.

lemma T1_unforgeability &m (A <: EUF_Adv) :
    `| Pr[EUF_CMA(A).main() @ &m : res]
       - Pr[ECDLP_Game(Reduction(A)).main() @ &m : res] |
    <= 0%r.   (* placeholder; actual bound is q_H/order + collision-style epsilon *)
proof.
  admit.   (* Phase 4 — formal methods consultant fills in:
              - forking lemma over H queries (q_H factor)
              - signing oracle simulation via programmed H
              - extraction algebra (Schnorr signature linearity in c).  *)
qed.

(* ---------- T1 corollary (threshold mint) ---------- *)

(* The threshold mint's joint signature is computationally
   indistinguishable from a single-party Schnorr signature under
   the same joint_pk; the previous lemma therefore extends to the
   threshold setting under the additional assumption that fewer
   than t shares are corrupted. *)

lemma T1_threshold &m (A <: EUF_Adv) (t n : int) :
    1 < t /\ t <= n =>
    `| Pr[EUF_CMA(A).main() @ &m : res]
       - Pr[ECDLP_Game(Reduction(A)).main() @ &m : res] |
    <= 0%r.   (* same placeholder *)
proof.
  admit.   (* Phase 4 — combine T1 with threshold-simulator argument. *)
qed.
