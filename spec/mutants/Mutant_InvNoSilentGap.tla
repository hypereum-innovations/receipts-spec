------------------------- MODULE Mutant_InvNoSilentGap -------------------------
(*
 * Formal TLA+ Specification of the Hivemind Agent Action Receipts Protocol
 * (`urn:hivemind:receipts:capsule:1` over IETF SCITT + RFC 9162 + C2SP
 * tlog-checkpoint / tlog-cosignature).
 *
 * Models capsule issuance, COSE_Sign1 statement signing, transparency log
 * registration, checkpoint publication, witness cosigning (Byzantine quorum
 * intersection), offline Class-1 bundle verification, and Byzantine/adversarial
 * fault injection (split-view equivocation, unsigned statement injection,
 * unanchored "anchored" claims, and unobserved "confirmed" effects).
 *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
  CapsuleIds,        \* Finite set of candidate capsule identifiers
  Witnesses,         \* Set of all configured witnesses
  HonestWitnesses,   \* Subset of Witnesses that never equivocate on same treeSize
  WitnessQuorum      \* Required cosignature quorum satisfying Byzantine intersection

ASSUME
  /\ HonestWitnesses \subseteq Witnesses
  /\ WitnessQuorum \in 1..Cardinality(Witnesses)
  \* Quorum intersection: any two quorums of size WitnessQuorum intersect in
  \* at least one honest witness, preventing split-view equivocation.
  /\ (2 * WitnessQuorum - Cardinality(Witnesses)) > (Cardinality(Witnesses) - Cardinality(HonestWitnesses))

Verdicts == {"executed", "blocked", "denied", "errored", "engine_failure", "timed_out"}
EffectStatuses == {"confirmed", "asserted", "none"}
LedgerModes == {"standalone", "chained", "anchored"}
Roots == {"root_A", "root_B"}
TreeSizes == 1..Cardinality(CapsuleIds)

VARIABLES
  capsules,          \* Set of issued capsule records
  statements,        \* Set of signed/unsigned statement envelopes
  logEntries,        \* Set of [cid: CapsuleIds, treeSize: Nat, root: Roots]
  checkpoints,       \* Set of published checkpoints [treeSize: Nat, root: Roots, logSigned: BOOLEAN]
  witnessCosigs,     \* Set of [witness: Witnesses, treeSize: Nat, root: Roots]
  verifiedBundles    \* Set of bundles accepted by the Class-1 offline verifier

vars == <<capsules, statements, logEntries, checkpoints, witnessCosigs, verifiedBundles>>

-----------------------------------------------------------------------------
(* Well-formedness predicate enforced at capsule construction & parsing *)
ValidCapsuleSemantics(verdict, effectStatus, hasRespDigest) ==
  /\ (effectStatus = "confirmed") => (verdict = "executed" /\ hasRespDigest = TRUE)
  /\ (verdict /= "executed") => (effectStatus /= "confirmed")

Init ==
  /\ capsules = {}
  /\ statements = {}
  /\ logEntries = {}
  /\ checkpoints = {}
  /\ witnessCosigs = {}
  /\ verifiedBundles = {}

-----------------------------------------------------------------------------
(* Action 1: Issue a well-formed Agent Action Capsule and sign statement *)
IssueCapsule(cid, verdict, effectStatus, hasRespDigest, ledgerMode, signedOk) ==
  /\ ~(\E c \in capsules : c.cid = cid)
  /\ ValidCapsuleSemantics(verdict, effectStatus, hasRespDigest)
  /\ LET cap == [
       cid |-> cid,
       verdict |-> verdict,
       effectStatus |-> effectStatus,
       hasRespDigest |-> hasRespDigest,
       ledgerMode |-> ledgerMode
     ] IN
     /\ capsules' = capsules \cup {cap}
     /\ statements' = statements \cup {[cid |-> cid, signedByTrustedIssuer |-> signedOk]}
     /\ UNCHANGED <<logEntries, checkpoints, witnessCosigs, verifiedBundles>>

(* Action 2: Transparency log registration policy (admits only validly signed statements) *)
AppendToLog(cid, treeSize, root) ==
  /\ \E s \in statements : s.cid = cid \* MUTANT: removed /\ s.signedByTrustedIssuer = TRUE
  /\ logEntries' = logEntries \cup {[cid |-> cid, treeSize |-> treeSize, root |-> root]}
  /\ checkpoints' = checkpoints \cup {[treeSize |-> treeSize, root |-> root, logSigned |-> TRUE]}
  /\ UNCHANGED <<capsules, statements, witnessCosigs, verifiedBundles>>

(* Action 3: Adversary / compromised log publishes a conflicting checkpoint (split-view attempt) *)
AdversaryPublishConflictingCheckpoint(treeSize, root) ==
  /\ checkpoints' = checkpoints \cup {[treeSize |-> treeSize, root |-> root, logSigned |-> TRUE]}
  /\ UNCHANGED <<capsules, statements, logEntries, witnessCosigs, verifiedBundles>>

(* Action 4: Witness cosigns a checkpoint. Honest witnesses refuse to cosign two different roots at same treeSize. *)
WitnessCosign(w, treeSize, root) ==
  /\ \E cp \in checkpoints : cp.treeSize = treeSize /\ cp.root = root /\ cp.logSigned = TRUE
  /\ (w \in HonestWitnesses) =>
       ~(\E cs \in witnessCosigs : cs.witness = w /\ cs.treeSize = treeSize /\ cs.root /= root)
  /\ witnessCosigs' = witnessCosigs \cup {[witness |-> w, treeSize |-> treeSize, root |-> root]}
  /\ UNCHANGED <<capsules, statements, logEntries, checkpoints, verifiedBundles>>

(* Helper: Witness set that cosigned (treeSize, root) *)
CosignersFor(treeSize, root) ==
  {w \in Witnesses : [witness |-> w, treeSize |-> treeSize, root |-> root] \in witnessCosigs}

QuorumReached(treeSize, root) ==
  Cardinality(CosignersFor(treeSize, root)) >= WitnessQuorum

(* Action 5: Offline Class-1 Verifier (`verifyReceiptBundle`) *)
VerifyBundle(cid, hasReceipt, treeSize, root) ==
  /\ \E cap \in capsules :
       /\ cap.cid = cid
       /\ ValidCapsuleSemantics(cap.verdict, cap.effectStatus, cap.hasRespDigest)
       /\ \E stmt \in statements :
            /\ stmt.cid = cid
            /\ stmt.signedByTrustedIssuer = TRUE
            /\ (hasReceipt = TRUE =>
                 /\ [cid |-> cid, treeSize |-> treeSize, root |-> root] \in logEntries
                 /\ [treeSize |-> treeSize, root |-> root, logSigned |-> TRUE] \in checkpoints
                 /\ QuorumReached(treeSize, root))
            /\ (cap.ledgerMode = "anchored" => hasReceipt = TRUE)
            /\ verifiedBundles' = verifiedBundles \cup {[
                 cid |-> cid,
                 verdict |-> cap.verdict,
                 effectStatus |-> cap.effectStatus,
                 hasRespDigest |-> cap.hasRespDigest,
                 ledgerMode |-> cap.ledgerMode,
                 signedByTrustedIssuer |-> stmt.signedByTrustedIssuer,
                 receiptVerified |-> hasReceipt,
                 treeSize |-> treeSize,
                 root |-> root
               ]}
  /\ UNCHANGED <<capsules, statements, logEntries, checkpoints, witnessCosigs>>

-----------------------------------------------------------------------------
Next ==
  \/ \E cid \in CapsuleIds, v \in Verdicts, es \in EffectStatuses,
        hrd \in BOOLEAN, lm \in LedgerModes, sigOk \in BOOLEAN :
       IssueCapsule(cid, v, es, hrd, lm, sigOk)
  \/ \E cid \in CapsuleIds, ts \in TreeSizes, r \in Roots :
       AppendToLog(cid, ts, r)
  \/ \E ts \in TreeSizes, r \in Roots :
       AdversaryPublishConflictingCheckpoint(ts, r)
  \/ \E w \in Witnesses, ts \in TreeSizes, r \in Roots :
       WitnessCosign(w, ts, r)
  \/ \E cid \in CapsuleIds, hr \in BOOLEAN, ts \in TreeSizes, r \in Roots :
       VerifyBundle(cid, hr, ts, r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* SAFETY INVARIANTS *)

\* Invariant 1: No unsigned statement is ever registered in the log or verified.
INV_NoUnsignedRegistered ==
  /\ \A le \in logEntries :
       \E s \in statements : s.cid = le.cid /\ s.signedByTrustedIssuer = TRUE
  /\ \A vb \in verifiedBundles :
       vb.signedByTrustedIssuer = TRUE

\* Invariant 2: Any verified bundle claiming `ledger_mode = "anchored"` has a
\* verified SCITT receipt anchored in a log-signed, quorum-cosigned checkpoint.
INV_AnchoredRequiresVerifiedReceipt ==
  \A vb \in verifiedBundles :
    (vb.ledgerMode = "anchored") =>
      /\ vb.receiptVerified = TRUE
      /\ [cid |-> vb.cid, treeSize |-> vb.treeSize, root |-> vb.root] \in logEntries
      /\ [treeSize |-> vb.treeSize, root |-> vb.root, logSigned |-> TRUE] \in checkpoints
      /\ QuorumReached(vb.treeSize, vb.root)

\* Invariant 3: No two conflicting checkpoint roots for the same treeSize can
\* simultaneously achieve witness quorum under Byzantine quorum intersection.
INV_NoSplitViewWithWitnessQuorum ==
  \A cp1, cp2 \in checkpoints :
    (cp1.treeSize = cp2.treeSize /\ QuorumReached(cp1.treeSize, cp1.root) /\ QuorumReached(cp2.treeSize, cp2.root))
      => (cp1.root = cp2.root)

\* Invariant 4: Every capsule and every verified bundle with a `confirmed`
\* effect carries `verdict = "executed"` and an observed `response_digest`.
INV_ConfirmedEffectHasObservedDigest ==
  /\ \A c \in capsules :
       (c.effectStatus = "confirmed") => (c.verdict = "executed" /\ c.hasRespDigest = TRUE)
  /\ \A vb \in verifiedBundles :
       (vb.effectStatus = "confirmed") => (vb.verdict = "executed" /\ vb.hasRespDigest = TRUE)

\* Temporal box properties corresponding to the four safety invariants
PROP_NoUnsignedRegistered == []INV_NoUnsignedRegistered
PROP_AnchoredRequiresVerifiedReceipt == []INV_AnchoredRequiresVerifiedReceipt
PROP_NoSplitViewWithWitnessQuorum == []INV_NoSplitViewWithWitnessQuorum
PROP_ConfirmedEffectHasObservedDigest == []INV_ConfirmedEffectHasObservedDigest

THEOREM Spec => [](
  /\ INV_NoUnsignedRegistered
  /\ INV_AnchoredRequiresVerifiedReceipt
  /\ INV_NoSplitViewWithWitnessQuorum
  /\ INV_ConfirmedEffectHasObservedDigest
)
=============================================================================
