# Class-1 verification algorithm (formal sketch)

Inputs: transparent statement `S`, pinned trust roots `T` (issuer keys with
tiers + revocation state, log keys per shard, signed-note verifiers, witness
quorum policy, optional PQ countersigners, TSA roots), a cosigned checkpoint
`C`, optionally a disclosure `D`, a consistency chain `(root₀, proof₀→C)`,
batch membership data, confirmations and criteria. No network, no model, no
clock heuristics. Output: per-check statuses and one verdict.

1. **Envelope.** Strict-deterministic CBOR-decode `S`; it must be COSE_Sign1
   (tag 18). Any non-canonical encoding fails.
2. **Issuer.** `kid` must be pinned in `T` and not revoked at registration
   time per key-transparency events. Report the tier (T0 "Unverified
   issuer", T1 domain, T2 legal entity + LEI, T3 qualified seal).
3. **Signature.** Rebuild the RFC 9052 `Sig_structure` over the protected
   header bytes and payload (or the supplied detached payload, whose digest
   must equal `capsule_id`); verify ES256/EdDSA. If a PQ countersigner is
   pinned, also verify the RFC 9338 countersignature.
4. **Capsule.** Decode the payload; recompute `capsule_id` over the canonical
   CBOR without that field; enforce the profile invariants (every verdict
   representable; confirmed ⇒ `response_digest`; namespaced extensions).
   A batch payload instead defers to step 5b.
5. **Disclosure (if given).** Salt digest must equal
   `privacy.salt_commitment`; each disclosed field must open its HMAC
   commitment. Undisclosed fields simply stay closed.
6. **Inclusion.** Let `L = H(0x00 ‖ leaf-bytes(S))` (receipts removed). For
   each attached receipt: parse `vds = 1`, read `(treeSize, leafIndex,
   hashes)` from `vdp[-1]`, verify the log signature with `external_aad = L`,
   then either (a) `treeSize = C.size` and the RFC 9162 audit path recomputes
   `C.root`, or (b) the path recomputes `root₀` and the RFC 9162 consistency
   proof carries `root₀ → C.root`. If `assurance.ledger_mode = anchored`,
   this check is mandatory, not advisory.
7. **Checkpoint.** Parse the signed note; the log signature must verify over
   the checkpoint body with a pinned note verifier; witness cosignatures
   (72-byte timestamp‖Ed25519 over `cosignature/v1\ntime <t>\n<body>`) must
   meet the pinned quorum. Cosignature times bound registration time; an
   RFC 3161 token over the root, when present, is verified against pinned
   TSA roots and reported — recency never flips a verdict.
8. **Confirmations + criteria (when billed on outcomes).** Parse each
   confirmation statement; check witness signatures and levels; rebuild the
   CEL environment from observations; re-run the program committed by
   `criteria_ref`; the verdict statement must reproduce. AI-judge opinions
   never count as confirmations.
9. **Verdict.** `VERIFIED` iff no check failed. The report lists every claim
   that remains asserted-only (e.g. model id, issuer clock, unwitnessed
   effects).

Conformance: `conformance/receipts/vectors.json` pins expected verdicts for
valid, tampered, equivocated, revoked, unknown-issuer,
missing-receipt/anchored, disclosure-mismatch and batch inputs. The TS,
Rust and Python implementations pass all of them in CI; Go and Java ports
consume the same file.
