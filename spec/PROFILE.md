# Agent Action Capsule profile on SCITT — `urn:hivemind:receipts:capsule:1`

Working draft owned by Hypereum for submission to the IETF SCITT working
group. Goal: convergence of the Agent Action Capsule, the SCITT agent-receipt
draft, AIVS and the binding/permit drafts into one profile, with this
repository as the reference implementation and
`conformance/receipts/vectors.json` as the conformance suite.

## 1. Envelope

- A receipt is a SCITT Transparent Statement: COSE_Sign1 (RFC 9052, tag 18)
  over deterministic CBOR (RFC 8949 core deterministic encoding). Only the
  CBOR bytes are signed; the JCS (RFC 8785) JSON view is for developers.
- Protected header: `alg` (1), `content-type` (3,
  `application/vnd.hivemind.agent-action-capsule+cbor`), `kid` (4), CWT
  claims (15, RFC 9597): `iss` (1), `sub` = `action_id` (2), `iat` (6).
- Unprotected header: COSE receipts (394, RFC 9942), countersignatures (7,
  RFC 9338 — the hybrid post-quantum second signature), timestamp tokens
  (private label −25900 in this profile until assigned).
- Receipts: VDS `RFC9162_SHA256` (395 = 1), proofs under 396:
  `-1` = `[treeSize, leafIndex, hashes…]` (inclusion), consistency proofs
  served on request (`-2`). The receipt signature's `external_aad` is the
  leaf hash `H(0x00 ‖ statement-leaf-bytes)`, where statement-leaf-bytes is
  the signed statement with the unprotected receipts removed.
- Detached payloads: the payload digest is pinned by `capsule_id`; a verifier
  refuses a detached payload whose content address differs.

## 2. Payload

Deterministic-CBOR map with the fields of the specification's payload table
(`capsule_id` = SHA-256 over the canonical CBOR of the payload without that
field; `action_id` a ULID, retries linked via `retry_of`; `verdict_class`
one of executed/blocked/denied/errored/engine_failure/timed_out;
`request_digest` and `effect.response_digest` salted HMAC-SHA-256
commitments under a per-receipt 256-bit salt whose digest is
`privacy.salt_commitment`; `disposition.authority` references the signed
authorization decision; `criteria_ref` the pre-agreed outcome criteria;
`causality` parent capsules + W3C trace/span + A2A task + MCP request ids;
`assurance.ledger_mode` ∈ standalone/chained/anchored).
Extensions are namespaced (`io.hivemind.*`, dotted keys); unknown extension
values are informational to verifiers.

### Invariants (normative)

1. A capsule is emitted on every verdict, refusals and timeouts included.
2. A confirmed effect must carry the digest of the observed response.
3. `anchored` may be claimed only with a verified SCITT receipt.
4. Class-1 verification consults no model, no network and no clock heuristics.
5. Optional unlinkable selective disclosure over capsule attributes uses IETF CFRG BBS signatures (`draft-irtf-cfrg-bbs-signatures-09`, ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_`) in `src/receipts/core/bbs.ts`.

## 3. Batches, graphs, versioning

- Batch profile `urn:hivemind:receipts:capsule-batch:1`: one statement over
  the RFC 9162 root of up to 4,096 capsule payloads; each capsule keeps its
  own inclusion path.
- Causal graph: capsule ids of a trace fold into one graph root
  (SHA-256 over the canonical CBOR list of sorted ids), anchored by a single
  checkpoint via a `urn:hivemind:receipts:causal-graph:1` statement.
- Breaking changes mint a new profile URI; verifiers accept every version
  they know.

## 4. Associated statement kinds (same log)

authorization decisions (`...authorization-decision:1`), confirmations
(`...confirmation:1`, levels W0–W3), criteria + verdicts (CEL, replayable),
key events, revocations, break-glass records, opinions (labelled opinions,
never confirmations), registration policy and trust anchors (shard genesis),
checkpoint anchors (private shards anchoring into the public shard).

## 5. Verification

Reference algorithm: `src/receipts/core/verify.ts`; ports in
`receipts-verify-rs/` (Rust/WASM), `sdks/python`, `sdks/go`, `sdks/java`,
`site/public/receipts/verify-receipt.mjs`. All consume the vectors in
`conformance/receipts/vectors.json` (valid, tampered, equivocated,
missing-receipt, revoked, unknown-issuer, disclosure-mismatch and batch
cases). Reports are per-check and always list the claims that remain only
asserted.
