---
title: "SCITT Agent Action Receipts and Transparent Capsule Profile"
abbrev: "SCITT Agent Action Receipts"
docname: draft-hypereum-scitt-agent-action-00
category: std
ipr: trust200902
area: Security
workgroup: SCITT Working Group
date: 2026-10-30

author:
 -
    ins: G. Hypereum
    name: Hypereum Security Architecture Team
    organization: Hypereum Ltd
    email: security@hypereum.tech
    uri: https://hypereum.tech

normative:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard (ML-DSA)"
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2024-08
    seriesinfo:
      FIPS: PUB 204
  RFC2119:
  RFC3161:
  RFC4998:
  RFC8174:
  RFC8610:
  RFC8785:
  RFC8949:
  RFC9052:
  RFC9162:
  RFC9380:
  RFC9597:
  RFC9942:
    title: "COSE Receipts for Verifiable Data Structures"
    date: 2026
  RFC9964:
    title: "Use of ML-DSA in CBOR Object Signing and Encryption (COSE)"
    date: 2026

informative:
  I-D.ietf-scitt-architecture:
  I-D.ietf-scitt-scrapi:

--- abstract

This document specifies the Agent Action Capsule profile (`urn:hivemind:receipts:capsule:1`) for Supply Chain Integrity, Transparency, and Trust (SCITT) Signed Statements and portable `.hvr` (`application/vnd.hivemind.receipt+cose`) bundles. It defines a deterministic CBOR and RFC 8785 (JCS) dual-digest payload format, COSE_Sign1 envelope profiling, hybrid post-quantum countersignatures (ML-DSA-65 per FIPS 204 and RFC 9964), privacy-preserving off-log salted commitments with KMS envelope crypto-shredding and BBS over BLS12-381 unlinkable selective disclosure, RFC 9162 Merkle inclusion receipts anchored in C2SP signed-note checkpoints with a 3-of-5 witness cosignature quorum, and long-term archive preservation via RFC 4998 Evidence Record Syntax (ERS) with RFC 3161 timestamps.

--- middle

# Introduction

Autonomous AI agents invoke tools, Model Context Protocol (MCP) endpoints, Agent-to-Agent (A2A) tasks, and external HTTP APIs on behalf of human and workload principals. Conventional telemetry logs are mutable, omit denied or failed attempts (survivorship bias), conflate attempted tool calls with confirmed side effects, and leak sensitive PII or prompt arguments into append-only storage.

This specification profiles the IETF SCITT architecture {{I-D.ietf-scitt-architecture}} and SCRAPI {{I-D.ietf-scitt-scrapi}} to provide cryptographically verifiable, offline-auditable receipts for every agent action decision and execution outcome.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

# Agent Action Capsule Format and Invariants

## Binding Protocol Invariants

Every implementation conforming to profile `urn:hivemind:receipts:capsule:1` MUST enforce four binding invariants:

1. **No Survivorship Bias (Completeness)**: A signed capsule MUST be emitted for every verdict class: `"executed"`, `"blocked"`, `"denied"`, `"errored"`, `"engine_failure"`, and `"timed_out"`.
2. **Confirmed Effect Binding (`INV_ConfirmedEffectHasObservedDigest`)**: A capsule with `effect.status == "confirmed"` MUST have `verdict_class == "executed"` AND MUST carry a valid `effect.response_digest` computed over the observed response.
3. **Anchored Ledger Claim (`INV_AnchoredRequiresVerifiedReceipt`)**: A capsule claiming `assurance.ledger_mode == "anchored"` MUST be rejected by verifiers unless accompanied by a verified RFC 9162 inclusion receipt anchored in a log-signed and witness-quorum-cosigned checkpoint.
4. **Offline Class-1 Verification**: Class-1 verification MUST be deterministic and completely offline, consulting no external network, no AI model, and no heuristic wall-clock skew assumptions.

## Dual Canonical Digests (CBOR and JCS JSON-DIGEST)

The canonical identifier `capsule_id` (`capsuleCborDigest`) MUST be computed as `sha256:<hex>` over the {{RFC8949}} Section 4.2 Core Deterministic Encoding CBOR bytes of the CapsuleCore map (excluding `capsule_id`). Implementations SHOULD also compute `capsuleJsonDigest` (`JSON-DIGEST`) as `sha256:<hex>` over the UTF-8 bytes of the {{RFC8785}} JSON Canonicalization Scheme (JCS) serialization of the CapsuleCore object.

# SCITT Envelope, Transparency Log, and Post-Quantum Profile

## COSE_Sign1 Statement and CWT Claims

An Agent Action Capsule is carried as the payload of a tagged `COSE_Sign1` (CBOR Tag 18, {{RFC9052}}) envelope (`0xd2 0x84`):

- Protected header parameter `1` (`alg`) MUST be ES256 (`-7`), EdDSA (`-8`), or an {{RFC9964}} ML-DSA algorithm (`-48`, `-49`, `-50`).
- Protected header parameter `3` (`content_type`) MUST be `"application/vnd.hivemind.agent-action-capsule+cbor"` (or `"application/vnd.hivemind.receipt+cose"` / `"application/scitt-statement+cose"` at the transport/file layer).
- Protected header parameter `4` (`kid`) MUST identify the issuer key.
- Protected header parameter `15` (`cwt_claims`, {{RFC9597}}) SHOULD carry CWT claims `1` (`iss`), `2` (`sub`), and `6` (`iat`).

## Hybrid Post-Quantum Countersignatures (ML-DSA-65)

Statements MAY carry an ML-DSA-65 {{FIPS204}} {{RFC9964}} countersignature in unprotected header parameter `7` (or `-25900`) using NIST OID `2.16.840.1.101.3.4.3.18` (`id-ml-dsa-65`) and algorithm `-49`.

## RFC 9162 Inclusion Proofs and 3-of-5 Witness Quorum

Transparency log receipts (`application/scitt-receipt+cose`) are attached in unprotected header parameter `394` (`receipts`) per {{RFC9942}}, with protected parameter `395` (`vds = 1` for {{RFC9162}} SHA-256 Merkle trees) and parameter `396` (`vdp = {-1: [bstr .cbor [tree_size, leaf_index, [* sha256_hash]]]}`). Production deployments MUST enforce a minimum witness cosignature policy of 3-of-5 independent C2SP `tlog-cosignature` witnesses.

## Long-Term Archive Evidence Records (RFC 4998 + RFC 3161)

Archives requiring 10-year non-repudiation across cryptographic algorithm transitions MUST encapsulate batch Merkle roots inside ASN.1 DER `EvidenceRecord` structures {{RFC4998}} stamped with {{RFC3161}} CMS `TimeStampToken`s.

# Selective Disclosure and Privacy Architecture

## Salted HMAC Commitments and KMS Envelope Crypto-Shredding

Sensitive fields (`principal.subject`, `operation.target`, `request`, `response`, `effect.summary`) MUST NOT appear in cleartext in the logged capsule. Each field enters the capsule as `HMAC-SHA-256(salt_32, field_name || 0x00 || det_cbor(value))` where `privacy.salt_commitment = sha256(salt_32)`.

## Unlinkable Zero-Knowledge Proofs via BBS on BLS12-381

When a holder must disclose a subset of capsule attributes to multiple verifiers without correlation, issuers MAY sign the attribute vector using BBS over BLS12-381 {{RFC9380}}.

# Normative CDDL Specification

~~~cddl
sha256-digest = tstr .regexp "^sha256:[0-9a-f]{64}$"
ulid-str      = tstr .regexp "^[0-9A-HJKMNP-TV-Z]{26}$"

verdict-class = "executed" / "blocked" / "denied"
              / "errored" / "engine_failure" / "timed_out"

risk-tier     = "read" / "write" / "destructive"
              / "financial" / "external_communication"

ledger-mode   = "standalone" / "chained" / "anchored"
attest-mode   = "none" / "nitro" / "sev-snp" / "tdx" / "gpu"

agent-action-capsule = {
  profile: "urn:hivemind:receipts:capsule:1",
  capsule_id: sha256-digest,
  action_id: ulid-str,
  ? retry_of: ulid-str,
  agent: {
    ? spiffe_id: tstr,
    ? agent_card_digest: sha256-digest,
    ? key_thumbprint: tstr,
  },
  principal: {
    subject_commitment: sha256-digest,
    ? delegation_chain_digest: sha256-digest,
    ? token_issuer: tstr,
    ? token_scopes: [* tstr],
  },
  operation: {
    kind: "mcp" / "a2a" / "http" / "tool" / "other",
    method: tstr,
    ? target_commitment: sha256-digest,
    ? tool_schema_digest: sha256-digest,
    risk_tier: risk-tier,
  },
  request_digest: sha256-digest,
  verdict_class: verdict-class,
  ? effect: {
    status: "confirmed" / "asserted" / "none",
    ? response_digest: sha256-digest,
    ? summary_commitment: sha256-digest,
  },
  disposition: {
    ? authority: tstr,
    ? decision_digest: sha256-digest,
    ? approval_digest: sha256-digest,
    ? break_glass: bool,
  },
  ? criteria_ref: sha256-digest,
  ? model: {
    ? provider: tstr,
    ? model_id: tstr,
    ? model_version: tstr,
    ? region: tstr,
    ? provider_request_id: tstr,
  },
  ? runtime: {
    ? image_digest: sha256-digest,
    ? attestation_ref: tstr,
  },
  causality: {
    ? parent_capsule_ids: [* sha256-digest],
    ? dag_root: sha256-digest,
    ? trace_id: tstr,
    ? span_id: tstr,
    ? a2a_task_id: tstr,
    ? mcp_request_id: tstr,
  },
  assurance: {
    ledger_mode: ledger-mode,
    attestation_mode: attest-mode,
  },
  privacy: {
    disclosure_policy_id: tstr,
    salt_commitment: sha256-digest,
  },
  issued_at: tstr,
  ? extensions: { * tstr => any },
}
~~~

# Security Considerations

- **Split-View / Equivocation Resistance**: Enforcing a 3-of-5 C2SP witness quorum ensures any two quorums intersect in at least `2*3 - 5 = 1` witness (`INV_NoSplitViewWithWitnessQuorum`).
- **Threshold Key Custody**: Splitting the checkpoint signing seed via 3-of-5 Shamir Secret Sharing over `GF(2^256 + 297)` eliminates single-host key compromise.
- **Post-Quantum Transition**: Hybrid FIPS 204 ML-DSA-65 countersignatures protect long-lived receipts against quantum adversaries.

# Privacy Considerations

- **Off-Log Salted Commitments**: Storing only 256-bit salted HMAC commitments on the log prevents dictionary attacks on low-entropy attributes.
- **Crypto-Shredding**: Per-subject DEK wrapping under KMS KEKs enables GDPR Article 17 erasure without mutating the Merkle tree.

# IANA Considerations

## Media Types Registration

IANA is requested to register `application/vnd.hivemind.receipt+cose` (file extension `.hvr`), `application/vnd.hivemind.agent-action-capsule+cbor`, `application/scitt-statement+cose`, and `application/scitt-receipt+cose`.
