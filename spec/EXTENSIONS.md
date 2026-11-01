# Extensions Hivemind leads

Each has a working implementation in this repository; these are the drafts
to take to their venues (IETF SCITT WG, Agentic AI Foundation for A2A/MCP,
OpenTelemetry GenAI SIG, C2SP).

## 1. A2A receipts extension

- URI: `https://hivemind.example/a2a/extensions/receipts/v1` (to be moved to
  the hivemindax.com domain on submission).
- Declared in the Agent Card `extensions` list with params
  `{profiles: [...], receipt_artifact_metadata_key: "io.hivemind/receipt_id"}`.
- Activated per request through the `A2A-Extensions` header naming the URI.
- Receipts ride in task artifact metadata: `io.hivemind/receipt_id`,
  `io.hivemind/action_id`. A delegation opens a child capsule whose
  `causality.a2a_task_id` and parent ids link the sub-graph.
- Implementation: `src/receipts/integrations/surfaces.ts`
  (`a2aAgentCardExtension`, `a2aExtensionActivated`, `a2aTaskArtifact`).

## 2. MCP receipts extension

- Uses the extensions capability of the 2026-07-28 MCP revision.
- The receipt id returns in the tool result `_meta` under
  `io.hivemind/receipt_id`; W3C trace context continues to travel in `_meta`
  and is bound into `causality` (trace/span/MCP request ids).
- A `receipts` MCP server exposes `hivemind.authorize`, `hivemind.record`,
  `hivemind.verify` to agents that call receipts directly.
- Implementation: `wrapMcpHandler`, `RECEIPTS_MCP_TOOLS` in `surfaces.ts`;
  gateway posture (authorize before `tools/call`, record after) identical to
  the in-server gate.

## 3. OpenTelemetry GenAI link attribute

- Proposed attribute: `hivemind.receipt_id` on `execute_tool` and
  `invoke_agent` spans, value = capsule id. Until upstreamed under a
  GenAI namespace it ships with the `hivemind.` vendor prefix per OTel rules.
- Zero-code capture: the Collector ships GenAI spans to the converter in
  `src/receipts/integrations/otel-processor.ts`, which maps the GenAI
  attributes (operation, tool name, agent id, model, MCP request id) into
  capsules (`otelSpanToAction`). Collector config:
  `docs/receipts/integrations/otel-collector.yaml`.

## 4. Witness policy for agent logs

- C2SP tlog-policy file: a `quorum <k>` line plus one
  `witness <note-verifier-string>` per witness; finality at 3-of-5 in the
  reference deployment. Hivemind operates witnesses for other agent logs
  under the same policy and joins the public witness network.
- A witness cosigns only with a consistency proof from the last tree it saw,
  refuses same-size/different-root equivocation, and its refusal is visible
  by absence (`src/receipts/log/witness.ts`, `/witness/add-checkpoint` API).

## 5. Claude Code / agent-framework posture (non-normative)

PreToolUse = AuthZEN evaluate (may deny with the signed decision digest),
PostToolUse + PostToolUseFailure = record. One settings file plus
`docs/receipts/integrations/hivemind-receipts-hook.mjs`. Framework adapters
(OpenAI Agents SDK, LangGraph, Microsoft Agent Framework, CrewAI, Vercel AI
SDK, Pydantic AI, Agno) share `wrapToolHandler`.

## 6. Unlinkable selective disclosure via IETF CFRG BBS (`BLS12-381-SHA-256`)

- Specification revision: `draft-irtf-cfrg-bbs-signatures-09`, ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_`.
- Reference implementation: `src/receipts/core/bbs.ts` (`bbsKeygen`, `bbsGenerators`, `bbsMessageToScalar`, `bbsSign`, `bbsVerify`, `bbsCreateProof`, `bbsVerifyProof`).
