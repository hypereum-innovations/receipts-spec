# Data Protection Impact Assessment — customer template (Hivemind Receipts)

Fill the bracketed parts; the technical statements describe the shipped
defaults so your DPO can adopt them verbatim where they match your use.

## 1. Processing description

- Controller: [customer]. Processor: Hypereum Ltd (Hivemind Receipts), EU-only
  sub-processors, DPA standard.
- Data in the public transparency log: **salted HMAC commitments only**
  (per-receipt 256-bit salt), key ids, timestamps at checkpoint granularity,
  digests. **No plaintext content, no names in public tiles.**
- Content (requests/responses) stays with the issuer. It transits Hypereum
  only if the customer opts into custody, encrypted under per-subject keys.
- Metadata leakage: inclusion proofs reveal log size (RFC 9942 warning);
  sensitive tenants use private shards whose checkpoints anchor into the
  public log, revealing only shard activity, not entries.

## 2. Necessity and proportionality

Verification of agent actions with evidentiary weight cannot be achieved by
access-controlled logs alone (the operator could rewrite them). Commitments
plus selective disclosure provide the same verifiability with minimal data:
receivers open only the fields they need (SD-JWT in the JSON view,
per-field disclosures in the CBOR form), encrypted to the receiver with
HPKE when shared.

## 3. Risks and measures

| Risk | Measure |
|---|---|
| Brute-forcing low-entropy fields from digests | Per-receipt salted HMAC commitments; unsalted digests never used for content fields |
| Correlation across presentations | Unlinkability option (BBS, roadmap of the profile); private shards |
| Erasure requests vs append-only log | Crypto-shredding: destroy the per-subject key; content is gone, the commitment remains as proof-of-existence (legal basis: [customer to record]) |
| Insider/operator rewrite | Append-only Merkle log, witness quorums, consistency proofs, monitors |
| Key compromise | HSM custody, 10-minute keyless certificates, key transparency, revocation statements |

## 4. Retention

Tiles, checkpoints and timestamp tokens: S3 Object Lock COMPLIANCE, minimum
10 years (legal durability requirement). Custodied content: per the
customer's retention schedule, erased by key destruction. Residency: EU
regions only (log, keys, custody stores, backups).
