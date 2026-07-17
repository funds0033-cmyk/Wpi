# Public attestations

This directory is the **public surface** for short-term proof-of-reserve (Issue #25).

| File | Purpose |
|------|---------|
| `latest.json` | Most recent signed attestation |
| `history/` | Optional dated snapshots (`YYYY-MM-DDTHH.json`) |
| `schema.json` | JSON Schema for attestations |
| `ATTESTOR_PUBLIC_KEY` | Hex Ed25519 public key used to verify signatures |
| `sample.json` | Example attestation for docs / offline verify demos |

## Verify

```bash
node scripts/por/verify.mjs attestations/latest.json
```

Process documentation: [`docs/proof-of-reserve.md`](../docs/proof-of-reserve.md).
