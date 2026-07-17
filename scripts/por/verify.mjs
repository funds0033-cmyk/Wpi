#!/usr/bin/env node
/**
 * Verify a Wpi proof-of-reserve attestation signature and basic health checks.
 *
 * Usage:
 *   node scripts/por/verify.mjs <attestation.json> [--pubkey HEX|PATH]
 */

import { createPublicKey, verify } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");

const DEFAULT_SIGNED_FIELDS = [
  "schema_version",
  "issued_at",
  "network",
  "wpi_contract_id",
  "wpi_total_supply",
  "pi_custody_account",
  "pi_custody_balance",
  "pi_balance_source",
  "safety_margin_bps",
];

function hexToBuf(hex) {
  const h = hex.trim().replace(/^0x/i, "");
  return Buffer.from(h, "hex");
}

function loadExpectedPubkey(argPubkey, attestation) {
  if (argPubkey) {
    if (existsSync(argPubkey)) {
      return readFileSync(argPubkey, "utf8").trim().replace(/^0x/i, "");
    }
    return argPubkey.trim().replace(/^0x/i, "");
  }
  const committed = join(REPO_ROOT, "attestations/ATTESTOR_PUBLIC_KEY");
  if (existsSync(committed)) {
    return readFileSync(committed, "utf8").trim().replace(/^0x/i, "");
  }
  return (attestation.attestor_public_key || "").trim();
}

function rawPubToKeyObject(rawHex) {
  const raw = hexToBuf(rawHex);
  if (raw.length !== 32) {
    throw new Error("public key must be 32 bytes hex");
  }
  // SPKI DER prefix for Ed25519 public key
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([prefix, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function canonicalPayload(attestation) {
  const fields = attestation.signed_fields || DEFAULT_SIGNED_FIELDS;
  const body = {};
  for (const k of fields) {
    if (!(k in attestation)) {
      throw new Error(`attestation missing signed field: ${k}`);
    }
    body[k] = attestation[k];
  }
  return JSON.stringify(body);
}

function recomputeStatus(attestation) {
  const pi = BigInt(attestation.pi_custody_balance);
  const supply = BigInt(attestation.wpi_total_supply);
  const margin = BigInt(attestation.safety_margin_bps);
  if (supply === 0n) return "healthy";
  const cap = (pi * (10000n - margin)) / 10000n;
  return supply <= cap ? "healthy" : "under_collateralized";
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "-h" || args[0] === "--help") {
    console.log(
      "Usage: node scripts/por/verify.mjs <attestation.json> [--pubkey HEX|PATH]",
    );
    process.exit(args.length === 0 ? 1 : 0);
  }

  const path = resolve(args[0]);
  let pubkeyArg;
  const idx = args.indexOf("--pubkey");
  if (idx !== -1) pubkeyArg = args[idx + 1];

  const attestation = JSON.parse(readFileSync(path, "utf8"));
  const expectedPub = loadExpectedPubkey(pubkeyArg, attestation);
  if (!expectedPub) {
    throw new Error("no public key: pass --pubkey or commit ATTESTOR_PUBLIC_KEY");
  }

  if (
    attestation.attestor_public_key &&
    attestation.attestor_public_key.toLowerCase() !== expectedPub.toLowerCase()
  ) {
    console.error(
      "FAIL: attestor_public_key in file does not match expected pubkey",
    );
    process.exit(1);
  }

  if (!attestation.signature) {
    console.error("FAIL: missing signature");
    process.exit(1);
  }

  const payload = canonicalPayload(attestation);
  const pub = rawPubToKeyObject(expectedPub);
  const ok = verify(
    null,
    Buffer.from(payload, "utf8"),
    pub,
    hexToBuf(attestation.signature),
  );

  if (!ok) {
    console.error("FAIL: invalid signature");
    process.exit(1);
  }

  const expectedStatus = recomputeStatus(attestation);
  if (attestation.status !== expectedStatus) {
    console.error(
      `FAIL: status field "${attestation.status}" != recomputed "${expectedStatus}"`,
    );
    process.exit(1);
  }

  const ageMs = Date.now() - Date.parse(attestation.issued_at);
  const ageHours = ageMs / (1000 * 60 * 60);
  const stale = Number.isFinite(ageHours) && ageHours > 2;

  console.log("OK: signature valid");
  console.log(`  file:     ${path}`);
  console.log(`  status:   ${attestation.status}`);
  console.log(`  ratio:    ${attestation.collateral_ratio}`);
  console.log(`  supply:   ${attestation.wpi_total_supply}`);
  console.log(`  reserve:  ${attestation.pi_custody_balance}`);
  console.log(`  issued:   ${attestation.issued_at}`);
  if (stale) {
    console.warn(
      `WARN: attestation is ~${ageHours.toFixed(1)}h old (threshold 2h)`,
    );
  }
  if (attestation.status !== "healthy") {
    process.exitCode = 2;
  }
}

try {
  main();
} catch (e) {
  console.error("error:", e.message || e);
  process.exit(1);
}
