#!/usr/bin/env node
/**
 * Wpi proof-of-reserve attestor CLI (Issue #25).
 *
 * Commands:
 *   keygen                 Generate Ed25519 keypair (hex seed + public key)
 *   attest [--unsigned]    Produce signed (or unsigned) attestation JSON
 *
 * Env: see docs/proof-of-reserve.md
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");

const SIGNED_FIELDS = [
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

function usage() {
  console.log(`Usage:
  node scripts/por/attest.mjs keygen
  node scripts/por/attest.mjs attest [--unsigned]

Env for attest:
  POR_ATTESTOR_SECRET_KEY   hex 64-char seed (32 bytes) OR path to PEM
  WPI_CONTRACT_ID           Stellar contract id
  STELLAR_SOROBAN_RPC_URL   Soroban RPC URL
  STELLAR_NETWORK           testnet|public (default testnet)
  PI_CUSTODY_ACCOUNT        custody account id
  PI_CUSTODY_BALANCE        stroops (optional if file set)
  PI_CUSTODY_BALANCE_FILE   path to file with integer stroops
  PI_BALANCE_SOURCE         label (default: env|file)
  SAFETY_MARGIN_BPS         default 0
  POR_OUT                   default attestations/latest.json
  WPI_TOTAL_SUPPLY_OVERRIDE optional: skip RPC, use this supply (stroops)
`);
}

function hexToBuf(hex) {
  const h = hex.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(h) || h.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  return Buffer.from(h, "hex");
}

function bufToHex(buf) {
  return Buffer.from(buf).toString("hex");
}

/** 32-byte seed → PKCS8 DER for Ed25519 (Node crypto). */
function seedToPrivateKeyObject(seed32) {
  if (seed32.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  // PKCS8 prefix for Ed25519 private key
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const der = Buffer.concat([prefix, seed32]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function publicKeyRaw(publicKeyObject) {
  const spki = publicKeyObject.export({ type: "spki", format: "der" });
  // SPKI for Ed25519 ends with the 32-byte raw key
  return spki.subarray(spki.length - 32);
}

function loadPrivateKeyFromEnv() {
  const raw = process.env.POR_ATTESTOR_SECRET_KEY;
  if (!raw) {
    throw new Error("POR_ATTESTOR_SECRET_KEY is required to sign");
  }
  const trimmed = raw.trim();
  if (existsSync(trimmed)) {
    const pem = readFileSync(trimmed, "utf8");
    return createPrivateKey(pem);
  }
  // hex seed (64 hex chars = 32 bytes)
  const seed = hexToBuf(trimmed);
  if (seed.length === 32) {
    return seedToPrivateKeyObject(seed);
  }
  if (seed.length === 64) {
    // some tools export 64-byte expanded secret; use first 32 as seed
    return seedToPrivateKeyObject(seed.subarray(0, 32));
  }
  throw new Error(
    "POR_ATTESTOR_SECRET_KEY must be 32-byte hex seed or PEM file path",
  );
}

function canonicalPayload(fields) {
  const body = {};
  for (const k of SIGNED_FIELDS) {
    if (!(k in fields)) {
      throw new Error(`missing signed field: ${k}`);
    }
    body[k] = fields[k];
  }
  return JSON.stringify(body);
}

function computeStatus(piBalance, wpiSupply, marginBps) {
  if (wpiSupply < 0n || piBalance < 0n) {
    return { status: "unknown", collateral_ratio: "unknown" };
  }
  if (wpiSupply === 0n) {
    return { status: "healthy", collateral_ratio: "inf" };
  }
  // cap = reserve * (10000 - margin) / 10000
  const cap = (piBalance * BigInt(10000 - marginBps)) / 10000n;
  const ratio = Number(piBalance) / Number(wpiSupply);
  const collateral_ratio =
    Number.isFinite(ratio) ? ratio.toFixed(8) : "unknown";
  const status = wpiSupply <= cap ? "healthy" : "under_collateralized";
  return { status, collateral_ratio };
}

async function fetchTotalSupply(rpcUrl, contractId) {
  // Soroban JSON-RPC: simulate or getLedgerEntries is complex without XDR tooling.
  // Prefer getContractData via stellar-compatible RPC if available; fallback OVERRIDE.
  if (process.env.WPI_TOTAL_SUPPLY_OVERRIDE !== undefined) {
    return BigInt(process.env.WPI_TOTAL_SUPPLY_OVERRIDE);
  }

  // Attempt: call simulation of total_supply() via eth-like is not available.
  // Use Stellar Horizon/Soroban `getLedgerEntries` needs key encoding.
  // Practical approach for v1: `stellar contract invoke` if CLI present, else RPC simulate.
  const stellar = process.env.STELLAR_CLI || "stellar";
  const network = process.env.STELLAR_NETWORK || "testnet";
  const { spawnSync } = await import("node:child_process");

  const tryCli = spawnSync(
    stellar,
    [
      "contract",
      "invoke",
      "--id",
      contractId,
      "--source-account",
      process.env.STELLAR_SOURCE_ACCOUNT || "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
      "--rpc-url",
      rpcUrl,
      "--network-passphrase",
      network === "public"
        ? "Public Global Stellar Network ; September 2015"
        : "Test SDF Network ; September 2015",
      "--",
      "total_supply",
    ],
    { encoding: "utf8" },
  );

  if (tryCli.status === 0 && tryCli.stdout.trim() !== "") {
    const out = tryCli.stdout.trim().replace(/"/g, "");
    if (/^-?\d+$/.test(out)) {
      return BigInt(out);
    }
  }

  // JSON-RPC simulateTransaction requires a full envelope; too heavy without SDK.
  // Documented fallback:
  console.warn(
    "[por] Could not read total_supply via stellar CLI. " +
      "Set WPI_TOTAL_SUPPLY_OVERRIDE=<stroops> or install Stellar CLI. " +
      `CLI stderr: ${(tryCli.stderr || "").slice(0, 200)}`,
  );
  throw new Error(
    "Unable to fetch wpi total_supply; set WPI_TOTAL_SUPPLY_OVERRIDE for offline/demo",
  );
}

function readPiBalance() {
  if (process.env.PI_CUSTODY_BALANCE_FILE) {
    const p = process.env.PI_CUSTODY_BALANCE_FILE;
    const v = readFileSync(p, "utf8").trim();
    if (!/^-?\d+$/.test(v)) {
      throw new Error(`PI_CUSTODY_BALANCE_FILE invalid content: ${p}`);
    }
    return {
      balance: BigInt(v),
      source: process.env.PI_BALANCE_SOURCE || "file",
    };
  }
  if (process.env.PI_CUSTODY_BALANCE !== undefined) {
    const v = String(process.env.PI_CUSTODY_BALANCE).trim();
    if (!/^-?\d+$/.test(v)) {
      throw new Error("PI_CUSTODY_BALANCE must be an integer string (stroops)");
    }
    return {
      balance: BigInt(v),
      source: process.env.PI_BALANCE_SOURCE || "env",
    };
  }
  throw new Error(
    "Set PI_CUSTODY_BALANCE or PI_CUSTODY_BALANCE_FILE (Pi reserve in stroops)",
  );
}

function cmdKeygen() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPub = publicKeyRaw(publicKey);
  // Export PKCS8 DER and extract 32-byte seed (last 32 bytes of PKCS8)
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  console.log("POR_ATTESTOR_PUBLIC_KEY=" + bufToHex(rawPub));
  console.log("POR_ATTESTOR_SECRET_KEY=" + bufToHex(seed));
  console.log(
    "\n# Save the secret offline. Commit only the public key to attestations/ATTESTOR_PUBLIC_KEY",
  );
  // Also write PEM examples to stdout tip
  console.log("\n# Optional PEM private key:\n");
  console.log(privateKey.export({ type: "pkcs8", format: "pem" }));
}

async function cmdAttest(unsigned) {
  const contractId = process.env.WPI_CONTRACT_ID;
  if (!contractId) throw new Error("WPI_CONTRACT_ID is required");
  const rpcUrl =
    process.env.STELLAR_SOROBAN_RPC_URL ||
    "https://soroban-testnet.stellar.org";
  const network = process.env.STELLAR_NETWORK || "testnet";
  const custodyAccount = process.env.PI_CUSTODY_ACCOUNT;
  if (!custodyAccount) throw new Error("PI_CUSTODY_ACCOUNT is required");
  const marginBps = Number(process.env.SAFETY_MARGIN_BPS || "0");
  if (!Number.isInteger(marginBps) || marginBps < 0 || marginBps > 10000) {
    throw new Error("SAFETY_MARGIN_BPS must be integer 0..10000");
  }

  const wpiSupply = await fetchTotalSupply(rpcUrl, contractId);
  const { balance: piBalance, source: piSource } = readPiBalance();
  const { status, collateral_ratio } = computeStatus(
    piBalance,
    wpiSupply,
    marginBps,
  );

  const issued_at = new Date().toISOString();
  const core = {
    schema_version: "1.0",
    issued_at,
    network,
    wpi_contract_id: contractId,
    wpi_total_supply: wpiSupply.toString(),
    pi_custody_account: custodyAccount,
    pi_custody_balance: piBalance.toString(),
    pi_balance_source: piSource,
    safety_margin_bps: marginBps,
  };

  const payload = canonicalPayload(core);
  let attestor_public_key = "";
  let signature = "";

  if (!unsigned) {
    const priv = loadPrivateKeyFromEnv();
    const pub = createPublicKey(priv);
    attestor_public_key = bufToHex(publicKeyRaw(pub));
    const sig = sign(null, Buffer.from(payload, "utf8"), priv);
    signature = bufToHex(sig);
    // self-check
    const ok = verify(
      null,
      Buffer.from(payload, "utf8"),
      pub,
      sig,
    );
    if (!ok) throw new Error("internal: signature self-verify failed");
  } else {
    attestor_public_key = process.env.POR_ATTESTOR_PUBLIC_KEY || "";
    signature = "";
  }

  const attestation = {
    ...core,
    collateral_ratio,
    status,
    attestor_public_key,
    signature,
    signed_fields: [...SIGNED_FIELDS],
  };

  const outPath = resolve(
    process.env.POR_OUT || join(REPO_ROOT, "attestations/latest.json"),
  );
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(attestation, null, 2) + "\n");

  // history snapshot next to the output file (skip if POR_HISTORY=0)
  if (process.env.POR_HISTORY !== "0") {
    const histDir = join(dirname(outPath), "history");
    mkdirSync(histDir, { recursive: true });
    const stamp = issued_at.replace(/[:.]/g, "-");
    writeFileSync(
      join(histDir, `${stamp}.json`),
      JSON.stringify(attestation, null, 2) + "\n",
    );
  }

  console.log(JSON.stringify(attestation, null, 2));
  console.log(`\nWrote ${outPath}`);
  if (status !== "healthy") {
    console.error(`\nWARNING: attestation status is ${status}`);
    process.exitCode = 2;
  }
}

const [cmd, ...rest] = process.argv.slice(2);
if (!cmd || cmd === "-h" || cmd === "--help") {
  usage();
  process.exit(cmd ? 0 : 1);
}

try {
  if (cmd === "keygen") {
    cmdKeygen();
  } else if (cmd === "attest") {
    await cmdAttest(rest.includes("--unsigned"));
  } else {
    usage();
    process.exit(1);
  }
} catch (e) {
  console.error("error:", e.message || e);
  process.exit(1);
}
