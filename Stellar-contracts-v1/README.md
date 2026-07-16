# Stellar-contracts-v1

Soroban contracts deployed on **Stellar** (testnet/mainnet) for the PUSD decentralized reserve bridge:

| Crate        | WASM artifact   | Purpose                                      |
|-------------|-----------------|----------------------------------------------|
| `wpi-token` | `wpi_token.wasm` | Wrapped Pi minted by the relayer after Pi deposits |
| `mock-usdc` | `mock_usdc.wasm` | Test-only USDC stand-in for AMM / reserve sims |

## Requirements

- Rust stable + `wasm32-unknown-unknown` target
- Soroban CLI aligned with **soroban-sdk 23.0.1** (same as `Pusd-contracts-v1`)

## Build

```bash
cd Stellar-contracts-v1
cargo build --target wasm32-unknown-unknown --release
```

Artifacts: `target/wasm32-unknown-unknown/release/*.wasm`

## Deploy (Stellar testnet)

Use Stellar CLI / Soroban with Stellar testnet RPC and passphrase `Test SDF Network ; September 2015`.  
Initialize each contract with `initialize(admin_address)` after upload.

Set backend env:

- `STELLAR_SOROBAN_RPC_URL` — e.g. `https://soroban-testnet.stellar.org`
- `STELLAR_NETWORK_PASSPHRASE` — Stellar testnet passphrase
- `WPI_CONTRACT_ID` / `MOCK_USDC_CONTRACT_ID` — deployed contract IDs
- `BRIDGE_STELLAR_ADMIN_SECRET_KEY` — admin key that mints wPi (keep offline in production)

## DEX / AMM

Pool creation against Soroswap or another Stellar AMM is **not** included here; seed liquidity off-chain after deploying both tokens.

## End-to-End Testnet Simulation (Smoke Test)

To simulate the full deposit → mint → swap → burn lifecycle on the Stellar testnet, run the included script. This acts as the canonical "does the bridge work" smoke test across `wpi-token`, `mock-amm`, and `mock-usdc` (simulating the USDC SAC).

```bash
cd Stellar-contracts-v1
./testnet_e2e_simulation.sh
```

**What it does:**
1. Generates `relayer` and `alice` (user) identities and funds them via Friendbot.
2. Deploys the tokens and AMM to the Stellar testnet.
3. Seeds the Mock AMM with MockUSDC liquidity (as Admin).
4. Relayer mints wPi to Alice (Deposit).
5. Alice swaps wPi for MockUSDC (Swap).
6. Alice burns remaining wPi for withdrawal (Burn).
7. Verifies final balances match expectations.
