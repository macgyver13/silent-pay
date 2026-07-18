# silent-pay User Guide

## Overview

silent-pay coordinates payroll-style payouts from a MuSig2 Bitcoin treasury to
recipients addressed with [Silent Payments](https://bips.dev/352/) (BIP-352).

A Silent Payment address (`sp1…` on mainnet, `tsp1…` on testnet) lets a sender
derive a unique on-chain output for a recipient without any interaction and
without linking payments on-chain.

The treasury is an N-of-N MuSig2 wallet: every signer must contribute before a
transaction can be finalized. The coordinator (this app) builds the PSBT and
merges signer contributions; the signers hold the keys. DLEQ proofs and
output-script verification are mandatory before a transaction is finalized, so
the coordinator can trust that each signer's Silent Payment contribution is
correct.

The workspace has two crates:

- `silent-pay` — the library plus the `silent-pay` binary (the desktop app).
- `sp-demo` — deterministic demo/fixture CLIs for testing and receiver-side
  validation.

## Prerequisites

- Rust (stable, edition 2021).
- [`just`](https://github.com/casey/just) for the task recipes.
- Git access to the forked dependencies the crates pull from:
  `spdk` and `rust-psbt` (both on their `musig2-working` branches).
- Slint's desktop runtime dependencies (platform GUI toolkit).
- A Bitcoin Core node for broadcasting. The RPC URL, cookie file, and
  user/password are configurable from within the app.

Addresses in the shipped demo are testnet Silent Payment addresses (`tsp1…`).

## Using the GUI

Launch with:

```sh
just pay
```

On startup the app reads its saved configuration (network, data directory, fee
rate, dust limit, and Bitcoin Core RPC settings) and, if a wallet file already
exists for the configured network, loads it automatically. Wallet, UTXO, and
recipient files are stored per network under the configured data directory.

The screens follow the payout lifecycle:

1. **Treasury wallet** — set the network and define the MuSig2 signers (each is
   a fingerprint `xfp`, a derivation path, and an `xpub`) or import a descriptor.
   Save to persist the wallet file.
2. **Addresses** — derive and copy the current receive and change addresses;
   advance the derivation indices as needed.
3. **UTXOs** — record the treasury UTXOs available to spend, mark spent ones,
   and select which UTXO funds the payroll.
4. **Recipients** — add, edit, and remove recipients (label, amount, Silent
   Payment address). Save to persist the recipient file.
5. **Build** — build the payroll PSBT and the signer descriptor from the
   selected UTXO and recipients, using the configured fee rate and dust limit.
6. **Finalize** — load the PSBT returned by the signers, finalize it into a
   broadcastable transaction, review the transaction hex, and broadcast it over
   Bitcoin Core RPC.

Configuration changes (data directory, network, fee/dust, RPC settings) are
saved back to the app config so the next launch picks them up.

## Setup

1. Clone the repository.
2. Install `just`.
3. For broadcasting, point the app at a reachable Bitcoin Core node (RPC URL and
   cookie file or user/password) and select the matching network.

### Demo / hardware-signer setup

The demo recipes hand PSBTs off to a Coldcard running MuSig2 + Silent Payment
firmware. See the Coldcard firmware PR for that support:
<https://github.com/Coldcard/firmware/pull/683>.

The demo recipes read two `justfile` variables you can override:

- `coldcard_path` — where `just payroll` writes the descriptor and PSBTs
  (defaults to the Coldcard firmware testing data directory,
  `~/src/coldcard-firmware/testing/data`).
- `cc_sp_out` — where the signed, merged final PSBT is expected
  (defaults to `/tmp/cc-sp-out`).

Override at invocation, e.g.:

```sh
just coldcard_path=/path/to/out cc_sp_out=/path/to/signed payroll
```

## Demo end-to-end workflow

The demo drives the full coordinator flow against fixed key material: a MuSig2
3-of-3 treasury and the recipients in
[demo/recipients.toml](../demo/recipients.toml). It exists for testing and
receiver-side validation, not production payouts.

1. **Build** — `just payroll` writes a round-1 PSBT, a cosigner-contribution
   PSBT, and a Coldcard descriptor into `coldcard_path`.
2. **Sign (hardware handoff)** — import the descriptor into the signers. Each
   signer returns its round-1 contribution (ECDH share + DLEQ proof) and round-2
   contribution (public nonce + partial signature). The merged, fully signed
   PSBT is expected at `cc_sp_out/musig2-sp-final.psbt`.
3. **Finalize** — `just finalize` finalizes the signed PSBT into a broadcastable
   transaction.
4. **Scan** — `just scan` scans the final PSBT and reports which recipient
   Silent Payment outputs were detected.
5. **Verify** — `just verify` verifies a single recipient receipt against its
   Silent Payment address and scan key (the shipped recipe uses `recipient-3`
   from `demo/recipients.toml`).

### PSBT handoff map

| Step           | Reads                              | Writes / produces                                   |
| -------------- | ---------------------------------- | --------------------------------------------------- |
| `just payroll` | `demo/recipients.toml`             | round-1 PSBT, cosigner-contribution PSBT, descriptor (in `coldcard_path`) |
| signers        | descriptor                         | `cc_sp_out/musig2-sp-final.psbt`                    |
| `just finalize`| `cc_sp_out/musig2-sp-final.psbt`   | broadcastable transaction                          |
| `just scan`    | `cc_sp_out/musig2-sp-final.psbt`, `demo/recipients.toml` | detected recipient outputs             |
| `just verify`  | `cc_sp_out/musig2-sp-final.psbt`   | receipt verification for one recipient             |

## recipients.toml reference

Each recipient is a `[[recipients]]` record:

| Field          | Description                                                        |
| -------------- | ----------------------------------------------------------------- |
| `label`        | Human-readable identifier for the recipient.                      |
| `amount_sat`   | Amount to pay, in satoshis.                                        |
| `address`      | The recipient's Silent Payment address (`tsp1…` on testnet).      |
| `scan_key_hex` | The recipient's scan private key, hex. Demo/receiver-side **only**.   |

`scan_key_hex` is present so the demo can scan and verify receipts from the
receiver's perspective. Production sender configs must not carry recipient scan
or spend secrets. The demo key material is generated by the `gen_demo_recipients`
binary and is for testing only.

## Troubleshooting

- **Missing recipients file** — pass `--recipients <path>` (the demo bins
  default to `recipients.toml` in the working directory).
- **Unsigned / incomplete PSBT** — finalization fails until every signer has
  contributed. Confirm the merged PSBT at `cc_sp_out/musig2-sp-final.psbt`
  contains all round-1 and round-2 contributions.
