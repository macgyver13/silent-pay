# silent-pay

silent-pay is a desktop app for a MuSig2 Bitcoin treasury that pays recipients
via [Silent Payments](https://bips.dev/352/). It manages the treasury wallet and
its signers, tracks UTXOs, edits the recipient list, builds and finalizes the
payroll PSBT through a coordinator + hardware-signer handoff, and broadcasts the
final transaction via Bitcoin Core RPC.

## Run it

```sh
just pay
```

On launch the app loads your wallet and network configuration and opens the
treasury, UTXO, recipient, and finalize screens.

## What the app does

- Configure the treasury wallet and its MuSig2 signers.
- Derive receive and change addresses.
- Track and manage treasury UTXOs.
- Edit the recipient list (labels, amounts, Silent Payment addresses).
- Build the payroll PSBT.
- Finalize a signed PSBT into a broadcastable transaction.
- Broadcast the final transaction over Bitcoin Core RPC.

## Initial setup

The app reads its configuration from `~/.silent-pay/config.toml` (falling back to
`./config.toml` if `$HOME` is unset). The file is optional — every field has a
default, and the app writes it back whenever you change settings in the UI — but
creating it up front lets you point at your network and Bitcoin Core node before
first launch.

```toml
# ~/.silent-pay/config.toml
network = "testnet"                    # testnet, regtest, or bitcoin
data_dir = "."                         # where per-network wallet/utxos/recipients files live
fee_rate_sat_vb = 2                    # payroll build fee rate
dust_limit_sat = 546                   # outputs below this are rejected

rpc_url = "http://127.0.0.1:18332"     # Bitcoin Core RPC endpoint (for broadcast)
rpc_cookie_file = ""                   # path to Core's .cookie file, or...
rpc_user = ""                          # ...rpc user + password
rpc_password = ""
```

RPC authentication is resolved in order: a non-empty `rpc_cookie_file` is used
first; otherwise `rpc_user` + `rpc_password`; if all are empty, no auth is sent.
Only the broadcast step needs a reachable node.

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

Detailed prerequisites and a full workflow walkthrough are in
[docs/userguide.md](docs/userguide.md).

## Development

The workspace has two crates:

- `silent-pay` — the library and the `gui` binary (the app above).
- `sp-demo` — deterministic demo/fixture CLIs used for testing and receiver-side
  validation.

The demo CLIs exercise the full coordinator flow against fixed key material and
the recipients in [demo/recipients.toml](demo/recipients.toml):

| Recipe         | Purpose                                                        |
| -------------- | ------------------------------------------------------------- |
| `just payroll` | Build the demo payroll PSBTs and Coldcard descriptor          |
| `just finalize`| Finalize a signed demo PSBT into a broadcastable transaction  |
| `just scan`    | Scan the final PSBT for recipient Silent Payment outputs      |
| `just verify`  | Verify a single recipient receipt (address + scan key)        |
