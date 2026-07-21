# File-Based FROST Silent Payment Demo

This workspace member is an isolated proof of concept. It does not change the production Silent
Pay GUI and its plaintext share files must never control real funds.

Run the applications with:

```text
cargo run -p frost-demo --bin frost-coordinator
cargo run -p frost-demo --bin frost-companion
```

The coordinator provisions one public wallet file and three 2-of-3 companion share files. Start
two companion instances, load a different share in each, and exchange the files in this order:

1. Coordinator: create and save the initial PSBT.
2. Each companion: process that same initial PSBT and save an independent round-one PSBT. Keep
   both companion instances running so their nonces remain in memory.
3. Coordinator: collect exactly those two round-one files, then export the signing PSBT.
4. Each original companion: review and process that same signing PSBT, then save an independent
   round-two PSBT.
5. Coordinator: collect exactly those two round-two files, finalize, and export transaction hex.

The transaction builder currently uses the example's single synthetic prevout, one deterministic
Silent Payment recipient, a 1,000 sat fee, and 9,000 sat change. It demonstrates the complete PSBT
and threshold cryptographic flow but is intentionally not a broadcast wallet.

FROST fields use the provisional top-level keytypes from `bip375-examples`: input configuration
`0x30`, commitments `0x31`, signature shares `0x32`, verifying shares `0x33`, and output participant
shares `0x20`. Demo protocol version, random session ID, and child path use local global keytypes
`0x50` through `0x52`.
