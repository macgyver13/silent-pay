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

1. Coordinator: create the initial PSBT. It is written as `frost-initial.psbt` beside the wallet.
2. Each companion: process that same initial PSBT and save an independent round-one PSBT named
   `frost-round-one.<share-id>.psbt`. Keep
   both companion instances running so their nonces remain in memory.
3. Coordinator: collect exactly those two round-one files, then export `frost-signing.psbt`.
4. Each original companion: review and process that same signing PSBT, then save an independent
   round-two PSBT named `frost-round-two.<share-id>.psbt`.
5. Coordinator: collect exactly those two round-two files, finalize, and export
   `frost-finalized.psbt` plus `frost-transaction.hex`.

The **Auto Process Wallet Folder** button on a companion reads `frost-initial.psbt` before round one and `frost-signing.psbt`
while it holds its nonce. It always writes the participant-specific file names above.

The coordinator has **Launch Companion 1**, **Launch Companion 2**, and **Launch Companion 3**
buttons. Each starts a companion with the matching share already loaded. **Auto Collect Round One**
and **Auto Collect Round Two** read the corresponding numbered files from the wallet folder, require
exactly two files, report their identities, and reject one or three files.

The transaction builder currently uses the example's single synthetic prevout, one deterministic
Silent Payment recipient, a 1,000 sat fee, and 9,000 sat change. It demonstrates the complete PSBT
and threshold cryptographic flow but is intentionally not a broadcast wallet.

FROST fields use the provisional top-level keytypes from `bip375-examples`: input configuration
`0x30`, commitments `0x31`, signature shares `0x32`, verifying shares `0x33`, and output participant
shares `0x20`. Demo protocol version, random session ID, and child path use local global keytypes
`0x50` through `0x52`.
