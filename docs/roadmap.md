# silent-pay Roadmap

## Current State

`silent-pay` is a standalone Rust crate for payroll operations from a deterministic demo MuSig2 treasury to Silent Payments recipients.

Implemented:

- `build_payroll` creates the round-1 PSBT, cosigner contribution PSBT, and Coldcard descriptor.
- `finalize_payroll` aggregates MuSig2 signatures, extracts the final transaction, and verifies SP output discoverability.
- `scan_recipients` scans a PSBT for seed-backed recipients from `recipients.toml`.
- Shared workflow logic lives in library APIs so future GUI code can call the same operations.
- Demo recipients are loaded from `recipients.toml` instead of hard-coded Rust constants.
- Tests cover output discoverability, incomplete contributor rejection, invalid DLEQ rejection, repeated scan-key handling, and recipient config parsing.

## Ideas

- seperate the demo fixture creation from setup wallet using N of N xpubs
  - use different crates internally?

## Next Steps

### 1. Stabilize the CLI Workflow

- Add `README.md` with exact command examples for the full payroll flow.
- Document expected PSBT handoff points between coordinator and hardware signers.
- Add a small sample output directory description without committing generated PSBTs.
- Improve CLI errors for missing recipient files, unsigned PSBTs, and address-only recipients passed to `scan_recipients`.
- Add `--help` output tests or snapshot-style command smoke tests.

### 2. Recipient Wallet Model

- Evolve `recipients.toml` from a fixed demo list into a minimal recipient wallet file.
- Support recipient records with stable IDs, labels, amount defaults, and SP addresses.
- Keep seed-backed demo recipients only for testing and receiver-side validation.
- Add commands or library functions to:
  - list recipients
  - add recipient by Silent Payment address
  - update recipient label/default amount
  - build a payroll batch from selected recipients
- Keep private scan/spend seeds out of production sender configs.

### 3. Real Treasury Inputs

- Replace the fixture prevout with configurable treasury UTXO input data.
- Support configurable input amount, fee, and change amount.
- Validate that the MuSig2 descriptor path and input script match the selected treasury UTXO.
- Add guardrails for insufficient funds, dust outputs, and accidental mainnet/testnet mismatch.

### 4. Signing Flow Integration

- Decide how the coordinator imports signer-returned PSBTs for round 1 and round 2.
- Add explicit commands or API methods for each workflow phase:
  - create payroll PSBT
  - merge signer round-1 contributions
  - derive SP output scripts
  - merge round-2 signatures
  - finalize transaction
- Add tests for signer order independence and partial contribution merging.
- Keep DLEQ and output-script verification mandatory before signing/finalization.

### 5. GUI Preparation

- Keep all workflow logic in library APIs; bins should stay thin.
- Define GUI-facing result structs for:
  - payroll batch preview
  - signer contribution status
  - recipient scan results
  - final transaction summary
- Add progress/status enums that a Slint UI can bind to directly.
- Avoid GUI-specific dependencies until the CLI workflow is stable.

### 6. Slint GUI

- Build a single desktop GUI around the existing library API.
- Initial screens:
  - recipient wallet/batch editor
  - payroll build screen
  - PSBT handoff/status screen
  - finalize and scan verification screen
- Keep generated PSBT paths and signer status visible.
- Do not reimplement workflow logic in UI callbacks.

### 7. Production Hardening

- Replace deterministic demo key material with explicit treasury configuration.
- Add network selection and enforce it across treasury, recipients, and PSBT outputs.
- Add structured logging for coordinator operations.
- Add test vectors or fixtures for signed round-2 PSBT finalization.
- Review handling of proposed MuSig2 SP PSBT fields before treating the format as stable.

## Near-Term Acceptance Criteria

- A new user can run the full documented demo from `recipients.toml`.
- CLI output clearly identifies generated PSBTs, descriptor, recipient outputs, and final transaction files.
- Tests pass with `cargo test`.
- Binaries build with `cargo build --bins`.
- No generated PSBTs or smoke-test outputs are tracked by default.
