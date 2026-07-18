use anyhow::{bail, Context, Result};
use psbt::Psbt as SilentPaymentPsbt;
use secp256k1::{Secp256k1, SecretKey};
use silentpayments::SilentPaymentAddress;
use sp_demo::verify_receipt;
use std::fs;
use std::path::PathBuf;

// TODO: the scan key is passed on the command line and is therefore visible in
// process listings and shell history. This is acceptable for the demo; a real
// tool should read it from a file or environment variable.
fn main() -> Result<()> {
    let args = parse_args()?;

    let psbt_bytes = match &args.psbt_source {
        PsbtSource::File(path) => {
            fs::read(path).with_context(|| format!("failed to read PSBT {}", path.display()))?
        }
        PsbtSource::Hex(hex_str) => {
            hex::decode(hex_str.trim()).context("failed to decode --psbt-hex")?
        }
    };
    let psbt = SilentPaymentPsbt::deserialize(&psbt_bytes).context("failed to parse PSBT")?;

    let address = SilentPaymentAddress::try_from(args.address.as_str())
        .map_err(|e| anyhow::anyhow!("invalid --address: {e}"))?;

    let scan_bytes =
        hex::decode(args.scan_key_hex.trim()).context("failed to decode --scan-key")?;
    let scan_sk =
        SecretKey::from_slice(&scan_bytes).context("--scan-key is not a valid secret key")?;

    let secp = Secp256k1::new();
    let result = verify_receipt(&secp, &psbt, &address, scan_sk)?;

    println!(
        "Scanning {} candidate P2TR output(s) for the supplied scan key",
        result.candidate_outputs
    );
    if result.detections.is_empty() {
        println!("RECEIPT NOT PROVEN");
        std::process::exit(1);
    }
    for detection in &result.detections {
        println!(
            "  output[{}] {} sats (key {})",
            detection.output_index, detection.amount_sat, detection.xonly_hex
        );
    }
    println!("receipt proven");

    Ok(())
}

struct Args {
    address: String,
    scan_key_hex: String,
    psbt_source: PsbtSource,
}

enum PsbtSource {
    File(PathBuf),
    Hex(String),
}

fn parse_args() -> Result<Args> {
    let mut address = None;
    let mut scan_key_hex = None;
    let mut psbt_hex = None;
    let mut psbt_path = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--address" => {
                address = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--address requires a value"))?,
                );
            }
            "--scan-key" => {
                scan_key_hex = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--scan-key requires a value"))?,
                );
            }
            "--psbt-hex" => {
                psbt_hex = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--psbt-hex requires a value"))?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            path if psbt_path.is_none() => psbt_path = Some(PathBuf::from(path)),
            other => bail!("unknown argument: {other}"),
        }
    }

    let psbt_source = match (psbt_path, psbt_hex) {
        (Some(_), Some(_)) => bail!("provide either a PSBT path or --psbt-hex, not both"),
        (Some(path), None) => PsbtSource::File(path),
        (None, Some(hex)) => PsbtSource::Hex(hex),
        (None, None) => bail!("missing PSBT: provide a path or --psbt-hex"),
    };

    Ok(Args {
        address: address.ok_or_else(|| anyhow::anyhow!("missing --address"))?,
        scan_key_hex: scan_key_hex.ok_or_else(|| anyhow::anyhow!("missing --scan-key"))?,
        psbt_source,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: verify_receipt --address <sp1...> --scan-key <hex> (<psbt-path> | --psbt-hex <hex>)"
    );
}
