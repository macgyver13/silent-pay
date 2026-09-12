//! Verify recipient receipt for a broadcast, confirmed transaction: runs the
//! same cryptographic BIP-352 scan as `scan_recipients`, then cross-checks
//! each detected output against live chain state via `gettxout` -- proof
//! that a recipient's wallet would actually detect and could spend it, not
//! just that the PSBT math says so.

use anyhow::{bail, Result};
use silent_pay::node::{client, rpc_auth};
use sp_demo::live_cli::RpcArgs;
use sp_demo::{scan_recipients, verify_onchain_receipt};
use std::path::PathBuf;
use std::str::FromStr;

fn main() -> Result<()> {
    let args = parse_args()?;
    let result = scan_recipients(&args.psbt_path, &args.recipients_path)?;

    let auth = rpc_auth(&args.rpc.cookie, &args.rpc.user, &args.rpc.pass);
    let rpc_client = client(&args.rpc.url, auth)?;

    println!(
        "Scanning {} candidate P2TR output(s) for {} recipient(s)",
        result.candidate_outputs,
        result.recipient_results.len()
    );
    for recipient in &result.recipient_results {
        let label = recipient
            .label
            .as_deref()
            .map(|label| format!(" ({label})"))
            .unwrap_or_default();
        if recipient.detections.is_empty() {
            bail!(
                "recipient[{}]{label} expected {} sats: NOT DETECTED",
                recipient.recipient_index,
                recipient.expected_amount_sat
            );
        }
        let detections: Vec<(usize, u64)> = recipient
            .detections
            .iter()
            .map(|d| (d.output_index, d.amount_sat))
            .collect();
        verify_onchain_receipt(&rpc_client, args.txid, &detections)?;
        for detection in &recipient.detections {
            println!(
                "  recipient[{}]{label} -> output[{}] {} sats confirmed on-chain at {}:{}",
                recipient.recipient_index,
                detection.output_index,
                detection.amount_sat,
                args.txid,
                detection.output_index
            );
        }
    }
    println!();
    println!("all recipient outputs detected and confirmed on-chain");

    Ok(())
}

struct Args {
    psbt_path: PathBuf,
    recipients_path: PathBuf,
    txid: bitcoin::Txid,
    rpc: RpcArgs,
}

fn parse_args() -> Result<Args> {
    let mut recipients_path = PathBuf::from("recipients.toml");
    let mut psbt_path = None;
    let mut txid = None;
    let mut rpc = RpcArgs::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--recipients" => recipients_path = PathBuf::from(next(&mut args, "--recipients")?),
            "--txid" => {
                txid = Some(
                    bitcoin::Txid::from_str(&next(&mut args, "--txid")?)
                        .map_err(|e| anyhow::anyhow!("invalid --txid: {e}"))?,
                )
            }
            other if rpc.try_parse(other, &mut args)? => {}
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            path if psbt_path.is_none() => psbt_path = Some(PathBuf::from(path)),
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        psbt_path: psbt_path.ok_or_else(|| anyhow::anyhow!("missing PSBT path"))?,
        recipients_path,
        txid: txid.ok_or_else(|| anyhow::anyhow!("missing --txid"))?,
        rpc,
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: verify_onchain <path_to_final_psbt> --txid <broadcast txid> \
         [--recipients recipients.toml] [--rpc-url url] [--rpc-cookie path] \
         [--rpc-user u] [--rpc-pass p]"
    );
}
