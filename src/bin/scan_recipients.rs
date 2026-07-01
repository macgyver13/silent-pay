use anyhow::{bail, Result};
use silent_pay::scan_recipients;
use std::path::PathBuf;

fn main() -> Result<()> {
    let (psbt_path, recipients_path) = parse_args()?;
    let result = scan_recipients(psbt_path, recipients_path)?;

    println!(
        "Scanning {} candidate P2TR output(s) for {} recipient(s)",
        result.candidate_outputs,
        result.recipient_results.len()
    );
    println!();
    for recipient in result.recipient_results {
        let label = recipient
            .label
            .as_deref()
            .map(|label| format!(" ({label})"))
            .unwrap_or_default();
        if recipient.detections.is_empty() {
            println!(
                "  recipient[{}]{} expected {} sats: NOT DETECTED",
                recipient.recipient_index, label, recipient.expected_amount_sat
            );
            continue;
        }
        for detection in recipient.detections {
            println!(
                "  recipient[{}]{} -> output[{}] {} sats{} (key {})",
                recipient.recipient_index,
                label,
                detection.output_index,
                detection.amount_sat,
                if detection.amount_matches {
                    ""
                } else {
                    " [AMOUNT MISMATCH]"
                },
                detection.xonly_hex
            );
        }
    }
    println!();
    println!("all recipient outputs detected");

    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf)> {
    let mut recipients_path = PathBuf::from("recipients.toml");
    let mut psbt_path = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--recipients" => {
                recipients_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--recipients requires a path"))?,
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

    Ok((
        psbt_path.ok_or_else(|| anyhow::anyhow!("missing PSBT path"))?,
        recipients_path,
    ))
}

fn print_usage() {
    eprintln!("Usage: scan_recipients <path_to_psbt> [--recipients recipients.toml]");
}
