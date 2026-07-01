use anyhow::{bail, Result};
use silent_pay::{build_payroll, BuildPayrollConfig};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = parse_args()?;
    let result = build_payroll(args)?;

    println!("MuSig2 + SP payroll builder");
    println!("{} SP recipients", result.recipient_count);
    println!("wrote {}", result.round1_psbt_path.display());
    println!("wrote {}", result.cosigner_contrib_psbt_path.display());
    println!("wrote {}", result.descriptor_path.display());
    println!("descriptor: {}", result.descriptor);
    println!();
    println!("SP output scripts:");
    for output in result.outputs {
        println!(
            "  [{}] {} BTC  {}",
            output.output_index,
            output.amount.to_btc(),
            output.script_pubkey_hex
        );
        println!("       -> {}", output.address);
    }

    Ok(())
}

fn parse_args() -> Result<BuildPayrollConfig> {
    let mut recipients_path = PathBuf::from("recipients.toml");
    let mut out_dir = PathBuf::from("output");
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--recipients" => {
                recipients_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--recipients requires a path"))?,
                );
            }
            "--out-dir" => {
                out_dir = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--out-dir requires a path"))?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(BuildPayrollConfig {
        recipients_path,
        out_dir,
    })
}

fn print_usage() {
    eprintln!("Usage: build_payroll [--recipients recipients.toml] [--out-dir output]");
}
