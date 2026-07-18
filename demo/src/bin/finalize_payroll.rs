use anyhow::{bail, Result};
use silent_pay::finalize_payroll;
use std::path::PathBuf;

fn main() -> Result<()> {
    let psbt_path = parse_args()?;
    let result = finalize_payroll(psbt_path)?;

    println!("Final transaction");
    println!("txid: {}", result.txid);
    println!("hex:  {}", result.tx_hex);
    println!("verified {} SP output(s)", result.verified_outputs);
    println!("saved final PSBT to {}", result.final_psbt_path.display());
    println!("saved tx hex to {}", result.final_tx_hex_path.display());

    Ok(())
}

fn parse_args() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        print_usage();
        bail!("missing PSBT path");
    };
    if path == "-h" || path == "--help" {
        print_usage();
        std::process::exit(0);
    }
    if args.next().is_some() {
        bail!("finalize accepts exactly one PSBT path");
    }
    Ok(PathBuf::from(path))
}

fn print_usage() {
    eprintln!("Usage: finalize <path_to_signed.psbt>");
}
