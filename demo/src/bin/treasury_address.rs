//! Print a treasury wallet's receive or change address at a given derivation
//! index -- e.g. to know where to send funds before `fund_treasury` (regtest)
//! or an external funding step (signet), and before `build_round1` scans for
//! them.

use anyhow::{bail, Context, Result};
use bitcoin::Address;
use silent_pay::node::bitcoin_network;
use silent_pay::{derive_treasury_script_pubkey, load_wallet, CHANGE_CHAIN, RECEIVE_CHAIN};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = parse_args()?;
    let wallet = load_wallet(&args.wallet_path)?.normalized()?;
    let network = wallet.network_value()?;
    let index = args.index.unwrap_or(if args.chain == CHANGE_CHAIN {
        wallet.change_derivation_index
    } else {
        wallet.last_derivation_index
    });

    let script = derive_treasury_script_pubkey(&wallet, args.chain, index)?;
    let address = Address::from_script(&script, bitcoin_network(network))
        .context("failed to derive treasury address")?;

    println!("{address}");

    Ok(())
}

struct Args {
    wallet_path: PathBuf,
    chain: u32,
    index: Option<u32>,
}

fn parse_args() -> Result<Args> {
    let mut wallet_path = None;
    let mut chain = RECEIVE_CHAIN;
    let mut index = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wallet" => wallet_path = Some(PathBuf::from(next(&mut args, "--wallet")?)),
            "--chain" => {
                chain = match next(&mut args, "--chain")?.as_str() {
                    "receive" => RECEIVE_CHAIN,
                    "change" => CHANGE_CHAIN,
                    other => bail!("--chain must be receive or change, got {other}"),
                }
            }
            "--index" => index = Some(next(&mut args, "--index")?.parse()?),
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        wallet_path: wallet_path.ok_or_else(|| anyhow::anyhow!("missing --wallet"))?,
        chain,
        index,
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!("Usage: treasury_address --wallet wallet.toml [--chain receive|change] [--index N]");
}
