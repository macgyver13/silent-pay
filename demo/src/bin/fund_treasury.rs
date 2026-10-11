//! Regtest-only diagnostic: mine and mature a treasury deposit, and print the
//! resulting prevout. `build_round1` does this itself when pointed at a
//! regtest wallet -- this exists to sanity-check mining/scan plumbing in
//! isolation, and to fund a treasury ahead of time for manual inspection.

use anyhow::{bail, Result};
use silent_pay::node::{client, rpc_auth};
use silent_pay::{load_wallet, CHANGE_CHAIN, RECEIVE_CHAIN};
use silentpayments::Network as SpNetwork;
use sp_demo::fund_regtest_treasury;
use sp_demo::live_cli::RpcArgs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = parse_args()?;
    let wallet = load_wallet(&args.wallet_path)?.normalized()?;
    if wallet.network_value()? != SpNetwork::Regtest {
        bail!(
            "fund_treasury only works on regtest wallets; for signet, fund the treasury \
             address externally and use build_round1 (which scans for it)"
        );
    }

    let auth = rpc_auth(&args.rpc.cookie, &args.rpc.user, &args.rpc.pass);
    let rpc_client = client(&args.rpc.url, auth)?;
    let index = args.index.unwrap_or(if args.chain == CHANGE_CHAIN {
        wallet.change_derivation_index
    } else {
        wallet.last_derivation_index
    });

    let prevout = fund_regtest_treasury(&rpc_client, &wallet, args.chain, index)?;
    println!("funded treasury deposit:");
    println!("  txid: {}", prevout.txid);
    println!("  vout: {}", prevout.vout);
    println!("  amount: {} sat", prevout.amount.to_sat());
    println!("  chain: {}", prevout.chain);
    println!("  derivation_index: {}", prevout.derivation_index);

    Ok(())
}

struct Args {
    wallet_path: PathBuf,
    chain: u32,
    index: Option<u32>,
    rpc: RpcArgs,
}

fn parse_args() -> Result<Args> {
    let mut wallet_path = None;
    let mut chain = RECEIVE_CHAIN;
    let mut index = None;
    let mut rpc = RpcArgs::default();

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
            other if rpc.try_parse(other, &mut args)? => {}
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
        rpc,
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: fund_treasury --wallet wallet.toml [--chain receive|change] [--index N] \
         [--rpc-url url] [--rpc-cookie path] [--rpc-user u] [--rpc-pass p]"
    );
}
