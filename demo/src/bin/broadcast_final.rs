//! Broadcast a finalized transaction (the `final_tx_hex_path` output of
//! `finalize`) and wait for a confirmation. On regtest this mines the
//! confirmation block itself, to the wallet's own receive address.

use anyhow::{Context, Result};
use bitcoin::Address;
use silent_pay::node::{bitcoin_network, client, rpc_auth};
use silent_pay::{derive_treasury_script_pubkey, load_wallet, RECEIVE_CHAIN};
use silentpayments::Network as SpNetwork;
use sp_demo::broadcast_and_confirm;
use sp_demo::live_cli::RpcArgs;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn main() -> Result<()> {
    let args = parse_args()?;
    let wallet = load_wallet(&args.wallet_path)?.normalized()?;
    let sp_network = wallet.network_value()?;
    let tx_hex = fs::read_to_string(&args.tx_hex_path)
        .with_context(|| format!("failed to read {}", args.tx_hex_path.display()))?;

    let auth = rpc_auth(&args.rpc.cookie, &args.rpc.user, &args.rpc.pass);
    let rpc_client = client(&args.rpc.url, auth)?;

    let mine_to = if sp_network == SpNetwork::Regtest {
        let script =
            derive_treasury_script_pubkey(&wallet, RECEIVE_CHAIN, wallet.last_derivation_index)?;
        Some(Address::from_script(&script, bitcoin_network(sp_network))?)
    } else {
        None
    };

    let txid = broadcast_and_confirm(
        &rpc_client,
        tx_hex.trim(),
        sp_network,
        mine_to.as_ref(),
        Duration::from_secs(args.timeout_secs),
    )?;
    println!("broadcast and confirmed: {txid}");

    Ok(())
}

struct Args {
    wallet_path: PathBuf,
    tx_hex_path: PathBuf,
    timeout_secs: u64,
    rpc: RpcArgs,
}

fn parse_args() -> Result<Args> {
    let mut wallet_path = None;
    let mut tx_hex_path = None;
    let mut timeout_secs = 600;
    let mut rpc = RpcArgs::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wallet" => wallet_path = Some(PathBuf::from(next(&mut args, "--wallet")?)),
            "--tx-hex-file" => tx_hex_path = Some(PathBuf::from(next(&mut args, "--tx-hex-file")?)),
            "--timeout-secs" => timeout_secs = next(&mut args, "--timeout-secs")?.parse()?,
            other if rpc.try_parse(other, &mut args)? => {}
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        wallet_path: wallet_path.ok_or_else(|| anyhow::anyhow!("missing --wallet"))?,
        tx_hex_path: tx_hex_path.ok_or_else(|| anyhow::anyhow!("missing --tx-hex-file"))?,
        timeout_secs,
        rpc,
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: broadcast_final --wallet wallet.toml --tx-hex-file final-hex.txt \
         [--timeout-secs 600] [--rpc-url url] [--rpc-cookie path] [--rpc-user u] [--rpc-pass p]"
    );
}
