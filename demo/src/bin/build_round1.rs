//! Real-network counterpart to `payroll`: builds the initial, unsigned PSBT
//! and descriptor from an actual funded treasury UTXO on regtest or signet,
//! instead of the demo's static fixture prevout. No signer contributions are
//! added here -- the resulting PSBT + descriptor is the artifact handed off
//! for real signer rounds (e.g. via `bip375-interop`).

use anyhow::{bail, Context, Result};
use silent_pay::node::{client_with_timeout, rpc_auth, SCAN_RPC_TIMEOUT};
use silent_pay::{
    build_initial_payroll_psbt, load_wallet, BuildInitialPayrollConfig, CHANGE_CHAIN,
    RECEIVE_CHAIN,
};
use silentpayments::Network as SpNetwork;
use sp_demo::live_cli::RpcArgs;
use sp_demo::{fund_regtest_treasury, scan_funded_prevout};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = parse_args()?;
    let wallet = load_wallet(&args.wallet_path)?.normalized()?;
    let network = wallet.network_value()?;

    // `scantxoutset` blocks for as long as a full UTXO-set scan takes (minutes
    // on a real node), so this needs the long-timeout client, not the default
    // short one meant for status/broadcast calls -- see node::client_with_timeout.
    let auth = rpc_auth(&args.rpc.cookie, &args.rpc.user, &args.rpc.pass);
    let rpc_client = client_with_timeout(&args.rpc.url, auth, SCAN_RPC_TIMEOUT)?;

    let prevout = match network {
        SpNetwork::Regtest => {
            fund_regtest_treasury(&rpc_client, &wallet, args.chain, args.index)?
        }
        _ => scan_funded_prevout(&rpc_client, &wallet)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no funded treasury UTXO found on {network:?}; fund the wallet's receive/change \
                 addresses first (fund_treasury only works on regtest)"
            )
        })?,
    };

    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("failed to create {}", args.out_dir.display()))?;
    let psbt_path = args.out_dir.join("initial.psbt");
    let mut config = BuildInitialPayrollConfig::new(
        wallet,
        &args.recipients_path,
        prevout,
        &psbt_path,
    );
    if let Some(fee_sat) = args.fee_sat {
        config.fee = bitcoin::Amount::from_sat(fee_sat);
    }
    if let Some(dust_sat) = args.dust_sat {
        config.dust_limit = bitcoin::Amount::from_sat(dust_sat);
    }

    let result = build_initial_payroll_psbt(config)?;
    let descriptor_path = args.out_dir.join("descriptor.txt");
    fs::write(&descriptor_path, &result.descriptor)
        .with_context(|| format!("failed to write {}", descriptor_path.display()))?;

    println!("wrote {}", result.psbt_path.display());
    println!("wrote {}", descriptor_path.display());
    println!("descriptor: {}", result.descriptor);
    println!("{} recipient(s), {} total sat", result.recipient_count, result.total_output_sat);
    if let Some(change_sat) = result.change_sat {
        println!("change: {change_sat} sat");
    }
    println!("effective fee: {} sat", result.effective_fee_sat);

    Ok(())
}

struct Args {
    wallet_path: PathBuf,
    recipients_path: PathBuf,
    out_dir: PathBuf,
    chain: u32,
    index: u32,
    fee_sat: Option<u64>,
    dust_sat: Option<u64>,
    rpc: RpcArgs,
}

fn parse_args() -> Result<Args> {
    let mut wallet_path = None;
    let mut recipients_path = None;
    let mut out_dir = PathBuf::from("output");
    let mut chain = RECEIVE_CHAIN;
    let mut index = None;
    let mut fee_sat = None;
    let mut dust_sat = None;
    let mut rpc = RpcArgs::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--wallet" => wallet_path = Some(PathBuf::from(next(&mut args, "--wallet")?)),
            "--recipients" => {
                recipients_path = Some(PathBuf::from(next(&mut args, "--recipients")?))
            }
            "--out-dir" => out_dir = PathBuf::from(next(&mut args, "--out-dir")?),
            "--chain" => {
                chain = match next(&mut args, "--chain")?.as_str() {
                    "receive" => RECEIVE_CHAIN,
                    "change" => CHANGE_CHAIN,
                    other => bail!("--chain must be receive or change, got {other}"),
                }
            }
            "--index" => index = Some(next(&mut args, "--index")?.parse()?),
            "--fee-sat" => fee_sat = Some(next(&mut args, "--fee-sat")?.parse()?),
            "--dust-sat" => dust_sat = Some(next(&mut args, "--dust-sat")?.parse()?),
            other if rpc.try_parse(other, &mut args)? => {}
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let wallet_path = wallet_path.ok_or_else(|| anyhow::anyhow!("missing --wallet"))?;
    let index = match index {
        Some(index) => index,
        None => {
            let wallet = load_wallet(&wallet_path)?;
            if chain == CHANGE_CHAIN {
                wallet.change_derivation_index
            } else {
                wallet.last_derivation_index
            }
        }
    };

    Ok(Args {
        wallet_path,
        recipients_path: recipients_path
            .ok_or_else(|| anyhow::anyhow!("missing --recipients"))?,
        out_dir,
        chain,
        index,
        fee_sat,
        dust_sat,
        rpc,
    })
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "Usage: build_round1 --wallet wallet.toml --recipients recipients.toml \
         [--out-dir output] [--chain receive|change] [--index N] [--fee-sat N] \
         [--dust-sat N] [--rpc-url url] [--rpc-cookie path] [--rpc-user u] [--rpc-pass p]"
    );
}
