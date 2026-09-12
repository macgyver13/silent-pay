//! Live Bitcoin Core network plumbing for a regtest/signet round trip:
//! self-funding on regtest, scanning for an existing signet deposit,
//! broadcast/confirmation, and on-chain receipt verification.
//!
//! Unlike `operations.rs`/`workflow.rs`, this module talks to a real node,
//! is not deterministic, and never synthesizes signer contributions -- it
//! only produces the real-UTXO inputs `build_initial_payroll_psbt` needs and
//! checks real chain state after a signed transaction is broadcast.

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{Address, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use silent_pay::node::{self, build_scan_plan, run_funding_scan, SCAN_GAP};
use silent_pay::{derive_treasury_script_pubkey, TreasuryPrevout, TreasuryWalletConfig};
use silentpayments::Network as SpNetwork;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Mine a treasury deposit and mature it, entirely on regtest. Never call this
/// against any other network -- there is no way to auto-fund signet or
/// mainnet, and this function refuses to try.
pub fn fund_regtest_treasury(
    client: &Client,
    wallet: &TreasuryWalletConfig,
    chain: u32,
    derivation_index: u32,
) -> Result<TreasuryPrevout> {
    let sp_network = wallet.network_value()?;
    if sp_network != SpNetwork::Regtest {
        bail!("fund_regtest_treasury only supports regtest wallets (got {sp_network:?})");
    }
    let network = node::bitcoin_network(sp_network);
    let script = derive_treasury_script_pubkey(wallet, chain, derivation_index)?;
    let address = Address::from_script(&script, network)
        .context("failed to derive treasury address")?;

    // One block funds the treasury; coinbase maturity needs 100 confirmations,
    // so mine 100 more on top of it. Paying every block to the same treasury
    // address avoids depending on a Core wallet for a throwaway address.
    let funding_hashes = client
        .generate_to_address(1, &address)
        .context("generatetoaddress (fund) failed")?;
    let funding_block_hash = funding_hashes
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("generatetoaddress returned no block hash"))?;
    client
        .generate_to_address(100, &address)
        .context("generatetoaddress (maturity) failed")?;

    let block = client
        .get_block(&funding_block_hash)
        .context("failed to fetch the funding block")?;
    let coinbase = block
        .txdata
        .first()
        .ok_or_else(|| anyhow!("mined block has no coinbase transaction"))?;
    let (vout, txout) = coinbase
        .output
        .iter()
        .enumerate()
        .find(|(_, out)| out.script_pubkey == script)
        .ok_or_else(|| anyhow!("coinbase does not pay the treasury address"))?;

    Ok(TreasuryPrevout {
        txid: coinbase.compute_txid(),
        vout: vout as u32,
        amount: txout.value,
        chain,
        derivation_index,
    })
}

/// Find an existing funded treasury UTXO by scanning the node's UTXO set --
/// the signet path, where funding is external (a pre-funded wallet) and this
/// only needs to locate it. Returns the largest funded UTXO found, if any.
pub fn scan_funded_prevout(
    client: &Client,
    wallet: &TreasuryWalletConfig,
) -> Result<Option<TreasuryPrevout>> {
    let max_index = wallet
        .last_derivation_index
        .max(wallet.change_derivation_index)
        .saturating_add(SCAN_GAP);
    let ranges = [(0, 0, max_index), (1, 0, max_index)];
    let (requests, script_index) = build_scan_plan(wallet, &ranges)?;
    let findings = run_funding_scan(client, &requests, &script_index)?;
    if findings.aborted {
        bail!("scantxoutset was aborted");
    }
    Ok(findings
        .utxos
        .into_iter()
        .max_by_key(|utxo| utxo.amount_sat)
        .map(|utxo| {
            Ok::<_, anyhow::Error>(TreasuryPrevout {
                txid: utxo.txid.parse().context("scan returned an invalid txid")?,
                vout: utxo.vout,
                amount: bitcoin::Amount::from_sat(utxo.amount_sat),
                chain: utxo.chain,
                derivation_index: utxo.derivation_index,
            })
        })
        .transpose()?)
}

/// Broadcast a finalized transaction and wait for at least one confirmation.
/// On regtest this mines the confirmation block itself, to `regtest_mine_to`
/// (any valid regtest address -- the treasury address is a convenient choice
/// since the caller already has it, avoiding any dependency on a Core
/// wallet). On any other network it polls `gettransaction` until Core reports
/// a confirmation or `timeout` elapses.
pub fn broadcast_and_confirm(
    client: &Client,
    tx_hex: &str,
    network: SpNetwork,
    regtest_mine_to: Option<&Address>,
    timeout: Duration,
) -> Result<Txid> {
    let txid = node::broadcast(client, tx_hex)?;
    if network == SpNetwork::Regtest {
        let confirmation_target = regtest_mine_to
            .ok_or_else(|| anyhow!("regtest confirmation requires a mine-to address"))?;
        client
            .generate_to_address(1, confirmation_target)
            .context("generatetoaddress (confirmation) failed")?;
        return Ok(txid);
    }

    let deadline = Instant::now() + timeout;
    loop {
        let confirmed = client
            .get_transaction(&txid, None)
            .map(|result| result.info.confirmations > 0)
            .unwrap_or(false);
        if confirmed {
            return Ok(txid);
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for {txid} to confirm after {timeout:?}");
        }
        sleep(Duration::from_secs(5));
    }
}

/// Cross-check each cryptographically-detected receipt against live chain
/// state: the exact `txid:vout` the scan found must actually be an unspent
/// output on the node, with the amount the scan reported. This is what turns
/// "the PSBT math says the recipient would detect it" into "the recipient's
/// wallet would actually detect and could spend it."
///
/// `detections` is `(output_index, amount_sat)` pairs, matching either
/// `verify_receipt`'s `ReceiptDetection` or `scan_recipients`'s
/// `DetectedOutput` -- both carry exactly this.
pub fn verify_onchain_receipt(
    client: &Client,
    txid: Txid,
    detections: &[(usize, u64)],
) -> Result<()> {
    if detections.is_empty() {
        bail!("no detections to verify on-chain");
    }
    for &(output_index, amount_sat) in detections {
        let vout = u32::try_from(output_index)
            .map_err(|_| anyhow!("output index {output_index} does not fit in u32"))?;
        let found = client
            .get_tx_out(&txid, vout, Some(true))
            .with_context(|| format!("gettxout failed for {txid}:{vout}"))?
            .ok_or_else(|| anyhow!("{txid}:{vout} is not an unspent output on this node"))?;
        if found.value.to_sat() != amount_sat {
            bail!(
                "{txid}:{vout} on-chain amount {} sat does not match detected amount {amount_sat} sat",
                found.value.to_sat(),
            );
        }
    }
    Ok(())
}
