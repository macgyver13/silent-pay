//! Bitcoin Core RPC interaction for the payroll GUI: client construction,
//! transaction broadcast, and the `scantxoutset`-based funding-UTXO scan.
//!
//! This module owns all of the `bitcoincore-rpc` surface. The GUI orchestration
//! (threads, timers, UI state) lives in `gui.rs` and calls into here.

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{ScriptBuf, Txid};
use bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use silent_pay::{
    derive_treasury_script_pubkey, TreasuryWalletConfig, CHANGE_CHAIN, RECEIVE_CHAIN,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// How many indexes past the wallet's highest known index the funding scan
/// covers, on each of the receive and change chains.
pub const SCAN_GAP: u32 = 20;

/// Upper bound the scan client waits for the blocking `scantxoutset` response.
/// The scan itself finishes as soon as the node is done; this just has to be
/// longer than a full UTXO-set scan (the default 15s cuts the socket mid-scan).
pub const SCAN_RPC_TIMEOUT: Duration = Duration::from_secs(3600);

/// A funding output discovered by a scan, already mapped back to the treasury
/// `(chain, derivation_index)` that produced its scriptPubKey.
pub struct ScanUtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub chain: u32,
    pub derivation_index: u32,
}

pub struct ScanFindings {
    /// True when the scan was aborted (Bitcoin Core returned `success: false`).
    pub aborted: bool,
    pub utxos: Vec<ScanUtxo>,
}

pub fn rpc_auth(cookie_file: &str, user: &str, password: &str) -> Auth {
    let cookie_file = cookie_file.trim();
    if !cookie_file.is_empty() {
        return Auth::CookieFile(PathBuf::from(cookie_file));
    }

    if user.is_empty() && password.is_empty() {
        Auth::None
    } else {
        Auth::UserPass(user.to_string(), password.to_string())
    }
}

/// Client with the default request timeout, for short non-blocking calls
/// (broadcast, `scantxoutset` status/abort).
pub fn client(url: &str, auth: Auth) -> Result<Client> {
    Client::new(url, auth).context("failed to create RPC client")
}

/// Client with an explicit request timeout. `scantxoutset "start"` is a blocking
/// call that holds the connection open for the whole scan and returns the
/// results only in that response, so the scan client needs a timeout long enough
/// to outlast the scan.
pub fn client_with_timeout(url: &str, auth: Auth, timeout: Duration) -> Result<Client> {
    let (user, pass) = auth.get_user_pass().context("invalid RPC auth")?;
    let mut builder = bitcoincore_rpc::jsonrpc::simple_http::Builder::new()
        .url(url)
        .map_err(|err| anyhow!("invalid RPC url: {err}"))?
        .timeout(timeout);
    if let Some(user) = user {
        builder = builder.auth(user, pass);
    }
    let transport = builder.build();
    let jsonrpc = bitcoincore_rpc::jsonrpc::client::Client::with_transport(transport);
    Ok(Client::from_jsonrpc(jsonrpc))
}

pub fn broadcast(client: &Client, tx_hex: &str) -> Result<Txid> {
    client
        .send_raw_transaction(tx_hex)
        .context("Bitcoin Core sendrawtransaction failed")
}

/// Highest index the funding scan covers, derived from the wallet's known
/// receive/change indexes plus the gap limit.
pub fn scan_max_index(wallet: &TreasuryWalletConfig) -> u32 {
    wallet
        .last_derivation_index
        .max(wallet.change_derivation_index)
        .saturating_add(SCAN_GAP)
}

/// Derive the treasury scriptPubKeys for the given inclusive `(chain, start,
/// end)` index ranges and return (a) the `scantxoutset` requests for them and
/// (b) a map back from scriptPubKey to `(chain, derivation_index)` for labeling
/// the hits.
pub fn build_scan_plan(
    wallet: &TreasuryWalletConfig,
    ranges: &[(u32, u32, u32)],
) -> Result<(Vec<ScanTxOutRequest>, HashMap<ScriptBuf, (u32, u32)>)> {
    let mut requests = Vec::new();
    let mut script_index = HashMap::new();
    for &(chain, start, end) in ranges {
        for index in start..=end {
            let script = derive_treasury_script_pubkey(wallet, chain, index)?;
            requests.push(ScanTxOutRequest::Single(format!(
                "raw({})",
                hex::encode(script.as_bytes())
            )));
            script_index.insert(script, (chain, index));
        }
    }
    Ok((requests, script_index))
}

/// Run the blocking `scantxoutset` scan and map each unspent output back to its
/// treasury `(chain, derivation_index)`.
pub fn run_funding_scan(
    client: &Client,
    requests: &[ScanTxOutRequest],
    script_index: &HashMap<ScriptBuf, (u32, u32)>,
) -> Result<ScanFindings> {
    let result = match client.scan_tx_out_set_blocking(requests) {
        Ok(result) => result,
        Err(err) if is_scan_in_progress(&err) => {
            bail!("a UTXO-set scan is already running on this node — wait for it to finish (or use Cancel), then retry");
        }
        Err(err) => return Err(err).context("Bitcoin Core scantxoutset failed"),
    };
    if result.success != Some(true) {
        return Ok(ScanFindings {
            aborted: true,
            utxos: Vec::new(),
        });
    }
    let mut utxos = Vec::new();
    for unspent in &result.unspents {
        if let Some(&(chain, derivation_index)) = script_index.get(&unspent.script_pub_key) {
            utxos.push(ScanUtxo {
                txid: unspent.txid.to_string(),
                vout: unspent.vout,
                amount_sat: unspent.amount.to_sat(),
                chain,
                derivation_index,
            });
        }
    }
    Ok(ScanFindings {
        aborted: false,
        utxos,
    })
}

/// Poll the progress (0-100) of the scan currently running on the node, or
/// `None` when no scan is running (or the call fails).
pub fn scan_progress(client: &Client) -> Option<i64> {
    client
        .call::<serde_json::Value>("scantxoutset", &["status".into()])
        .ok()
        .and_then(|status| status.get("progress").and_then(|p| p.as_i64()))
}

/// Abort the scan currently running on the node. Returns whether a scan was
/// actually aborted.
pub fn abort_scan(client: &Client) -> Result<bool> {
    client
        .call("scantxoutset", &["abort".into()])
        .context("Bitcoin Core scantxoutset abort failed")
}

/// True when the error is Bitcoin Core's "scan already in progress" (RPC -8),
/// meaning another `scantxoutset` is running on the node.
fn is_scan_in_progress(err: &bitcoincore_rpc::Error) -> bool {
    matches!(
        err,
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc))
            if rpc.code == -8
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use silent_pay::parse_wallet;

    const TEST_WALLET_TOML: &str = r#"
network = "testnet"

[[signers]]
xfp = "0f056943"
derivation_path = "m/48h/1h/0h/3h"
xpub = "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez"

[[signers]]
xfp = "6ba6cfd0"
derivation_path = "m/48h/1h/0h/3h"
xpub = "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4"
"#;

    #[test]
    fn scan_plan_maps_each_script_back_to_its_chain_and_index() {
        let wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
        let max_index = 3;
        let (requests, script_index) = build_scan_plan(
            &wallet,
            &[(RECEIVE_CHAIN, 0, max_index), (CHANGE_CHAIN, 0, max_index)],
        )
        .unwrap();

        // Two chains x (max_index + 1) indexes.
        let expected = 2 * (max_index as usize + 1);
        assert_eq!(requests.len(), expected);
        assert_eq!(script_index.len(), expected);

        // Every derived script maps back to the exact (chain, index) that produces it.
        for chain in [RECEIVE_CHAIN, CHANGE_CHAIN] {
            for index in 0..=max_index {
                let script = derive_treasury_script_pubkey(&wallet, chain, index).unwrap();
                assert_eq!(script_index.get(&script), Some(&(chain, index)));
            }
        }

        // Requests are raw() descriptors of those scripts.
        let receive_script = derive_treasury_script_pubkey(&wallet, RECEIVE_CHAIN, 0).unwrap();
        let expected_req = format!("raw({})", hex::encode(receive_script.as_bytes()));
        assert!(requests
            .iter()
            .any(|req| matches!(req, ScanTxOutRequest::Single(desc) if *desc == expected_req)));
    }

    #[test]
    fn scan_plan_honors_a_non_zero_start_index() {
        let wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
        let (_, script_index) = build_scan_plan(&wallet, &[(RECEIVE_CHAIN, 3, 5)]).unwrap();

        // Exactly indexes 3, 4, 5 on the receive chain, nothing below the floor.
        assert_eq!(script_index.len(), 3);
        let mapped: Vec<(u32, u32)> = {
            let mut v: Vec<_> = script_index.values().copied().collect();
            v.sort();
            v
        };
        assert_eq!(
            mapped,
            vec![(RECEIVE_CHAIN, 3), (RECEIVE_CHAIN, 4), (RECEIVE_CHAIN, 5)]
        );
    }

    #[test]
    fn rpc_auth_uses_cookie_file_when_present() {
        match rpc_auth(" /tmp/bitcoin/.cookie ", "user", "password") {
            Auth::CookieFile(path) => assert_eq!(path, PathBuf::from("/tmp/bitcoin/.cookie")),
            auth => panic!("expected cookie auth, got {auth:?}"),
        }
    }

    #[test]
    fn rpc_auth_uses_user_pass_without_cookie_file() {
        match rpc_auth("", "user", "password") {
            Auth::UserPass(user, password) => {
                assert_eq!(user, "user");
                assert_eq!(password, "password");
            }
            auth => panic!("expected user/password auth, got {auth:?}"),
        }
    }
}
