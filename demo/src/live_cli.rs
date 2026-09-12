//! Shared Bitcoin Core RPC argument parsing for the live-network demo CLIs
//! (`build_round1`, `fund_treasury`, `broadcast_final`, `verify_onchain`).

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct RpcArgs {
    pub url: String,
    pub cookie: String,
    pub user: String,
    pub pass: String,
}

impl Default for RpcArgs {
    /// `18443` is Bitcoin Core's default regtest RPC port.
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:18443".to_string(),
            cookie: String::new(),
            user: String::new(),
            pass: String::new(),
        }
    }
}

impl RpcArgs {
    /// Consume `flag` (and its value, from `args`) if it names one of the RPC
    /// flags. Returns whether it matched, so callers can fall through to
    /// their own argument handling otherwise.
    pub fn try_parse(
        &mut self,
        flag: &str,
        args: &mut impl Iterator<Item = String>,
    ) -> Result<bool> {
        match flag {
            "--rpc-url" => self.url = next(args, flag)?,
            "--rpc-cookie" => self.cookie = next(args, flag)?,
            "--rpc-user" => self.user = next(args, flag)?,
            "--rpc-pass" => self.pass = next(args, flag)?,
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn next(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}
