//! Real payroll finalizer.
//!
//! Aggregates a fully-contributed MuSig2 + silent-payment PSBT into a broadcastable
//! transaction using only the PSBT's public data — participant pubkeys, aggregate
//! derivation path, partial ECDH shares (with DLEQ proofs), nonces, and partial
//! signatures. Unlike the demo finalizer it never reconstructs private key material,
//! so it works on PSBTs built from a real wallet (`payroll`).

use anyhow::{anyhow, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use psbt::roles::{ExtractorPsbtExt, InputWitnessFinalizerPsbtExt};
use psbt::Psbt as SilentPaymentPsbt;
use secp256k1::Secp256k1;
use std::fs;
use std::path::{Path, PathBuf};

use crate::musig2_spdk::finalize_sp_outputs;
use crate::musig2_spdk::keyagg::build_tweaked_key_agg_ctx;
use crate::musig2_spdk::signing::aggregate_musig2_sigs;

#[derive(Debug, Clone)]
pub struct FinalizePayrollResult {
    pub final_psbt_path: PathBuf,
    pub final_tx_hex_path: PathBuf,
    pub txid: String,
    pub tx_hex: String,
    pub verified_outputs: usize,
}

/// Finalize a signed MuSig2 + SP payroll PSBT into a broadcastable transaction.
pub fn finalize_payroll(psbt_path: impl AsRef<Path>) -> Result<FinalizePayrollResult> {
    let psbt_path = psbt_path.as_ref();
    let secp = Secp256k1::new();
    let psbt_bytes = fs::read(psbt_path)
        .with_context(|| format!("failed to read PSBT {}", psbt_path.display()))?;
    let mut psbt = SilentPaymentPsbt::deserialize(&psbt_bytes).context("failed to parse PSBT")?;

    // Derive the SP output scripts from the aggregated cosigner ECDH shares. This is
    // the recipient-derivable output key, so a successful derivation is the
    // finalizer's confirmation that each SP output is discoverable.
    finalize_sp_outputs(&secp, &mut psbt)?;
    let verified_outputs = psbt
        .outputs
        .iter()
        .filter(|output| output.sp_v0_info.is_some())
        .count();

    // Rebuild the tweaked MuSig2 aggregation context from the PSBT's public fields.
    let mut participants = psbt.inputs[0].parse_musig2_participant_pubkeys()?;
    if participants.len() != 1 {
        return Err(anyhow!(
            "expected exactly one MuSig2 aggregate key on input 0, found {}",
            participants.len()
        ));
    }
    let (_agg_pk, participant_pks) = participants.remove(0);
    let path = psbt.inputs[0].musig2_agg_path();
    let (key_agg_ctx, _gacc) = build_tweaked_key_agg_ctx(&secp, &participant_pks, &path)?;

    // Aggregate the partial signatures already present in the PSBT and extract the tx.
    let message = compute_sighash(&psbt)?;
    aggregate_musig2_sigs(&mut psbt.inputs[0], &key_agg_ctx, &message)?;
    let psbt = psbt
        .clone()
        .finalize()
        .map_err(|e| anyhow!("finalize witnesses: {e:?}"))?;
    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|e| anyhow!("extract: {e:?}"))?;
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);

    let out_dir = psbt_path.parent().unwrap_or_else(|| Path::new("."));
    let final_psbt_path = out_dir.join("musig2-sp-final.psbt");
    let final_tx_hex_path = out_dir.join("musig2-sp-final-hex.txt");
    fs::write(&final_psbt_path, psbt.serialize())?;
    fs::write(&final_tx_hex_path, &tx_hex)?;

    Ok(FinalizePayrollResult {
        final_psbt_path,
        final_tx_hex_path,
        txid: tx.compute_txid().to_string(),
        tx_hex,
        verified_outputs,
    })
}

/// Taproot key-spend sighash over the finalized outputs. Reimplemented locally so
/// this real path carries no dependency on the demo workflow module.
fn compute_sighash(psbt: &SilentPaymentPsbt) -> Result<[u8; 32]> {
    let utxo = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow!("input 0 missing witness_utxo"))?;
    let prevouts = vec![TxOut {
        value: utxo.value,
        script_pubkey: utxo.script_pubkey.clone(),
    }];

    let tx = build_unsigned_tx(psbt);
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .map_err(|e| anyhow!("taproot sighash: {e}"))?;
    Ok(sighash.to_byte_array())
}

fn build_unsigned_tx(psbt: &SilentPaymentPsbt) -> Transaction {
    let input = psbt
        .inputs
        .iter()
        .map(|i| TxIn {
            previous_output: OutPoint::new(i.previous_txid, i.spent_output_index),
            script_sig: ScriptBuf::new(),
            sequence: i.sequence.unwrap_or(Sequence::MAX),
            witness: Witness::new(),
        })
        .collect();
    let output = psbt
        .outputs
        .iter()
        .map(|o| TxOut {
            value: bitcoin::Amount::from_sat(o.amount.to_sat()),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input,
        output,
    }
}
