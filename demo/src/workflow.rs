//! Pure musig2-signer workflow logic.
//!
//! Each function corresponds to one step in the 10-step MuSig2 + BIP-375
//! silent payment workflow, independent of CLI or GUI concerns.

use anyhow::{bail, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use musig2::SecNonce;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

use psbt::core::utils::to_psbt_dleq;
use psbt::{generate_dleq_proof, verify_dleq_proof, Psbt};
use psbt_v2::{Output, PartialEcdhShareData};

use psbt::musig2::{build_psbt, finalize_sp_outputs};
use psbt::roles::musig2_signer as signing;

/// Build the 66-byte PSBT_OUT_SP_V0_INFO payload (scan_key || spend_key).
fn sp_v0_info_bytes(address: &SilentPaymentAddress) -> [u8; 66] {
    let mut bytes = [0u8; 66];
    bytes[..33].copy_from_slice(&address.get_scan_key().serialize());
    bytes[33..].copy_from_slice(&address.get_spend_key().serialize());
    bytes
}

/// How the per-index MuSig2 aggregate key is produced. Mirrors
/// `psbt::musig2::keyagg::AggregationMode`; kept as a separate demo-local type so
/// this crate does not need to depend on that module's private plumbing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyArch {
    /// BIP-328 synthetic derivation: aggregate the account-level participant keys,
    /// then derive the aggregate along `[0, sub_index]`. Matches the COLDCARD/Jade
    /// firmware and the signet interop demonstration -- the participant secret is
    /// account-level and never re-derived, so a partial ECDH share for a given
    /// scan key is identical at every index.
    AggregateThenDerive,
    /// BIP-390 ranged participants: derive each participant along
    /// `[0, sub_index]` first, then aggregate. Not exercised by any firmware yet --
    /// proof of concept only. The participant secret is a per-index child, so a
    /// partial ECDH share for a given scan key differs at every index.
    DeriveThenAggregate,
}

/// Static key material for the demo.
pub struct KeySetup {
    pub alice_sk: SecretKey,
    pub bob_sk: SecretKey,
    pub charlie_sk: SecretKey,
    pub alice_pk: PublicKey,
    pub bob_pk: PublicKey,
    pub charlie_pk: PublicKey,
    /// Pre-taproot-tweak aggregate pubkey — used as
    /// PSBT_IN/OUT_MUSIG2_PARTICIPANT_PUBKEYS keydata per BIP-373: "computed as
    /// specified in BIP-327 with no tweaks applied". Under `AggregateThenDerive`
    /// this is the bare aggregate of the account-level participants (before the
    /// BIP-328 derivation); under `DeriveThenAggregate` there is no separate
    /// account-level stage, so this is the bare aggregate of the already-derived
    /// participants.
    pub untweaked_agg_pk: PublicKey,
    /// Pre-taproot-tweak aggregate xonly — used in TAP_BIP32_DERIVATION entries
    /// and as the taproot internal key.
    pub untweaked_agg_xonly: bitcoin::key::XOnlyPublicKey,
    /// Post-tweak (taproot) aggregate pubkey — used for the P2TR scriptPubKey.
    pub agg_pk: PublicKey,
    pub agg_xonly: bitcoin::key::XOnlyPublicKey,
    pub key_agg_ctx: musig2::KeyAggContext,
    pub p2tr_script: ScriptBuf,
    pub scan_pk: PublicKey,
    pub scan_sk: SecretKey,
    pub sp_address: SilentPaymentAddress,
    /// Which key architecture produced this key material. `construct_psbt` reads
    /// this to decide whether to record a synthetic aggregate-derivation origin
    /// (`AggregateThenDerive`) or omit it (`DeriveThenAggregate`) -- see
    /// rust-psbt's `musig2_agg_path` doc comment for why the absence must be
    /// meaningful rather than defaulted.
    pub key_arch: KeyArch,
}

/// Index used by the demo fixtures for whichever derivation `KeyArch` implies:
/// under `AggregateThenDerive` it is the synthetic `/0/*` leaf on the aggregate
/// key; under `DeriveThenAggregate` it is each participant's own `/0/*` leaf. The
/// aggregate key, scriptPubKey, and PSBT derivation metadata all derive from this,
/// so build_payroll and finalize_payroll share this one source of truth to stay in
/// sync. Change this to regenerate fixtures at a different index.
pub const DEMO_SP_INDEX: u32 = 3;

/// Generate deterministic demo key material and aggregate the MuSig2 key.
///
/// `sub_index` is the `/0/*` leaf index; see [`DEMO_SP_INDEX`] and [`KeyArch`] for
/// which key it is derived on.
pub fn setup_keys(
    secp: &Secp256k1<secp256k1::All>,
    sub_index: u32,
    arch: KeyArch,
) -> Result<KeySetup> {
    use bip39::Mnemonic;
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use std::str::FromStr;

    type HmacSha512 = Hmac<Sha512>;

    let mnemonic_str = "wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify";
    let mnemonic =
        Mnemonic::parse(mnemonic_str).map_err(|e| anyhow::anyhow!("Mnemonic parse: {e}"))?;

    let account_path = DerivationPath::from_str("m/48'/1'/0'/3'")
        .map_err(|e| anyhow::anyhow!("Path parse: {e}"))?;

    let alice_master = {
        let seed = mnemonic.to_seed("");
        Xpriv::new_master(bitcoin::Network::Testnet, &seed)?.derive_priv(secp, &account_path)?
    };
    let bob_master = {
        let seed = mnemonic.to_seed("Me");
        Xpriv::new_master(bitcoin::Network::Testnet, &seed)?.derive_priv(secp, &account_path)?
    };
    let charlie_master = {
        let seed = mnemonic.to_seed("Myself");
        Xpriv::new_master(bitcoin::Network::Testnet, &seed)?.derive_priv(secp, &account_path)?
    };

    // Under AggregateThenDerive the participant secrets stay account-level; the
    // per-index derivation happens on the aggregate below. Under
    // DeriveThenAggregate each participant is derived at [0, sub_index] first,
    // and aggregation applies no further per-index tweak.
    let (alice_sk, bob_sk, charlie_sk) = match arch {
        KeyArch::AggregateThenDerive => (
            alice_master.private_key,
            bob_master.private_key,
            charlie_master.private_key,
        ),
        KeyArch::DeriveThenAggregate => {
            let index_path: DerivationPath =
                [0u32, sub_index].iter().map(|&n| ChildNumber::from(n)).collect();
            (
                alice_master.derive_priv(secp, &index_path)?.private_key,
                bob_master.derive_priv(secp, &index_path)?.private_key,
                charlie_master.derive_priv(secp, &index_path)?.private_key,
            )
        }
    };

    let alice_pk = PublicKey::from_secret_key(secp, &alice_sk);
    let bob_pk = PublicKey::from_secret_key(secp, &bob_sk);
    let charlie_pk = PublicKey::from_secret_key(secp, &charlie_sk);

    // BIP-327 KeySort: sort by 33-byte compressed representation before aggregating
    let mut participants = vec![alice_pk, bob_pk, charlie_pk];
    participants.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

    let musig_participants: Vec<musig2::secp256k1::PublicKey> = participants
        .iter()
        .map(|pk| musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap())
        .collect();

    let key_agg_ctx = musig2::KeyAggContext::new(musig_participants)
        .map_err(|e| anyhow::anyhow!("Key Aggregation: {e}"))?;

    let p_base: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let p_base_bitcoin = PublicKey::from_slice(&p_base.serialize())?;

    // Bare (pre-taproot-tweak) aggregate pubkey. Under AggregateThenDerive this is
    // the account-level aggregate, still needing the BIP-328 layer below. Under
    // DeriveThenAggregate the participants are already per-index, so this value
    // needs no further plain tweak.
    let untweaked_agg_pk = p_base_bitcoin;

    let (key_agg_ctx, untweaked_agg_xonly) = match arch {
        KeyArch::AggregateThenDerive => {
            // BIP-328 synthetic xpub chaincode (SHA256 of "MuSig2MuSig2MuSig2")
            let mut current_chaincode =
                hex::decode("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")
                    .map_err(|e| anyhow::anyhow!("Chaincode decode: {e}"))?;
            let mut current_pk = p_base_bitcoin;

            let derivation_indices = [0u32, sub_index];
            let mut tweaks = Vec::new();

            for index in derivation_indices {
                let mut data = Vec::new();
                data.extend_from_slice(&current_pk.serialize());
                data.extend_from_slice(&index.to_be_bytes());

                let mut mac = HmacSha512::new_from_slice(&current_chaincode)
                    .map_err(|e| anyhow::anyhow!("HMAC init: {e}"))?;
                mac.update(&data);
                let result = mac.finalize().into_bytes();

                let il = &result[0..32];
                let ir = &result[32..64];

                let scalar = secp256k1::Scalar::from_be_bytes(il.try_into()?)
                    .map_err(|e| anyhow::anyhow!("Scalar from BE: {e}"))?;
                tweaks.push(il.to_vec());

                current_pk = current_pk
                    .add_exp_tweak(secp, &scalar)
                    .map_err(|e| anyhow::anyhow!("Add exp tweak: {e}"))?;
                current_chaincode = ir.to_vec();
            }

            // Tweak the KeyAggContext with derived plain tweaks
            let mut key_agg_ctx = key_agg_ctx;
            for tweak in &tweaks {
                let tweak_arr: [u8; 32] = tweak.as_slice().try_into()?;
                let musig_scalar = musig2::secp256k1::Scalar::from_be_bytes(tweak_arr)
                    .map_err(|e| anyhow::anyhow!("MuSig Scalar from BE: {e}"))?;
                key_agg_ctx = key_agg_ctx
                    .with_plain_tweak(musig_scalar)
                    .map_err(|e| anyhow::anyhow!("With plain tweak: {e}"))?;
            }

            let tweaked_agg_pk_031: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
            let tweaked_agg_pk_bitcoin = PublicKey::from_slice(&tweaked_agg_pk_031.serialize())?;
            assert_eq!(current_pk, tweaked_agg_pk_bitcoin);

            // untweaked_agg_xonly is the x-only of the derived child key (/0/<sub_index>) before taproot tweak
            let (untweaked_agg_xonly, _) = current_pk.x_only_public_key();
            (key_agg_ctx, untweaked_agg_xonly)
        }
        KeyArch::DeriveThenAggregate => {
            // Participants are already the per-index children; there is no
            // BIP-328 layer, so the bare aggregate computed above is also the
            // pre-taproot-tweak internal key.
            let (untweaked_agg_xonly, _) = p_base_bitcoin.x_only_public_key();
            (key_agg_ctx, untweaked_agg_xonly)
        }
    };

    // Apply BIP-341 taproot tweak (no script tree => unspendable taproot tweak).
    let key_agg_ctx = key_agg_ctx
        .with_unspendable_taproot_tweak()
        .map_err(|e| anyhow::anyhow!("Taproot tweak failed: {e}"))?;

    // Extract the tweaked x-only key and convert to 0.29
    let tweaked_xonly_031: musig2::secp256k1::XOnlyPublicKey = key_agg_ctx.aggregated_pubkey();
    let agg_xonly = bitcoin::key::XOnlyPublicKey::from_slice(&tweaked_xonly_031.serialize())?;

    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(agg_xonly),
    );

    // Tweaked aggregate pubkey with its actual Y parity (used in BIP-373 metadata)
    let tweaked_full: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
    let agg_pk = PublicKey::from_slice(&tweaked_full.serialize())?;

    let scan_sk = SecretKey::from_slice(&[0x11_u8; 32])?;
    let spend_sk = SecretKey::from_slice(&[0x22_u8; 32])?;
    let scan_pk = PublicKey::from_secret_key(secp, &scan_sk);
    let spend_pk = PublicKey::from_secret_key(secp, &spend_sk);
    let sp_address =
        SilentPaymentAddress::new(scan_pk, spend_pk, SpNetwork::Mainnet, SpVersion::ZERO);

    Ok(KeySetup {
        alice_sk,
        bob_sk,
        charlie_sk,
        alice_pk,
        bob_pk,
        charlie_pk,
        untweaked_agg_pk,
        untweaked_agg_xonly,
        agg_pk,
        agg_xonly,
        key_agg_ctx,
        p2tr_script,
        scan_pk,
        scan_sk,
        sp_address,
        key_arch: arch,
    })
}

/// Create the PSBT with 1 MuSig2 P2TR input and N+1 outputs (N SP recipients + change).
///
/// `recipients` is a slice of (SP address, payment amount) pairs. A change output
/// returning to the same MuSig2 script is appended automatically (9 000 sats).
pub fn construct_psbt(
    keys: &KeySetup,
    recipients: &[(SilentPaymentAddress, Amount)],
) -> Result<Psbt> {
    let total_payment: u64 = recipients.iter().map(|(_, a)| a.to_sat()).sum();
    let change_amount = Amount::from_sat(9_000);
    let fee = Amount::from_sat(1_000);
    let input_amount = Amount::from_sat(total_payment) + change_amount + fee;

    // N silent-payment outputs (script computed later) + 1 change output to the
    // same MuSig2 script. `build_psbt` shuffles outputs (BIP-375), so SP vs change
    // is distinguished by `sp_v0_info`, not position.
    let mut outputs: Vec<Output> = recipients
        .iter()
        .map(|(addr, amount)| {
            let mut o = Output::new(TxOut {
                value: *amount,
                script_pubkey: ScriptBuf::new(),
            });
            o.sp_v0_info = Some(sp_v0_info_bytes(addr).into());
            o
        })
        .collect();
    outputs.push(Output::new(TxOut {
        value: change_amount,
        script_pubkey: keys.p2tr_script.clone(),
    }));

    let mut psbt = build_psbt(vec![OutPoint::new(Txid::all_zeros(), 0)], outputs)?;
    // Updater role: attach the funding UTXO the signers and finalizers spend.
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: input_amount,
        script_pubkey: keys.p2tr_script.clone(),
    });

    // PSBT_IN_TAP_INTERNAL_KEY holds the untweaked aggregate P (BIP-341/BIP-371);
    // the taproot tweak is applied when verifying the output key.
    psbt.inputs[0].tap_internal_key = Some(keys.untweaked_agg_xonly);
    psbt.inputs[0].set_musig2_participant_pubkeys(
        &keys.untweaked_agg_pk,
        &[keys.alice_pk, keys.bob_pk, keys.charlie_pk],
    );
    if keys.key_arch == KeyArch::AggregateThenDerive {
        // The aggregate MuSig2 key's [0, DEMO_SP_INDEX] child-derivation path is
        // stored as a TAP_BIP32_DERIVATION entry (BIP-373), not the BIP-376
        // SP-spend field. The finalizer reads it back to re-derive the aggregate
        // child for ECDH. Under DeriveThenAggregate there is no synthetic
        // derivation to record: the aggregate is built directly from the already-
        // derived participants, so this entry must be absent -- see rust-psbt's
        // `musig2_agg_path` doc comment for why the combiner must not default a
        // missing entry to [0, 0].
        psbt.inputs[0].set_musig2_agg_derivation(
            &keys.untweaked_agg_pk,
            keys.untweaked_agg_xonly,
            0,
            DEMO_SP_INDEX,
        );
    }

    // BIP-373: tag the change output (the non-SP output) with the participant
    // pubkeys to aid change detection.
    for output in psbt.outputs.iter_mut() {
        if output.sp_v0_info.is_none() {
            output.set_musig2_participant_pubkeys(
                &keys.untweaked_agg_pk,
                &[keys.alice_pk, keys.bob_pk, keys.charlie_pk],
            );
        }
    }

    Ok(psbt)
}

/// Add one party's partial ECDH share (with DLEQ proof) to the PSBT.
///
/// Returns an error if the DLEQ proof self-check fails.
pub fn add_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    scan_pk: &PublicKey,
) -> Result<()> {
    // Partial ECDH share: C_i = sk_i * B_scan.
    let scalar: Scalar = (*party_sk).into();
    let partial_share = scan_pk
        .mul_tweak(secp, &scalar)
        .map_err(|e| anyhow::anyhow!("{party_name} ECDH: {e}"))?;

    let rand_aux = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&party_pk.serialize()[1..]);
        r
    };
    let dleq_proof = generate_dleq_proof(secp, party_sk, scan_pk, &rand_aux, None)
        .map_err(|e| anyhow::anyhow!("{party_name} DLEQ gen: {e:?}"))?;

    let ok = verify_dleq_proof(secp, party_pk, scan_pk, &partial_share, &dleq_proof, None)
        .map_err(|e| anyhow::anyhow!("{party_name} DLEQ verify: {e:?}"))?;
    if !ok {
        bail!("{party_name} produced an invalid DLEQ proof");
    }

    let partial = PartialEcdhShareData {
        scan_key: *scan_pk,
        contributor_pk: *party_pk,
        share: partial_share,
        dleq_proof: to_psbt_dleq(dleq_proof),
    };
    psbt.inputs[0].add_sp_partial_ecdh_share(&partial);

    Ok(())
}

/// Combined Round 1: add partial ECDH share + nonce in a single pass.
///
/// BIP-327 allows nonce preprocessing (generating before the message is known).
/// Returns the `SecNonce` that must be consumed exactly once in `partial_sign`.
pub fn contribute(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    scan_pk: &PublicKey,
    agg_pk: &PublicKey,
    key_agg_ctx: &musig2::KeyAggContext,
    nonce_seed: [u8; 32],
) -> Result<SecNonce> {
    add_ecdh_share(secp, psbt, party_name, party_sk, party_pk, scan_pk)?;
    add_nonce(
        psbt,
        party_name,
        party_sk,
        party_pk,
        agg_pk,
        key_agg_ctx,
        nonce_seed,
    )
}

/// Compute the taproot sighash from the current PSBT state.
///
/// Must be called after finalize_inputs so that outputs have their final scripts.
pub fn compute_sighash(psbt: &Psbt) -> Result<[u8; 32]> {
    let utxo = psbt.inputs[0]
        .witness_utxo
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("input 0 missing witness_utxo"))?;
    let input_amount = utxo.value;
    let p2tr_script = utxo.script_pubkey.clone();

    let unsigned_tx = build_unsigned_tx(psbt);
    let prevouts = vec![TxOut {
        value: input_amount,
        script_pubkey: p2tr_script,
    }];
    compute_tap_sighash(&unsigned_tx, 0, &prevouts)
}

/// Add one party's public nonce to the PSBT.
///
/// Returns the `SecNonce` that must be stored by the caller and consumed
/// exactly once in the corresponding `partial_sign` call.
pub fn add_nonce(
    psbt: &mut Psbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    agg_pk: &PublicKey,
    key_agg_ctx: &musig2::KeyAggContext,
    seed: [u8; 32],
) -> Result<SecNonce> {
    let _ = key_agg_ctx; // kept for API symmetry; nonce generation needs only agg_pk
    let sec_nonce =
        signing::add_musig2_pub_nonce(&mut psbt.inputs[0], party_sk, party_pk, agg_pk, seed)
            .map_err(|e| anyhow::anyhow!("{party_name} nonce: {e}"))?;
    Ok(sec_nonce)
}

/// Add one party's partial signature to the PSBT.
///
/// Consumes the `SecNonce` returned by `add_nonce`.
pub fn partial_sign(
    psbt: &mut Psbt,
    party_name: &str,
    party_sk: &SecretKey,
    party_pk: &PublicKey,
    agg_pk: &PublicKey,
    sec_nonce: SecNonce,
    key_agg_ctx: &musig2::KeyAggContext,
    message: &[u8; 32],
) -> Result<()> {
    signing::add_musig2_partial_sig(
        &mut psbt.inputs[0],
        party_sk,
        party_pk,
        agg_pk,
        sec_nonce,
        key_agg_ctx,
        message,
    )
    .map_err(|e| anyhow::anyhow!("{party_name} partial sig: {e}"))?;
    Ok(())
}

/// Derive the SP output script from the aggregated ECDH shares.
pub fn derive_sp_output(secp: &Secp256k1<secp256k1::All>, psbt: &mut Psbt) -> Result<()> {
    finalize_sp_outputs(secp, psbt)?;

    Ok(())
}

// =========================================================================
// Helpers (shared with CLI path)
// =========================================================================

pub fn build_unsigned_tx(psbt: &Psbt) -> Transaction {
    let inputs = psbt
        .inputs
        .iter()
        .map(|i| TxIn {
            previous_output: OutPoint::new(i.previous_txid, i.spent_output_index),
            script_sig: ScriptBuf::new(),
            sequence: i.sequence.unwrap_or(Sequence::MAX),
            witness: Witness::new(),
        })
        .collect();

    let outputs = psbt
        .outputs
        .iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.amount.to_sat()),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: inputs,
        output: outputs,
    }
}

pub fn compute_tap_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| anyhow::anyhow!("taproot sighash: {e}"))?;
    Ok(sighash.to_byte_array())
}
