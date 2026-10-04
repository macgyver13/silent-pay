//! Pure 2-of-3 FROST + BIP-375 workflow logic.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use frost::keys::Tweak;
use frost_secp256k1_tr as frost;
use psbt::core::utils::to_sp_v0_info;
use psbt::roles::{ExtractorPsbtExt, InputWitnessFinalizerPsbtExt};
use psbt::Psbt;
use psbt_v2::Output;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress, SpVersion};

use crate::bip445_spdk;
use crate::derivation::DerivedPublic;
use crate::frost_spdk::{self, Round1Secret};

pub const MIN_SIGNERS: u16 = 2;
pub const MAX_SIGNERS: u16 = 3;

pub const PARTIES: [&str; 3] = ["Alice", "Bob", "Charlie"];

/// Static identifier-to-name bindings for this demo.
///
/// Identifiers `1..=3` map to BIP445 identifiers `0..=2` in the PSBT.
const PARTY_IDENTIFIERS: [(u16, &str); 3] = [(1, "Alice"), (2, "Bob"), (3, "Charlie")];

/// Deterministic fixtures for the example UI.
///
/// Real deployments must provision authenticated `KeyPackage`s through a
/// trusted-dealer or DKG ceremony and keep them on separate signing devices.
pub struct KeySetup {
    pub key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pub party_ids: BTreeMap<&'static str, frost::Identifier>,
    pub public_key_package: frost::keys::PublicKeyPackage,
    pub internal_key: bitcoin::key::XOnlyPublicKey,
    pub output_key: bitcoin::key::XOnlyPublicKey,
    pub p2tr_script: ScriptBuf,
    pub scan_key: PublicKey,
    pub sp_address: SilentPaymentAddress,
}

pub fn setup_keys() -> Result<KeySetup> {
    let mut rng = StdRng::from_seed([0x37; 32]);

    let party_ids = PARTY_IDENTIFIERS
        .iter()
        .map(|&(identifier, name)| {
            let identifier =
                frost::Identifier::try_from(identifier).context("parse static FROST identifier")?;
            Ok((name, identifier))
        })
        .collect::<Result<BTreeMap<&'static str, frost::Identifier>>>()?;
    let identifiers: Vec<_> = party_ids.values().copied().collect();

    let (shares, public_key_package) = frost::keys::generate_with_dealer(
        MAX_SIGNERS,
        MIN_SIGNERS,
        frost::keys::IdentifierList::Custom(&identifiers),
        &mut rng,
    )
    .context("generate deterministic FROST example fixtures")?;
    let key_packages = shares
        .into_iter()
        .map(|(identifier, share)| {
            let key_package = share
                .try_into()
                .context("verify dealer-generated FROST secret share")?;
            Ok((identifier, key_package))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let internal_bytes = public_key_package
        .verifying_key()
        .serialize()
        .context("serialize FROST internal key")?;
    let internal_full =
        PublicKey::from_slice(&internal_bytes).context("parse FROST internal key")?;
    let (internal_key, _) = internal_full.x_only_public_key();

    let tweaked_public = public_key_package.clone().tweak::<&[u8]>(None);
    let output_bytes = tweaked_public
        .verifying_key()
        .serialize()
        .context("serialize tweaked FROST output key")?;
    let output_full = PublicKey::from_slice(&output_bytes).context("parse FROST output key")?;
    let (output_key, _) = output_full.x_only_public_key();
    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key),
    );

    let secp = Secp256k1::new();
    let scan_secret = SecretKey::from_slice(&[0x11; 32])?;
    let spend_secret = SecretKey::from_slice(&[0x22; 32])?;
    let scan_key = PublicKey::from_secret_key(&secp, &scan_secret);
    let spend_key = PublicKey::from_secret_key(&secp, &spend_secret);
    let sp_address =
        SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Mainnet, SpVersion::ZERO);

    Ok(KeySetup {
        key_packages,
        party_ids,
        public_key_package,
        internal_key,
        output_key,
        p2tr_script,
        scan_key,
        sp_address,
    })
}

/// Build the transaction-facing keys for an already provisioned public FROST package.
pub fn setup_public(public_key_package: frost::keys::PublicKeyPackage) -> Result<KeySetup> {
    let internal_bytes = public_key_package
        .verifying_key()
        .serialize()
        .context("serialize FROST internal key")?;
    let internal_full = PublicKey::from_slice(&internal_bytes)?;
    let (internal_key, _) = internal_full.x_only_public_key();
    let tweaked_public = public_key_package.clone().tweak::<&[u8]>(None);
    let output_full = PublicKey::from_slice(&tweaked_public.verifying_key().serialize()?)?;
    let (output_key, _) = output_full.x_only_public_key();
    let p2tr_script = ScriptBuf::new_p2tr_tweaked(
        bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key),
    );
    let secp = Secp256k1::new();
    let scan_key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32])?);
    let spend_key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32])?);
    let sp_address =
        SilentPaymentAddress::new(scan_key, spend_key, SpNetwork::Mainnet, SpVersion::ZERO);
    Ok(KeySetup {
        key_packages: BTreeMap::new(),
        party_ids: BTreeMap::new(),
        public_key_package,
        internal_key,
        output_key,
        p2tr_script,
        scan_key,
        sp_address,
    })
}

pub fn construct_psbt(
    keys: &KeySetup,
    root: &frost::keys::PublicKeyPackage,
    recipients: &[(SilentPaymentAddress, Amount)],
) -> Result<Psbt> {
    let total_payment: u64 = recipients.iter().map(|(_, amount)| amount.to_sat()).sum();
    let change_amount = Amount::from_sat(9_000);
    let fee = Amount::from_sat(1_000);
    let input_amount = Amount::from_sat(total_payment) + change_amount + fee;
    let mut outputs: Vec<Output> = recipients
        .iter()
        .map(|(address, amount)| {
            let mut output = Output::new(TxOut {
                value: *amount,
                script_pubkey: ScriptBuf::new(),
            });
            output.sp_v0_info = Some(to_sp_v0_info(address));
            output
        })
        .collect();
    outputs.push(Output::new(TxOut {
        value: change_amount,
        script_pubkey: keys.p2tr_script.clone(),
    }));

    let fixture_txid = Txid::from_byte_array([1; 32]);
    let mut psbt = frost_spdk::build_psbt(vec![OutPoint::new(fixture_txid, 0)], outputs)?;
    psbt.inputs[0].sequence = Some(Sequence::MAX);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: input_amount,
        script_pubkey: keys.p2tr_script.clone(),
    });
    psbt.inputs[0].tap_internal_key = Some(keys.internal_key);
    frost_spdk::configure_input(&mut psbt.inputs[0], root)?;

    // BIP-373 parallel: tag the non-SP change output with the wallet's
    // threshold info to aid change / self-payment detection.
    for output in psbt.outputs.iter_mut() {
        if output.sp_v0_info.is_none() {
            frost_spdk::configure_output(output, root)?;
        }
    }
    Ok(psbt)
}

/// Round one for one selected signer: FROST commitment plus ECDH/DLEQ shares.
pub fn contribute<R: RngCore + rand::CryptoRng>(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    rng: &mut R,
) -> Result<Round1Secret> {
    add_ecdh_shares(secp, psbt, root_key, public, rng)?;
    frost_spdk::commit(&mut psbt.inputs[0], root_key, public, rng)
}

/// BIP445 round one for one selected signer: public nonce plus ECDH/DLEQ shares.
pub fn contribute_bip445<R: RngCore + rand::CryptoRng>(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    rng: &mut R,
) -> Result<bip445_spdk::Round1Secret> {
    add_ecdh_shares(secp, psbt, root_key, public, rng)?;
    bip445_spdk::commit(&mut psbt.inputs[0], root_key, public, rng)
}

fn add_ecdh_shares<R: RngCore + rand::CryptoRng>(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    rng: &mut R,
) -> Result<()> {
    let scan_keys: Vec<_> = psbt
        .outputs
        .iter()
        .filter_map(|output| output.sp_v0_info)
        .map(|info| {
            info.scan_key()
                .map(|key| key.0)
                .context("parse Silent Payment scan key")
        })
        .collect::<Result<_>>()?;
    for scan_key in scan_keys {
        let mut aux_rand = [0; 32];
        rng.fill_bytes(&mut aux_rand);
        frost_spdk::add_ecdh_share(
            secp,
            &mut psbt.inputs[0],
            root_key,
            public,
            &scan_key,
            aux_rand,
        )?;
    }
    Ok(())
}

pub fn derive_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    public: &DerivedPublic,
) -> Result<()> {
    frost_spdk::select_signers(&mut psbt.inputs[0], &public.root)?;
    frost_spdk::finalize_sp_outputs(secp, psbt, public)
}

pub fn compute_sighash(psbt: &Psbt) -> Result<[u8; 32]> {
    let utxo = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or_else(|| anyhow!("input 0 missing witness_utxo"))?;
    compute_tap_sighash(&build_unsigned_tx(psbt), 0, &[utxo])
}

pub fn signing_package(
    psbt: &Psbt,
    message: &[u8; 32],
    public: &DerivedPublic,
) -> Result<frost::SigningPackage> {
    frost_spdk::signing_package(&psbt.inputs[0], message, public)
}

pub fn partial_sign(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    signing_package: &frost::SigningPackage,
    secret: Round1Secret,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    expected_recipients: &[SilentPaymentAddress],
) -> Result<()> {
    verify_before_signing(secp, psbt, public, expected_recipients)?;
    let expected = compute_sighash(psbt)?;
    if signing_package.message() != expected.as_slice() {
        return Err(anyhow!(
            "FROST signing package message does not match the PSBT sighash"
        ));
    }
    frost_spdk::sign(
        &mut psbt.inputs[0],
        signing_package,
        secret,
        root_key,
        public,
    )
}

/// BIP445 round two: check the PSBT, then sign its sighash.
pub fn partial_sign_bip445(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    secret: bip445_spdk::Round1Secret,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    expected_recipients: &[SilentPaymentAddress],
) -> Result<()> {
    verify_before_signing(secp, psbt, public, expected_recipients)?;
    let sighash = compute_sighash(psbt)?;
    bip445_spdk::sign(&mut psbt.inputs[0], secret, root_key, public, &sighash)
}

/// Checks a signer makes on its own key material before any signature share.
fn verify_before_signing(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    public: &DerivedPublic,
    expected_recipients: &[SilentPaymentAddress],
) -> Result<()> {
    verify_recipients(psbt, expected_recipients)?;
    frost_spdk::verify_sp_outputs(secp, psbt, public)?;
    frost_spdk::verify_participant_tags(psbt, &public.root)
}

/// Confirm every Silent Payment output pays a recipient the signer authorized.
///
/// `verify_sp_outputs` only proves the output scripts are consistent with the
/// `sp_v0_info` inside the PSBT; a malicious coordinator can still swap that
/// address. The signer must independently authenticate the recipient.
fn verify_recipients(psbt: &Psbt, expected_recipients: &[SilentPaymentAddress]) -> Result<()> {
    for output in &psbt.outputs {
        let Some(info) = output.sp_v0_info else {
            continue;
        };
        let matches = expected_recipients.iter().any(|recipient| {
            recipient.get_scan_key() == info.scan_key().context("parse SP scan key").unwrap().0
                && recipient.get_spend_key() == info.spend_key().context("parse SP spend key").unwrap().0
        });
        if !matches {
            return Err(anyhow!(
                "Silent Payment output pays an unauthorized recipient"
            ));
        }
    }
    Ok(())
}

pub fn aggregate_and_extract(
    psbt: &mut Psbt,
    signing_package: &frost::SigningPackage,
    public: &DerivedPublic,
) -> Result<Transaction> {
    let signature = frost_spdk::aggregate(&psbt.inputs[0], signing_package, public)?;
    let bytes = signature
        .serialize()
        .context("serialize aggregate FROST signature")?;
    finish(psbt, &bytes)
}

pub fn aggregate_and_extract_bip445(
    psbt: &mut Psbt,
    public: &DerivedPublic,
) -> Result<Transaction> {
    let sighash = compute_sighash(psbt)?;
    let signature = bip445_spdk::aggregate(&psbt.inputs[0], public, &sighash)?;
    finish(psbt, &signature)
}

/// Attach the aggregate BIP340 signature, finalize, and extract.
fn finish(psbt: &mut Psbt, signature: &[u8]) -> Result<Transaction> {
    let schnorr = secp256k1::schnorr::Signature::from_slice(signature)
        .context("convert aggregate FROST signature")?;
    psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
        signature: schnorr,
        sighash_type: TapSighashType::Default,
    });
    *psbt = psbt
        .clone()
        .finalize()
        .map_err(|error| anyhow!("finalize witnesses: {error:?}"))?;
    psbt.clone()
        .extract_tx()
        .map_err(|error| anyhow!("extract transaction: {error:?}"))
}

pub fn build_unsigned_tx(psbt: &Psbt) -> Transaction {
    Transaction {
        version: psbt.global.tx_version,
        lock_time: psbt.global.fallback_lock_time.unwrap_or(LockTime::ZERO),
        input: psbt
            .inputs
            .iter()
            .map(|input| TxIn {
                previous_output: OutPoint::new(input.previous_txid, input.spent_output_index),
                script_sig: ScriptBuf::new(),
                sequence: input.sequence.unwrap_or(Sequence::MAX),
                witness: Witness::new(),
            })
            .collect(),
        output: psbt
            .outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect(),
    }
}

pub fn compute_tap_sighash(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map(|hash| hash.to_byte_array())
        .context("compute Taproot key-spend sighash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_psbt::{FrostInputExt, FrostOutputExt, ThresholdInfo};
    use secp256k1::Scalar;

    /// The in-process fixtures sign with the root key directly (no path).
    fn underived(keys: &KeySetup) -> DerivedPublic {
        DerivedPublic::underived(keys.public_key_package.clone())
    }

    #[test]
    fn uses_static_party_identifiers() {
        let keys = setup_keys().unwrap();

        for (expected, name) in PARTY_IDENTIFIERS {
            assert_eq!(
                keys.party_ids[&name],
                frost::Identifier::try_from(expected).unwrap()
            );
            assert_eq!(
                frost_spdk::psbt_identifier(keys.party_ids[&name]).unwrap(),
                expected as u8 - 1
            );
        }
    }

    #[test]
    fn full_two_of_three_silent_payment_flow() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x42; 32]);
        let secrets: Vec<_> = selected
            .iter()
            .map(|key| contribute(&secp, &mut psbt, key, &underived(&keys), &mut rng).unwrap())
            .collect();

        derive_sp_outputs(&secp, &mut psbt, &underived(&keys)).unwrap();
        assert!(psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap()
            .script_pubkey
            .is_p2tr());
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &underived(&keys)).unwrap();
        for (key, secret) in selected.into_iter().zip(secrets) {
            partial_sign(
                &secp,
                &mut psbt,
                &package,
                secret,
                key,
                &underived(&keys),
                &[keys.sp_address],
            )
            .unwrap();
        }
        let transaction = aggregate_and_extract(&mut psbt, &package, &underived(&keys)).unwrap();
        let signature = secp256k1::schnorr::Signature::from_slice(
            transaction.input[0].witness.iter().next().unwrap(),
        )
        .unwrap();
        secp.verify_schnorr(
            &signature,
            &secp256k1::Message::from_digest(message),
            &keys.output_key,
        )
        .unwrap();
    }

    #[test]
    fn partitioned_flow_via_serialized_psbt() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();

        // Coordinator constructs the PSBT and ships only its serialized bytes.
        let psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let mut bytes = psbt.serialize();

        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x48; 32]);

        // Each device loads the bytes, runs round one, and keeps its own
        // single-use Round1Secret locally before shipping the bytes onward.
        let mut secrets = Vec::new();
        for key in &selected {
            let mut device_psbt = Psbt::deserialize(&bytes).unwrap();
            let secret =
                contribute(&secp, &mut device_psbt, key, &underived(&keys), &mut rng).unwrap();
            secrets.push(secret);
            bytes = device_psbt.serialize();
        }

        // Coordinator loads the round-one bytes and derives the SP outputs.
        let mut coordinator_psbt = Psbt::deserialize(&bytes).unwrap();
        derive_sp_outputs(&secp, &mut coordinator_psbt, &underived(&keys)).unwrap();
        bytes = coordinator_psbt.serialize();

        // Each device loads the derived bytes, independently reconstructs the
        // signing package and sighash from the PSBT alone, and signs using only
        // its own Round1Secret and key package.
        for (key, secret) in selected.into_iter().zip(secrets) {
            let mut device_psbt = Psbt::deserialize(&bytes).unwrap();
            let message = compute_sighash(&device_psbt).unwrap();
            let package = signing_package(&device_psbt, &message, &underived(&keys)).unwrap();
            partial_sign(
                &secp,
                &mut device_psbt,
                &package,
                secret,
                key,
                &underived(&keys),
                &[keys.sp_address],
            )
            .unwrap();
            bytes = device_psbt.serialize();
        }

        // Coordinator loads the fully signed bytes, reconstructs the package, and
        // aggregates into a final transaction.
        let mut final_psbt = Psbt::deserialize(&bytes).unwrap();
        let message = compute_sighash(&final_psbt).unwrap();
        let package = signing_package(&final_psbt, &message, &underived(&keys)).unwrap();
        let transaction =
            aggregate_and_extract(&mut final_psbt, &package, &underived(&keys)).unwrap();

        let signature = secp256k1::schnorr::Signature::from_slice(
            transaction.input[0].witness.iter().next().unwrap(),
        )
        .unwrap();
        secp.verify_schnorr(
            &signature,
            &secp256k1::Message::from_digest(message),
            &keys.output_key,
        )
        .unwrap();
    }

    #[test]
    fn signer_rejects_tampered_silent_payment_output() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x43; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| contribute(&secp, &mut psbt, key, &underived(&keys), &mut rng).unwrap())
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &underived(&keys)).unwrap();
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &underived(&keys)).unwrap();
        let sp_output = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        sp_output.script_pubkey = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(keys.output_key),
        );
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &underived(&keys),
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn signer_rejects_mismatched_signing_message() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x45; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| contribute(&secp, &mut psbt, key, &underived(&keys), &mut rng).unwrap())
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &underived(&keys)).unwrap();
        // A coordinator that binds the FROST session to a different message than
        // the PSBT sighash must be rejected before any share is produced.
        let package = signing_package(&psbt, &[0xab; 32], &underived(&keys)).unwrap();
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &underived(&keys),
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn signer_rejects_swapped_recipient() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        // Coordinator builds the PSBT toward an attacker's address, but the signer
        // only authorized `keys.sp_address`.
        let attacker_scan =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x51; 32]).unwrap());
        let attacker_spend =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x52; 32]).unwrap());
        let attacker = SilentPaymentAddress::new(
            attacker_scan,
            attacker_spend,
            SpNetwork::Mainnet,
            SpVersion::ZERO,
        );
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(attacker, Amount::from_sat(90_000))],
        )
        .unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x46; 32]);
        let mut secrets: Vec<_> = selected
            .iter()
            .map(|key| contribute(&secp, &mut psbt, key, &underived(&keys), &mut rng).unwrap())
            .collect();
        derive_sp_outputs(&secp, &mut psbt, &underived(&keys)).unwrap();
        let message = compute_sighash(&psbt).unwrap();
        let package = signing_package(&psbt, &message, &underived(&keys)).unwrap();
        assert!(partial_sign(
            &secp,
            &mut psbt,
            &package,
            secrets.remove(0),
            selected[0],
            &underived(&keys),
            &[keys.sp_address],
        )
        .is_err());
    }

    #[test]
    fn recipient_recovers_derived_silent_payment_output() {
        let secp = Secp256k1::new();
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let selected: Vec<_> = keys.key_packages.values().take(2).collect();
        let mut rng = StdRng::from_seed([0x47; 32]);
        for key in &selected {
            contribute(&secp, &mut psbt, key, &underived(&keys), &mut rng).unwrap();
        }
        derive_sp_outputs(&secp, &mut psbt, &underived(&keys)).unwrap();
        let derived = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap()
            .script_pubkey
            .clone();

        // Independently recompute the output from the recipient's scan secret,
        // proving the threshold ECDH interpolation reconstructs the correct
        // shared secret rather than merely producing some P2TR script.
        let scan_secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32]).unwrap());
        let output_full = PublicKey::from_slice(
            &keys
                .public_key_package
                .clone()
                .tweak::<&[u8]>(None)
                .verifying_key()
                .serialize()
                .unwrap(),
        )
        .unwrap();
        let (output_xonly, _) = output_full.x_only_public_key();
        let canonical_output_key =
            PublicKey::from_x_only_public_key(output_xonly, secp256k1::Parity::Even);
        let input_hash =
            frost_spdk::input_hash(&psbt.inputs[0].outpoint_bytes(), &canonical_output_key)
                .unwrap();
        let input_scalar = Scalar::from_be_bytes(input_hash).unwrap();
        let shared = canonical_output_key
            .mul_tweak(&secp, &Scalar::from(scan_secret))
            .unwrap()
            .mul_tweak(&secp, &input_scalar)
            .unwrap();
        let expected =
            frost_spdk::derive_silent_payment_output(&secp, &spend_key, &shared, 0).unwrap();
        let (expected_xonly, _) = expected.x_only_public_key();
        let expected_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(expected_xonly),
        );
        assert_eq!(derived, expected_script);
    }

    #[test]
    fn frost_fields_survive_psbt_serialization() {
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let mut rng = StdRng::from_seed([0x44; 32]);
        contribute(
            &Secp256k1::new(),
            &mut psbt,
            keys.key_packages.values().next().unwrap(),
            &underived(&keys),
            &mut rng,
        )
        .unwrap();
        let encoded = psbt.serialize();
        let decoded = Psbt::deserialize(&encoded).unwrap();
        assert_eq!(
            decoded.inputs[0].frost_threshold_info().unwrap(),
            psbt.inputs[0].frost_threshold_info().unwrap()
        );
        assert_eq!(
            decoded.inputs[0].frost_commitments().unwrap(),
            psbt.inputs[0].frost_commitments().unwrap()
        );
        assert_eq!(
            decoded.inputs[0]
                .parse_sp_partial_ecdh_shares()
                .unwrap()
                .len(),
            1
        );
        // The FROST output tag round-trips through the top-level keytype in
        // `.unknowns`, confirming 0x20 does not collide with a known keytype.
        let change = decoded
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        assert_eq!(
            change.frost_threshold_info().unwrap(),
            psbt.outputs
                .iter()
                .find(|output| output.sp_v0_info.is_none())
                .unwrap()
                .frost_threshold_info()
                .unwrap()
        );
    }

    #[test]
    fn change_output_is_tagged_and_sp_output_is_not() {
        let keys = setup_keys().unwrap();
        let psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        let sp = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_some())
            .unwrap();
        let change = psbt
            .outputs
            .iter()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        assert!(sp.frost_threshold_info().unwrap().is_none());
        let (threshold_key, info) = change.frost_threshold_info().unwrap().unwrap();
        assert_eq!(
            threshold_key.to_vec(),
            keys.public_key_package.verifying_key().serialize().unwrap()
        );
        assert_eq!(
            info.public_shares.len(),
            keys.public_key_package.verifying_shares().len()
        );
        assert_eq!(
            psbt.inputs[0].frost_threshold_info().unwrap(),
            Some((threshold_key, info))
        );
    }

    #[test]
    fn signer_rejects_mislabeled_participant_tag() {
        let keys = setup_keys().unwrap();
        let mut psbt = construct_psbt(
            &keys,
            &keys.public_key_package,
            &[(keys.sp_address, Amount::from_sat(90_000))],
        )
        .unwrap();
        // Overwrite the change output's tag with foreign threshold info.
        let change = psbt
            .outputs
            .iter_mut()
            .find(|output| output.sp_v0_info.is_none())
            .unwrap();
        change.unknowns.clear();
        let foreign = ThresholdInfo {
            threshold: 1,
            public_shares: BTreeMap::from([(0, [3; 33]), (1, [4; 33])]),
        };
        change.set_frost_threshold_info(&[2; 33], &foreign).unwrap();
        assert!(frost_spdk::verify_participant_tags(&psbt, &keys.public_key_package).is_err());
    }
}
