//! FROST signer/coordinator roles over PSBTv2.
//!
//! Cryptographic operations remain in `frost-secp256k1-tr`; this module only
//! validates round state and moves public commitments/signature shares through
//! the local PSBT extension.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use bitcoin::hashes::Hash;
use frost_secp256k1_tr as frost;
use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar as KScalar};
use psbt::Psbt;
use psbt_v2::{Input, Output, PartialEcdhShareData};
use rand::{CryptoRng, RngCore};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

use crate::bip445::{self, TweakContext};
use crate::derivation::DerivedPublic;
use crate::ecdh;
use crate::frost_psbt::{FrostInputExt, FrostOutputExt, PublicShare, ThresholdInfo, ThresholdKey};

/// Construct the base BIP-375 PSBT while the generic upstream builder remains
/// under its historical `musig2` module name.
pub fn build_psbt(inputs: Vec<bitcoin::OutPoint>, outputs: Vec<Output>) -> Result<Psbt> {
    psbt::musig2::build_psbt(inputs, outputs)
}

/// Secret, single-use state returned to a signer in round one.
///
/// Consuming this value in [`sign`] prevents accidental nonce reuse through
/// the normal API.
pub struct Round1Secret {
    identifier: frost::Identifier,
    nonces: frost::round1::SigningNonces,
}

/// Write the root threshold info the input is signed under.
pub fn configure_input(input: &mut Input, root: &frost::keys::PublicKeyPackage) -> Result<()> {
    input
        .set_frost_threshold_info(&threshold_key(root)?, &threshold_info(root)?)
        .context("set FROST threshold info")
}

/// Tag an output that pays the same threshold wallet (change).
pub fn configure_output(output: &mut Output, root: &frost::keys::PublicKeyPackage) -> Result<()> {
    output
        .set_frost_threshold_info(&threshold_key(root)?, &threshold_info(root)?)
        .context("tag FROST output with threshold info")
}

/// Generate and publish one signer's round-one commitment.
pub fn commit<R: RngCore + CryptoRng>(
    input: &mut Input,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    rng: &mut R,
) -> Result<Round1Secret> {
    validate_key_package(input, root_key, &public.root)?;
    let key_package = public.key(root_key)?;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
    let identifier = *root_key.identifier();
    input
        .add_frost_commitment(
            &public_share(&public.root, &identifier)?,
            &threshold_key(&public.root)?,
            &commitments
                .serialize()
                .context("serialize FROST signing commitments")?,
        )
        .context("add FROST signing commitment")?;
    Ok(Round1Secret { identifier, nonces })
}

/// Coordinator: select every participant that committed as the signer set.
pub fn select_signers(input: &mut Input, root: &frost::keys::PublicKeyPackage) -> Result<()> {
    validate_threshold_info(input, root)?;
    let mut identifiers = parse_commitments(input, root)?
        .into_keys()
        .map(psbt_identifier)
        .collect::<Result<Vec<_>>>()?;
    identifiers.sort_unstable();
    let threshold = root
        .min_signers()
        .context("FROST public key package is missing its threshold")?;
    if identifiers.len() < usize::from(threshold) {
        bail!(
            "insufficient FROST commitments: got {}, need {threshold}",
            identifiers.len()
        );
    }
    input
        .set_frost_signer_set(&threshold_key(root)?, &identifiers)
        .context("set FROST signer set")
}

/// Build the signing package for the PSBT's signer set.
pub fn signing_package(
    input: &Input,
    message: &[u8],
    public: &DerivedPublic,
) -> Result<frost::SigningPackage> {
    let selected = signer_set(input, &public.root)?;
    let mut commitments = parse_commitments(input, &public.root)?;
    commitments.retain(|identifier, _| selected.contains(identifier));
    if commitments.len() != selected.len() {
        bail!("missing FROST commitment for a selected signer");
    }
    Ok(frost::SigningPackage::new(commitments, message))
}

/// Consume the signer's round-one secret and publish its signature share.
pub fn sign(
    input: &mut Input,
    signing_package: &frost::SigningPackage,
    round1_secret: Round1Secret,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
) -> Result<()> {
    validate_key_package(input, root_key, &public.root)?;
    if round1_secret.identifier != *root_key.identifier() {
        bail!("round-one nonce belongs to a different FROST participant");
    }
    let expected = signing_package
        .signing_commitment(root_key.identifier())
        .ok_or_else(|| anyhow!("signer was not selected in the FROST signing package"))?;
    let actual = frost::round1::SigningCommitments::from(&round1_secret.nonces);
    if actual != expected {
        bail!("round-one nonce does not match the published FROST commitment");
    }
    let share = frost::round2::sign_with_tweak(
        signing_package,
        &round1_secret.nonces,
        &public.key(root_key)?,
        None,
    )
    .context("create FROST signature share")?;
    input
        .add_frost_signature_share(
            &public_share(&public.root, &round1_secret.identifier)?,
            &threshold_key(&public.root)?,
            &share.serialize(),
        )
        .context("add FROST signature share")
}

/// Verify and aggregate all selected signature shares into a Taproot signature.
pub fn aggregate(
    input: &Input,
    signing_package: &frost::SigningPackage,
    public: &DerivedPublic,
) -> Result<frost::Signature> {
    validate_threshold_info(input, &public.root)?;
    let mut shares = BTreeMap::new();
    for ((share_key, threshold), share_bytes) in input
        .frost_signature_shares()
        .context("parse FROST signature shares")?
    {
        let identifier = participant(&public.root, &share_key, &threshold)?;
        if signing_package.signing_commitment(&identifier).is_none() {
            bail!("signature share supplied by an unselected FROST participant");
        }
        let share = frost::round2::SignatureShare::deserialize(&share_bytes)
            .context("deserialize FROST signature share")?;
        shares.insert(identifier, share);
    }
    if shares.len() != signing_package.signing_commitments().len() {
        bail!(
            "incomplete FROST signature shares: got {}, expected {}",
            shares.len(),
            signing_package.signing_commitments().len()
        );
    }
    frost::aggregate_with_tweak(signing_package, &shares, &public.derived, None)
        .context("aggregate FROST signature")
}
/// Add the BIP-375 ECDH share for one selected FROST participant.
///
/// The existing proposed `PSBT_IN_SP_PARTIAL_ECDH_SHARE` and
/// `PSBT_IN_SP_PARTIAL_DLEQ` fields are intentionally reused until their
/// names are generalized upstream.
pub fn add_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    input: &mut Input,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    scan_key: &PublicKey,
    aux_rand: [u8; 32],
) -> Result<()> {
    validate_key_package(input, root_key, &public.root)?;
    // BIP445 model: the root share is untweaked; derivation and Taproot
    // tweaks are applied at combination time through `gacc`/`tacc` (see
    // `crate::ecdh`).
    let secret = SecretKey::from_slice(&root_key.signing_share().serialize())
        .context("convert FROST signing share to secp256k1")?;
    let contributor_pk = PublicKey::from_slice(
        &root_key
            .verifying_share()
            .serialize()
            .context("serialize FROST verifying share")?,
    )
    .context("convert FROST verifying share to secp256k1")?;
    //FIXME: is the the correct guard or should this be handled elsewhere?
    if input
        .parse_sp_partial_ecdh_shares()
        .context("parse existing FROST partial ECDH shares")?
        .iter()
        .any(|partial| partial.scan_key == *scan_key && partial.contributor_pk == contributor_pk)
    {
        bail!("duplicate FROST partial ECDH contribution");
    }
    let share = scan_key
        .mul_tweak(secp, &Scalar::from(secret))
        .context("compute FROST partial ECDH share")?;
    let proof = psbt::generate_dleq_proof(secp, &secret, scan_key, &aux_rand, None)
        .context("generate FROST partial ECDH DLEQ proof")?;
    input.add_sp_partial_ecdh_share(&PartialEcdhShareData {
        scan_key: *scan_key,
        contributor_pk,
        share,
        dleq_proof: psbt::core::utils::to_psbt_dleq(proof),
    });
    Ok(())
}

/// Verify selected participants' DLEQ proofs and materialize Silent Payment outputs.
pub fn finalize_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    public: &DerivedPublic,
) -> Result<()> {
    if psbt.inputs.len() != 1 {
        bail!("frost-signer currently requires exactly one eligible input");
    }
    let mut selected = BTreeMap::new();
    for identifier in &signer_set(&psbt.inputs[0], &public.root)? {
        let verifying_share = public
            .root
            .verifying_shares()
            .get(identifier)
            .ok_or_else(|| anyhow!("selected FROST identifier is not in the public key package"))?;
        let public_key = PublicKey::from_slice(
            &verifying_share
                .serialize()
                .context("serialize selected FROST verifying share")?,
        )
        .context("convert selected FROST verifying share")?;
        selected.insert(*identifier, public_key);
    }

    let contributions = psbt.inputs[0]
        .parse_sp_partial_ecdh_shares()
        .context("parse FROST partial ECDH shares")?;
    let mut by_scan: BTreeMap<[u8; 33], BTreeMap<frost::Identifier, PublicKey>> = BTreeMap::new();
    for contribution in contributions {
        let identifier = selected
            .iter()
            .find_map(|(identifier, pk)| {
                (*pk == contribution.contributor_pk).then_some(*identifier)
            })
            .ok_or_else(|| anyhow!("ECDH share belongs to an unselected FROST participant"))?;
        let proof = psbt::core::utils::to_rust_dleq(contribution.dleq_proof);
        let valid = psbt::verify_dleq_proof(
            secp,
            &contribution.contributor_pk,
            &contribution.scan_key,
            &contribution.share,
            &proof,
            None,
        )
        .context("verify FROST partial ECDH DLEQ proof")?;
        if !valid {
            bail!("invalid FROST partial ECDH DLEQ proof");
        }
        if by_scan
            .entry(contribution.scan_key.serialize())
            .or_default()
            .insert(identifier, contribution.share)
            .is_some()
        {
            bail!("duplicate FROST partial ECDH contribution");
        }
    }

    let expected_identifiers: Vec<_> = selected.keys().copied().collect();
    let tweak_context = tweak_context(public)?;
    let input_hash = input_hash(
        &psbt.inputs[0].outpoint_bytes(),
        &ecdh::output_key(&tweak_context)?,
    )?;
    let input_scalar = Scalar::from_be_bytes(input_hash)
        .map_err(|_| anyhow!("BIP-352 input hash is not a valid scalar"))?;

    let mut output_indices = BTreeMap::<[u8; 33], u32>::new();
    for output in &mut psbt.outputs {
        let Some(info) = output.sp_v0_info else {
            continue;
        };
        let scan_key = &info.scan_key().context("parse SP scan key")?.0;
        let spend_key = &info.spend_key().context("parse SP spend key")?.0;
        let shares = by_scan
            .get(&scan_key.serialize())
            .ok_or_else(|| anyhow!("missing FROST ECDH shares for Silent Payment output"))?;
        if shares.keys().copied().collect::<Vec<_>>() != expected_identifiers {
            bail!("incomplete FROST ECDH signer set for Silent Payment output");
        }
        let aggregate = ecdh::combine_ecdh(&tweak_context, scan_key, &lagrange_weighted(shares)?)?
            .mul_tweak(secp, &input_scalar)
            .context("apply BIP-352 input hash to aggregate ECDH share")?;
        let index = output_indices.entry(scan_key.serialize()).or_default();
        let output_pubkey = derive_silent_payment_output(secp, &spend_key, &aggregate, *index)?;
        let (xonly, _) = output_pubkey.x_only_public_key();
        output.script_pubkey = bitcoin::ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly),
        );
        *index += 1;
    }
    psbt.global.tx_modifiable_flags = 0;
    Ok(())
}

/// Re-derive every Silent Payment output and reject coordinator tampering.
pub fn verify_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &Psbt,
    public: &DerivedPublic,
) -> Result<()> {
    let expected: Vec<_> = psbt
        .outputs
        .iter()
        .map(|output| output.script_pubkey.clone())
        .collect();
    let mut derived = psbt.clone();
    finalize_sp_outputs(secp, &mut derived, public)?;
    for (index, (expected, actual)) in expected
        .iter()
        .zip(derived.outputs.iter().map(|output| &output.script_pubkey))
        .enumerate()
    {
        if expected != actual {
            bail!("Silent Payment output {index} does not match the verified FROST ECDH shares");
        }
    }
    Ok(())
}

/// Validate any FROST threshold-info output tags against the known root.
///
/// The tag is advisory: outputs without it are ignored. When present, it must
/// match the caller's own threshold info, so a change output mislabeled with
/// a foreign participant set is rejected before any share is produced.
pub fn verify_participant_tags(psbt: &Psbt, root: &frost::keys::PublicKeyPackage) -> Result<()> {
    let expected = (threshold_key(root)?, threshold_info(root)?);
    for output in &psbt.outputs {
        let Some(tag) = output
            .frost_threshold_info()
            .context("parse FROST output threshold info")?
        else {
            continue;
        };
        if tag != expected {
            bail!("FROST output threshold info does not match the known threshold key");
        }
    }
    Ok(())
}
/// BIP445 tweaks for the address: the plain derivation tweaks, then the
/// key-path-only Taproot tweak of the derived internal key. ECDH combination
/// and BIP445 signing both use this list.
pub(crate) fn address_tweaks(public: &DerivedPublic) -> Result<(Vec<Vec<u8>>, Vec<bool>)> {
    let mut tweaks: Vec<Vec<u8>> = public.tweaks.iter().map(|tweak| tweak.to_vec()).collect();
    let mut is_xonly = vec![false; tweaks.len()];
    let internal =
        bip445::thresh_pubkey_and_tweak(&threshold_key(&public.root)?, &tweaks, &is_xonly)?;
    let internal_key = bitcoin::key::UntweakedPublicKey::from_slice(&internal.xonly_pk())
        .context("derived FROST internal key")?;
    tweaks.push(
        bitcoin::taproot::TapTweakHash::from_key_and_tweak(internal_key, None)
            .to_byte_array()
            .to_vec(),
    );
    is_xonly.push(true);
    Ok((tweaks, is_xonly))
}

fn tweak_context(public: &DerivedPublic) -> Result<TweakContext> {
    let (tweaks, is_xonly) = address_tweaks(public)?;
    Ok(bip445::thresh_pubkey_and_tweak(
        &threshold_key(&public.root)?,
        &tweaks,
        &is_xonly,
    )?)
}

fn lagrange_weighted(
    shares: &BTreeMap<frost::Identifier, PublicKey>,
) -> Result<Vec<(Scalar, PublicKey)>> {
    let identifiers: Vec<_> = shares.keys().copied().collect();
    shares
        .iter()
        .map(|(identifier, share)| Ok((lagrange_coefficient(*identifier, &identifiers)?, *share)))
        .collect()
}

fn lagrange_coefficient(
    identifier: frost::Identifier,
    identifiers: &[frost::Identifier],
) -> Result<Scalar> {
    let x_i = scalar_from_bytes(&identifier.serialize())?;
    let mut numerator = KScalar::ONE;
    let mut denominator = KScalar::ONE;
    for other in identifiers
        .iter()
        .copied()
        .filter(|other| *other != identifier)
    {
        let x_j = scalar_from_bytes(&other.serialize())?;
        numerator *= x_j;
        denominator *= x_j - x_i;
    }
    let inverse = Option::<KScalar>::from(denominator.invert())
        .ok_or_else(|| anyhow!("duplicate FROST identifiers"))?;
    Scalar::from_be_bytes((numerator * inverse).to_bytes().into())
        .map_err(|_| anyhow!("invalid FROST Lagrange coefficient"))
}

fn scalar_from_bytes(bytes: &[u8]) -> Result<KScalar> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid FROST identifier length"))?;
    let field_bytes: FieldBytes = array.into();
    // FROST identifiers are always canonical scalars in [1, n); a non-canonical
    // value indicates corruption and must not be silently reduced.
    Option::<KScalar>::from(KScalar::from_repr(field_bytes))
        .ok_or_else(|| anyhow!("non-canonical FROST identifier scalar"))
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub(crate) fn input_hash(outpoint: &[u8; 36], output_key: &PublicKey) -> Result<[u8; 32]> {
    Ok(tagged_hash(
        b"BIP0352/Inputs",
        &[outpoint, &output_key.serialize()],
    ))
}

pub(crate) fn derive_silent_payment_output(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    shared_secret: &PublicKey,
    index: u32,
) -> Result<PublicKey> {
    let tweak = tagged_hash(
        b"BIP0352/SharedSecret",
        &[&shared_secret.serialize(), &index.to_be_bytes()],
    );
    let tweak = SecretKey::from_slice(&tweak).context("invalid Silent Payment output tweak")?;
    spend_key
        .combine(&PublicKey::from_secret_key(secp, &tweak))
        .context("derive Silent Payment output key")
}

/// BIP445 identifier for a frost-secp256k1-tr identifier: ZF identifier `k`
/// sits at x = `k`, BIP445 identifier `id` at x = `id + 1`.
pub fn psbt_identifier(identifier: frost::Identifier) -> Result<u8> {
    let bytes = identifier.serialize();
    match bytes.split_last() {
        Some((&last, rest)) if last != 0 && rest.iter().all(|byte| *byte == 0) => Ok(last - 1),
        _ => bail!("FROST identifier has no BIP445 equivalent"),
    }
}

fn frost_identifier(identifier: u8) -> Result<frost::Identifier> {
    frost::Identifier::try_from(u16::from(identifier) + 1).context("invalid BIP445 identifier")
}

fn threshold_key(root: &frost::keys::PublicKeyPackage) -> Result<ThresholdKey> {
    root.verifying_key()
        .serialize()
        .context("serialize FROST threshold key")?
        .try_into()
        .map_err(|_| anyhow!("FROST threshold key is not compressed"))
}

fn public_share(
    root: &frost::keys::PublicKeyPackage,
    identifier: &frost::Identifier,
) -> Result<PublicShare> {
    root.verifying_shares()
        .get(identifier)
        .context("FROST participant is not in the threshold info")?
        .serialize()
        .context("serialize FROST public share")?
        .try_into()
        .map_err(|_| anyhow!("FROST public share is not compressed"))
}

fn threshold_info(root: &frost::keys::PublicKeyPackage) -> Result<ThresholdInfo> {
    let threshold = root
        .min_signers()
        .context("FROST public key package is missing its threshold")?;
    Ok(ThresholdInfo {
        threshold: u8::try_from(threshold).context("FROST threshold exceeds 255")?,
        public_shares: root
            .verifying_shares()
            .keys()
            .map(|identifier| {
                Ok((
                    psbt_identifier(*identifier)?,
                    public_share(root, identifier)?,
                ))
            })
            .collect::<Result<_>>()?,
    })
}

/// Map a `(public share, threshold key)` field key to its participant.
fn participant(
    root: &frost::keys::PublicKeyPackage,
    share: &PublicShare,
    threshold: &ThresholdKey,
) -> Result<frost::Identifier> {
    if *threshold != threshold_key(root)? {
        bail!("FROST field belongs to a different threshold key");
    }
    for identifier in root.verifying_shares().keys() {
        if public_share(root, identifier)? == *share {
            return Ok(*identifier);
        }
    }
    bail!("FROST field supplied by an unknown participant")
}

/// The coordinator-selected signers, checked against the known threshold info.
fn signer_set(
    input: &Input,
    root: &frost::keys::PublicKeyPackage,
) -> Result<Vec<frost::Identifier>> {
    validate_threshold_info(input, root)?;
    let (key, identifiers) = input
        .frost_signer_set()
        .context("parse FROST signer set")?
        .context("missing FROST signer set")?;
    if key != threshold_key(root)? {
        bail!("FROST signer set belongs to a different threshold key");
    }
    let selected = identifiers
        .into_iter()
        .map(frost_identifier)
        .collect::<Result<Vec<_>>>()?;
    if selected
        .iter()
        .any(|identifier| !root.verifying_shares().contains_key(identifier))
    {
        bail!("FROST signer set names an unknown participant");
    }
    let threshold = root
        .min_signers()
        .context("FROST public key package is missing its threshold")?;
    if selected.len() < usize::from(threshold) {
        bail!("FROST signer set is below the threshold");
    }
    Ok(selected)
}

fn parse_commitments(
    input: &Input,
    root: &frost::keys::PublicKeyPackage,
) -> Result<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> {
    let mut commitments = BTreeMap::new();
    for ((share, threshold), bytes) in input
        .frost_commitments()
        .context("parse FROST signing commitments")?
    {
        let commitment = frost::round1::SigningCommitments::deserialize(&bytes)
            .context("deserialize FROST signing commitment")?;
        commitments.insert(participant(root, &share, &threshold)?, commitment);
    }
    Ok(commitments)
}

fn validate_key_package(
    input: &Input,
    root_key: &frost::keys::KeyPackage,
    root: &frost::keys::PublicKeyPackage,
) -> Result<()> {
    validate_threshold_info(input, root)?;
    if root_key.verifying_key() != root.verifying_key()
        || Some(*root_key.min_signers()) != root.min_signers()
        || root.verifying_shares().get(root_key.identifier()) != Some(root_key.verifying_share())
    {
        bail!("FROST key package does not match the root threshold info");
    }
    Ok(())
}

/// The PSBT must carry exactly the threshold info the caller already holds.
pub fn validate_threshold_info(input: &Input, root: &frost::keys::PublicKeyPackage) -> Result<()> {
    let expected = (threshold_key(root)?, threshold_info(root)?);
    if input
        .frost_threshold_info()
        .context("parse FROST threshold info")?
        != Some(expected)
    {
        bail!("PSBT FROST threshold info does not match the known threshold key");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::derive_public;
    use crate::frost_psbt::{PSBT_IN_FROST_RFC9591_COMMITMENT, PSBT_IN_FROST_THRESHOLD_INFO};
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use frost::keys::Tweak;
    use rand::{rngs::StdRng, SeedableRng};

    fn input() -> Input {
        Input::new(&OutPoint::new(Txid::all_zeros(), 0))
    }

    fn packages() -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        packages_with_seed(7)
    }

    fn packages_with_seed(
        seed: u64,
    ) -> (
        BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let keys = shares
            .into_iter()
            .map(|(identifier, share)| (identifier, share.try_into().unwrap()))
            .collect();
        (keys, public)
    }

    fn verify(public: &DerivedPublic, message: &[u8], signature: &frost::Signature) {
        public
            .derived
            .clone()
            .tweak::<&[u8]>(None)
            .verifying_key()
            .verify(message, signature)
            .unwrap();
    }

    #[test]
    fn every_two_of_three_subset_signs_in_any_order() {
        let (keys, root) = packages();
        let public = derive_public(&root, &[0, 5]).unwrap();
        let keys: Vec<_> = keys.values().collect();
        for (case, pair) in [[0, 1], [0, 2], [1, 2]].into_iter().enumerate() {
            let mut input = input();
            configure_input(&mut input, &root).unwrap();
            let mut rng = StdRng::seed_from_u64(8 + case as u64);
            let mut selected = Vec::new();
            for index in pair {
                let key = keys[index];
                selected.push((key, commit(&mut input, key, &public, &mut rng).unwrap()));
            }
            select_signers(&mut input, &root).unwrap();
            let message = [42 + case as u8; 32];
            let package = signing_package(&input, &message, &public).unwrap();
            for (key, secret) in selected.into_iter().rev() {
                sign(&mut input, &package, secret, key, &public).unwrap();
            }
            let signature = aggregate(&input, &package, &public).unwrap();
            verify(&public, &message, &signature);
        }
    }

    #[test]
    fn rejects_fewer_than_threshold_commitments() {
        let (keys, root) = packages();
        let public = DerivedPublic::underived(root.clone());
        let mut input = input();
        configure_input(&mut input, &root).unwrap();
        let mut rng = StdRng::seed_from_u64(9);
        commit(&mut input, keys.values().next().unwrap(), &public, &mut rng).unwrap();
        assert!(select_signers(&mut input, &root).is_err());
        assert!(signing_package(&input, &[1; 32], &public).is_err());
    }

    #[test]
    fn signer_set_selects_who_signs() {
        let (keys, root) = packages();
        let public = DerivedPublic::underived(root.clone());
        let threshold = threshold_key(&root).unwrap();
        let mut input = input();
        configure_input(&mut input, &root).unwrap();
        let mut rng = StdRng::seed_from_u64(10);
        let mut secrets = keys
            .values()
            .map(|key| commit(&mut input, key, &public, &mut rng).unwrap())
            .collect::<Vec<_>>();

        for (identifiers, valid) in [(&[0][..], false), (&[0, 7][..], false), (&[0, 2][..], true)] {
            let mut candidate = input.clone();
            candidate
                .set_frost_signer_set(&threshold, identifiers)
                .unwrap();
            assert_eq!(
                signing_package(&candidate, &[1; 32], &public).is_ok(),
                valid,
                "{identifiers:?}"
            );
        }

        input.set_frost_signer_set(&threshold, &[0, 2]).unwrap();
        let message = [3; 32];
        let package = signing_package(&input, &message, &public).unwrap();
        assert_eq!(package.signing_commitments().len(), 2);
        let keys: Vec<_> = keys.values().collect();
        let charlie = secrets.pop().unwrap();
        let bob = secrets.pop().unwrap();
        let alice = secrets.pop().unwrap();
        assert!(sign(&mut input.clone(), &package, bob, keys[1], &public).is_err());
        sign(&mut input, &package, alice, keys[0], &public).unwrap();
        sign(&mut input, &package, charlie, keys[2], &public).unwrap();
        verify(
            &public,
            &message,
            &aggregate(&input, &package, &public).unwrap(),
        );
    }

    #[test]
    fn identifiers_map_to_bip445() {
        let (keys, root) = packages();
        let identifiers = keys
            .keys()
            .map(|identifier| psbt_identifier(*identifier).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(identifiers, [0, 1, 2]);
        for identifier in keys.keys() {
            let bip445 = psbt_identifier(*identifier).unwrap();
            assert_eq!(frost_identifier(bip445).unwrap(), *identifier);
            assert_eq!(
                threshold_info(&root).unwrap().public_shares[&bip445],
                public_share(&root, identifier).unwrap()
            );
        }
        let custom = frost::Identifier::deserialize(&[0x1a; 32]).unwrap();
        assert!(psbt_identifier(custom).is_err());
    }

    #[test]
    fn rejects_threshold_info_that_differs_from_own() {
        let (keys, root) = packages();
        let (foreign_keys, foreign_root) = packages_with_seed(17);
        let mut configured = input();
        configure_input(&mut configured, &root).unwrap();
        validate_threshold_info(&configured, &root).unwrap();

        let key = threshold_key(&root).unwrap();
        let info = threshold_info(&root).unwrap();
        let foreign_share = threshold_info(&foreign_root).unwrap().public_shares[&0];
        let mut missing = info.clone();
        missing.public_shares.remove(&2);
        let mut extra = info.clone();
        extra.public_shares.insert(3, foreign_share);
        let mut swapped = info.clone();
        let first = swapped.public_shares[&0];
        let second = swapped.public_shares[&1];
        swapped.public_shares.insert(0, second);
        swapped.public_shares.insert(1, first);
        let mut substituted = info.clone();
        substituted.public_shares.insert(0, foreign_share);
        let raised = ThresholdInfo {
            threshold: 3,
            ..info.clone()
        };
        for (threshold_key, info) in [
            (key, missing),
            (key, extra),
            (key, swapped.clone()),
            (key, substituted),
            (key, raised),
            (threshold_key(&foreign_root).unwrap(), info),
        ] {
            let mut tampered = input();
            tampered
                .set_frost_threshold_info(&threshold_key, &info)
                .unwrap();
            assert!(validate_threshold_info(&tampered, &root).is_err());
        }

        let public = DerivedPublic::underived(root.clone());
        let mut rng = StdRng::seed_from_u64(18);
        let mut foreign_signer = configured.clone();
        assert!(commit(
            &mut foreign_signer,
            foreign_keys.values().next().unwrap(),
            &public,
            &mut rng,
        )
        .is_err());
        let mut swapped_input = input();
        swapped_input
            .set_frost_threshold_info(&key, &swapped)
            .unwrap();
        assert!(commit(
            &mut swapped_input,
            keys.values().next().unwrap(),
            &public,
            &mut rng,
        )
        .is_err());
        for rejected in [foreign_signer, swapped_input] {
            assert!(rejected
                .unknowns
                .keys()
                .all(|key| key.type_value != PSBT_IN_FROST_RFC9591_COMMITMENT));
        }
        assert!(configured
            .unknowns
            .keys()
            .any(|key| key.type_value == PSBT_IN_FROST_THRESHOLD_INFO));
    }

    /// Untweaked root shares combined through `gacc`/`tacc` must equal the
    /// recipient-side ECDH with the derived Taproot output key, for every
    /// subset, with and without derivation, and for both internal-key and
    /// output-key parities.
    #[test]
    fn untweaked_shares_combine_to_output_key_ecdh() {
        let secp = Secp256k1::new();
        let scan_secret = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_secret);
        let mut parities = std::collections::BTreeSet::new();
        for (seed, path) in
            (0..16).flat_map(|seed| [&[][..], &[0, 7][..], &[1, 3][..]].map(|path| (seed, path)))
        {
            let (keys, root) = packages_with_seed(seed);
            let public = derive_public(&root, path).unwrap();
            let internal_key =
                PublicKey::from_slice(&public.derived.verifying_key().serialize().unwrap())
                    .unwrap();
            let zf_output = PublicKey::from_slice(
                &public
                    .derived
                    .clone()
                    .tweak::<&[u8]>(None)
                    .verifying_key()
                    .serialize()
                    .unwrap(),
            )
            .unwrap();
            parities.insert((
                internal_key.x_only_public_key().1,
                zf_output.x_only_public_key().1,
            ));

            let context = tweak_context(&public).unwrap();
            let output_key = PublicKey::from_x_only_public_key(
                zf_output.x_only_public_key().0,
                secp256k1::Parity::Even,
            );
            assert_eq!(ecdh::output_key(&context).unwrap(), output_key);
            let expected = output_key
                .mul_tweak(&secp, &Scalar::from(scan_secret))
                .unwrap();

            let keys: Vec<_> = keys.values().collect();
            for pair in [[0, 1], [0, 2], [1, 2]] {
                let shares = pair
                    .iter()
                    .map(|&index| {
                        let secret =
                            SecretKey::from_slice(&keys[index].signing_share().serialize())
                                .unwrap();
                        let share = scan_key.mul_tweak(&secp, &Scalar::from(secret)).unwrap();
                        (*keys[index].identifier(), share)
                    })
                    .collect::<BTreeMap<_, _>>();
                let combined =
                    ecdh::combine_ecdh(&context, &scan_key, &lagrange_weighted(&shares).unwrap())
                        .unwrap();
                assert_eq!(
                    combined, expected,
                    "seed {seed}, path {path:?}, pair {pair:?}"
                );
            }
        }
        assert_eq!(
            parities.len(),
            4,
            "seeds must cover every parity combination"
        );
    }
}
