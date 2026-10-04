//! BIP445 signer/coordinator roles over PSBTv2.
//!
//! The BIP445 counterpart of the RFC 9591 roles in `frost_spdk`. Public nonces
//! and partial signatures travel in `PSBT_IN_FROST_PUB_NONCE` and
//! `PSBT_IN_FROST_PARTIAL_SIG`; threshold info, the signer set, the tweak
//! list, and Silent Payment ECDH are shared with `frost_spdk`.

use anyhow::{bail, Context, Result};
use frost_secp256k1_tr as frost;
use psbt_v2::Input;
use rand::{CryptoRng, RngCore};

use crate::bip445::{self, SecNonce, SessionContext};
use crate::derivation::DerivedPublic;
use crate::frost_psbt::FrostInputExt;
use crate::frost_spdk::{
    address_tweaks, psbt_identifier, public_share, signer_set, threshold_key, validate_key_package,
};

/// Secret, single-use state returned to a signer in round one.
///
/// Consuming this value in [`sign`] consumes the secret nonce.
pub struct Round1Secret {
    identifier: frost::Identifier,
    secnonce: SecNonce,
    pubnonce: [u8; 66],
}

/// Generate and publish one signer's BIP445 public nonce.
///
/// The message is not known yet: the Silent Payment outputs, and so the
/// sighash, are only fixed after round one.
pub fn commit<R: RngCore + CryptoRng>(
    input: &mut Input,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    rng: &mut R,
) -> Result<Round1Secret> {
    validate_key_package(input, root_key, &public.root)?;
    let identifier = *root_key.identifier();
    let pubshare = public_share(&public.root, &identifier)?;
    let thresh_pk = threshold_key(&public.root)?;
    let (tweaks, is_xonly) = address_tweaks(public)?;
    let output_key = bip445::thresh_pubkey_and_tweak(&thresh_pk, &tweaks, &is_xonly)?.xonly_pk();
    let (secnonce, pubnonce) = bip445::nonce_gen(
        rng,
        Some(&secshare(root_key)?),
        Some(&pubshare),
        Some(&output_key),
        None,
        None,
    );
    input
        .add_frost_pub_nonce(&pubshare, &thresh_pk, &pubnonce)
        .context("add BIP445 public nonce")?;
    Ok(Round1Secret {
        identifier,
        secnonce,
        pubnonce,
    })
}

/// Consume the signer's round-one secret and publish its partial signature.
pub fn sign(
    input: &mut Input,
    secret: Round1Secret,
    root_key: &frost::keys::KeyPackage,
    public: &DerivedPublic,
    msg: &[u8; 32],
) -> Result<()> {
    validate_key_package(input, root_key, &public.root)?;
    if secret.identifier != *root_key.identifier() {
        bail!("round-one nonce belongs to a different FROST participant");
    }
    let session = Session::from_psbt(input, public)?;
    let my_id = u32::from(psbt_identifier(secret.identifier)?);
    let Some(position) = session.ids.iter().position(|id| *id == my_id) else {
        bail!("signer was not selected in the FROST signer set");
    };
    if session.pubnonces[position] != secret.pubnonce {
        bail!("round-one nonce does not match the published BIP445 public nonce");
    }
    let aggnonce = bip445::nonce_agg(&session.pubnonces)?;
    let psig = bip445::sign(
        secret.secnonce,
        &secshare(root_key)?,
        my_id,
        &session.context(&aggnonce, msg),
    )?;
    input
        .add_frost_partial_sig(
            &public_share(&public.root, &secret.identifier)?,
            &threshold_key(&public.root)?,
            &psig,
        )
        .context("add BIP445 partial signature")
}

/// Verify every selected partial signature and aggregate them into a BIP340
/// signature for the address's Taproot output key.
pub fn aggregate(input: &Input, public: &DerivedPublic, msg: &[u8; 32]) -> Result<[u8; 64]> {
    let session = Session::from_psbt(input, public)?;
    let thresh_pk = threshold_key(&public.root)?;
    let partial_sigs = input
        .frost_partial_sigs()
        .context("parse BIP445 partial signatures")?;
    if partial_sigs.keys().any(|(share, key)| {
        *key != thresh_pk
            || !session
                .pubshares
                .iter()
                .any(|selected| selected[..] == share[..])
    }) {
        bail!("partial signature supplied by an unselected FROST participant");
    }
    let psigs = session
        .pubshares
        .iter()
        .map(|share| {
            let share: [u8; 33] = share[..].try_into().expect("33-byte public share");
            partial_sigs
                .get(&(share, thresh_pk))
                .cloned()
                .context("incomplete BIP445 partial signatures")
        })
        .collect::<Result<Vec<_>>>()?;
    for (position, psig) in psigs.iter().enumerate() {
        let valid = bip445::partial_sig_verify(
            psig,
            &session.pubnonces,
            session.n,
            session.t,
            &session.ids,
            &session.pubshares,
            &session.thresh_pk,
            &session.tweaks,
            &session.is_xonly,
            msg,
            position,
        )?;
        if !valid {
            bail!(
                "invalid BIP445 partial signature from participant {}",
                session.ids[position]
            );
        }
    }
    let aggnonce = bip445::nonce_agg(&session.pubnonces)?;
    Ok(bip445::partial_sig_agg(
        &psigs,
        &session.context(&aggnonce, msg),
    )?)
}

/// The BIP445 session inputs a PSBT fixes: the signer set from
/// `PSBT_IN_FROST_SIGNER_SET`, their public shares from the caller's own
/// threshold info, their public nonces, and the address's tweak list.
struct Session {
    n: u32,
    t: u32,
    ids: Vec<u32>,
    pubshares: Vec<Vec<u8>>,
    pubnonces: Vec<Vec<u8>>,
    thresh_pk: Vec<u8>,
    tweaks: Vec<Vec<u8>>,
    is_xonly: Vec<bool>,
}

impl Session {
    fn from_psbt(input: &Input, public: &DerivedPublic) -> Result<Self> {
        let root = &public.root;
        let thresh_pk = threshold_key(root)?;
        let pub_nonces = input
            .frost_pub_nonces()
            .context("parse BIP445 public nonces")?;
        let mut ids = Vec::new();
        let mut pubshares = Vec::new();
        let mut pubnonces = Vec::new();
        for identifier in signer_set(input, root)? {
            let share = public_share(root, &identifier)?;
            let nonce = pub_nonces
                .get(&(share, thresh_pk))
                .context("missing BIP445 public nonce for a selected signer")?;
            ids.push(u32::from(psbt_identifier(identifier)?));
            pubshares.push(share.to_vec());
            pubnonces.push(nonce.clone());
        }
        let (tweaks, is_xonly) = address_tweaks(public)?;
        Ok(Self {
            n: root.verifying_shares().len() as u32,
            t: u32::from(
                root.min_signers()
                    .context("FROST public key package is missing its threshold")?,
            ),
            ids,
            pubshares,
            pubnonces,
            thresh_pk: thresh_pk.to_vec(),
            tweaks,
            is_xonly,
        })
    }

    fn context<'a>(&'a self, aggnonce: &'a [u8], msg: &'a [u8]) -> SessionContext<'a> {
        SessionContext {
            n: self.n,
            t: self.t,
            ids: &self.ids,
            pubshares: Some(&self.pubshares),
            thresh_pk: &self.thresh_pk,
            aggnonce,
            tweaks: &self.tweaks,
            is_xonly: &self.is_xonly,
            msg,
        }
    }
}

fn secshare(root_key: &frost::keys::KeyPackage) -> Result<[u8; 32]> {
    root_key
        .signing_share()
        .serialize()
        .try_into()
        .map_err(|_| anyhow::anyhow!("FROST signing share is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derivation::derive_public;
    use crate::frost_psbt::{PSBT_IN_FROST_PARTIAL_SIG, PSBT_IN_FROST_PUB_NONCE};
    use crate::frost_spdk::{self, configure_input, select_signers};
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};
    use frost::keys::Tweak;
    use rand::{rngs::StdRng, SeedableRng};

    fn setup() -> (
        Vec<frost::keys::KeyPackage>,
        frost::keys::PublicKeyPackage,
        DerivedPublic,
        Input,
    ) {
        let mut rng = StdRng::seed_from_u64(5);
        let (shares, root) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let keys = shares
            .into_values()
            .map(|share| share.try_into().unwrap())
            .collect();
        let public = derive_public(&root, &[0, 3]).unwrap();
        let mut input = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        configure_input(&mut input, &root).unwrap();
        (keys, root, public, input)
    }

    fn output_key(public: &DerivedPublic) -> secp256k1::XOnlyPublicKey {
        let zf_output = public.derived.clone().tweak::<&[u8]>(None);
        secp256k1::XOnlyPublicKey::from_slice(&zf_output.verifying_key().serialize().unwrap()[1..])
            .unwrap()
    }

    fn verify(public: &DerivedPublic, msg: &[u8; 32], signature: &[u8; 64]) {
        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(signature).unwrap(),
                &secp256k1::Message::from_digest(*msg),
                &output_key(public),
            )
            .unwrap();
    }

    #[test]
    fn every_two_of_three_subset_signs_for_the_derived_output_key() {
        let (keys, root, public, configured) = setup();
        for (case, pair) in [[0, 1], [0, 2], [1, 2]].into_iter().enumerate() {
            let mut input = configured.clone();
            let mut rng = StdRng::seed_from_u64(20 + case as u64);
            let secrets: Vec<_> = pair
                .iter()
                .map(|&i| commit(&mut input, &keys[i], &public, &mut rng).unwrap())
                .collect();
            select_signers(&mut input, &root).unwrap();
            let msg = [case as u8 + 1; 32];
            for (secret, &i) in secrets.into_iter().zip(&pair).rev() {
                sign(&mut input, secret, &keys[i], &public, &msg).unwrap();
            }
            verify(&public, &msg, &aggregate(&input, &public, &msg).unwrap());
        }
    }

    #[test]
    fn signer_rejects_a_replaced_public_nonce() {
        let (keys, root, public, mut input) = setup();
        let mut rng = StdRng::seed_from_u64(30);
        let alice = commit(&mut input, &keys[0], &public, &mut rng).unwrap();
        commit(&mut input, &keys[1], &public, &mut rng).unwrap();
        select_signers(&mut input, &root).unwrap();

        // The coordinator swaps Alice's published nonce for a fresh one.
        let mut other = configured_copy(&root);
        commit(&mut other, &keys[0], &public, &mut rng).unwrap();
        let (key, nonce) = other
            .unknowns
            .iter()
            .find(|(key, _)| key.type_value == PSBT_IN_FROST_PUB_NONCE)
            .unwrap();
        input.unknowns.insert(key.clone(), nonce.clone());

        let error = sign(&mut input, alice, &keys[0], &public, &[1; 32]).unwrap_err();
        assert!(error.to_string().contains("does not match the published"));
        assert!(input
            .unknowns
            .keys()
            .all(|key| key.type_value != PSBT_IN_FROST_PARTIAL_SIG));
    }

    #[test]
    fn unselected_signer_cannot_sign() {
        let (keys, root, public, mut input) = setup();
        let mut rng = StdRng::seed_from_u64(31);
        let secrets: Vec<_> = keys
            .iter()
            .map(|key| commit(&mut input, key, &public, &mut rng).unwrap())
            .collect();
        input
            .set_frost_signer_set(&threshold_key(&root).unwrap(), &[0, 2])
            .unwrap();
        let bob = secrets.into_iter().nth(1).unwrap();
        let error = sign(&mut input, bob, &keys[1], &public, &[1; 32]).unwrap_err();
        assert!(error.to_string().contains("not selected"));
    }

    #[test]
    fn aggregate_blames_an_invalid_partial_signature() {
        let (keys, root, public, mut input) = setup();
        let mut rng = StdRng::seed_from_u64(32);
        let secrets: Vec<_> = keys[..2]
            .iter()
            .map(|key| commit(&mut input, key, &public, &mut rng).unwrap())
            .collect();
        select_signers(&mut input, &root).unwrap();
        let msg = [7; 32];
        for (secret, key) in secrets.into_iter().zip(&keys) {
            sign(&mut input, secret, key, &public, &msg).unwrap();
        }
        verify(&public, &msg, &aggregate(&input, &public, &msg).unwrap());

        let bob_share = public_share(&root, keys[1].identifier()).unwrap();
        let mut tampered = input.clone();
        let (_, psig) = tampered
            .unknowns
            .iter_mut()
            .find(|(key, _)| {
                key.type_value == PSBT_IN_FROST_PARTIAL_SIG && key.key[..33] == bob_share[..]
            })
            .unwrap();
        psig[31] ^= 1;
        let error = aggregate(&tampered, &public, &msg).unwrap_err();
        assert!(error.to_string().contains("from participant 1"), "{error}");

        let mut missing = input.clone();
        missing.unknowns.retain(|key, _| {
            !(key.type_value == PSBT_IN_FROST_PARTIAL_SIG && key.key[..33] == bob_share[..])
        });
        assert!(aggregate(&missing, &public, &msg).is_err());
    }

    #[test]
    fn coordinator_rejects_mixed_nonce_kinds() {
        let (keys, root, public, mut input) = setup();
        let mut rng = StdRng::seed_from_u64(33);
        commit(&mut input, &keys[0], &public, &mut rng).unwrap();
        frost_spdk::commit(&mut input, &keys[1], &public, &mut rng).unwrap();
        let error = select_signers(&mut input, &root).unwrap_err();
        assert!(error.to_string().contains("mixes"));
    }

    fn configured_copy(root: &frost::keys::PublicKeyPackage) -> Input {
        let mut input = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        configure_input(&mut input, root).unwrap();
        input
    }
}
