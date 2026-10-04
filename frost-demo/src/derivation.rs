use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use frost_secp256k1_tr as frost;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;

/// BIP328 synthetic xpub chain code, SHA256("MuSig2MuSig2MuSig2"). Applied to
/// the FROST threshold public key so FROST and MuSig2 wallets derive alike.
pub const ROOT_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// One wallet address derived from a root FROST threshold key.
///
/// `root` and `tweaks` are the BIP445 view: untweaked shares plus the plain
/// BIP32 tweaks applied to the threshold public key. `derived` folds those
/// tweaks into every share, which is what frost-secp256k1-tr signs with.
#[derive(Clone)]
pub struct DerivedPublic {
    pub root: frost::keys::PublicKeyPackage,
    pub tweaks: Vec<[u8; 32]>,
    pub derived: frost::keys::PublicKeyPackage,
}

impl DerivedPublic {
    /// The root key itself, with no derivation.
    pub fn underived(root: frost::keys::PublicKeyPackage) -> Self {
        Self {
            derived: root.clone(),
            root,
            tweaks: Vec::new(),
        }
    }

    /// Fold the tweaks into a root key package for frost-secp256k1-tr signing.
    pub fn key(&self, root_key: &frost::keys::KeyPackage) -> Result<frost::keys::KeyPackage> {
        tweak_key(root_key, &self.derived, &self.tweaks)
    }
}

pub fn derive_public(root: &frost::keys::PublicKeyPackage, path: &[u32]) -> Result<DerivedPublic> {
    let mut derived = root.clone();
    let mut tweaks = Vec::with_capacity(path.len());
    let mut chain_code = ROOT_CHAIN_CODE;
    for child in path {
        if child & (1 << 31) != 0 {
            bail!("hardened FROST child derivation is not supported");
        }
        let (tweak, next_chain_code) = child_tweak(&derived, chain_code, *child)?;
        derived = tweak_public(&derived, tweak)?;
        tweaks.push(tweak);
        chain_code = next_chain_code;
    }
    Ok(DerivedPublic {
        root: root.clone(),
        tweaks,
        derived,
    })
}

fn child_tweak(
    package: &frost::keys::PublicKeyPackage,
    chain_code: [u8; 32],
    child: u32,
) -> Result<([u8; 32], [u8; 32])> {
    let group = package
        .verifying_key()
        .serialize()
        .context("serialize group key")?;
    let mut mac = Hmac::<Sha512>::new_from_slice(&chain_code).expect("HMAC accepts any key");
    mac.update(&group);
    mac.update(&child.to_be_bytes());
    let output = mac.finalize().into_bytes();
    let mut left = [0; 32];
    let mut right = [0; 32];
    left.copy_from_slice(&output[..32]);
    right.copy_from_slice(&output[32..]);
    SecretKey::from_slice(&left).context("BIP-32 child tweak is zero or out of range")?;
    Ok((left, right))
}

fn tweak_public(
    package: &frost::keys::PublicKeyPackage,
    tweak: [u8; 32],
) -> Result<frost::keys::PublicKeyPackage> {
    let secp = Secp256k1::verification_only();
    let scalar =
        Scalar::from_be_bytes(tweak).map_err(|_| anyhow::anyhow!("invalid child tweak"))?;
    let tweak_point = |bytes: Vec<u8>| -> Result<Vec<u8>> {
        Ok(PublicKey::from_slice(&bytes)?
            .add_exp_tweak(&secp, &scalar)?
            .serialize()
            .to_vec())
    };
    let verifying_key =
        frost::VerifyingKey::deserialize(&tweak_point(package.verifying_key().serialize()?)?)?;
    let shares = package
        .verifying_shares()
        .iter()
        .map(|(id, share)| {
            Ok((
                *id,
                frost::keys::VerifyingShare::deserialize(&tweak_point(share.serialize()?)?)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(frost::keys::PublicKeyPackage::new(
        shares,
        verifying_key,
        package.min_signers(),
    ))
}

fn tweak_key(
    key: &frost::keys::KeyPackage,
    derived_public: &frost::keys::PublicKeyPackage,
    tweaks: &[[u8; 32]],
) -> Result<frost::keys::KeyPackage> {
    let mut signing = SecretKey::from_slice(&key.signing_share().serialize())?;
    for tweak in tweaks {
        signing = signing.add_tweak(
            &Scalar::from_be_bytes(*tweak).map_err(|_| anyhow::anyhow!("invalid child tweak"))?,
        )?;
    }
    let signing_share = frost::keys::SigningShare::deserialize(&signing.secret_bytes())?;
    let verifying_share = *derived_public
        .verifying_shares()
        .get(key.identifier())
        .context("derived public package is missing participant")?;
    Ok(frost::keys::KeyPackage::new(
        *key.identifier(),
        signing_share,
        verifying_share,
        *derived_public.verifying_key(),
        *key.min_signers(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, Xpub};
    use bitcoin::Network;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn root_chain_code_is_bip328_constant() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            ROOT_CHAIN_CODE,
            <[u8; 32]>::from(Sha256::digest(b"MuSig2MuSig2MuSig2"))
        );
    }

    #[test]
    fn synthetic_chain_code_matches_ckdpub() {
        let mut rng = StdRng::seed_from_u64(4);
        let (_, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let secp = Secp256k1::verification_only();
        let root_key = PublicKey::from_slice(&public.verifying_key().serialize().unwrap()).unwrap();
        let root = Xpub {
            network: Network::Bitcoin.into(),
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: root_key,
            chain_code: ROOT_CHAIN_CODE.into(),
        };
        let path = [0, 17];
        let expected = path.iter().fold(root, |xpub, index| {
            xpub.ckd_pub(&secp, ChildNumber::from_normal_idx(*index).unwrap())
                .unwrap()
        });
        let actual = derive_public(&public, &path).unwrap();
        assert_eq!(
            actual.derived.verifying_key().serialize().unwrap(),
            expected.public_key.serialize()
        );
        // The plain tweaks alone carry the root key to the child key.
        let tweaked = actual.tweaks.iter().fold(root_key, |key, tweak| {
            key.add_exp_tweak(&secp, &Scalar::from_be_bytes(*tweak).unwrap())
                .unwrap()
        });
        assert_eq!(tweaked, expected.public_key);
    }

    #[test]
    fn secret_and_public_derivation_match() {
        let mut rng = StdRng::seed_from_u64(5);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        for share in shares.into_values() {
            let key: frost::keys::KeyPackage = share.try_into().unwrap();
            for path in [[0, 3], [1, 8]] {
                let derived = derive_public(&public, &path).unwrap();
                let derived_key = derived.key(&key).unwrap();
                assert_eq!(
                    derived
                        .derived
                        .verifying_shares()
                        .get(derived_key.identifier()),
                    Some(derived_key.verifying_share())
                );
                assert_eq!(derived.derived.verifying_key(), derived_key.verifying_key());
            }
        }
    }

    #[test]
    fn hardened_children_are_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let (_, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        assert!(derive_public(&public, &[1 << 31]).is_err());
    }
}
