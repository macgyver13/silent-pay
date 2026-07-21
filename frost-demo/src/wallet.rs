use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::{hash160, Hash};
use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::derivation::ROOT_CHAIN_CODE;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicWalletFile {
    pub format: String,
    pub threshold: u16,
    pub participants: u16,
    pub root_fingerprint: String,
    pub chain_code: String,
    pub public_key_package: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareFile {
    pub warning: String,
    pub format: String,
    pub participant: u16,
    pub root_fingerprint: String,
    pub public_key_package: String,
    pub key_package: String,
}

impl PublicWalletFile {
    pub fn package(&self) -> Result<frost::keys::PublicKeyPackage> {
        frost::keys::PublicKeyPackage::deserialize(&hex::decode(&self.public_key_package)?)
            .context("deserialize public FROST package")
    }

    pub fn fingerprint(&self) -> Result<Fingerprint> {
        let bytes: [u8; 4] = hex::decode(&self.root_fingerprint)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("root fingerprint must be four bytes"))?;
        Ok(Fingerprint::from(bytes))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        serde_json::from_slice(&fs::read(path)?).context("parse coordinator wallet file")
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_vec_pretty(self)?).context("write coordinator wallet file")
    }
}

impl ShareFile {
    pub fn packages(&self) -> Result<(frost::keys::KeyPackage, frost::keys::PublicKeyPackage)> {
        let key = frost::keys::KeyPackage::deserialize(&hex::decode(&self.key_package)?)
            .context("deserialize FROST key package")?;
        let public =
            frost::keys::PublicKeyPackage::deserialize(&hex::decode(&self.public_key_package)?)
                .context("deserialize public FROST package")?;
        Ok((key, public))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        serde_json::from_slice(&fs::read(path)?).context("parse companion share file")
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::write(path, serde_json::to_vec_pretty(self)?).context("write companion share file")
    }
}

pub fn provision(directory: impl AsRef<Path>) -> Result<(PathBuf, Vec<PathBuf>)> {
    let directory = directory.as_ref();
    fs::create_dir_all(directory).context("create wallet directory")?;
    let rng = OsRng;
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
            .context("generate 2-of-3 FROST wallet")?;
    let key_packages = shares
        .into_iter()
        .map(|(id, share)| Ok((id, frost::keys::KeyPackage::try_from(share)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let public_bytes = public.serialize().context("serialize public package")?;
    let group_key = public
        .verifying_key()
        .serialize()
        .context("serialize group key")?;
    let root_fingerprint = hex::encode(&hash160::Hash::hash(&group_key).to_byte_array()[..4]);
    let wallet = PublicWalletFile {
        format: "silent-pay-frost-demo-v1".into(),
        threshold: 2,
        participants: 3,
        root_fingerprint: root_fingerprint.clone(),
        chain_code: hex::encode(ROOT_CHAIN_CODE),
        public_key_package: hex::encode(&public_bytes),
    };
    let wallet_path = directory.join("frost-wallet.json");
    wallet.save(&wallet_path)?;
    let mut share_paths = Vec::new();
    for (index, key) in key_packages.values().enumerate() {
        let share = ShareFile {
            warning: "DEMO ONLY: plaintext FROST secret share; do not fund with real bitcoin"
                .into(),
            format: "silent-pay-frost-demo-share-v1".into(),
            participant: index as u16 + 1,
            root_fingerprint: root_fingerprint.clone(),
            public_key_package: hex::encode(&public_bytes),
            key_package: hex::encode(key.serialize().context("serialize key package")?),
        };
        let path = directory.join(format!("frost-share-{}.json", index + 1));
        share.save(&path)?;
        share_paths.push(path);
    }
    Ok((wallet_path, share_paths))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioned_files_share_one_authenticated_roster() {
        let directory = std::env::temp_dir().join(format!("frost-demo-{}", rand::random::<u64>()));
        let (wallet_path, shares) = provision(&directory).unwrap();
        let wallet = PublicWalletFile::load(wallet_path).unwrap();
        assert_eq!(shares.len(), 3);
        for path in shares {
            let share = ShareFile::load(path).unwrap();
            let (key, public) = share.packages().unwrap();
            assert_eq!(share.root_fingerprint, wallet.root_fingerprint);
            assert_eq!(public, wallet.package().unwrap());
            assert_eq!(
                public.verifying_shares().get(key.identifier()),
                Some(key.verifying_share())
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
