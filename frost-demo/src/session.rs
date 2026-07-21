use anyhow::{bail, Context, Result};
use psbt::Psbt;
use psbt_v2::raw;
use rand::{CryptoRng, RngCore};

pub const PROTOCOL_VERSION: u8 = 1;
const PSBT_GLOBAL_FROST_PROTOCOL_VERSION: u64 = 0x50;
const PSBT_GLOBAL_FROST_SESSION_ID: u64 = 0x51;
const PSBT_GLOBAL_FROST_CHILD_PATH: u64 = 0x52;

fn key(key_type: u64) -> raw::Key {
    raw::Key {
        type_value: key_type,
        key: Vec::new(),
    }
}

pub fn initialize<R: RngCore + CryptoRng>(psbt: &mut Psbt, rng: &mut R) -> [u8; 32] {
    let mut session_id = [0; 32];
    rng.fill_bytes(&mut session_id);
    psbt.global.unknowns.insert(
        key(PSBT_GLOBAL_FROST_PROTOCOL_VERSION),
        vec![PROTOCOL_VERSION],
    );
    psbt.global
        .unknowns
        .insert(key(PSBT_GLOBAL_FROST_SESSION_ID), session_id.to_vec());
    session_id
}

pub fn validate(psbt: &Psbt) -> Result<[u8; 32]> {
    let version = psbt
        .global
        .unknowns
        .get(&key(PSBT_GLOBAL_FROST_PROTOCOL_VERSION))
        .context("missing FROST demo protocol version")?;
    if version.as_slice() != [PROTOCOL_VERSION] {
        bail!("unsupported FROST demo protocol version");
    }
    psbt.global
        .unknowns
        .get(&key(PSBT_GLOBAL_FROST_SESSION_ID))
        .context("missing FROST session id")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("FROST session id must be 32 bytes"))
}

pub fn set_child_path(psbt: &mut Psbt, branch: u32, index: u32) {
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&branch.to_be_bytes());
    value.extend_from_slice(&index.to_be_bytes());
    psbt.global
        .unknowns
        .insert(key(PSBT_GLOBAL_FROST_CHILD_PATH), value);
}

pub fn child_path(psbt: &Psbt) -> Result<[u32; 2]> {
    let bytes = psbt
        .global
        .unknowns
        .get(&key(PSBT_GLOBAL_FROST_CHILD_PATH))
        .context("missing FROST child path")?;
    if bytes.len() != 8 {
        bail!("malformed FROST child path");
    }
    let branch = u32::from_be_bytes(bytes[..4].try_into().expect("checked length"));
    let index = u32::from_be_bytes(bytes[4..].try_into().expect("checked length"));
    if branch > 1 || branch & (1 << 31) != 0 || index & (1 << 31) != 0 {
        bail!("unsupported FROST child path");
    }
    Ok([branch, index])
}

pub fn read(path: impl AsRef<std::path::Path>) -> Result<Psbt> {
    Psbt::deserialize(&std::fs::read(path)?).context("deserialize PSBT")
}

pub fn write(psbt: &Psbt, path: impl AsRef<std::path::Path>) -> Result<()> {
    std::fs::write(path, psbt.serialize()).context("write PSBT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, OutPoint, Txid};
    use psbt_v2::v2::Output;
    use rand::{rngs::StdRng, SeedableRng};

    fn psbt() -> Psbt {
        psbt::musig2::build_psbt(
            vec![OutPoint::new(Txid::from_byte_array([1; 32]), 0)],
            Vec::<Output>::new(),
        )
        .unwrap()
    }

    #[test]
    fn session_survives_psbt_serialization() {
        let mut psbt = psbt();
        let id = initialize(&mut psbt, &mut StdRng::seed_from_u64(1));
        let decoded = Psbt::deserialize(&psbt.serialize()).unwrap();
        assert_eq!(validate(&decoded).unwrap(), id);
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut psbt = psbt();
        initialize(&mut psbt, &mut StdRng::seed_from_u64(1));
        psbt.global
            .unknowns
            .insert(key(PSBT_GLOBAL_FROST_PROTOCOL_VERSION), vec![9]);
        assert!(validate(&psbt).is_err());
    }
}
