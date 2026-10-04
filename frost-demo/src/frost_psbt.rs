//! PSBT representations that are not yet provided by upstream `rust-psbt`.
//!
//! Strawman FROST fields following the BIP373 layout. Participants carry
//! BIP445 identifiers (`0..n-1`); per-participant fields are keyed by the
//! participant's public share plus the threshold public key. Secret signing
//! nonces and key packages must never be stored in a PSBT.

use std::collections::{BTreeMap, BTreeSet};

use psbt_v2::raw;
use psbt_v2::{Input, Output};
use thiserror::Error;

/// Top-level FROST PSBT keytypes. Input fields occupy the `0x3x` range; the
/// FROST output field occupies the `0x2x` range to keep the two maps separate.
pub const PSBT_IN_FROST_THRESHOLD_INFO: u64 = 0x30;
pub const PSBT_IN_FROST_SIGNER_SET: u64 = 0x31;
// 0x32 and 0x33 are reserved for BIP445 public nonces and partial signatures.
// frost-secp256k1-tr (RFC 9591) values are not BIP445 compatible, so they use
// their own keytypes.
pub const PSBT_IN_FROST_RFC9591_COMMITMENT: u64 = 0x34;
pub const PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE: u64 = 0x35;
pub const PSBT_OUT_FROST_THRESHOLD_INFO: u64 = 0x20;

/// Human-readable name for a FROST PSBT keytype.
pub fn field_name(key_type: u64) -> Option<&'static str> {
    match key_type {
        PSBT_IN_FROST_THRESHOLD_INFO => Some("PSBT_IN_FROST_THRESHOLD_INFO"),
        PSBT_IN_FROST_SIGNER_SET => Some("PSBT_IN_FROST_SIGNER_SET"),
        PSBT_IN_FROST_RFC9591_COMMITMENT => Some("PSBT_IN_FROST_RFC9591_COMMITMENT"),
        PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE => Some("PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE"),
        PSBT_OUT_FROST_THRESHOLD_INFO => Some("PSBT_OUT_FROST_THRESHOLD_INFO"),
        _ => None,
    }
}

/// Compressed threshold public key.
pub type ThresholdKey = [u8; 33];
/// Compressed participant public share.
pub type PublicShare = [u8; 33];

/// BIP445 threshold info: `t` and each participant's public share by identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThresholdInfo {
    pub threshold: u8,
    pub public_shares: BTreeMap<u8, PublicShare>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid FROST threshold {threshold}-of-{participants}")]
    InvalidThreshold { threshold: u8, participants: usize },
    #[error("invalid FROST {field} field")]
    Malformed { field: &'static str },
    #[error("duplicate FROST {field} for participant {identifier}")]
    Duplicate {
        field: &'static str,
        identifier: String,
    },
    #[error("conflicting FROST {field} already exists")]
    Conflicting { field: &'static str },
}

/// Input-map accessors for the local FROST PSBT extension.
pub trait FrostInputExt {
    fn set_frost_threshold_info(
        &mut self,
        threshold_key: &ThresholdKey,
        info: &ThresholdInfo,
    ) -> Result<(), Error>;
    fn frost_threshold_info(&self) -> Result<Option<(ThresholdKey, ThresholdInfo)>, Error>;
    fn set_frost_signer_set(
        &mut self,
        threshold_key: &ThresholdKey,
        identifiers: &[u8],
    ) -> Result<(), Error>;
    fn frost_signer_set(&self) -> Result<Option<(ThresholdKey, Vec<u8>)>, Error>;
    fn add_frost_commitment(
        &mut self,
        public_share: &PublicShare,
        threshold_key: &ThresholdKey,
        commitment: &[u8],
    ) -> Result<(), Error>;
    fn frost_commitments(&self) -> Result<ParticipantValues, Error>;
    fn add_frost_signature_share(
        &mut self,
        public_share: &PublicShare,
        threshold_key: &ThresholdKey,
        share: &[u8],
    ) -> Result<(), Error>;
    fn frost_signature_shares(&self) -> Result<ParticipantValues, Error>;
}

/// Per-participant values keyed by `(public share, threshold key)`.
pub type ParticipantValues = BTreeMap<(PublicShare, ThresholdKey), Vec<u8>>;

/// Output-map accessors for the local FROST PSBT extension.
pub trait FrostOutputExt {
    fn set_frost_threshold_info(
        &mut self,
        threshold_key: &ThresholdKey,
        info: &ThresholdInfo,
    ) -> Result<(), Error>;
    fn frost_threshold_info(&self) -> Result<Option<(ThresholdKey, ThresholdInfo)>, Error>;
}

impl FrostInputExt for Input {
    fn set_frost_threshold_info(
        &mut self,
        threshold_key: &ThresholdKey,
        info: &ThresholdInfo,
    ) -> Result<(), Error> {
        set_single(
            &mut self.unknowns,
            PSBT_IN_FROST_THRESHOLD_INFO,
            "threshold info",
            threshold_key,
            encode_threshold_info(info)?,
        )
    }

    fn frost_threshold_info(&self) -> Result<Option<(ThresholdKey, ThresholdInfo)>, Error> {
        threshold_info(&self.unknowns, PSBT_IN_FROST_THRESHOLD_INFO)
    }

    fn set_frost_signer_set(
        &mut self,
        threshold_key: &ThresholdKey,
        identifiers: &[u8],
    ) -> Result<(), Error> {
        validate_signer_set(identifiers)?;
        set_single(
            &mut self.unknowns,
            PSBT_IN_FROST_SIGNER_SET,
            "signer set",
            threshold_key,
            identifiers.to_vec(),
        )
    }

    fn frost_signer_set(&self) -> Result<Option<(ThresholdKey, Vec<u8>)>, Error> {
        let Some((threshold_key, value)) =
            get_single(&self.unknowns, PSBT_IN_FROST_SIGNER_SET, "signer set")?
        else {
            return Ok(None);
        };
        validate_signer_set(value)?;
        Ok(Some((threshold_key, value.clone())))
    }

    fn add_frost_commitment(
        &mut self,
        public_share: &PublicShare,
        threshold_key: &ThresholdKey,
        commitment: &[u8],
    ) -> Result<(), Error> {
        insert_participant_field(
            self,
            PSBT_IN_FROST_RFC9591_COMMITMENT,
            "commitment",
            public_share,
            threshold_key,
            commitment,
        )
    }

    fn frost_commitments(&self) -> Result<ParticipantValues, Error> {
        participant_fields(self, PSBT_IN_FROST_RFC9591_COMMITMENT, "commitment")
    }

    fn add_frost_signature_share(
        &mut self,
        public_share: &PublicShare,
        threshold_key: &ThresholdKey,
        share: &[u8],
    ) -> Result<(), Error> {
        insert_participant_field(
            self,
            PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE,
            "signature share",
            public_share,
            threshold_key,
            share,
        )
    }

    fn frost_signature_shares(&self) -> Result<ParticipantValues, Error> {
        participant_fields(
            self,
            PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE,
            "signature share",
        )
    }
}

impl FrostOutputExt for Output {
    fn set_frost_threshold_info(
        &mut self,
        threshold_key: &ThresholdKey,
        info: &ThresholdInfo,
    ) -> Result<(), Error> {
        set_single(
            &mut self.unknowns,
            PSBT_OUT_FROST_THRESHOLD_INFO,
            "threshold info",
            threshold_key,
            encode_threshold_info(info)?,
        )
    }

    fn frost_threshold_info(&self) -> Result<Option<(ThresholdKey, ThresholdInfo)>, Error> {
        threshold_info(&self.unknowns, PSBT_OUT_FROST_THRESHOLD_INFO)
    }
}

/// `t`, then `(identifier, public share)` per participant in ascending order.
fn encode_threshold_info(info: &ThresholdInfo) -> Result<Vec<u8>, Error> {
    validate_threshold_info(info)?;
    let mut value = Vec::with_capacity(1 + 34 * info.public_shares.len());
    value.push(info.threshold);
    for (identifier, public_share) in &info.public_shares {
        value.push(*identifier);
        value.extend_from_slice(public_share);
    }
    Ok(value)
}

fn threshold_info(
    unknowns: &BTreeMap<raw::Key, Vec<u8>>,
    key_type: u64,
) -> Result<Option<(ThresholdKey, ThresholdInfo)>, Error> {
    let field = "threshold info";
    let Some((threshold_key, value)) = get_single(unknowns, key_type, field)? else {
        return Ok(None);
    };
    let Some((&threshold, entries)) = value.split_first() else {
        return Err(Error::Malformed { field });
    };
    if entries.is_empty() || entries.len() % 34 != 0 {
        return Err(Error::Malformed { field });
    }
    let mut public_shares = BTreeMap::new();
    let mut previous = None;
    for entry in entries.chunks(34) {
        let identifier = entry[0];
        if previous.is_some_and(|previous| identifier <= previous) {
            return Err(Error::Malformed { field });
        }
        previous = Some(identifier);
        public_shares.insert(identifier, entry[1..].try_into().expect("34-byte chunk"));
    }
    let info = ThresholdInfo {
        threshold,
        public_shares,
    };
    validate_threshold_info(&info)?;
    Ok(Some((threshold_key, info)))
}

fn validate_threshold_info(info: &ThresholdInfo) -> Result<(), Error> {
    let participants = info.public_shares.len();
    if info.threshold == 0 || usize::from(info.threshold) > participants {
        return Err(Error::InvalidThreshold {
            threshold: info.threshold,
            participants,
        });
    }
    let mut seen = BTreeSet::new();
    for (identifier, public_share) in &info.public_shares {
        if !seen.insert(public_share) {
            return Err(Error::Duplicate {
                field: "public share",
                identifier: identifier.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_signer_set(identifiers: &[u8]) -> Result<(), Error> {
    if identifiers.is_empty() || identifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Malformed {
            field: "signer set",
        });
    }
    Ok(())
}

/// Insert the single field of `key_type` allowed in a map, keyed by the
/// threshold public key.
fn set_single(
    unknowns: &mut BTreeMap<raw::Key, Vec<u8>>,
    key_type: u64,
    field: &'static str,
    threshold_key: &ThresholdKey,
    value: Vec<u8>,
) -> Result<(), Error> {
    let key = field_key(key_type, threshold_key);
    match get_single(unknowns, key_type, field)? {
        None => {
            unknowns.insert(key, value);
            Ok(())
        }
        Some((existing_key, existing)) if existing_key == *threshold_key && *existing == value => {
            Ok(())
        }
        Some(_) => Err(Error::Conflicting { field }),
    }
}

fn get_single<'a>(
    unknowns: &'a BTreeMap<raw::Key, Vec<u8>>,
    key_type: u64,
    field: &'static str,
) -> Result<Option<(ThresholdKey, &'a Vec<u8>)>, Error> {
    let mut fields = unknowns
        .iter()
        .filter(|(key, _)| key.type_value == key_type);
    let Some((key, value)) = fields.next() else {
        return Ok(None);
    };
    if fields.next().is_some() {
        return Err(Error::Conflicting { field });
    }
    let threshold_key = key
        .key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed { field })?;
    Ok(Some((threshold_key, value)))
}

fn insert_participant_field(
    input: &mut Input,
    key_type: u64,
    field: &'static str,
    public_share: &PublicShare,
    threshold_key: &ThresholdKey,
    value: &[u8],
) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Malformed { field });
    }
    let key = field_key(key_type, &[&public_share[..], &threshold_key[..]].concat());
    if input.unknowns.contains_key(&key) {
        return Err(Error::Duplicate {
            field,
            identifier: hex::encode(public_share),
        });
    }
    input.unknowns.insert(key, value.to_vec());
    Ok(())
}

fn participant_fields(
    input: &Input,
    key_type: u64,
    field: &'static str,
) -> Result<ParticipantValues, Error> {
    let mut fields = BTreeMap::new();
    for (key, value) in &input.unknowns {
        if key.type_value != key_type {
            continue;
        }
        if key.key.len() != 66 || value.is_empty() {
            return Err(Error::Malformed { field });
        }
        let public_share = key.key[..33].try_into().expect("33-byte public share");
        let threshold_key = key.key[33..].try_into().expect("33-byte threshold key");
        fields.insert((public_share, threshold_key), value.clone());
    }
    Ok(fields)
}

fn field_key(type_value: u64, key: &[u8]) -> raw::Key {
    raw::Key {
        type_value,
        key: key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};

    fn input() -> Input {
        Input::new(&OutPoint::new(Txid::all_zeros(), 0))
    }

    fn output() -> Output {
        Output::new(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        })
    }

    fn info() -> ThresholdInfo {
        ThresholdInfo {
            threshold: 2,
            public_shares: BTreeMap::from([(0, [3; 33]), (1, [4; 33]), (2, [5; 33])]),
        }
    }

    #[test]
    fn threshold_info_round_trips_in_identifier_order() {
        let mut input = input();
        input.set_frost_threshold_info(&[2; 33], &info()).unwrap();
        assert_eq!(
            input.frost_threshold_info().unwrap(),
            Some(([2; 33], info()))
        );
        let value = &input.unknowns[&field_key(PSBT_IN_FROST_THRESHOLD_INFO, &[2; 33])];
        assert_eq!(value.len(), 1 + 3 * 34);
        assert_eq!((value[0], value[1], value[35], value[69]), (2, 0, 1, 2));
    }

    #[test]
    fn rejects_invalid_threshold() {
        let mut input = input();
        for threshold in [0, 4] {
            let info = ThresholdInfo {
                threshold,
                ..info()
            };
            assert_eq!(
                input.set_frost_threshold_info(&[2; 33], &info),
                Err(Error::InvalidThreshold {
                    threshold,
                    participants: 3
                })
            );
        }
    }

    #[test]
    fn threshold_info_rejects_duplicate_shares_and_malformed_values() {
        let mut duplicate = info();
        duplicate.public_shares.insert(2, [3; 33]);
        assert!(matches!(
            input().set_frost_threshold_info(&[2; 33], &duplicate),
            Err(Error::Duplicate { .. })
        ));

        let encoded = encode_threshold_info(&info()).unwrap();
        let mut unsorted = encoded.clone();
        unsorted[35] = 0;
        let mut short = encoded.clone();
        short.pop();
        for (key, value) in [
            (vec![2; 33], unsorted),
            (vec![2; 33], short),
            (vec![2; 32], encoded),
        ] {
            let mut input = input();
            input
                .unknowns
                .insert(field_key(PSBT_IN_FROST_THRESHOLD_INFO, &key), value);
            assert!(matches!(
                input.frost_threshold_info(),
                Err(Error::Malformed { .. })
            ));
        }
    }

    #[test]
    fn threshold_info_rejects_conflicts() {
        let mut input = input();
        input.set_frost_threshold_info(&[2; 33], &info()).unwrap();
        input.set_frost_threshold_info(&[2; 33], &info()).unwrap();
        assert_eq!(
            input.set_frost_threshold_info(&[9; 33], &info()),
            Err(Error::Conflicting {
                field: "threshold info"
            })
        );
        let other = ThresholdInfo {
            threshold: 3,
            ..info()
        };
        assert_eq!(
            input.set_frost_threshold_info(&[2; 33], &other),
            Err(Error::Conflicting {
                field: "threshold info"
            })
        );
    }

    #[test]
    fn signer_set_round_trips_and_rejects_unsorted() {
        let mut signed = input();
        signed.set_frost_signer_set(&[2; 33], &[0, 2]).unwrap();
        assert_eq!(
            signed.frost_signer_set().unwrap(),
            Some(([2; 33], vec![0, 2]))
        );
        for identifiers in [&[][..], &[2, 0], &[1, 1]] {
            assert!(matches!(
                input().set_frost_signer_set(&[2; 33], identifiers),
                Err(Error::Malformed { .. })
            ));
        }
    }

    #[test]
    fn participant_fields_round_trip_and_reject_duplicates() {
        let mut input = input();
        input
            .add_frost_commitment(&[3; 33], &[2; 33], &[7; 66])
            .unwrap();
        assert_eq!(
            input.frost_commitments().unwrap(),
            BTreeMap::from([(([3; 33], [2; 33]), vec![7; 66])])
        );
        assert!(matches!(
            input.add_frost_commitment(&[3; 33], &[2; 33], &[8; 66]),
            Err(Error::Duplicate { .. })
        ));
        input.unknowns.insert(
            field_key(PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE, &[3; 65]),
            vec![1],
        );
        assert!(matches!(
            input.frost_signature_shares(),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn ignores_unrelated_unknown_fields() {
        let mut input = input();
        input.unknowns.insert(
            raw::Key {
                type_value: 0xaa,
                key: vec![1],
            },
            vec![2],
        );
        assert!(input.frost_commitments().unwrap().is_empty());
        assert!(input.frost_threshold_info().unwrap().is_none());
    }

    #[test]
    fn output_threshold_info_round_trips() {
        let mut output = output();
        output.set_frost_threshold_info(&[2; 33], &info()).unwrap();
        assert_eq!(
            output.frost_threshold_info().unwrap(),
            Some(([2; 33], info()))
        );
        assert!(output
            .unknowns
            .keys()
            .all(|key| key.type_value == PSBT_OUT_FROST_THRESHOLD_INFO));
    }

    #[test]
    fn names_frost_fields() {
        for (key_type, expected) in [
            (PSBT_IN_FROST_THRESHOLD_INFO, "PSBT_IN_FROST_THRESHOLD_INFO"),
            (PSBT_IN_FROST_SIGNER_SET, "PSBT_IN_FROST_SIGNER_SET"),
            (
                PSBT_IN_FROST_RFC9591_COMMITMENT,
                "PSBT_IN_FROST_RFC9591_COMMITMENT",
            ),
            (
                PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE,
                "PSBT_IN_FROST_RFC9591_SIGNATURE_SHARE",
            ),
            (
                PSBT_OUT_FROST_THRESHOLD_INFO,
                "PSBT_OUT_FROST_THRESHOLD_INFO",
            ),
        ] {
            assert_eq!(field_name(key_type), Some(expected));
        }
        assert_eq!(field_name(0x32), None);
    }
}
