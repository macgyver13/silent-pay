//! BIP445 FROST signing for BIP340 signatures.
//!
//! A direct port of the draft's reference `frost_ref/signing.py`
//! (bitcoin/bips#2070 at 8e25d579), checked against its JSON vectors in
//! `vectors/bip445`. Function names, check order, and error messages follow
//! the reference so the two can be read side by side. Deterministic signing
//! is not ported.
//!
//! Demo only: like the reference, this is not constant time.

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;

const FROST_TAG_AUX: &str = "BIP0445/aux";
const FROST_TAG_NONCE: &str = "BIP0445/nonce";
const FROST_TAG_NONCECOEF: &str = "BIP0445/noncecoef";
const BIP340_TAG_CHALLENGE: &str = "BIP0340/challenge";

/// Upper bound on the total number of participants `n`.
pub const MAX_PARTICIPANTS: u32 = 128;

/// `Value` is a violated precondition (the reference's `ValueError`);
/// `InvalidContribution` blames a signer (`Some(index)`) or the coordinator
/// (`None`) for a malformed contribution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Value(String),
    #[error("invalid {contrib} from signer {signer_index:?}")]
    InvalidContribution {
        signer_index: Option<usize>,
        contrib: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

fn value_error<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Value(message.into()))
}

/// A signer's secret nonce. It is consumed by [`sign`], so it cannot be used
/// twice through this API, and it is deliberately neither `Clone` nor
/// serializable.
pub struct SecNonce([u8; 64]);

#[cfg(test)]
impl SecNonce {
    fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

fn derive_interpolating_value(ids: &[u32], my_id: u32) -> Scalar {
    debug_assert!(ids.contains(&my_id) && !has_duplicates(ids));
    let mut num = Scalar::ONE;
    let mut deno = Scalar::ONE;
    for &curr_id in ids {
        if curr_id == my_id {
            continue;
        }
        num *= Scalar::from(u64::from(curr_id) + 1);
        deno *= Scalar::from(u64::from(curr_id)) - Scalar::from(u64::from(my_id));
    }
    num * Option::<Scalar>::from(deno.invert()).expect("ids are distinct")
}

/// Interpolate the public share polynomial at `x` (in identifier space).
fn derive_pubshare_at(ids: &[u32], pubshares: &[ProjectivePoint], x: Scalar) -> ProjectivePoint {
    let mut q = ProjectivePoint::IDENTITY;
    for (&my_id, x_i) in ids.iter().zip(pubshares) {
        let mut num = Scalar::ONE;
        let mut deno = Scalar::ONE;
        for &curr_id in ids {
            if curr_id == my_id {
                continue;
            }
            num *= x - Scalar::from(u64::from(curr_id));
            deno *= Scalar::from(u64::from(my_id)) - Scalar::from(u64::from(curr_id));
        }
        q += *x_i * (num * Option::<Scalar>::from(deno.invert()).expect("ids are distinct"));
    }
    q
}

fn derive_thresh_pubkey(ids: &[u32], pubshares: &[ProjectivePoint]) -> Result<[u8; 33]> {
    // Identifier `id` sits at x = id + 1, so the secret (x = 0) is at -1.
    let q = derive_pubshare_at(ids, pubshares, -Scalar::ONE);
    if bool::from(q.is_identity()) {
        return value_error("The threshold public key must not be the point at infinity.");
    }
    Ok(compressed(&q))
}

/// Accumulated BIP445 tweak state: `Q = g * (gacc * P) + tacc * G`.
#[derive(Clone, Copy, Debug)]
pub struct TweakContext {
    pub q: ProjectivePoint,
    pub gacc: Scalar,
    pub tacc: Scalar,
}

impl TweakContext {
    pub fn xonly_pk(&self) -> [u8; 32] {
        xonly(&self.q)
    }

    pub fn plain_pk(&self) -> [u8; 33] {
        compressed(&self.q)
    }
}

fn tweak_ctx_init(thresh_pk: &[u8]) -> Result<TweakContext> {
    let Some(q) = point_from_compressed(thresh_pk) else {
        return value_error("Invalid threshold public key.");
    };
    Ok(TweakContext {
        q,
        gacc: Scalar::ONE,
        tacc: Scalar::ZERO,
    })
}

pub fn apply_tweak(tweak_ctx: TweakContext, tweak: &[u8], is_xonly: bool) -> Result<TweakContext> {
    if tweak.len() != 32 {
        return value_error("The tweak must be a 32-byte array.");
    }
    let TweakContext { q, gacc, tacc } = tweak_ctx;
    let g = if is_xonly && !has_even_y(&q) {
        -Scalar::ONE
    } else {
        Scalar::ONE
    };
    let Some(twk) = scalar_checked(tweak) else {
        return value_error("The tweak value is out of range.");
    };
    let q_ = q * g + ProjectivePoint::GENERATOR * twk;
    if bool::from(q_.is_identity()) {
        return value_error("The result of tweaking cannot be infinity.");
    }
    Ok(TweakContext {
        q: q_,
        gacc: g * gacc,
        tacc: twk + g * tacc,
    })
}

pub fn thresh_pubkey_and_tweak(
    thresh_pk: &[u8],
    tweaks: &[Vec<u8>],
    is_xonly: &[bool],
) -> Result<TweakContext> {
    if tweaks.len() != is_xonly.len() {
        return value_error("The tweaks and is_xonly arrays must have the same length.");
    }
    let mut tweak_ctx = tweak_ctx_init(thresh_pk)?;
    for (tweak, &is_xonly) in tweaks.iter().zip(is_xonly) {
        tweak_ctx = apply_tweak(tweak_ctx, tweak, is_xonly)?;
    }
    Ok(tweak_ctx)
}

fn nonce_hash(
    rand_: &[u8],
    pubshare: &[u8],
    thresh_pk_xonly: &[u8],
    i: u8,
    msg_prefixed: &[u8],
    extra_in: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(rand_);
    buf.push(pubshare.len() as u8);
    buf.extend_from_slice(pubshare);
    buf.push(thresh_pk_xonly.len() as u8);
    buf.extend_from_slice(thresh_pk_xonly);
    buf.extend_from_slice(msg_prefixed);
    buf.extend_from_slice(&(extra_in.len() as u32).to_be_bytes());
    buf.extend_from_slice(extra_in);
    buf.push(i);
    tagged_hash(FROST_TAG_NONCE, &buf)
}

fn nonce_gen_internal(
    rand: &[u8; 32],
    secshare: Option<&[u8; 32]>,
    pubshare: Option<&[u8; 33]>,
    thresh_pk_xonly: Option<&[u8; 32]>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
) -> (SecNonce, [u8; 66]) {
    let rand_ = match secshare {
        Some(secshare) => {
            let aux = tagged_hash(FROST_TAG_AUX, rand);
            std::array::from_fn::<u8, 32, _>(|i| secshare[i] ^ aux[i])
        }
        None => *rand,
    };
    let msg_prefixed = match msg {
        None => vec![0],
        Some(msg) => [&[1][..], &(msg.len() as u64).to_be_bytes(), msg].concat(),
    };
    let pubshare = pubshare.map_or(&[][..], |pubshare| &pubshare[..]);
    let thresh_pk_xonly = thresh_pk_xonly.map_or(&[][..], |key| &key[..]);
    let extra_in = extra_in.unwrap_or_default();
    let k = |i| {
        scalar_wrapping(nonce_hash(
            &rand_,
            pubshare,
            thresh_pk_xonly,
            i,
            &msg_prefixed,
            extra_in,
        ))
    };
    let (k_1, k_2) = (k(0), k(1));
    // k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert!(!bool::from(k_1.is_zero()) && !bool::from(k_2.is_zero()));
    let mut secnonce = [0; 64];
    secnonce[..32].copy_from_slice(&k_1.to_bytes());
    secnonce[32..].copy_from_slice(&k_2.to_bytes());
    (SecNonce(secnonce), pubnonce(&k_1, &k_2))
}

/// BIP445 `NonceGen`. Every optional input strengthens the nonce against a
/// weak `rng`; none of them replaces fresh randomness.
pub fn nonce_gen<R: RngCore + CryptoRng>(
    rng: &mut R,
    secshare: Option<&[u8; 32]>,
    pubshare: Option<&[u8; 33]>,
    thresh_pk_xonly: Option<&[u8; 32]>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
) -> (SecNonce, [u8; 66]) {
    let mut rand = [0; 32];
    rng.fill_bytes(&mut rand);
    nonce_gen_internal(&rand, secshare, pubshare, thresh_pk_xonly, msg, extra_in)
}

pub fn nonce_agg(pubnonces: &[Vec<u8>]) -> Result<[u8; 66]> {
    let mut aggnonce = [0; 66];
    for j in 0..2 {
        let mut r_j = ProjectivePoint::IDENTITY;
        for (idx, pubnonce) in pubnonces.iter().enumerate() {
            let Some(r_ij) = pubnonce
                .get(j * 33..(j + 1) * 33)
                .and_then(point_from_compressed)
            else {
                return Err(Error::InvalidContribution {
                    signer_index: Some(idx),
                    contrib: "pubnonce",
                });
            };
            r_j += r_ij;
        }
        aggnonce[j * 33..(j + 1) * 33].copy_from_slice(&compressed_with_infinity(&r_j));
    }
    Ok(aggnonce)
}

/// One signing session: the signer set, key material, aggregate nonce,
/// tweaks, and message.
pub struct SessionContext<'a> {
    pub n: u32,
    pub t: u32,
    pub ids: &'a [u32],
    /// The signers' public shares, or `None` when they are unknown.
    pub pubshares: Option<&'a [Vec<u8>]>,
    pub thresh_pk: &'a [u8],
    pub aggnonce: &'a [u8],
    pub tweaks: &'a [Vec<u8>],
    pub is_xonly: &'a [bool],
    pub msg: &'a [u8],
}

fn validate_session_params(
    n: u32,
    t: u32,
    ids: &[u32],
    pubshares: Option<&[Vec<u8>]>,
    thresh_pk: &[u8],
) -> Result<()> {
    if !(1 <= t && t <= n) {
        return value_error("The threshold must be 1 <= t <= n.");
    }
    if n > MAX_PARTICIPANTS {
        return value_error(format!(
            "The number of participants must be n <= {MAX_PARTICIPANTS}."
        ));
    }
    if !(t as usize <= ids.len() && ids.len() <= n as usize) {
        return value_error("The number of signers must be between t and n.");
    }
    if pubshares.is_some_and(|pubshares| pubshares.len() != ids.len()) {
        return value_error("The pubshares and ids lists must have the same length.");
    }
    let mut pubshare_points = Vec::new();
    for (idx, &i) in ids.iter().enumerate() {
        if i > n - 1 {
            return value_error(format!("Invalid id at index {idx}"));
        }
        if let Some(pubshares) = pubshares {
            let Some(point) = point_from_compressed(&pubshares[idx]) else {
                return value_error(format!("Invalid pubshare at index {idx}."));
            };
            pubshare_points.push(point);
        }
    }
    if has_duplicates(ids) {
        return value_error("The ids list contains duplicate elements.");
    }
    if pubshares.is_some() && derive_thresh_pubkey(ids, &pubshare_points)? != thresh_pk {
        return value_error(
            "The provided key material is incorrect: the public shares do not match the threshold public key.",
        );
    }
    Ok(())
}

struct SessionValues {
    q: ProjectivePoint,
    gacc: Scalar,
    tacc: Scalar,
    b: Scalar,
    r: ProjectivePoint,
    e: Scalar,
}

fn get_session_values(session_ctx: &SessionContext) -> Result<SessionValues> {
    let SessionContext {
        n,
        t,
        ids,
        pubshares,
        thresh_pk,
        aggnonce,
        tweaks,
        is_xonly,
        msg,
    } = *session_ctx;
    validate_session_params(n, t, ids, pubshares, thresh_pk)?;
    let TweakContext { q, gacc, tacc } = thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)?;
    // The signers are a set, so serialize_ids sorts to keep b independent of
    // the order of ids.
    let b = scalar_wrapping(tagged_hash(
        FROST_TAG_NONCECOEF,
        &[
            &(ids.len() as u32).to_be_bytes()[..],
            &serialize_ids(ids),
            aggnonce,
            &xonly(&q),
            msg,
        ]
        .concat(),
    ));
    assert!(!bool::from(b.is_zero()));
    let (Some(r1), Some(r2)) = (
        aggnonce
            .get(0..33)
            .and_then(point_from_compressed_with_infinity),
        aggnonce
            .get(33..66)
            .and_then(point_from_compressed_with_infinity),
    ) else {
        // The coordinator sent an invalid aggnonce.
        return Err(Error::InvalidContribution {
            signer_index: None,
            contrib: "aggnonce",
        });
    };
    let r_ = r1 + r2 * b;
    let r = if bool::from(r_.is_identity()) {
        ProjectivePoint::GENERATOR
    } else {
        r_
    };
    let e = scalar_wrapping(tagged_hash(
        BIP340_TAG_CHALLENGE,
        &[&xonly(&r)[..], &xonly(&q), msg].concat(),
    ));
    assert!(!bool::from(e.is_zero()));
    Ok(SessionValues {
        q,
        gacc,
        tacc,
        b,
        r,
        e,
    })
}

fn serialize_ids(ids: &[u32]) -> Vec<u8> {
    let mut sorted_ids = ids.to_vec();
    sorted_ids.sort_unstable();
    sorted_ids.iter().flat_map(|id| id.to_be_bytes()).collect()
}

/// BIP445 `Sign`: consume `secnonce` and return the 32-byte partial signature.
pub fn sign(
    secnonce: SecNonce,
    secshare: &[u8],
    my_id: u32,
    session_ctx: &SessionContext,
) -> Result<[u8; 32]> {
    let SessionValues {
        q, gacc, b, r, e, ..
    } = get_session_values(session_ctx)?;
    let Some(k_1_) = scalar_nonzero_checked(&secnonce.0[0..32]) else {
        return value_error("first secnonce value is out of range.");
    };
    let Some(k_2_) = scalar_nonzero_checked(&secnonce.0[32..64]) else {
        return value_error("second secnonce value is out of range.");
    };
    let (k_1, k_2) = if has_even_y(&r) {
        (k_1_, k_2_)
    } else {
        (-k_1_, -k_2_)
    };
    let Some(d_) = scalar_nonzero_checked(secshare) else {
        return value_error("The signer's secret share value is out of range.");
    };
    let my_pubshare = compressed(&(ProjectivePoint::GENERATOR * d_));
    let Some(signer_index) = session_ctx.ids.iter().position(|&id| id == my_id) else {
        return value_error("The signer's id is missing from the ids list.");
    };
    if session_ctx
        .pubshares
        .is_some_and(|pubshares| pubshares[signer_index] != my_pubshare)
    {
        return value_error("The signer's pubshare is missing from the pubshares list.");
    }
    let a = derive_interpolating_value(session_ctx.ids, my_id);
    let g = if has_even_y(&q) {
        Scalar::ONE
    } else {
        -Scalar::ONE
    };
    let d = g * gacc * d_;
    let s = k_1 + b * k_2 + e * a * d;
    let psig: [u8; 32] = s.to_bytes().into();
    // Optional correctness check: the result must pass partial verification.
    debug_assert_eq!(
        partial_sig_verify_internal(
            &psig,
            my_id,
            &pubnonce(&k_1_, &k_2_),
            &my_pubshare,
            session_ctx
        ),
        Ok(true)
    );
    Ok(psig)
}

/// BIP445 `PartialSigVerify` for the signer at position `i` of `ids`.
#[allow(clippy::too_many_arguments)]
pub fn partial_sig_verify(
    psig: &[u8],
    pubnonces: &[Vec<u8>],
    n: u32,
    t: u32,
    ids: &[u32],
    pubshares: &[Vec<u8>],
    thresh_pk: &[u8],
    tweaks: &[Vec<u8>],
    is_xonly: &[bool],
    msg: &[u8],
    i: usize,
) -> Result<bool> {
    if pubnonces.len() != ids.len() || pubshares.len() != ids.len() {
        return value_error("The pubnonces, pubshares and ids lists must have the same length.");
    }
    if i >= ids.len() {
        return value_error("The signer index must satisfy 0 <= i <= u - 1.");
    }
    if tweaks.len() != is_xonly.len() {
        return value_error("The tweaks and is_xonly lists must have the same length.");
    }
    validate_session_params(n, t, ids, Some(pubshares), thresh_pk)?;
    let aggnonce = nonce_agg(pubnonces)?;
    let session_ctx = SessionContext {
        n,
        t,
        ids,
        pubshares: Some(pubshares),
        thresh_pk,
        aggnonce: &aggnonce,
        tweaks,
        is_xonly,
        msg,
    };
    partial_sig_verify_internal(psig, ids[i], &pubnonces[i], &pubshares[i], &session_ctx)
}

fn partial_sig_verify_internal(
    psig: &[u8],
    my_id: u32,
    pubnonce: &[u8],
    pubshare: &[u8],
    session_ctx: &SessionContext,
) -> Result<bool> {
    let SessionValues {
        q, gacc, b, r, e, ..
    } = get_session_values(session_ctx)?;
    let Some(s) = scalar_checked(psig) else {
        return Ok(false);
    };
    let (Some(r1_partial), Some(r2_partial)) = (
        pubnonce.get(0..33).and_then(point_from_compressed),
        pubnonce.get(33..66).and_then(point_from_compressed),
    ) else {
        return Ok(false);
    };
    let re_s_ = r1_partial + r2_partial * b;
    let re_s = if has_even_y(&r) { re_s_ } else { -re_s_ };
    let Some(p) = point_from_compressed(pubshare) else {
        return Ok(false);
    };
    let a = derive_interpolating_value(session_ctx.ids, my_id);
    let g = if has_even_y(&q) {
        Scalar::ONE
    } else {
        -Scalar::ONE
    };
    let g_ = g * gacc;
    Ok(ProjectivePoint::GENERATOR * s == re_s + p * (e * a * g_))
}

/// BIP445 `PartialSigAgg`: combine partial signatures into a BIP340 signature.
pub fn partial_sig_agg(psigs: &[Vec<u8>], session_ctx: &SessionContext) -> Result<[u8; 64]> {
    let SessionValues { q, tacc, r, e, .. } = get_session_values(session_ctx)?;
    if psigs.len() != session_ctx.ids.len() {
        return value_error("The psigs and ids lists must have the same length.");
    }
    let mut s = Scalar::ZERO;
    for (idx, psig) in psigs.iter().enumerate() {
        let Some(s_i) = scalar_checked(psig) else {
            return Err(Error::InvalidContribution {
                signer_index: Some(idx),
                contrib: "psig",
            });
        };
        s += s_i;
    }
    let g = if has_even_y(&q) {
        Scalar::ONE
    } else {
        -Scalar::ONE
    };
    s += e * g * tacc;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&xonly(&r));
    signature[32..].copy_from_slice(&s.to_bytes());
    Ok(signature)
}

fn has_duplicates(ids: &[u32]) -> bool {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|pair| pair[0] == pair[1])
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    Sha256::new()
        .chain_update(tag_hash)
        .chain_update(tag_hash)
        .chain_update(data)
        .finalize()
        .into()
}

fn pubnonce(k_1: &Scalar, k_2: &Scalar) -> [u8; 66] {
    let mut pubnonce = [0; 66];
    pubnonce[..33].copy_from_slice(&compressed(&(ProjectivePoint::GENERATOR * k_1)));
    pubnonce[33..].copy_from_slice(&compressed(&(ProjectivePoint::GENERATOR * k_2)));
    pubnonce
}

fn point_from_compressed(bytes: &[u8]) -> Option<ProjectivePoint> {
    if bytes.len() != 33 || !matches!(bytes[0], 2 | 3) {
        return None;
    }
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)).map(Into::into)
}

/// Like [`point_from_compressed`], but 33 zero bytes decode to infinity.
fn point_from_compressed_with_infinity(bytes: &[u8]) -> Option<ProjectivePoint> {
    if bytes.len() == 33 && bytes.iter().all(|byte| *byte == 0) {
        return Some(ProjectivePoint::IDENTITY);
    }
    point_from_compressed(bytes)
}

fn compressed(point: &ProjectivePoint) -> [u8; 33] {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("a finite point encodes to 33 bytes")
}

fn compressed_with_infinity(point: &ProjectivePoint) -> [u8; 33] {
    if bool::from(point.is_identity()) {
        [0; 33]
    } else {
        compressed(point)
    }
}

fn xonly(point: &ProjectivePoint) -> [u8; 32] {
    point.to_affine().x().into()
}

fn has_even_y(point: &ProjectivePoint) -> bool {
    !bool::from(point.to_affine().y_is_odd())
}

fn scalar_checked(bytes: &[u8]) -> Option<Scalar> {
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_repr(FieldBytes::from(bytes)))
}

fn scalar_nonzero_checked(bytes: &[u8]) -> Option<Scalar> {
    scalar_checked(bytes).filter(|scalar| !bool::from(scalar.is_zero()))
}

fn scalar_wrapping(hash: [u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn load(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }

    fn all(value: &Value) -> Vec<Vec<u8>> {
        value.as_array().unwrap().iter().map(bytes).collect()
    }

    fn index(value: &Value) -> usize {
        value.as_u64().unwrap() as usize
    }

    fn pick(items: &[Vec<u8>], indices: &Value) -> Vec<Vec<u8>> {
        indices
            .as_array()
            .unwrap()
            .iter()
            .map(|i| items[index(i)].clone())
            .collect()
    }

    fn ids(value: &Value) -> Vec<u32> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_u64().unwrap() as u32)
            .collect()
    }

    fn bools(value: &Value) -> Vec<bool> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_bool().unwrap())
            .collect()
    }

    fn secnonce(bytes: &[u8]) -> SecNonce {
        SecNonce::from_bytes(bytes.try_into().unwrap())
    }

    fn expect_error<T: std::fmt::Debug>(result: Result<T>, case: &Value) {
        let error = &case["error"];
        let comment = &case["comment"];
        match (result, error["type"].as_str().unwrap()) {
            (Err(Error::Value(message)), "ValueError") => {
                assert_eq!(message, error["message"].as_str().unwrap(), "{comment}")
            }
            (
                Err(Error::InvalidContribution {
                    signer_index,
                    contrib,
                }),
                "InvalidContributionError",
            ) => {
                assert_eq!(
                    signer_index,
                    error["signer_index"].as_u64().map(|i| i as usize),
                    "{comment}"
                );
                assert_eq!(contrib, error["contrib"].as_str().unwrap(), "{comment}");
            }
            (other, _) => panic!("{comment}: expected {error}, got {other:?}"),
        }
    }

    #[test]
    fn nonce_gen_vectors() {
        let data = load(include_str!("../vectors/bip445/nonce_gen_vectors.json"));
        for case in data["valid_tests"].as_array().unwrap() {
            let maybe = |key: &str| (!case[key].is_null()).then(|| bytes(&case[key]));
            let (secshare, pubshare, thresh_pk_xonly, msg, extra_in) = (
                maybe("secshare"),
                maybe("pubshare"),
                maybe("thresh_pk_xonly"),
                maybe("msg"),
                maybe("extra_in"),
            );
            let (secnonce, pubnonce) = nonce_gen_internal(
                &bytes(&case["rand"]).try_into().unwrap(),
                secshare.as_deref().map(|b| b.try_into().unwrap()),
                pubshare.as_deref().map(|b| b.try_into().unwrap()),
                thresh_pk_xonly.as_deref().map(|b| b.try_into().unwrap()),
                msg.as_deref(),
                extra_in.as_deref(),
            );
            let expected = all(&case["expected"]);
            assert_eq!(secnonce.0.to_vec(), expected[0], "{}", case["comment"]);
            assert_eq!(pubnonce.to_vec(), expected[1], "{}", case["comment"]);
        }
    }

    #[test]
    fn nonce_agg_vectors() {
        let data = load(include_str!("../vectors/bip445/nonce_agg_vectors.json"));
        let pubnonces = all(&data["pubnonces"]);
        for case in data["valid_tests"].as_array().unwrap() {
            let aggnonce = nonce_agg(&pick(&pubnonces, &case["pubnonce_indices"])).unwrap();
            assert_eq!(aggnonce.to_vec(), bytes(&case["expected"]));
        }
        for case in data["error_tests"].as_array().unwrap() {
            expect_error(
                nonce_agg(&pick(&pubnonces, &case["pubnonce_indices"])),
                case,
            );
        }
    }

    #[test]
    fn sign_verify_vectors() {
        let data = load(include_str!("../vectors/bip445/sign_verify_vectors.json"));
        for group in data["test_groups"].as_array().unwrap() {
            let n = group["n"].as_u64().unwrap() as u32;
            let t = group["t"].as_u64().unwrap() as u32;
            let thresh_pk = bytes(&group["thresh_pk"]);
            let pubshares = all(&group["pubshares"]);
            let pubnonces = all(&group["pubnonces"]);
            let secshares = all(&group["secshares"]);
            let secnonces = all(&group["secnonces"]);

            for case in group["valid_tests"].as_array().unwrap() {
                let ids = ids(&case["ids"]);
                let case_pubshares = (!case["pubshare_indices"].is_null())
                    .then(|| pick(&pubshares, &case["pubshare_indices"]));
                let case_pubnonces = pick(&pubnonces, &case["pubnonce_indices"]);
                let aggnonce = bytes(&case["aggnonce"]);
                assert_eq!(nonce_agg(&case_pubnonces).unwrap().to_vec(), aggnonce);
                let msg = bytes(&case["msg"]);
                let my_id = case["my_id"].as_u64().unwrap() as u32;
                let session_ctx = SessionContext {
                    n,
                    t,
                    ids: &ids,
                    pubshares: case_pubshares.as_deref(),
                    thresh_pk: &thresh_pk,
                    aggnonce: &aggnonce,
                    tweaks: &[],
                    is_xonly: &[],
                    msg: &msg,
                };
                let psig = sign(
                    secnonce(&secnonces[index(&case["secnonce_index"])]),
                    &secshares[index(&case["secshare_index"])],
                    my_id,
                    &session_ctx,
                )
                .unwrap();
                assert_eq!(
                    psig.to_vec(),
                    bytes(&case["expected"]),
                    "{}",
                    case["comment"]
                );
                if let Some(case_pubshares) = &case_pubshares {
                    let signer_index = ids.iter().position(|&id| id == my_id).unwrap();
                    assert_eq!(
                        partial_sig_verify(
                            &psig,
                            &case_pubnonces,
                            n,
                            t,
                            &ids,
                            case_pubshares,
                            &thresh_pk,
                            &[],
                            &[],
                            &msg,
                            signer_index,
                        ),
                        Ok(true)
                    );
                }
            }

            for case in group["sign_error_tests"].as_array().unwrap() {
                let ids = ids(&case["ids"]);
                let case_pubshares = pick(&pubshares, &case["pubshare_indices"]);
                let aggnonce = bytes(&case["aggnonce"]);
                let msg = bytes(&case["msg"]);
                let session_ctx = SessionContext {
                    n,
                    t,
                    ids: &ids,
                    pubshares: Some(&case_pubshares),
                    thresh_pk: &thresh_pk,
                    aggnonce: &aggnonce,
                    tweaks: &[],
                    is_xonly: &[],
                    msg: &msg,
                };
                expect_error(
                    sign(
                        secnonce(&secnonces[index(&case["secnonce_index"])]),
                        &secshares[index(&case["secshare_index"])],
                        case["my_id"].as_u64().unwrap() as u32,
                        &session_ctx,
                    ),
                    case,
                );
            }

            for (cases, fails) in [("verify_fail_tests", true), ("verify_error_tests", false)] {
                for case in group[cases].as_array().unwrap() {
                    let result = partial_sig_verify(
                        &bytes(&case["psig"]),
                        &pick(&pubnonces, &case["pubnonce_indices"]),
                        n,
                        t,
                        &ids(&case["ids"]),
                        &pick(&pubshares, &case["pubshare_indices"]),
                        &thresh_pk,
                        &[],
                        &[],
                        &bytes(&case["msg"]),
                        index(&case["signer_index"]),
                    );
                    if fails {
                        assert_eq!(result, Ok(false), "{}", case["comment"]);
                    } else {
                        expect_error(result, case);
                    }
                }
            }
        }
    }

    #[test]
    fn tweak_vectors() {
        let data = load(include_str!("../vectors/bip445/tweak_vectors.json"));
        for group in data["test_groups"].as_array().unwrap() {
            let n = group["n"].as_u64().unwrap() as u32;
            let t = group["t"].as_u64().unwrap() as u32;
            let thresh_pk = bytes(&group["thresh_pk"]);
            let pubshares = all(&group["pubshares"]);
            let pubnonces = all(&group["pubnonces"]);
            let secshares = all(&group["secshares"]);
            let secnonces = all(&group["secnonces"]);
            let tweaks = all(&group["tweaks"]);

            for (cases, valid) in [("valid_tests", true), ("error_tests", false)] {
                for case in group[cases].as_array().unwrap() {
                    let ids = ids(&case["ids"]);
                    let case_pubshares = pick(&pubshares, &case["pubshare_indices"]);
                    let aggnonce = bytes(&case["aggnonce"]);
                    let msg = bytes(&case["msg"]);
                    let case_tweaks = pick(&tweaks, &case["tweak_indices"]);
                    let is_xonly = bools(&case["is_xonly"]);
                    let my_id = case["my_id"].as_u64().unwrap() as u32;
                    let session_ctx = SessionContext {
                        n,
                        t,
                        ids: &ids,
                        pubshares: Some(&case_pubshares),
                        thresh_pk: &thresh_pk,
                        aggnonce: &aggnonce,
                        tweaks: &case_tweaks,
                        is_xonly: &is_xonly,
                        msg: &msg,
                    };
                    let result = sign(
                        secnonce(&secnonces[index(&case["secnonce_index"])]),
                        &secshares[index(&case["secshare_index"])],
                        my_id,
                        &session_ctx,
                    );
                    if !valid {
                        expect_error(result, case);
                        continue;
                    }
                    let psig = result.unwrap();
                    assert_eq!(
                        psig.to_vec(),
                        bytes(&case["expected"]),
                        "{}",
                        case["comment"]
                    );
                    let case_pubnonces = pick(&pubnonces, &case["pubnonce_indices"]);
                    assert_eq!(nonce_agg(&case_pubnonces).unwrap().to_vec(), aggnonce);
                    assert_eq!(
                        partial_sig_verify(
                            &psig,
                            &case_pubnonces,
                            n,
                            t,
                            &ids,
                            &case_pubshares,
                            &thresh_pk,
                            &case_tweaks,
                            &is_xonly,
                            &msg,
                            ids.iter().position(|&id| id == my_id).unwrap(),
                        ),
                        Ok(true)
                    );
                }
            }
        }
    }

    #[test]
    fn sig_agg_vectors() {
        let secp = secp256k1::Secp256k1::verification_only();
        let data = load(include_str!("../vectors/bip445/sig_agg_vectors.json"));
        for group in data["test_groups"].as_array().unwrap() {
            let n = group["n"].as_u64().unwrap() as u32;
            let t = group["t"].as_u64().unwrap() as u32;
            let thresh_pk = bytes(&group["thresh_pk"]);
            let pubshares = all(&group["pubshares"]);
            let tweaks = all(&group["tweaks"]);

            for (cases, valid) in [("valid_tests", true), ("error_tests", false)] {
                for case in group[cases].as_array().unwrap() {
                    let ids = ids(&case["ids"]);
                    let case_pubshares = (!case["pubshare_indices"].is_null())
                        .then(|| pick(&pubshares, &case["pubshare_indices"]));
                    let aggnonce = bytes(&case["aggnonce"]);
                    let case_tweaks = pick(&tweaks, &case["tweak_indices"]);
                    let is_xonly = bools(&case["is_xonly"]);
                    let msg = bytes(&case["msg"]);
                    let session_ctx = SessionContext {
                        n,
                        t,
                        ids: &ids,
                        pubshares: case_pubshares.as_deref(),
                        thresh_pk: &thresh_pk,
                        aggnonce: &aggnonce,
                        tweaks: &case_tweaks,
                        is_xonly: &is_xonly,
                        msg: &msg,
                    };
                    let result = partial_sig_agg(&all(&case["psigs"]), &session_ctx);
                    if !valid {
                        expect_error(result, case);
                        continue;
                    }
                    let signature = result.unwrap();
                    assert_eq!(
                        signature.to_vec(),
                        bytes(&case["expected"]),
                        "{}",
                        case["comment"]
                    );
                    // Independent check with libsecp256k1's BIP340 verifier.
                    let output_key = thresh_pubkey_and_tweak(&thresh_pk, &case_tweaks, &is_xonly)
                        .unwrap()
                        .xonly_pk();
                    secp.verify_schnorr(
                        &secp256k1::schnorr::Signature::from_slice(&signature).unwrap(),
                        &secp256k1::Message::from_digest_slice(&msg).unwrap(),
                        &secp256k1::XOnlyPublicKey::from_slice(&output_key).unwrap(),
                    )
                    .unwrap();
                }
            }
        }
    }

    /// frost-secp256k1-tr dealer keys are valid BIP445 key material: with the
    /// wallet's BIP32 tweaks plus the Taproot tweak, every 2-of-3 subset signs
    /// for the output key that frost-secp256k1-tr itself derives.
    #[test]
    fn signs_for_frost_secp256k1_tr_wallet_keys() {
        use crate::derivation::derive_public;
        use crate::frost_spdk::psbt_identifier;
        use bitcoin::hashes::Hash;
        use frost::keys::Tweak;
        use frost_secp256k1_tr as frost;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(445);
        let (shares, root) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let public = derive_public(&root, &[0, 7]).unwrap();
        let thresh_pk = root.verifying_key().serialize().unwrap();

        let internal = thresh_pubkey_and_tweak(
            &thresh_pk,
            &public.tweaks.iter().map(|t| t.to_vec()).collect::<Vec<_>>(),
            &vec![false; public.tweaks.len()],
        )
        .unwrap();
        let taproot_tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(
            bitcoin::key::UntweakedPublicKey::from_slice(&internal.xonly_pk()).unwrap(),
            None,
        )
        .to_byte_array();
        let mut tweaks: Vec<Vec<u8>> = public.tweaks.iter().map(|t| t.to_vec()).collect();
        tweaks.push(taproot_tweak.to_vec());
        let mut is_xonly = vec![false; public.tweaks.len()];
        is_xonly.push(true);

        let zf_output = public.derived.clone().tweak::<&[u8]>(None);
        let output_key = secp256k1::XOnlyPublicKey::from_slice(
            &zf_output.verifying_key().serialize().unwrap()[1..],
        )
        .unwrap();

        let signers: Vec<_> = shares
            .iter()
            .map(|(identifier, share)| {
                let key: frost::keys::KeyPackage = share.clone().try_into().unwrap();
                (
                    psbt_identifier(*identifier).unwrap() as u32,
                    key.signing_share().serialize(),
                    key.verifying_share().serialize().unwrap(),
                )
            })
            .collect();
        let msg = [0x45; 32];
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let ids: Vec<u32> = pair.iter().map(|&i| signers[i].0).collect();
            let pubshares: Vec<Vec<u8>> = pair.iter().map(|&i| signers[i].2.clone()).collect();
            let (secnonces, pubnonces): (Vec<_>, Vec<_>) = pair
                .iter()
                .map(|&i| {
                    let (secnonce, pubnonce) = nonce_gen(
                        &mut rng,
                        Some(&signers[i].1.clone().try_into().unwrap()),
                        Some(&signers[i].2.clone().try_into().unwrap()),
                        Some(&internal.xonly_pk()),
                        None,
                        None,
                    );
                    (secnonce, pubnonce.to_vec())
                })
                .unzip();
            let aggnonce = nonce_agg(&pubnonces).unwrap();
            let session_ctx = SessionContext {
                n: 3,
                t: 2,
                ids: &ids,
                pubshares: Some(&pubshares),
                thresh_pk: &thresh_pk,
                aggnonce: &aggnonce,
                tweaks: &tweaks,
                is_xonly: &is_xonly,
                msg: &msg,
            };
            let psigs: Vec<Vec<u8>> = secnonces
                .into_iter()
                .zip(&pair)
                .map(|(secnonce, &i)| {
                    sign(secnonce, &signers[i].1, signers[i].0, &session_ctx)
                        .unwrap()
                        .to_vec()
                })
                .collect();
            for (position, psig) in psigs.iter().enumerate() {
                assert_eq!(
                    partial_sig_verify(
                        psig, &pubnonces, 3, 2, &ids, &pubshares, &thresh_pk, &tweaks, &is_xonly,
                        &msg, position,
                    ),
                    Ok(true)
                );
            }
            let signature = partial_sig_agg(&psigs, &session_ctx).unwrap();
            secp256k1::Secp256k1::verification_only()
                .verify_schnorr(
                    &secp256k1::schnorr::Signature::from_slice(&signature).unwrap(),
                    &secp256k1::Message::from_digest(msg),
                    &output_key,
                )
                .unwrap();
        }
    }
}
