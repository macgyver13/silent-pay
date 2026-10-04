//! Threshold ECDH combination under the BIP445 tweak model.
//!
//! Signers contribute `xᵢ * B_scan` from their untweaked shares. Tweaks are
//! tracked as a BIP445 tweak context (`gacc`/`tacc`) and applied once here, so
//! the combined point is the ECDH point of the tweaked (Taproot output) key:
//! `(gᵥ * gacc) * Σ(cᵢ * shareᵢ) + (gᵥ * tacc) * B_scan`.

use anyhow::{Context, Result};
use k256::Scalar as KScalar;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

use crate::bip445::TweakContext;

/// Even-Y lift of the tweaked key, as used by the BIP352 input hash.
pub fn output_key(context: &TweakContext) -> Result<PublicKey> {
    let xonly = XOnlyPublicKey::from_slice(&context.xonly_pk()).context("tweaked key")?;
    Ok(PublicKey::from_x_only_public_key(xonly, Parity::Even))
}

/// Combine `(coefficient, shareᵢ)` pairs into the ECDH point of [`output_key`].
pub fn combine_ecdh(
    context: &TweakContext,
    scan_key: &PublicKey,
    weighted: &[(Scalar, PublicKey)],
) -> Result<PublicKey> {
    let secp = Secp256k1::verification_only();
    let terms = weighted
        .iter()
        .map(|(coefficient, share)| share.mul_tweak(&secp, coefficient))
        .collect::<Result<Vec<_>, _>>()
        .context("weight ECDH share")?;
    let sum = PublicKey::combine_keys(&terms.iter().collect::<Vec<_>>())
        .context("combine weighted ECDH shares")?;
    let gv = if context.has_even_y() {
        KScalar::ONE
    } else {
        -KScalar::ONE
    };
    let sum = if gv * context.gacc == KScalar::ONE {
        sum
    } else {
        sum.negate(&secp)
    };
    let tweak = gv * context.tacc;
    if tweak == KScalar::ZERO {
        return Ok(sum);
    }
    sum.combine(
        &scan_key
            .mul_tweak(&secp, &to_scalar(tweak))
            .context("apply tacc to scan key")?,
    )
    .context("add tacc term to ECDH point")
}

fn to_scalar(scalar: KScalar) -> Scalar {
    Scalar::from_be_bytes(scalar.to_bytes().into()).expect("k256 scalars are reduced")
}
