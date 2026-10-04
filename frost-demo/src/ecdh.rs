//! Threshold ECDH combination under the BIP445 tweak model.
//!
//! Signers contribute `xᵢ * B_scan` from their untweaked shares. Tweaks are
//! tracked as BIP445 `gacc`/`tacc` and applied once here, so the combined
//! point is the ECDH point of the tweaked (Taproot output) key:
//! `(gᵥ * gacc) * Σ(cᵢ * shareᵢ) + (gᵥ * tacc) * B_scan`.

use anyhow::{anyhow, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::taproot::TapTweakHash;
use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar as KScalar};
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1};

/// BIP445 tweak context over a threshold public key.
pub struct TweakContext {
    q: PublicKey,
    gacc: KScalar,
    tacc: KScalar,
}

impl TweakContext {
    pub fn new(threshold_pk: PublicKey) -> Self {
        Self {
            q: threshold_pk,
            gacc: KScalar::ONE,
            tacc: KScalar::ZERO,
        }
    }

    /// BIP445 `ApplyTweak`.
    pub fn apply_tweak(mut self, tweak: [u8; 32], is_xonly: bool) -> Result<Self> {
        let secp = Secp256k1::verification_only();
        let t = Option::<KScalar>::from(KScalar::from_repr(FieldBytes::from(tweak)))
            .ok_or_else(|| anyhow!("tweak is not a valid scalar"))?;
        let g = if is_xonly && !has_even_y(&self.q) {
            -KScalar::ONE
        } else {
            KScalar::ONE
        };
        let gq = if g == KScalar::ONE {
            self.q
        } else {
            self.q.negate(&secp)
        };
        self.q = gq
            .add_exp_tweak(&secp, &to_scalar(t))
            .context("tweaked key is the point at infinity")?;
        self.gacc = g * self.gacc;
        self.tacc = t + g * self.tacc;
        Ok(self)
    }

    /// BIP341 key-path-only Taproot tweak of the current key.
    pub fn apply_taproot_tweak(self) -> Result<Self> {
        let (internal_key, _) = self.q.x_only_public_key();
        let tweak = TapTweakHash::from_key_and_tweak(internal_key, None).to_byte_array();
        self.apply_tweak(tweak, true)
    }

    /// Even-Y lift of the tweaked key, as used by the BIP352 input hash.
    pub fn output_key(&self) -> PublicKey {
        PublicKey::from_x_only_public_key(self.q.x_only_public_key().0, Parity::Even)
    }

    /// Combine `(coefficient, shareᵢ)` pairs into the ECDH point of [`Self::output_key`].
    pub fn combine_ecdh(
        &self,
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
        let gv = if has_even_y(&self.q) {
            KScalar::ONE
        } else {
            -KScalar::ONE
        };
        let sum = if gv * self.gacc == KScalar::ONE {
            sum
        } else {
            sum.negate(&secp)
        };
        let tweak = gv * self.tacc;
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
}

fn has_even_y(point: &PublicKey) -> bool {
    point.x_only_public_key().1 == Parity::Even
}

fn to_scalar(scalar: KScalar) -> Scalar {
    Scalar::from_be_bytes(scalar.to_bytes().into()).expect("k256 scalars are reduced")
}
