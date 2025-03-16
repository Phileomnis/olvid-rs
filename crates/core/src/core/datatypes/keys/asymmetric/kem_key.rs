use std::{rc::Rc, sync::Arc};

use num::{BigInt, BigUint};

use crate::core::{cryptographic_key::KeyError, edwards_curve::{CurvePoint, CurveType, EdwardsCurve}};

use super::{authentication_key::{AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, edwards_key::{PrivateKeyOverEC, PublicKeyOverEC}};

#[derive(Debug, Clone)]
pub struct KEMPublicKeyOverEC {
    pub public_key_over_ec: PublicKeyOverEC
}

impl KEMPublicKeyOverEC {
    pub fn init(curve: Arc<EdwardsCurve>, p: CurvePoint) -> Result<Self, KeyError> {
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init(0x12, curve.algo_implem_id(), curve, p)? })
    }

    pub fn init_with_y_only(curve: Arc<EdwardsCurve>, y: BigInt) -> Result<Self, KeyError> {
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init_with_y_only(0x12, curve.algo_implem_id(), curve, y)? })
    }

    pub fn expand_compact_key(compact_key: &[u8]) -> Result<Self, KeyError> {
        if compact_key.len() == 0 {
            return Err(KeyError::Technical);
        }

        let algoImplemId = compact_key[0];
        let y_coord = &compact_key[1..compact_key.len()];
        let curve = EdwardsCurve::curve_from_algo_implem_byte_id(algoImplemId).unwrap();
        if compact_key.len() != 1 + 32 {
            return Err(KeyError::Technical);
        }
        let y = BigUint::from_bytes_be(y_coord);
        return Ok(Self::init_with_y_only(Arc::new(curve), y.into())?);
    }
}

pub struct KEMPrivateKeyOverEc {
    pub private_key_over_ec: PrivateKeyOverEC
}

impl KEMPrivateKeyOverEc {
    pub fn init(curve: Arc<EdwardsCurve>, lambda: BigInt) -> Result<Self, KeyError> {
        Ok(Self { private_key_over_ec: PrivateKeyOverEC::init(0x12, curve.algo_implem_id(), curve, lambda)? })
    }
}

pub struct KEMOverECKeyPair(pub KEMPublicKeyOverEC, pub KEMPrivateKeyOverEc);
