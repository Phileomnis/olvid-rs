use std::{rc::Rc, sync::Arc};

use num::{BigInt, BigUint};

use crate::core::{cryptographic_key::KeyError, edwards_curve::{CurvePoint, EdwardsCurve}};

use super::{edwards_key::{PrivateKeyOverEC, PublicKeyOverEC}, signature_key::{SignaturePrivateKeyOverEc, SignaturePublicKeyOverEC}};

#[derive(Debug, Clone)]
pub struct AuthenticationPublicKeyOverEC {
    pub public_key_over_ec: PublicKeyOverEC
}

impl AuthenticationPublicKeyOverEC {
    pub fn new(curve: Arc<EdwardsCurve>, p: CurvePoint) -> Result<Self, KeyError> {
        let algo_implem_id = curve.algo_implem_id();
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init(0x14, algo_implem_id, curve, p)? })
    }

    pub fn init_with_y_only(curve: Arc<EdwardsCurve>, y: BigInt) -> Result<Self, KeyError> {
        let algo_implem_id = curve.algo_implem_id();
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init_with_y_only(0x14, algo_implem_id, curve, y)? })
    }

    pub fn to_signature_public_key_over_ec(&self) -> SignaturePublicKeyOverEC {
        if self.public_key_over_ec.point.is_some() {
            return SignaturePublicKeyOverEC::init(Arc::clone(&self.public_key_over_ec.curve), self.public_key_over_ec.point.clone().unwrap()).expect("Convert AuthenticationPublicKeyOverEC to SignaturePublicKeyOverEC");
        }

        return SignaturePublicKeyOverEC::init_with_y_only(Arc::clone(&self.public_key_over_ec.curve), self.public_key_over_ec.y.clone()).expect("Convert AuthenticationPublicKeyOverEC to SignaturePublicKeyOverEC");
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

pub struct AuthenticationPrivateKeyOverEC {
    pub private_key_over_ec: PrivateKeyOverEC
}

impl AuthenticationPrivateKeyOverEC {
    pub fn new(curve: Arc<EdwardsCurve>, lambda: BigInt) -> Result<Self, KeyError> {
        let algo_implem_id = curve.algo_implem_id();
        Ok(Self { private_key_over_ec: PrivateKeyOverEC::init(0x14, algo_implem_id, curve, lambda)? })
    }

    pub fn to_signature_private_key_over_ec(&self) -> SignaturePrivateKeyOverEc {
        return SignaturePrivateKeyOverEc::init(Arc::clone(&self.private_key_over_ec.curve), self.private_key_over_ec.scalar.clone()).expect("Convert AuthenticationPrivateKeyOverEC to SignaturePrivateKeyOverEc");
    }
}

pub struct AuthenticationOverECKeyPair(pub AuthenticationPublicKeyOverEC, pub AuthenticationPrivateKeyOverEC);

