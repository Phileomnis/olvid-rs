use std::{rc::Rc, sync::Arc};

use num::{BigInt, BigUint};

use crate::{core::{bytes_from_biguint, cryptographic_key::{CryptographicKeyDetails, KeyError}, datatypes::edwards_curve::EdwardsCurve, edwards_curve::CurvePoint}, encoding::{BytesArray, Decoder, Dictionary, Encoder}};

use super::{private_key::PrivateKey, public_key::PublicKey};

#[derive(Debug, Clone)]
pub struct PublicKeyOverEC {
    pub cryptographic_key_details: CryptographicKeyDetails,
    pub curve: Arc<EdwardsCurve>,
    pub point: Option<CurvePoint>,
    pub y: BigInt
}

impl PublicKey for PublicKeyOverEC {
    fn get_compact_key(&self) -> Vec<u8> {
        let mut compact_key = Vec::<u8>::new();
        compact_key.push(self.cryptographic_key_details.algo_implem_byte_id);
        compact_key.append(&mut bytes_from_biguint(&self.y.to_biguint().unwrap(), 32));
        return compact_key;
    }
}

impl PublicKeyOverEC {
    pub fn init(algo_class_byte_id: u8, algo_implem_byte_id: u8, curve: Arc<EdwardsCurve>, p: CurvePoint) -> Result<PublicKeyOverEC, KeyError> {
        if !curve.is_on_curve(&p.x, &p.y) {
            return Err(KeyError::BasePointNotOnCurve)
        }

        let mut dict = Dictionary::new();
        let px_encoded = (&p.x % &curve.p).to_biguint().ok_or(KeyError::Technical)?.encode()?;
        dict.add("x", px_encoded);
        let py_encoded = (&p.y % &curve.p).to_biguint().ok_or(KeyError::Technical)?.encode()?;
        dict.add("y", py_encoded);

        Ok(Self {
            cryptographic_key_details: CryptographicKeyDetails::new(algo_class_byte_id, algo_implem_byte_id, Arc::new(dict), Self::get_encoding_byte_id()),
            curve,
            y: p.y.clone(),
            point: Some(p),
        })
    }

    pub fn init_with_y_only(algo_class_byte_id: u8, algo_implem_byte_id: u8, curve: Arc<EdwardsCurve>, y: BigInt) -> Result<PublicKeyOverEC, KeyError> {
        let mut dict = Dictionary::new();
        let py_encoded = (&y % &curve.p).to_biguint().ok_or(KeyError::Technical)?.encode()?;
        dict.add("y", py_encoded);

        Ok(Self {
            cryptographic_key_details: CryptographicKeyDetails::new(algo_class_byte_id, algo_implem_byte_id, Arc::new(dict), Self::get_encoding_byte_id()),
            curve,
            y,
            point: None
        })
    }

    pub fn from_dict(algo_class_byte_id: u8, algo_implem_byte_id: u8, dict: Arc<Dictionary>) -> Result<Self, KeyError> {
        let encoded_x = dict.get("x");
        let encoded_y = dict.get("y").unwrap();
        let y = BigInt::decode(&encoded_y)?;

        let curve = EdwardsCurve::curve_from_algo_implem_byte_id(algo_implem_byte_id).map_err(|_| KeyError::UnknownAlgoImplemByteId)?;

        if encoded_x.is_some() {
            let x = BigInt::decode(&encoded_x.unwrap())?;
            return Ok(Self::init(algo_class_byte_id, algo_implem_byte_id, Arc::new(curve), CurvePoint::new(x, y))?);
        }

        return Ok(Self::init_with_y_only(algo_class_byte_id, algo_implem_byte_id, Arc::new(curve), y)?);
    } 

    pub fn get_compact_key(&self) -> Result<Vec<u8>, KeyError> {
        let mut result = Vec::<u8>::new();

        result.push(self.cryptographic_key_details.algo_implem_byte_id);
        // result.push(self.);

        result.append(&mut bytes_from_biguint(&self.y.to_biguint().unwrap(), 32));
        Ok(result)
    }
}

#[derive(PartialEq, Eq)]
pub struct PrivateKeyOverEC {
    pub cryptographic_key_details: CryptographicKeyDetails,
    pub curve: Arc<EdwardsCurve>,
    pub scalar: BigInt
}

impl PrivateKey for PrivateKeyOverEC {}

impl PrivateKeyOverEC {
    pub fn init(algo_class_byte_id: u8, algo_implem_byte_id: u8, curve: Arc<EdwardsCurve>, lambda: BigInt) -> Result<PrivateKeyOverEC, KeyError> {
        let mut dict = Dictionary::new();
        let lambda_encoded = (&lambda % &curve.q).to_biguint().ok_or(KeyError::Technical)?.encode()?;
        dict.add("y", lambda_encoded);

        Ok(Self {
            cryptographic_key_details: CryptographicKeyDetails::new(algo_class_byte_id, algo_implem_byte_id, Arc::new(dict), Self::get_encoding_byte_id()),
            curve,
            scalar: lambda,
        })
    }

    pub fn from_dict(algo_class_byte_id: u8, algo_implem_byte_id: u8, dict: Arc<Dictionary>) -> Result<Self, KeyError> {
        let encoded_n = dict.get("n").unwrap();
        let n = BigInt::decode(&encoded_n)?;

        let curve = EdwardsCurve::curve_from_algo_implem_byte_id(algo_implem_byte_id).map_err(|_| KeyError::UnknownAlgoImplemByteId)?;

        return Ok(Self::init(algo_class_byte_id, algo_implem_byte_id, Arc::new(curve), n)?);
    } 
}

pub const ALGO_IMPLEM_BYTE_ID_CURVE_MDC: u8 = 0x00;
pub const ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519: u8 = 0x01;
