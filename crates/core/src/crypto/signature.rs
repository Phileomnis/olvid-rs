use std::{rc::Rc, sync::Arc};

use num::{bigint::Sign, traits::SaturatingMul, BigInt, BigUint, One, ToPrimitive};
use thiserror::Error;

use crate::{core::{asymmetric::{edwards_key::PrivateKeyOverEC, signature_key::{SignaturePrivateKeyOverEc, SignaturePublicKeyOverEC}}, bytes_from_biguint, cryptographic_key::KeyError, edwards_curve::{EdwardsCurve, EdwardsCurveError}}, crypto::hash::{Hash, SHA256}, encoding::{BytesArray, Decoder, DecodingParsingError, Encoder}};

use super::prng::PRNG;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Private key and public key don't share same curve")]
    DifferentCurve,
    #[error("Couldn't generate key pair")]
    KeyPair,
    #[error("Technical error")]
    Technical,
    #[error("Decoding or parsing error")]
    DecodingParsing(#[from] DecodingParsingError),
    #[error("Edwards Curve Error")]
    EdwardsCurveError(#[from] EdwardsCurveError)
}

pub struct SignatureOverEc;

impl SignatureOverEc {
    pub fn generate_key_pair(prng: &mut impl PRNG, curve: &Arc<EdwardsCurve>) -> Result<(SignaturePublicKeyOverEC, SignaturePrivateKeyOverEc), KeyError> {
        let (lambda, p) = curve.generate_random_scalar_and_point(prng).map_err(|_| KeyError::GenerationFailed)?;
        let pk = SignaturePublicKeyOverEC::init(Arc::clone(&curve), p)?;
        let sk = SignaturePrivateKeyOverEc::init(Arc::clone(&curve), lambda)?;
        Ok((pk, sk))
    } 

    // pub fn sign(sk: &SignaturePrivateKeyOverEc, m: &[u8], pk: &SignaturePublicKeyOverEC, prng: &mut impl PRNG) -> Result<Vec<u8>, SignatureError> {
    //     if &sk.private_key_over_ec.curve != &pk.public_key_over_ec.curve {
    //         return Err(SignatureError::DifferentCurve)
    //     }

    //     let secret_curve = &sk.private_key_over_ec.curve;
        
    //     let (pk_, sk_) = Self::generate_key_pair(prng, secret_curve).map_err(|_| SignatureError::KeyPair)?;

    //     let pk_y = &pk_.public_key_over_ec.y % &secret_curve.p;
    //     // let mut ay_ = pk_y.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
    //     let mut ay_ = pk_y.to_biguint().ok_or(SignatureError::Technical)?.to_bytes_be();

    //     let pky = &pk.public_key_over_ec.y % &secret_curve.p;
    //     // let mut ay = pky.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
    //     let mut ay = pky.to_biguint().ok_or(SignatureError::Technical)?.to_bytes_be();

    //     let mut data = Vec::<u8>::new();
    //     data.append(&mut ay_);
    //     data.append(&mut ay);
    //     data.append(&mut m.to_vec());

    //     let h: Vec<u8> = SHA256::digest(&data);
    //     let e = BigInt::from_bytes_be(Sign::Plus, &h);

    //     let r = &sk_.private_key_over_ec.scalar;
    //     let a = &sk.private_key_over_ec.scalar;
    //     let y = (r - a * &e).modpow(&BigInt::one(), &secret_curve.q);
    //     let mut z = y.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
    //     let mut sigma = Vec::<u8>::new();
    //     sigma.append(&mut h.clone());
    //     sigma.append(&mut z);
    //     Ok(sigma)
    // }

    pub fn sign(sk: &SignaturePrivateKeyOverEc, m: &[u8], pk: &SignaturePublicKeyOverEC, prng: &mut impl PRNG) -> Result<Vec<u8>, SignatureError> {
        if &sk.private_key_over_ec.curve != &pk.public_key_over_ec.curve {
            return Err(SignatureError::DifferentCurve)
        }

        let secret_curve = &sk.private_key_over_ec.curve;
        
        let (aA, aG) = secret_curve.generate_random_scalar_and_point(prng)?;
        
        
        // let (pk_, sk_) = Self::generate_key_pair(prng, secret_curve).map_err(|_| SignatureError::KeyPair)?;

        // let pk_y = &pk_.public_key_over_ec.y % &secret_curve.p;
        // // let mut ay_ = pk_y.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
        // let mut ay_ = pk_y.to_biguint().ok_or(SignatureError::Technical)?.to_bytes_be();

        // let pky = &pk.public_key_over_ec.y % &secret_curve.p;
        // // let mut ay = pky.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
        // let mut ay = pky.to_biguint().ok_or(SignatureError::Technical)?.to_bytes_be();

        let mut data = Vec::<u8>::new();
        data.append(&mut bytes_from_biguint(&aG.y.to_biguint().unwrap(), 32));
        data.append(&mut bytes_from_biguint(&pk.public_key_over_ec.y.to_biguint().unwrap(), 32));
        data.append(&mut m.to_vec());

        let h: Vec<u8> = SHA256::digest(&data);
        let e = BigInt::from_bytes_be(Sign::Plus, &h);

        // let r = &sk_.private_key_over_ec.scalar;
        // let a = &sk.private_key_over_ec.scalar;
        let y = (&aA - &sk.private_key_over_ec.scalar * &e).modpow(&BigInt::one(), &secret_curve.q);
        // let mut z = y.to_biguint().ok_or(SignatureError::Technical)?.encode().map_err(|_| SignatureError::Technical)?;
        
        
        let mut sigma = Vec::<u8>::new();
        sigma.append(&mut h.clone());
        sigma.append(&mut bytes_from_biguint(&y.to_biguint().unwrap(), 32));
        Ok(sigma)
    }

    pub fn verify(pk: &SignaturePublicKeyOverEC, m: &[u8], sigma: &[u8]) -> Result<bool, SignatureError> {
        let public_curve = &pk.public_key_over_ec.curve;
        let p_len = public_curve.p.bits().to_usize().ok_or(SignatureError::Technical)?;

        if sigma.len() != 32 + p_len {
            return Ok(false);
        }

        let encoded_sigma = BytesArray::parse(sigma)?;
        let h = &encoded_sigma.content[0..32];
        let z = &encoded_sigma.content[32..];

        let e = BigUint::decode(h)?;
        let y = BigUint::decode(z)?;

        let p: (Option<&BigInt>, &BigInt) = match &pk.public_key_over_ec.point.is_none() {
            true =>  (None, &pk.public_key_over_ec.y),
            false => (Some(&pk.public_key_over_ec.point.as_ref().unwrap().x), &pk.public_key_over_ec.point.as_ref().unwrap().y)
        };
        
        let (a1, a2) = public_curve.mul_add(&BigInt::from_biguint(Sign::Plus, y), &public_curve.G, &BigInt::from_biguint(Sign::Plus, e), p)?;

        let ay = pk.public_key_over_ec.y.to_biguint().ok_or(SignatureError::Technical)?.encode()?;
        let mut a1_y = a1.y.to_biguint().ok_or(SignatureError::Technical)?.encode()?;
        let mut a2_y = a2.y.to_biguint().ok_or(SignatureError::Technical)?.encode()?;

        let mut data1 = Vec::<u8>::new();
        data1.append(&mut a1_y);
        data1.append(&mut ay.clone());
        data1.append(&mut m.to_vec());

        let mut data2 = Vec::<u8>::new();
        data2.append(&mut a2_y);
        data2.append(&mut ay.clone());
        data2.append(&mut m.to_vec());

        let h1 = SHA256::digest(&data1);
        let h2 = SHA256::digest(&data2);
        
        Ok(h == h1 || h == h2)
    }

    pub fn generate_key_pair_mdc(prng: &mut impl PRNG) -> Result<(SignaturePublicKeyOverEC, SignaturePrivateKeyOverEc), KeyError> {
        let curve = EdwardsCurve::new_mdc().map_err(|_| KeyError::Technical)?;
        Ok(Self::generate_key_pair(prng, &Arc::new(curve))?)
    }

    pub fn generate_key_pair_curve25519(prng: &mut impl PRNG) -> Result<(SignaturePublicKeyOverEC, SignaturePrivateKeyOverEc), KeyError> {
        let curve = EdwardsCurve::new_curve25519().map_err(|_| KeyError::Technical)?;
        Ok(Self::generate_key_pair(prng, &Arc::new(curve))?)
    }
}


#[cfg(test)]
mod tests {
    use crate::crypto::utils::tests::get_test_vectors;

    // #[derive(Deserialize)]
    // struct TestServerAuthentication {
    //     algorithmImplementationByteIdValue: TestBigInteger,
    //     seed: TestBigInteger,
    //     encodedPublicKey: TestBigInteger,
    //     encodedPrivateKey: String,
    //     challenge: String,
    //     response: String,

    // }

    // #[test]
    // fn scalar_multiplication_mdc() {
    //     let curve = EdwardsCurve::new_mdc().unwrap();
    //     let test_cases = get_test_vectors::<TestServerAuthentication>("TestVectorsServerAuthentication.json");

    //     test_cases.iter().for_each(|test_case| {
    //         let n = BigInt::from_str(&test_case.n.0).unwrap();
    //         let ny = BigInt::from_str(&test_case.ny.0).unwrap();
    //         let y = BigInt::from_str(&test_case.y.0).unwrap();

    //         let computed_ny = curve.scalar_multiplication(&n, &y).unwrap();
    //         assert_eq!(ny, computed_ny);
    //     });
    // }
}