use std::{rc::Rc, sync::Arc};

use num::{bigint::Sign, BigInt, BigUint, One, Zero};
use thiserror::Error;

use crate::{core::{asymmetric::kem_key::{KEMOverECKeyPair, KEMPrivateKeyOverEc, KEMPublicKeyOverEC}, bytes_from_biguint, edwards_curve::{EdwardsCurve, EdwardsCurveError}, symmetric::{auth_enc_key::{AES256CTRHMACSHA256Key, AuthEncKey}, symmetric_key::SymmetricKey}}, crypto::kdf::{KDFFromPRNGWithHMACWithSHA256, KDF}};

use super::prng::PRNG;

#[derive(Debug, Error)]
pub enum KemError {
    #[error("Technical error")]
    Technical,
    #[error("Low Order Point error")]
    LowOrderPoint,
    #[error("Computation error")]
    Computation(#[from] EdwardsCurveError),
}

pub struct KEMOverEC;

impl KEMOverEC {
    pub fn generate_key_pair(prng: &mut dyn PRNG, curve: Arc<EdwardsCurve>) -> Result<KEMOverECKeyPair, KemError> {
        let (lambda, p) = curve.generate_random_scalar_and_point(prng)?;
        let pk = KEMPublicKeyOverEC::init(Arc::clone(&curve), p).map_err(|_| KemError::Technical)?;
        let sk = KEMPrivateKeyOverEc::init(Arc::clone(&curve), lambda).map_err(|_| KemError::Technical)?;

        Ok(KEMOverECKeyPair(pk, sk))
    }

    pub fn encrypt<T: SymmetricKey>(public_key: &KEMPublicKeyOverEC, prng: &mut impl PRNG) -> Result<(Vec<u8>, T), KemError> {
        let Ay = &public_key.public_key_over_ec.y;

        let curve = &public_key.public_key_over_ec.curve;

        if curve.is_low_order_point(&Ay)? {
            return Err(KemError::LowOrderPoint);
        }

        let curve_byte_length = 32;
        let mut r = prng.big_int(&curve.q).unwrap();
        while r == BigInt::zero() {
            r = prng.big_int(&curve.q).unwrap();
        }
        let Gy = &curve.G.y;
        let By = curve.scalar_multiplication(&r, Gy)?;
        let Dy = curve.scalar_multiplication(&r, &Ay)?;

        let mut ciphertext = bytes_from_biguint(&By.to_biguint().unwrap(), curve_byte_length);
        let mut seed_bytes = Vec::<u8>::new();
        seed_bytes.append(&mut ciphertext.clone());
        seed_bytes.append(&mut bytes_from_biguint(&Dy.to_biguint().unwrap(), curve_byte_length));
        let key = KDFFromPRNGWithHMACWithSHA256::compute::<T>(&seed_bytes).unwrap();
        return Ok((ciphertext, key));
    }

    pub fn decrypt<T: SymmetricKey>(encrypted_key: &[u8], sk: &KEMPrivateKeyOverEc) -> Result<T, KemError> {
        let mut a = &sk.private_key_over_ec.scalar;
        let curve_byte_length = 32;
        if encrypted_key.len() != curve_byte_length {
            return Err(KemError::Technical);
        }

        let mut By = BigInt::from_bytes_be(Sign::Plus, &encrypted_key);
        
        let curve = &sk.private_key_over_ec.curve;
        By = curve.scalar_multiplication(&curve.nu, &By).unwrap();

        if By == BigInt::one() {
            return Err(KemError::Technical);
        }

        let binding = ((a * &curve.nu.modinv(&curve.q).unwrap()) % &curve.q);
        a = &binding;
        let Dy = curve.scalar_multiplication(&a, &By).unwrap();

        let mut seed_bytes = Vec::<u8>::new();
        seed_bytes.extend_from_slice(encrypted_key);
        seed_bytes.append(&mut bytes_from_biguint(&Dy.to_biguint().unwrap(), curve_byte_length));
        let key = KDFFromPRNGWithHMACWithSHA256::compute::<T>(&seed_bytes).unwrap();
        return Ok(key);
    }
}

#[cfg(test)]
mod tests {
    use std::{rc::Rc, sync::Arc};

    use rand::random;

    use crate::{core::{edwards_curve::EdwardsCurve, symmetric::{aes_key::AES256CTRKey, auth_enc_key::AES256CTRHMACSHA256Key, mac_key::HMACWithSHA256Key, symmetric_key::SymmetricKey}}, crypto::prng::{PRNGHmacSHA256, PRNG}};

    use super::KEMOverEC;

    #[test]
    fn test_kem() {
        let seed: [u8; 32] = random();
        let mut prng = PRNGHmacSHA256::init(&seed).unwrap();

        for i in 0..10 {
            let curve = EdwardsCurve::new_mdc().unwrap();
            let pair = KEMOverEC::generate_key_pair(&mut prng, Arc::new(curve)).unwrap();

            for j in 0..100 {
                let (ciphertext, key) = KEMOverEC::encrypt::<HMACWithSHA256Key>(&pair.0, &mut prng).unwrap();
                let dec = KEMOverEC::decrypt::<HMACWithSHA256Key>(&ciphertext, &pair.1).unwrap();
                assert_eq!(key, dec);
            }
        }
    }
}

