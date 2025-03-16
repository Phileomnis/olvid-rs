use std::{rc::Rc, sync::Arc};

use thiserror::Error;

use crate::{core::{asymmetric::{authentication_key::{AuthenticationOverECKeyPair, AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, edwards_key::{ALGO_IMPLEM_BYTE_ID_CURVE_CURVE_25519, ALGO_IMPLEM_BYTE_ID_CURVE_MDC}, signature_key::SignaturePublicKeyOverEC}, edwards_curve::{CurveType, EdwardsCurve, EdwardsCurveError}}, crypto::signature::SignatureOverEc, encoding::Encoder};

use super::{prng::{PRNGError, PRNG}, signature::SignatureError};

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Technical error")]
    Technical,
    #[error("Unknown algo implem byte id")]
    UnknownAlgoImplemByteId,
    #[error("Private key and public key don't share same curve")]
    DifferentCurve,
    #[error("Edwards curve error")]
    EdwardsCurveError(#[from] EdwardsCurveError),
    #[error("PRNG error")]
    PRNGError(#[from] PRNGError),
    #[error("Signature error")]
    SignatureError(#[from] SignatureError),
    
}

pub struct AuthenticationOverEC {
    key_pair: AuthenticationOverECKeyPair,
}

impl AuthenticationOverEC {
    fn init(authentication_over_ec_key_pair: AuthenticationOverECKeyPair ) -> Self {
        AuthenticationOverEC { key_pair: authentication_over_ec_key_pair }
    }

    pub fn generate_key_pair(prng: &mut dyn PRNG, curve: Arc<EdwardsCurve>) -> Result<AuthenticationOverECKeyPair, AuthenticationError> {
        let (lambda, p) = curve.generate_random_scalar_and_point(prng)?;
        let pk = AuthenticationPublicKeyOverEC::new(Arc::clone(&curve), p).map_err(|_| AuthenticationError::Technical)?;
        let sk = AuthenticationPrivateKeyOverEC::new(Arc::clone(&curve), lambda).map_err(|_| AuthenticationError::Technical)?;

        Ok(AuthenticationOverECKeyPair(pk, sk))
    }

    fn solve(&mut self, challenge: &[u8], prefix: &[u8], prng: &mut impl PRNG) -> Result<Vec<u8>, AuthenticationError> {
        if self.key_pair.0.public_key_over_ec.curve != self.key_pair.1.private_key_over_ec.curve {
            return Err(AuthenticationError::DifferentCurve)
        }

        let suffix = prng.bytes(16)?;
        let mut formatted_challenge = Vec::<u8>::new();
        formatted_challenge.extend_from_slice(prefix);
        formatted_challenge.extend_from_slice(challenge);
        formatted_challenge.append(&mut suffix.clone());

        let pk_sigma = self.key_pair.0.to_signature_public_key_over_ec();
        let sk_sigma = self.key_pair.1.to_signature_private_key_over_ec();

        let mut sigma = SignatureOverEc::sign(&sk_sigma, &formatted_challenge, &pk_sigma, prng)?;

        let mut result = Vec::<u8>::new();
        result.append(&mut suffix.clone());
        result.append(&mut sigma);
        
        Ok(result)
    }

    // fn check()
}

#[cfg(test)]
mod tests {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use serde::Deserialize;

    use crate::{core::asymmetric::authentication_key::{AuthenticationOverECKeyPair, AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, crypto::{authentication::AuthenticationOverEC, prng::{PRNGHmacSHA256, PRNG}, utils::tests::get_test_vectors}, encoding::{Decoder, Encoder}};

    #[derive(Deserialize)]
    struct TestServerAuthentication {
        algorithmImplementationByteIdValue: u8,
        seed: String,
        encodedPublicKey: String,
        encodedPrivateKey: String,
        challenge: String,
        response: String,
    }

    #[test]
    fn test_server_authentication() {
        let test_cases = get_test_vectors::<TestServerAuthentication>("TestVectorsServerAuthentication.json");

        test_cases.par_iter().for_each(|test_case| {
            let seed = hex::decode(&test_case.seed).unwrap();
            let encodedPublicKey = hex::decode(&test_case.encodedPublicKey).unwrap();
            let encodedPrivateKey = hex::decode(&test_case.encodedPrivateKey).unwrap();
            let challenge = hex::decode(&test_case.challenge).unwrap();
            let response = hex::decode(&test_case.response).unwrap();

            let mut prng = PRNGHmacSHA256::init(&seed).unwrap();
            let pk = AuthenticationPublicKeyOverEC::decode(&encodedPublicKey).unwrap();
            let sk = AuthenticationPrivateKeyOverEC::decode(&encodedPrivateKey).unwrap();
            let mut authentication_over_ec = AuthenticationOverEC::init(AuthenticationOverECKeyPair(pk, sk));
            
            let computed_response = authentication_over_ec.solve(&challenge, &"authentChallenge".to_string().as_bytes(), &mut prng).unwrap();

            assert_eq!(computed_response, response);
        });
    }
}

