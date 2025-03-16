use std::{rc::Rc, sync::Arc};

use num::BigInt;

use crate::core::{cryptographic_key::KeyError, edwards_curve::{CurvePoint, CurveType, EdwardsCurve}};

use super::{authentication_key::{AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, edwards_key::{PrivateKeyOverEC, PublicKeyOverEC}};

pub struct SignaturePublicKeyOverEC {
    pub public_key_over_ec: PublicKeyOverEC
}

impl SignaturePublicKeyOverEC {
    pub fn init(curve: Arc<EdwardsCurve>, p: CurvePoint) -> Result<Self, KeyError> {
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init(0x11, curve.algo_implem_id(), curve, p)? })
    }

    pub fn init_with_y_only(curve: Arc<EdwardsCurve>, y: BigInt) -> Result<Self, KeyError> {
        Ok(Self { public_key_over_ec: PublicKeyOverEC::init_with_y_only(0x11, curve.algo_implem_id(), curve, y)? })
    }
}

pub struct SignaturePrivateKeyOverEc {
    pub private_key_over_ec: PrivateKeyOverEC
}

impl SignaturePrivateKeyOverEc {
    pub fn init(curve: Arc<EdwardsCurve>, lambda: BigInt) -> Result<Self, KeyError> {
        Ok(Self { private_key_over_ec: PrivateKeyOverEC::init(0x11, curve.algo_implem_id(), curve, lambda)? })
    }
}

// impl Into<SignaturePublicKeyOverEC> for AuthenticationPublicKeyOverEC {
//     fn into(self) -> SignaturePublicKeyOverEC {
//         if self.public_key_over_ec.point.is_some() {
//             return SignaturePublicKeyOverEC::init(self.public_key_over_ec.curve, self.public_key_over_ec.point.unwrap()).expect("Convert AuthenticationPublicKeyOverEC to SignaturePublicKeyOverEC");
//         }

//         return SignaturePublicKeyOverEC::init_with_y_only(self.public_key_over_ec.curve, self.public_key_over_ec.y).expect("Convert AuthenticationPublicKeyOverEC to SignaturePublicKeyOverEC");
//     }
// }

// impl Into<SignaturePrivateKeyOverEc> for AuthenticationPrivateKeyOverEC {
//     fn into(self) -> SignaturePrivateKeyOverEc {
//         return SignaturePrivateKeyOverEc::init(self.private_key_over_ec.curve, self.private_key_over_ec.scalar).expect("Convert AuthenticationPrivateKeyOverEC to SignaturePrivateKeyOverEc");
//     }
// }