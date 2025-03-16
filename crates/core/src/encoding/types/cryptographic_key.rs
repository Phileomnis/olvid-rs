// use crate::{
//     encoding::{
//         encoding::{BytesArray, Decoder, Encoder},
//         errors::DecodingParsingError,
//         Dictionary,
//     }
// };

// impl Encoder for CryptographicKey {
//     fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
//         let byte_ids_to_encode = [self.algo_class_byte_id, self.algo_implem_byte_id];
//         let encoded_byte_ids = BytesArray::encode_slice(&byte_ids_to_encode)?;
//         let encoded_dict = self.dict.encode()?;
//         let to_pack: [BytesArray; 2] = [encoded_byte_ids, encoded_dict];

//         return Ok(Self::pack(self.encoding_byte_id, &to_pack)?);
//     }
// }

// impl Decoder for CryptographicKey {
//     fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
//         let (byte_id, encoded_values) = Self::unpack(input)?;

//         if encoded_values.len() != 2 {
//             return Err(DecodingParsingError::Malformed(String::from(
//                 "incorrect number of values in encoded crytographic key",
//             )));
//         }

//         // Use of unwrap in the following is safe because lengths of vectors are checked to be exactly 2
//         let byte_ids = encoded_values.get(0).unwrap();
//         if byte_ids.len() != 2 {
//             return Err(DecodingParsingError::Malformed(String::from(
//                 "incorrect number of byte identifiers in encoded crytographic key",
//             )));
//         }

//         let algo_class_byte_id = byte_ids.get(0).unwrap();
//         let algo_implem_byte_id = byte_ids.get(1).unwrap();
//         let dict = Dictionary::decode(encoded_values.get(1).unwrap())?;

//         return Ok(CryptographicKey::new(
//             *algo_class_byte_id,
//             *algo_implem_byte_id,
//             dict,
//             byte_id,
//         ));
//     }
// }

// // impl Encoder for SymmetricKey {
// //     fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
// //         return Ok(CryptographicKey::from(self).encode()?);
// //     }

// //     fn decode(input: &Vec<u8>) -> Result<Self, DecodingParsingError> {
// //         let decoded = CryptographicKey::decode(&input)?;

// //         if decoded.encoding_byte_id != 0x90 {
// //             return Err(DecodingParsingError::IncorrecByteIdentifier { set: decoded.encoding_byte_id, decoding: 0x90 });
// //         }

// //     }
// // }

use std::{rc::Rc, sync::Arc};

use crate::{core::{asymmetric::{authentication_key::{AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, edwards_key::{PrivateKeyOverEC, PublicKeyOverEC}}, cryptographic_key::CryptographicKeyDetails, symmetric::symmetric_key::SymmetricKey}, encoding::{BytesArray, Decoder, DecodingParsingError, Dictionary, Encoder}};

impl Encoder for CryptographicKeyDetails {
    fn encode(&self) -> Result<Vec<u8>, crate::encoding::DecodingParsingError> {
        let encoded_byte_ids = vec![self.algo_class_byte_id, self.algo_implem_byte_id].encode()?;
        let encoded_dict = self.dict.encode()?;

        Ok(Self::pack(self.encoding_byte_id, &vec![encoded_byte_ids, encoded_dict])?)
    }
}

impl Decoder for CryptographicKeyDetails {
    fn decode(input: &[u8]) -> Result<Self, crate::encoding::DecodingParsingError> {
        let (byte_id, encoded_vals) = Self::unpack(input)?;
        if encoded_vals.len() != 2 {
            return Err(DecodingParsingError::Decoding("Wrong number of encoded values".to_string()));
        }

        let byte_ids = BytesArray::decode(&encoded_vals[0])?;
        if byte_ids.len() != 2 {
            return Err(DecodingParsingError::Decoding("Wrong number of byte ids".to_string()));
        }

        let algo_class_byte_id = &byte_ids[0];
        let algo_implem_byte_id = &byte_ids[1];

        let dict = Dictionary::decode(&encoded_vals[1])?;

        Ok(CryptographicKeyDetails::new(*algo_class_byte_id, *algo_implem_byte_id, Arc::new(dict), byte_id))
    }
}

// pub fn decode_sym_key(raw_key: &[u8]) -> Result<Box<impl SymmetricKey>, DecodingParsingError> {
//     todo!()
// }
pub const ENCODING_BYTE_ID_PUBLIC_KEY: u8 = 0x91;

impl Decoder for PublicKeyOverEC {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let cryptographic_key_details = CryptographicKeyDetails::decode(input)?;
        if cryptographic_key_details.encoding_byte_id !=  ENCODING_BYTE_ID_PUBLIC_KEY {
            return Err(DecodingParsingError::IncorrecByteIdentifier { set: cryptographic_key_details.encoding_byte_id, decoding: ENCODING_BYTE_ID_PUBLIC_KEY })
        }
        Ok(PublicKeyOverEC::from_dict(cryptographic_key_details.algo_class_byte_id, cryptographic_key_details.algo_implem_byte_id, cryptographic_key_details.dict).map_err(|_| DecodingParsingError::Technical)?)
    }
}

impl Decoder for AuthenticationPublicKeyOverEC {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        Ok(Self { public_key_over_ec: PublicKeyOverEC::decode(input)? })
    }
}

pub const ENCODING_BYTE_ID_PRIVATE_KEY: u8 = 0x92;

impl Decoder for PrivateKeyOverEC {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let cryptographic_key_details = CryptographicKeyDetails::decode(input)?;
        if cryptographic_key_details.encoding_byte_id !=  ENCODING_BYTE_ID_PRIVATE_KEY {
            return Err(DecodingParsingError::IncorrecByteIdentifier { set: cryptographic_key_details.encoding_byte_id, decoding: ENCODING_BYTE_ID_PUBLIC_KEY })
        }
        Ok(PrivateKeyOverEC::from_dict(cryptographic_key_details.algo_class_byte_id, cryptographic_key_details.algo_implem_byte_id, cryptographic_key_details.dict).map_err(|_| DecodingParsingError::Technical)?)
    }
}

impl Decoder for AuthenticationPrivateKeyOverEC {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        Ok(Self { private_key_over_ec: PrivateKeyOverEC::decode(input)? })
    }
}