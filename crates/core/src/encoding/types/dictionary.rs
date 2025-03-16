use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{core::cryptographic_key::KeyError, encoding::{
    encoding::{ByteIdentifier, BytesArray, Decoder, Encoder},
    errors::DecodingParsingError,
}};

// pub type Dictionary = HashMap<String, BytesArray>;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dictionary(pub HashMap<String, BytesArray>);

pub const BYTE_IDENTIFIER_DICTIONARY: ByteIdentifier = 0x04;

impl Encoder for Dictionary {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let mut to_pack: Vec<BytesArray> = Vec::new();

        for (key, value) in &self.0 {
            let k = key.clone();
            to_pack.push(k.to_string().encode()?);
            to_pack.push(value.clone());
        }
        return Ok(Self::pack(BYTE_IDENTIFIER_DICTIONARY, &mut to_pack)?);
    }
}

impl Decoder for Dictionary {
    // fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
    //     let (byte_identifier, mut encoded_values) = Self::unpack(input)?;
        
    //     let mut decoded: Self = Dictionary(HashMap::new());

    //     if byte_identifier != BYTE_IDENTIFIER_DICTIONARY {
    //         return Err(DecodingParsingError::IncorrecByteIdentifier {
    //             set: byte_identifier,
    //             decoding: BYTE_IDENTIFIER_DICTIONARY,
    //         });
    //     }

    //     if encoded_values.len() % 2 != 0 {
    //         return Err(DecodingParsingError::Malformed(String::from(
    //             "decoding dictionary with an odd number of values",
    //         )));
    //     }

    //     while encoded_values.len() > 0 {
    //         let encoded_value =
    //             encoded_values
    //                 .pop()
    //                 .ok_or(DecodingParsingError::Decoding(String::from(
    //                     "cannot decode value of dictionary",
    //                 )))?;
    //         let encoded_key =
    //             encoded_values
    //                 .pop()
    //                 .ok_or(DecodingParsingError::Decoding(String::from(
    //                     "cannot decode key of dictionary",
    //                 )))?;

    //         let decoded_key = String::decode(&encoded_key)?;
    //         decoded.0.insert(decoded_key, encoded_value);
    //     }

    //     return Ok(decoded);
    // }
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let byte_id = input[0];


        // let (byte_identifier, mut encoded_values) = Self::unpack(input)?;
        
        let mut decoded: Self = Dictionary(HashMap::new());

        if byte_id != BYTE_IDENTIFIER_DICTIONARY {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: byte_id,
                decoding: BYTE_IDENTIFIER_DICTIONARY,
            });
        }

        let input_len = input.len();

        let mut offset = 5usize;
        while offset + 4 < input_len {
            let mut len: usize = Self::u32_from_bytes(&input[offset+1..offset+5]).unwrap().try_into().unwrap();
            if offset + 5 + len > input_len {
                return Err(DecodingParsingError::Decoding("".to_string()))
            } 

            let dict_key = String::decode(&input[offset..offset+5+len])?;
            offset = offset + 5 + len;

            if offset + 5 > input_len {
                return Err(DecodingParsingError::Decoding("".to_string())) 
            }
            len = Self::u32_from_bytes(&input[offset+1..offset+5]).unwrap().try_into().unwrap();
            if offset + 5 + len > input.len() {
                return Err(DecodingParsingError::Decoding("".to_string())) 
            }

            let value = &input[offset..offset+5+len];
            offset = offset + 5 + len;
            decoded.0.insert(dict_key, value.to_vec());
        }

        return Ok(decoded);
    }
}

impl Dictionary {
    pub fn new() -> Self {
        Dictionary(HashMap::new())
    }

    pub fn add(&mut self, key: &str, value: BytesArray) -> &Self {
        self.0.insert(key.to_string(), value);
        self
    }

    pub fn get(&self, key: &str) -> Option<&BytesArray> {
        self.0.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_input(value: &HashMap<String, BytesArray>) -> Vec<u8> {
        let mut input = vec![BYTE_IDENTIFIER_DICTIONARY];

        for (k, v) in value {
            input.append(&mut k.clone().encode().unwrap());
            input.append(&mut v.clone());
        }

        return input;
    }

    #[test]
    fn decode() {
        let mut dict: HashMap<String, BytesArray> = HashMap::new();
        dict.insert(String::from("ABC"), String::from("DEF").encode().unwrap());
        dict.insert(String::from("123"), String::from("456").encode().unwrap());

        let input = create_input(&dict);
        let decoded = Dictionary::decode(&input).unwrap();
        assert_eq!(2, decoded.0.len());
        assert_eq!(
            String::from("DEF"),
            String::decode(decoded.0.get(&String::from("ABC")).unwrap()).unwrap()
        );
        assert_eq!(
            String::from("456"),
            String::decode(decoded.0.get(&String::from("123")).unwrap()).unwrap()
        );
        assert_eq!(decoded.0, dict);
    }

    #[test]
    fn encode() {
        let mut dict = Dictionary(HashMap::new());
        dict.0.insert(String::from("ABC"), String::from("DEF").encode().unwrap());
        dict.0.insert(String::from("123"), String::from("456").encode().unwrap());

        let encoded = Dictionary::encode(&dict).unwrap();
        assert_eq!(create_input(&dict.0), encoded);
    }
}