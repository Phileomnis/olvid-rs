use crate::encoding::{
    encoding::{BytesArray, Decoder, Encoder},
    errors::DecodingParsingError,
};

impl Encoder for String {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let string_bytes = self.as_bytes().to_vec();
        return Ok(string_bytes.encode()?);
    }
}

impl Decoder for String {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        return Ok(String::from_utf8(BytesArray::decode(input)?)
            .map_err(|_| DecodingParsingError::Decoding(String::from("not a ut8 string")))?);
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::types::bytes_array::BYTE_IDENTIFIER_ARRAY;

    use super::*;

    fn create_input(value: String) -> Vec<u8> {
        let length: u32 = value.len().try_into().unwrap();
        let mut input = vec![BYTE_IDENTIFIER_ARRAY];
        input.extend_from_slice(&length.to_be_bytes());
        input.extend_from_slice(value.as_bytes());

        return input;
    }

    #[test]
    fn decode() {
        let input = create_input(String::from("What's your name?"));
        let decoded = String::decode(&input).unwrap();
        assert_eq!("What's your name?", decoded);
    }

    #[test]
    fn encode() {
        let encoded = String::encode(&String::from("Plz encode me")).unwrap();
        assert_eq!(create_input(String::from("Plz encode me")), encoded);
    }
}
