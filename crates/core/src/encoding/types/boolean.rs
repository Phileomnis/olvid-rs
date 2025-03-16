use crate::encoding::{
    encoding::{ByteIdentifier, Decoder, Encoder},
    errors::DecodingParsingError,
};

const BYTE_IDENTIFIER_BOOL: ByteIdentifier = 0x02;

impl Encoder for bool {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let content_byte_length = 1_u32.to_be_bytes();
        let content: u8 = match self {
            true => 0x01,
            false => 0x00,
        };

        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(BYTE_IDENTIFIER_BOOL);
        encoded.append(&mut content_byte_length.to_vec());
        encoded.push(content);

        return Ok(encoded);
    }
}

impl Decoder for bool {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let encoded = Self::parse(input)?;

        if encoded.identifier != BYTE_IDENTIFIER_BOOL {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: BYTE_IDENTIFIER_BOOL,
            });
        }

        if encoded.length != 1 {
            return Err(DecodingParsingError::InvalidLength(encoded.length));
        }

        let content_byte = encoded.content.get(0).unwrap_or(&0x00);
        return Ok(*content_byte == 0x01_u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_input(value: u8) -> Vec<u8> {
        let length = 1_u32.to_be_bytes();
        let mut input = vec![BYTE_IDENTIFIER_BOOL];
        input.extend_from_slice(&length);
        input.push(value);

        return input;
    }

    #[test]
    fn decode() {
        let input_false = create_input(0x00);
        let decoded_false = bool::decode(&input_false).unwrap();
        assert!(decoded_false == false);

        let input_true = create_input(0x01);
        let decoded_true = bool::decode(&input_true).unwrap();
        assert!(decoded_true == true);
    }

    #[test]
    fn encode() {
        let encode_false = bool::encode(&false).unwrap();
        assert_eq!(encode_false, create_input(0x00));

        let encode_true = bool::encode(&true).unwrap();
        assert_eq!(encode_true, create_input(0x01));
    }
}
