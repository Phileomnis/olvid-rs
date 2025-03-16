use super::{types::{bytes_array::BYTE_IDENTIFIER_ARRAY, dictionary::BYTE_IDENTIFIER_DICTIONARY}, DecodingParsingError};

pub type ByteIdentifier = u8;

pub enum ByteIdentifierType {
    BytesArray,
    BigInteger,
    Boolean,
    UnisgnedBigInterger,
    List,
    Dictionary,
    SymmetricKey,
    PublicKey,
    PrivateKey,
}

pub struct Encoded {
    pub identifier: ByteIdentifier,
    pub length: u32,
    pub content: Vec<u8>,
}

pub fn get_byte_identifier_from_type(identifier_type: ByteIdentifierType) -> ByteIdentifier {
    match identifier_type {
        ByteIdentifierType::BytesArray => 0x00,
        ByteIdentifierType::BigInteger => 0x01,
        ByteIdentifierType::Boolean => 0x02,
        ByteIdentifierType::UnisgnedBigInterger => 0x80,
        ByteIdentifierType::List => 0x03,
        ByteIdentifierType::Dictionary => 0x04,
        ByteIdentifierType::SymmetricKey => 0x90,
        ByteIdentifierType::PublicKey => 0x91,
        ByteIdentifierType::PrivateKey => 0x92,
    }
}

pub trait Encoder {
    fn u32_from_bytes(bytes: &[u8]) -> Result<u32, DecodingParsingError> {
        return Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            DecodingParsingError::Decoding(String::from("couldn't convert bytes to u32"))
        })?));
    }

    fn parse(bytes: &[u8]) -> Result<Encoded, DecodingParsingError> {
        let total_length =
            u32::try_from(bytes.len()).map_err(|_| DecodingParsingError::InvalidLength(0))?;

        let byte_identifier = bytes[0];
        if total_length < 5 {
            return Err(DecodingParsingError::InvalidLength(total_length));
        }

        if byte_identifier == BYTE_IDENTIFIER_DICTIONARY {
            return Ok(Encoded {
                identifier: byte_identifier,
                length: 0,
                content: bytes[1..usize::try_from(total_length).unwrap()].to_vec(),
            });
        }

        let content_length_bytes: [u8; 4] = bytes[1..5]
            .try_into()
            .map_err(|_| DecodingParsingError::Malformed(String::from("Content length")))?;
        let l = u32::from_be_bytes(content_length_bytes);

        if 5 + l != total_length {
            return Err(DecodingParsingError::IncorrectLength {
                set_length: total_length,
                real_length: 5 + l,
            });
        }

        return Ok(Encoded {
            identifier: byte_identifier,
            length: l,
            content: bytes[5..usize::try_from(total_length).unwrap()].to_vec(),
        });
    }

    fn pack(
        byte_id: u8,
        encoded_values: &[BytesArray],
    ) -> Result<BytesArray, DecodingParsingError> {
        let mut total_length = 0;
        encoded_values
            .iter()
            .for_each(|encoded_val| total_length += encoded_val.len());

        let content_byte_length: u32 = total_length
            .try_into()
            .map_err(|_| DecodingParsingError::InvalidLength(0))?;

        let mut encoded: Vec<u8> = vec![byte_id];

        if byte_id != BYTE_IDENTIFIER_DICTIONARY {
            encoded.extend_from_slice(&content_byte_length.to_be_bytes());
        }

        // encoded_values
        //     .iter()
        //     .for_each(|encoded_val| encoded.append(&mut encoded_val.clone()));

        for encoded_val in encoded_values {
            encoded.extend_from_slice(&mut encoded_val.clone());
        }

        return Ok(encoded);
    }

    fn unpack(input: &[u8]) -> Result<(ByteIdentifier, Vec<BytesArray>), DecodingParsingError> {
        let encoded = Self::parse(input)?;

        let inner_data = encoded.content;
        let mut encoded_values: Vec<BytesArray> = Vec::new();

        let (mut encoded_value, mut remaining) = Self::extract_first_encoded_value(&inner_data)?;
        encoded_values.push(encoded_value);

        while remaining.len() > 0 {
            (encoded_value, remaining) = Self::extract_first_encoded_value(&remaining)?;
            
            encoded_values.push(encoded_value);
        }

        return Ok((encoded.identifier, encoded_values));
    }

    fn usize_as_u32(value: usize) -> Result<u32, DecodingParsingError> {
        return Ok(value.try_into().map_err(|_| {
            DecodingParsingError::Malformed(String::from("couldn't get usize as u32"))
        })?);
    }

    fn u32_as_usize(value: u32) -> Result<usize, DecodingParsingError> {
        return Ok(value.try_into().map_err(|_| {
            DecodingParsingError::Malformed(String::from("couldn't get u32 as usize"))
        })?);
    }

    // Returns a tuple of first encoded value and the rest
    fn extract_first_encoded_value(
        input: &BytesArray,
    ) -> Result<(BytesArray, BytesArray), DecodingParsingError> {
        let n = input.len();
        if n < 5 {
            return Err(DecodingParsingError::InvalidLength(Self::usize_as_u32(n)?));
        }

        let l = Self::u32_as_usize(Self::u32_from_bytes(&input[1..5])?)?;
        if n < l + 5 {
            return Err(DecodingParsingError::InvalidLength(Self::usize_as_u32(n)?));
        }

        if n == l + 5 {
            let first_encoded_value = input.clone();
            // input.clear();
            return Ok((first_encoded_value, vec![]));
        }

        let (first_encoded_value, remaining) = input.split_at(5 + l);
        return Ok((first_encoded_value.to_vec(), remaining.to_vec()));
    }

    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError>;

    fn encode_slice(input: &[u8]) -> Result<Vec<u8>, DecodingParsingError> {
        let content_byte_length = Self::usize_as_u32(input.len())?.to_be_bytes();

        let mut encoded: Vec<u8> = vec![BYTE_IDENTIFIER_ARRAY];
        encoded.append(&mut content_byte_length.to_vec());
        // encoded.append(&mut input.to_vec());
        encoded.extend_from_slice(&input);

        return Ok(encoded);
    }
}

pub trait Decoder {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError>
    where
        Self: Sized;
}

pub type BytesArray = Vec<u8>;

#[cfg(test)]
mod tests {
    use crate::encoding::types::bytes_array::BYTE_IDENTIFIER_ARRAY;

    use super::Encoder;

    #[test]
    fn unpack() {
        let mut input = vec![0x01];
        let length = 32u32.to_be_bytes();
        let encoded_val1 = String::encode(&"encoded_one".to_string()).unwrap();
        let encoded_val2 = String::encode(&"encoded_two".to_string()).unwrap();
        input.extend_from_slice(&length);
        input.append(&mut encoded_val1.clone());
        input.append(&mut encoded_val2.clone());

        let (byteId, encoded_values) = String::unpack(&input).unwrap();
        assert_eq!(byteId, 0x01);
        assert_eq!(encoded_values.get(0).unwrap(), &encoded_val1);
        assert_eq!(encoded_values.get(1).unwrap(), &encoded_val2);
    }
}