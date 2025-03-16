use num::{BigUint, ToPrimitive};

pub fn pad_bytes_slice(bytes: &[u8], length: usize) -> Vec<u8> {
    let mut result: Vec<u8> = vec![0; length - bytes.len()];
    result.extend_from_slice(bytes);
    result
}


/// Returns a new vector of the given length, with 0s left padded.
// #[inline]
pub fn left_pad(input: &[u8], padded_len: usize) -> Vec<u8> {
    // if input.len() > padded_len {
    //     return Err(Error::InvalidPadLen);
    // }
    let mut out = vec![0u8; padded_len];
    out[padded_len - input.len()..].copy_from_slice(input);
    out
}

pub fn bytes_from_biguint(n: &BigUint, len: usize) -> Vec<u8> {
    let mut data = Vec::<u8>::new();
    let bytes = n.to_bytes_be();
    let offset: i32 = len.to_i32().unwrap() - bytes.len().to_i32().unwrap();
    if offset == -1 {
        data.extend_from_slice(&bytes[1..len]);
    } else {
        for _ in 0..offset {
            data.push(0);
        }
        data.extend_from_slice(&bytes);
    }

    data
}