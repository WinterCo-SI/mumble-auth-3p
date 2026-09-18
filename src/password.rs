use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use crate::error::AppError;

const COMPACT_JWS_PASSWORD_PREFIX: &str = "z";
const MAX_JWT_BYTES: usize = 2 * 1024;
const MAX_TOKEN_SEGMENT_BYTES: usize = 2 * 1024;
const MAX_BINARY_PASSWORD_BYTES: usize = 2 * 1024;
const JWS_SEGMENT_COUNT: usize = 3;

// Password layout:
//   "z" base64url(u16le(header_len) u16le(payload_len)
//                 zlib(header || payload) signature u16le(signature_len))
//
// The signature stays as raw bytes; the other two segments are compressed.
// No claim names, values, or header fields are assumed.
pub fn compress_password(jwt: &str) -> Result<String, AppError> {
    if jwt.len() > MAX_JWT_BYTES {
        return Err(AppError::Internal("jwt is too large".into()));
    }

    let segments: Vec<_> = jwt.split('.').collect();
    if segments.len() != JWS_SEGMENT_COUNT {
        return Err(AppError::Internal("unsupported jwt segment count".into()));
    }

    let header = decode_segment(segments[0], "jwt header")?;
    let payload = decode_segment(segments[1], "jwt payload")?;
    let signature = decode_segment(segments[2], "jwt signature")?;
    let signature_len = segment_len(signature.len(), "jwt signature")?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&header)
        .and_then(|()| encoder.write_all(&payload))
        .map_err(|e| AppError::Internal(format!("compress jwt: {e}")))?;
    let mut compressed = encoder
        .finish()
        .map_err(|e| AppError::Internal(format!("compress jwt: {e}")))?;

    let mut binary = Vec::with_capacity(compressed.len() + signature.len() + 6);
    binary.extend_from_slice(&segment_len(header.len(), "jwt header")?.to_le_bytes());
    binary.extend_from_slice(&segment_len(payload.len(), "jwt payload")?.to_le_bytes());
    binary.append(&mut compressed);
    binary.extend_from_slice(&signature);
    binary.extend_from_slice(&signature_len.to_le_bytes());

    if binary.len() > MAX_BINARY_PASSWORD_BYTES {
        return Err(AppError::Internal("compressed jwt is too large".into()));
    }

    Ok(format!(
        "{COMPACT_JWS_PASSWORD_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(binary)
    ))
}

pub fn decompress_password(password: &str) -> Result<String, AppError> {
    let Some(encoded) = password.strip_prefix(COMPACT_JWS_PASSWORD_PREFIX) else {
        return Ok(password.to_owned());
    };

    let mut binary = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| AppError::Unauthorized(format!("invalid password encoding: {e}")))?;
    if binary.len() > MAX_BINARY_PASSWORD_BYTES || binary.len() < 6 {
        return Err(AppError::Unauthorized(
            "password has an invalid size".into(),
        ));
    }

    let header_len = u16::from_le_bytes([binary[0], binary[1]]) as usize;
    let payload_len = u16::from_le_bytes([binary[2], binary[3]]) as usize;
    let signature_len =
        u16::from_le_bytes([binary[binary.len() - 2], binary[binary.len() - 1]]) as usize;
    if signature_len == 0 || signature_len > MAX_TOKEN_SEGMENT_BYTES {
        return Err(AppError::Unauthorized("invalid jwt layout".into()));
    }

    let binary_len = binary.len();
    binary.truncate(binary_len - 2);
    let signature_start = binary
        .len()
        .checked_sub(signature_len)
        .ok_or_else(|| AppError::Unauthorized("invalid jwt layout".into()))?;
    if signature_start < 4 {
        return Err(AppError::Unauthorized("invalid jwt layout".into()));
    }
    let signature = binary.split_off(signature_start);
    binary.truncate(signature_start);
    binary.drain(..4);
    let compressed = binary;

    let expected = header_len
        .checked_add(payload_len)
        .and_then(|len| len.checked_add(signature_len))
        .ok_or_else(|| AppError::Unauthorized("invalid jwt lengths".into()))?;
    if expected > MAX_JWT_BYTES {
        return Err(AppError::Unauthorized("password is too large".into()));
    }

    // Bound the read with the declared lengths before decompressing.
    let mut decoder =
        ZlibDecoder::new(&compressed[..]).take(header_len as u64 + payload_len as u64 + 1);
    let mut header_payload = Vec::new();
    decoder
        .read_to_end(&mut header_payload)
        .map_err(|e| AppError::Unauthorized(format!("invalid password compression: {e}")))?;
    if header_payload.len() != header_len + payload_len {
        return Err(AppError::Unauthorized("invalid jwt lengths".into()));
    }

    let (header, payload) = header_payload.split_at(header_len);
    Ok(format!(
        "{}.{}.{}",
        encode_segment(header)?,
        encode_segment(payload)?,
        encode_segment(&signature)?
    ))
}

fn segment_len(len: usize, name: &str) -> Result<u16, AppError> {
    u16::try_from(len).map_err(|_| AppError::Internal(format!("{name} is too large")))
}

fn decode_segment(segment: &str, name: &str) -> Result<Vec<u8>, AppError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| AppError::Internal(format!("invalid {name}: {e}")))?;
    if decoded.len() > MAX_TOKEN_SEGMENT_BYTES {
        return Err(AppError::Internal(format!("{name} is too large")));
    }
    Ok(decoded)
}

fn encode_segment(segment: &[u8]) -> Result<String, AppError> {
    if segment.len() > MAX_TOKEN_SEGMENT_BYTES {
        return Err(AppError::Unauthorized("jwt segment is too large".into()));
    }
    Ok(URL_SAFE_NO_PAD.encode(segment))
}

#[cfg(test)]
mod tests {
    use super::{
        compress_password, decompress_password, COMPACT_JWS_PASSWORD_PREFIX,
        MAX_BINARY_PASSWORD_BYTES, MAX_JWT_BYTES, MAX_TOKEN_SEGMENT_BYTES,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn compact_jws_password_round_trips() {
        let header = URL_SAFE_NO_PAD.encode("header".repeat(60));
        let payload = URL_SAFE_NO_PAD.encode("payload".repeat(90));
        let signature = URL_SAFE_NO_PAD.encode("signature".repeat(32));
        let jwt = format!("{header}.{payload}.{signature}");
        let password = compress_password(&jwt).expect("compress jwt");

        assert!(password.starts_with(COMPACT_JWS_PASSWORD_PREFIX));
        assert!(password.len() < jwt.len());
        assert_eq!(decompress_password(&password).expect("decompress jwt"), jwt);
    }

    #[test]
    fn compact_jws_password_keeps_signature_outside_compression() {
        let header = URL_SAFE_NO_PAD.encode("header".repeat(60));
        let payload = URL_SAFE_NO_PAD.encode("payload".repeat(90));
        let signature = URL_SAFE_NO_PAD.encode("signature".repeat(32));
        let jwt = format!("{header}.{payload}.{signature}");
        let password = compress_password(&jwt).expect("compress jwt");

        let binary = URL_SAFE_NO_PAD
            .decode(
                password
                    .strip_prefix(COMPACT_JWS_PASSWORD_PREFIX)
                    .expect("prefix"),
            )
            .expect("binary password");
        let signature_len =
            u16::from_le_bytes([binary[binary.len() - 2], binary[binary.len() - 1]]) as usize;

        assert_eq!(
            signature_len,
            URL_SAFE_NO_PAD.decode(signature).expect("signature").len()
        );
        assert!(password.len() < jwt.len());
        assert_eq!(decompress_password(&password).expect("decompress jwt"), jwt);
    }

    #[test]
    fn raw_password_is_accepted() {
        let jwt = "header.payload.signature";

        assert_eq!(decompress_password(jwt).expect("decompress raw jwt"), jwt);
    }

    #[test]
    fn invalid_password_encoding_is_rejected() {
        assert!(decompress_password("z:not-base64!!").is_err());
    }

    #[test]
    fn invalid_password_compression_is_rejected() {
        assert!(decompress_password("z:aGVsbG8=").is_err());
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&vec![b'A'; MAX_JWT_BYTES + 1024])
            .expect("write bomb");
        let mut compressed = encoder.finish().expect("compress bomb");

        let mut password_bytes = (MAX_TOKEN_SEGMENT_BYTES as u16).to_le_bytes().to_vec();
        password_bytes.extend_from_slice(&1024u16.to_le_bytes());
        password_bytes.append(&mut compressed);
        password_bytes.push(b'B');
        password_bytes.extend_from_slice(&1u16.to_le_bytes());
        assert!(password_bytes.len() <= MAX_BINARY_PASSWORD_BYTES);

        let password = format!(
            "{COMPACT_JWS_PASSWORD_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(password_bytes)
        );
        let error = decompress_password(&password).expect_err("oversized decompressed password");
        assert!(error.to_string().contains("password is too large"));
    }
}
