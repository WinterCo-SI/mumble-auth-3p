use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use crate::error::AppError;

const COMPRESSED_PASSWORD_PREFIX: &str = "z";
const MAX_JWT_BYTES: usize = 2 * 1024;
const MAX_COMPRESSED_BYTES: usize = 2 * 1024;

pub fn compress_password(jwt: &str) -> Result<String, AppError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(jwt.as_bytes())
        .map_err(|e| AppError::Internal(format!("compress jwt: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| AppError::Internal(format!("compress jwt: {e}")))?;

    Ok(format!(
        "{COMPRESSED_PASSWORD_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(compressed)
    ))
}

pub fn decompress_password(password: &str) -> Result<String, AppError> {
    let Some(encoded) = password.strip_prefix(COMPRESSED_PASSWORD_PREFIX) else {
        return Ok(password.to_owned());
    };

    let compressed = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| AppError::Unauthorized(format!("invalid password encoding: {e}")))?;
    if compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(AppError::Unauthorized("password is too large".into()));
    }

    let mut decoder = ZlibDecoder::new(&compressed[..]).take(MAX_JWT_BYTES as u64 + 1);
    let mut jwt = Vec::new();
    decoder
        .read_to_end(&mut jwt)
        .map_err(|e| AppError::Unauthorized(format!("invalid password compression: {e}")))?;
    if jwt.len() > MAX_JWT_BYTES {
        return Err(AppError::Unauthorized("password is too large".into()));
    }

    String::from_utf8(jwt)
        .map_err(|e| AppError::Unauthorized(format!("invalid password contents: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{
        compress_password, decompress_password, COMPRESSED_PASSWORD_PREFIX, MAX_COMPRESSED_BYTES,
        MAX_JWT_BYTES,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::io::Write;

    use flate2::{write::ZlibEncoder, Compression};

    #[test]
    fn compressed_password_round_trips() {
        let jwt = "header.payload.signature".repeat(16);
        let password = compress_password(&jwt).expect("compress jwt");

        assert!(password.starts_with("z"));
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
        let result = decompress_password("z:not-base64!!");

        assert!(result.is_err());
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        let jwt = vec![b'A'; MAX_JWT_BYTES + 1024];
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&jwt).expect("write jwt");
        let compressed = encoder.finish().expect("compress jwt");

        assert!(compressed.len() <= MAX_COMPRESSED_BYTES);

        let password = format!(
            "{COMPRESSED_PASSWORD_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(compressed)
        );
        let error = decompress_password(&password).expect_err("oversized decompressed password");
        assert!(error.to_string().contains("password is too large"));
    }

    #[test]
    fn invalid_password_compression_is_rejected() {
        let result = decompress_password("z:aGVsbG8=");

        assert!(result.is_err());
    }
}
