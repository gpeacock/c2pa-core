//! Cryptographic hashing for C2PA hashed-URI validation.
//!
//! Only the algorithms in the C2PA data-hash algorithm registry are supported.
//! The `alg` strings are the registry identifiers (`sha256`, `sha384`,
//! `sha512`).

use sha2::{Digest, Sha256, Sha384, Sha512};

/// Compute the digest of `data` under the named algorithm, or `None` if the
/// algorithm identifier is not recognized.
pub fn digest(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    match alg {
        "sha256" => Some(Sha256::digest(data).to_vec()),
        "sha384" => Some(Sha384::digest(data).to_vec()),
        "sha512" => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// Compute the digest of all of `reader`'s bytes under the named algorithm,
/// reading in bounded chunks so the source never has to be fully in memory
/// (e.g. hashing a whole asset file for a `c2pa.hash.data` assertion).
///
/// Errs with [`io::ErrorKind::InvalidInput`] if the algorithm identifier is
/// not recognized, or propagates the reader's own I/O errors.
///
/// Requires the `std` feature (the only place in this crate that needs
/// `std::io` rather than borrowing `&[u8]`/`&str`).
#[cfg(feature = "std")]
pub fn digest_reader(alg: &str, reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    match alg {
        "sha256" => stream_digest::<Sha256>(reader),
        "sha384" => stream_digest::<Sha384>(reader),
        "sha512" => stream_digest::<Sha512>(reader),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown hash algorithm: {alg}"),
        )),
    }
}

#[cfg(feature = "std")]
fn stream_digest<D: Digest>(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut hasher = D::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}
