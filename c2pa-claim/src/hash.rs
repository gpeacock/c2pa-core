//! Hashing with the C2PA hash algorithms, shared by hashed URIs and the hash
//! assertions in `c2pa-assertions`.
//!
//! Only the algorithms in the C2PA data-hash algorithm registry are supported.
//! The `alg` strings are the registry identifiers (`sha256`, `sha384`,
//! `sha512`).

use sha2::{Digest, Sha256, Sha384, Sha512};

/// Compute the digest of `data` under the named algorithm, or `None` if the
/// algorithm identifier is not recognized.
pub fn digest(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    hasher.update(data);
    Some(hasher.finalize())
}

/// An incremental digest under one of the C2PA hash algorithms, for bytes that
/// arrive in pieces. It hashes the slices it is given in place, never copying.
#[derive(Clone)]
pub struct Hasher(Inner);

#[derive(Clone)]
enum Inner {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    /// A hasher for the named algorithm, or `None` if it is not recognized.
    pub fn new(alg: &str) -> Option<Self> {
        Some(Self(match alg {
            "sha256" => Inner::Sha256(Sha256::new()),
            "sha384" => Inner::Sha384(Sha384::new()),
            "sha512" => Inner::Sha512(Sha512::new()),
            _ => return None,
        }))
    }

    /// Hash `data` after everything given so far.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            Inner::Sha256(h) => h.update(data),
            Inner::Sha384(h) => h.update(data),
            Inner::Sha512(h) => h.update(data),
        }
    }

    /// The digest of everything given.
    pub fn finalize(self) -> Vec<u8> {
        match self.0 {
            Inner::Sha256(h) => h.finalize().to_vec(),
            Inner::Sha384(h) => h.finalize().to_vec(),
            Inner::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self.0 {
            Inner::Sha256(_) => "Hasher(sha256)",
            Inner::Sha384(_) => "Hasher(sha384)",
            Inner::Sha512(_) => "Hasher(sha512)",
        })
    }
}

/// Compute the digest of all of `reader`'s bytes under the named algorithm,
/// reading in bounded chunks so the source never has to be fully in memory
/// (e.g. hashing a whole asset file for a `c2pa.hash.data` assertion).
///
/// Errs with [`std::io::ErrorKind::InvalidInput`] if the algorithm identifier is
/// not recognized, or propagates the reader's own I/O errors.
///
/// Requires the `std` feature (the only place in this crate that needs
/// `std::io`). Callers doing their own I/O feed a [`Hasher`] instead.
#[cfg(feature = "std")]
pub fn digest_reader(alg: &str, mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut hasher = Hasher::new(alg).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unknown hash algorithm: {alg}"),
        )
    })?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize()),
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
