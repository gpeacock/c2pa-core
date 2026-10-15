//! A sans-I/O, caller-driven signing pipeline: no callbacks, no threads, no
//! async runtime.
//!
//! [`SignSession`] is a state machine. The caller repeatedly calls
//! [`poll`](SignSession::poll), which either does one bounded unit of
//! internal work and returns [`Action::Continue`], or tells the caller what
//! it's waiting on:
//!
//! * [`Action::NeedAssetData`] -- feed the next chunk with
//!   [`write_asset`](SignSession::write_asset), or call
//!   [`end_asset`](SignSession::end_asset) at end of input. The session never
//!   reads anything itself, so the bytes can come from a blocking file, an
//!   async stream, a network buffer, or memory.
//! * [`Action::NeedSignature`] -- sign the given bytes however and whenever
//!   is convenient (local key, HSM, remote service) and hand the result back
//!   with [`provide_signature`](SignSession::provide_signature).
//! * [`Action::Complete`] -- take the manifest store with
//!   [`into_store_bytes`](SignSession::into_store_bytes).
//!
//! Every return to the caller is a yield point: report
//! [`progress`](SignSession::progress), interleave other work, or cancel.
//! Cancelling is just dropping the session; it holds no OS resources and nothing has
//! been written anywhere but its own memory.
//!
//! Any error is fail-stop: the session moves to a terminal failed state and
//! every later call returns [`SignError::Failed`].

use std::fmt;

use c2pa_cbor::Value;
use c2pa_cbor::cose::{CoseSign1, CoseSign1Builder, HeaderBuilder};
use c2pa_claim::{
    Action as ClaimAction, Actions, Claim, DataHash, DataHasher, GeneratorInfo, HashedUri,
};
use c2pa_store::{AssertionHash, ManifestStoreBuilder};

/// COSE header parameter label for `x5chain` (IANA COSE Header Parameters
/// registry).
const COSE_HEADER_X5CHAIN: i64 = 33;
/// Must match the algorithm `ManifestStoreBuilder` hashes assertions with.
const ASSERTION_HASH_ALG: &str = "sha256";

/// Everything the session needs up front. The signing key itself is *not*
/// here: the session yields the bytes to sign instead.
#[derive(Clone, Debug)]
pub struct SignParams {
    pub manifest_label: String,
    pub instance_id: String,
    pub generator: GeneratorInfo,
    /// Hash algorithm for the `c2pa.hash.data` assertion.
    pub data_hash_alg: String,
    /// COSE algorithm identifier of the signature the caller will provide.
    pub cose_alg: i64,
    /// DER certificates, end-entity first, embedded as `x5chain`.
    pub x5chain: Vec<Vec<u8>>,
    /// The asset's total length, if known: used for progress reporting and
    /// checked against the bytes actually supplied.
    pub asset_len: Option<u64>,
}

/// Coarse pipeline stage, for progress reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    HashingAsset,
    AddingAssertions,
    BuildingClaim,
    AwaitingSignature,
    Finalizing,
    Complete,
    Failed,
}

/// A snapshot of how far along the session is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub phase: Phase,
    pub asset_bytes_hashed: u64,
    pub asset_len: Option<u64>,
}

/// What [`SignSession::poll`] needs from the caller next.
#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// Call [`SignSession::write_asset`] with the next chunk, or
    /// [`SignSession::end_asset`] at end of input.
    NeedAssetData,
    /// A unit of internal work finished; poll again when convenient.
    Continue,
    /// Sign these bytes (the COSE `Sig_structure`) with the key matching
    /// `x5chain[0]`, then call [`SignSession::provide_signature`].
    NeedSignature(&'a [u8]),
    /// Call [`SignSession::into_store_bytes`].
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The call isn't valid in the session's current phase. Non-fatal: the
    /// session is unchanged.
    WrongPhase {
        called: &'static str,
        phase: Phase,
    },
    UnknownHashAlgorithm(String),
    /// The supplied asset length didn't match [`SignParams::asset_len`].
    AssetLengthMismatch {
        expected: u64,
        actual: u64,
    },
    Store(c2pa_store::Error),
    Encode(String),
    /// A previous call failed; the session can't continue.
    Failed,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPhase { called, phase } => {
                write!(f, "{called} is not valid during phase {phase:?}")
            }
            Self::UnknownHashAlgorithm(alg) => write!(f, "unknown hash algorithm: {alg}"),
            Self::AssetLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "asset length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Store(e) => write!(f, "manifest store: {e}"),
            Self::Encode(e) => write!(f, "encode: {e}"),
            Self::Failed => f.write_str("session already failed"),
        }
    }
}

impl std::error::Error for SignError {}

impl From<c2pa_store::Error> for SignError {
    fn from(e: c2pa_store::Error) -> Self {
        Self::Store(e)
    }
}

fn encode_err(e: impl fmt::Display) -> SignError {
    SignError::Encode(e.to_string())
}

type Builder = ManifestStoreBuilder<Vec<u8>>;

enum State {
    Hashing(DataHasher),
    AddHardBinding(DataHash),
    AddActions {
        builder: Builder,
        hrefs: Vec<HashedUri>,
    },
    BuildClaim {
        builder: Builder,
        hrefs: Vec<HashedUri>,
    },
    AwaitingSignature {
        builder: Builder,
        sign1: CoseSign1,
        tbs: Vec<u8>,
    },
    Finalize {
        builder: Builder,
        signature_cbor: Vec<u8>,
    },
    Complete(Vec<u8>),
    Failed,
}

impl State {
    fn phase(&self) -> Phase {
        match self {
            Self::Hashing(_) => Phase::HashingAsset,
            Self::AddHardBinding(_) | Self::AddActions { .. } => Phase::AddingAssertions,
            Self::BuildClaim { .. } => Phase::BuildingClaim,
            Self::AwaitingSignature { .. } => Phase::AwaitingSignature,
            Self::Finalize { .. } => Phase::Finalizing,
            Self::Complete(_) => Phase::Complete,
            Self::Failed => Phase::Failed,
        }
    }
}

fn hashed_uri(a: AssertionHash) -> HashedUri {
    HashedUri::new(a.url, Some(a.alg.to_string()), &a.hash)
}

/// See the [module docs](self).
pub struct SignSession {
    params: SignParams,
    state: State,
    asset_bytes_hashed: u64,
}

impl fmt::Debug for SignSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignSession")
            .field("progress", &self.progress())
            .finish_non_exhaustive()
    }
}

impl SignSession {
    pub fn new(params: SignParams) -> Result<Self, SignError> {
        let hasher = DataHash::hasher(&params.data_hash_alg)
            .ok_or_else(|| SignError::UnknownHashAlgorithm(params.data_hash_alg.clone()))?;
        Ok(Self {
            params,
            state: State::Hashing(hasher),
            asset_bytes_hashed: 0,
        })
    }

    pub fn progress(&self) -> Progress {
        Progress {
            phase: self.state.phase(),
            asset_bytes_hashed: self.asset_bytes_hashed,
            asset_len: self.params.asset_len,
        }
    }

    /// Advance by at most one bounded unit of work, or report what the
    /// caller must supply next. Never blocks.
    pub fn poll(&mut self) -> Result<Action<'_>, SignError> {
        match self.state {
            State::Hashing(_) => return Ok(Action::NeedAssetData),
            State::Complete(_) => return Ok(Action::Complete),
            State::Failed => return Err(SignError::Failed),
            State::AwaitingSignature { .. } => {}
            _ => {
                self.step()?;
                return Ok(Action::Continue);
            }
        }
        match &self.state {
            State::AwaitingSignature { tbs, .. } => Ok(Action::NeedSignature(tbs)),
            _ => Err(SignError::Failed),
        }
    }

    /// Hash the next chunk of the asset. Work is proportional to
    /// `chunk.len()`, so the caller bounds each step by its chunk size.
    pub fn write_asset(&mut self, chunk: &[u8]) -> Result<(), SignError> {
        let State::Hashing(hasher) = &mut self.state else {
            return Err(self.wrong_phase("write_asset"));
        };
        hasher.update(chunk);
        self.asset_bytes_hashed = hasher.bytes_hashed();
        Ok(())
    }

    /// Signal end of asset input.
    pub fn end_asset(&mut self) -> Result<(), SignError> {
        if !matches!(self.state, State::Hashing(_)) {
            return Err(self.wrong_phase("end_asset"));
        }
        if let Some(expected) = self.params.asset_len
            && expected != self.asset_bytes_hashed
        {
            self.state = State::Failed;
            return Err(SignError::AssetLengthMismatch {
                expected,
                actual: self.asset_bytes_hashed,
            });
        }
        let State::Hashing(hasher) = std::mem::replace(&mut self.state, State::Failed) else {
            return Err(SignError::Failed);
        };
        self.state = State::AddHardBinding(hasher.finish());
        Ok(())
    }

    /// Supply the signature over the bytes from [`Action::NeedSignature`].
    pub fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), SignError> {
        if !matches!(self.state, State::AwaitingSignature { .. }) {
            return Err(self.wrong_phase("provide_signature"));
        }
        let State::AwaitingSignature {
            builder, mut sign1, ..
        } = std::mem::replace(&mut self.state, State::Failed)
        else {
            return Err(SignError::Failed);
        };
        sign1.signature = signature;
        // C2PA uses detached content: the claim lives in its own box, so the
        // COSE payload must be nil. c2pa-rs/c2patool expect the tagged form (CBOR tag 18).
        sign1.payload = None;
        let signature_cbor = sign1.to_tagged_vec().map_err(encode_err)?;
        self.state = State::Finalize {
            builder,
            signature_cbor,
        };
        Ok(())
    }

    /// Take the finished manifest store bytes.
    pub fn into_store_bytes(self) -> Result<Vec<u8>, SignError> {
        match self.state {
            State::Complete(bytes) => Ok(bytes),
            ref other => Err(SignError::WrongPhase {
                called: "into_store_bytes",
                phase: other.phase(),
            }),
        }
    }

    fn wrong_phase(&self, called: &'static str) -> SignError {
        match self.state {
            State::Failed => SignError::Failed,
            _ => SignError::WrongPhase {
                called,
                phase: self.state.phase(),
            },
        }
    }

    /// Run one internal (non-caller-dependent) step. On error the state is
    /// left as `Failed`.
    fn step(&mut self) -> Result<(), SignError> {
        let state = std::mem::replace(&mut self.state, State::Failed);
        self.state = match state {
            State::AddHardBinding(data_hash) => {
                let mut builder = Builder::new(Vec::new(), &self.params.manifest_label)?;
                let cbor = data_hash.to_cbor().map_err(encode_err)?;
                let href = builder.add_cbor_assertion(DataHash::LABEL, None, &cbor)?;
                State::AddActions {
                    builder,
                    hrefs: vec![hashed_uri(href)],
                }
            }
            State::AddActions {
                mut builder,
                mut hrefs,
            } => {
                let mut actions = Actions::new();
                actions.add_action(
                    ClaimAction::new(ClaimAction::CREATED)
                        .with_digital_source_type(ClaimAction::DIGITAL_SOURCE_TYPE_EMPTY),
                );
                let cbor = actions.to_cbor().map_err(encode_err)?;
                hrefs.push(hashed_uri(builder.add_cbor_assertion(
                    Actions::LABEL,
                    None,
                    &cbor,
                )?));
                State::BuildClaim { builder, hrefs }
            }
            State::BuildClaim { mut builder, hrefs } => {
                let mut claim = Claim::new(
                    &self.params.manifest_label,
                    self.params.instance_id.clone(),
                    self.params.generator.clone(),
                );
                claim.alg = Some(ASSERTION_HASH_ALG.to_string());
                for href in hrefs {
                    claim.add_created_assertion(href);
                }
                let claim_cbor = claim.to_cbor().map_err(encode_err)?;
                builder.add_claim("c2pa.claim.v2", &claim_cbor)?;

                let x5chain = Value::Array(
                    self.params
                        .x5chain
                        .iter()
                        .map(|der| Value::Bytes(der.clone()))
                        .collect(),
                );
                let protected = HeaderBuilder::new()
                    .algorithm(self.params.cose_alg)
                    .value(COSE_HEADER_X5CHAIN, x5chain)
                    .build();
                let sign1 = CoseSign1Builder::new()
                    .protected(protected)
                    .payload(claim_cbor)
                    .build();
                let tbs = sign1.tbs_data(&[]).map_err(encode_err)?;
                State::AwaitingSignature {
                    builder,
                    sign1,
                    tbs,
                }
            }
            State::Finalize {
                mut builder,
                signature_cbor,
            } => {
                builder.add_signature(&signature_cbor)?;
                State::Complete(builder.finish()?)
            }
            // Caller-dependent or terminal states are handled by `poll`.
            other => other,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_store::ManifestStore;

    const ASSET: &[u8] = b"some asset bytes that get hashed in pieces";

    fn params(asset_len: Option<u64>) -> SignParams {
        SignParams {
            manifest_label: "urn:c2pa:test".to_string(),
            instance_id: "xmp:iid:test".to_string(),
            generator: GeneratorInfo::new("test"),
            data_hash_alg: "sha256".to_string(),
            cose_alg: -8,
            x5chain: vec![vec![1, 2, 3]],
            asset_len,
        }
    }

    /// Drive a session to completion with a fake signer, feeding `chunk`-sized
    /// pieces, and return the store bytes plus the bytes it asked to sign.
    fn run(chunk: usize) -> (Vec<u8>, Vec<u8>) {
        let mut s = SignSession::new(params(Some(ASSET.len() as u64))).unwrap();
        let mut fed = 0;
        let mut tbs_seen = Vec::new();
        loop {
            match s.poll().unwrap() {
                Action::NeedAssetData if fed < ASSET.len() => {
                    let end = (fed + chunk).min(ASSET.len());
                    s.write_asset(&ASSET[fed..end]).unwrap();
                    fed = end;
                }
                Action::NeedAssetData => s.end_asset().unwrap(),
                Action::NeedSignature(tbs) => {
                    tbs_seen = tbs.to_vec();
                    s.provide_signature(vec![0xAB; 64]).unwrap();
                }
                Action::Continue => {}
                Action::Complete => break,
            }
        }
        assert_eq!(s.progress().phase, Phase::Complete);
        (s.into_store_bytes().unwrap(), tbs_seen)
    }

    #[test]
    fn chunking_does_not_change_output() {
        let (a, tbs_a) = run(1);
        let (b, tbs_b) = run(7);
        let (c, tbs_c) = run(ASSET.len());
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(tbs_a, tbs_b);
        assert_eq!(tbs_a, tbs_c);

        let store = ManifestStore::parse(&a).unwrap();
        let manifest = store.active_manifest().unwrap();
        let dh_assertion = manifest.assertions().unwrap().next().unwrap();
        let dh = DataHash::from_cbor(dh_assertion.payload().unwrap().data).unwrap();
        assert_eq!(
            dh.hash,
            c2pa_claim::DataHash::from_reader("sha256", ASSET)
                .unwrap()
                .hash
        );
        let sign1 = CoseSign1::from_tagged_slice(manifest.signature_cose().unwrap()).unwrap();
        assert_eq!(sign1.signature, vec![0xAB; 64]);
        assert!(sign1.payload.is_none(), "C2PA requires a detached payload");
    }

    #[test]
    fn yields_between_internal_steps_and_reports_phases() {
        let mut s = SignSession::new(params(None)).unwrap();
        s.write_asset(ASSET).unwrap();
        assert_eq!(s.progress().asset_bytes_hashed, ASSET.len() as u64);
        s.end_asset().unwrap();

        let mut phases = vec![s.progress().phase];
        while s.poll().unwrap() == Action::Continue {
            phases.push(s.progress().phase);
        }
        assert_eq!(
            phases,
            [
                Phase::AddingAssertions,
                Phase::AddingAssertions,
                Phase::BuildingClaim,
                Phase::AwaitingSignature,
            ]
        );
    }

    #[test]
    fn out_of_order_calls_are_rejected_without_breaking_the_session() {
        let mut s = SignSession::new(params(None)).unwrap();
        assert_eq!(
            s.provide_signature(vec![]),
            Err(SignError::WrongPhase {
                called: "provide_signature",
                phase: Phase::HashingAsset
            })
        );
        s.write_asset(ASSET).unwrap();
        s.end_asset().unwrap();
        assert!(matches!(
            s.write_asset(b"late"),
            Err(SignError::WrongPhase { .. })
        ));
        assert_eq!(s.poll().unwrap(), Action::Continue);
    }

    #[test]
    fn asset_length_mismatch_is_fail_stop() {
        let mut s = SignSession::new(params(Some(999))).unwrap();
        s.write_asset(ASSET).unwrap();
        assert_eq!(
            s.end_asset(),
            Err(SignError::AssetLengthMismatch {
                expected: 999,
                actual: ASSET.len() as u64
            })
        );
        assert_eq!(s.progress().phase, Phase::Failed);
        assert_eq!(s.poll(), Err(SignError::Failed));
        assert_eq!(s.write_asset(ASSET), Err(SignError::Failed));
    }

    #[test]
    fn unknown_hash_algorithm_is_rejected_up_front() {
        let mut p = params(None);
        p.data_hash_alg = "md5".to_string();
        assert!(matches!(
            SignSession::new(p),
            Err(SignError::UnknownHashAlgorithm(_))
        ));
    }

    #[test]
    fn can_cancel_while_awaiting_signature() {
        let mut s = SignSession::new(params(None)).unwrap();
        s.end_asset().unwrap();
        while !matches!(s.poll().unwrap(), Action::NeedSignature(_)) {}
        assert!(matches!(
            s.into_store_bytes(),
            Err(SignError::WrongPhase {
                phase: Phase::AwaitingSignature,
                ..
            })
        ));
    }
}
