//! A sans-I/O, caller-driven signing pipeline: no callbacks, no threads, no
//! async runtime.
//!
//! [`SignSession`] drives a sequential async workflow, using compiler-generated
//! state rather than a hand-written state machine. The caller repeatedly calls
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
//! Workflow errors are fail-stop; out-of-order client calls are non-fatal.
//! Asset chunks are borrowed and hashed directly before
//! [`write_asset`](SignSession::write_asset) returns, with no chunk allocation
//! or copy. The client may immediately reuse its buffer and controls the chunk
//! size. Only the hasher state crosses the suspension boundary at end-of-input.
//! Checkpoints explicitly suspend even when no external input is needed.

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;

use crate::workflow::{Context, Workflow};
use c2pa_cbor::Value;
use c2pa_cbor::cose::{CoseSign1Builder, HeaderBuilder};
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

enum Request {
    AssetData(Box<DataHasher>),
    Signature(Vec<u8>),
}

enum Response {
    AssetData(Box<DataHasher>),
    Signature(Vec<u8>),
}

fn hashed_uri(a: AssertionHash) -> HashedUri {
    HashedUri::new(a.url, Some(a.alg.to_string()), &a.hash)
}

/// See the [module docs](self).
pub struct SignSession {
    workflow: Option<Workflow<Request, Response, Result<Vec<u8>, SignError>>>,
    progress: Rc<Cell<Progress>>,
    output: Option<Vec<u8>>,
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
            .map_err(|error| SignError::UnknownHashAlgorithm(error.0))?;
        let progress = Rc::new(Cell::new(Progress {
            phase: Phase::HashingAsset,
            asset_bytes_hashed: 0,
            asset_len: params.asset_len,
        }));
        let workflow_progress = Rc::clone(&progress);
        let workflow =
            Workflow::new(move |cx| sign_workflow(cx, params, hasher, workflow_progress));
        let mut session = Self {
            workflow: Some(workflow),
            progress,
            output: None,
        };
        session.advance()?;
        Ok(session)
    }

    pub fn progress(&self) -> Progress {
        self.progress.get()
    }

    /// Advance by at most one bounded unit of work, or report what the
    /// caller must supply next. Never blocks.
    pub fn poll(&mut self) -> Result<Action<'_>, SignError> {
        if self.progress().phase == Phase::Complete {
            return Ok(Action::Complete);
        }
        self.advance()?;
        if self.progress().phase == Phase::Complete {
            return Ok(Action::Complete);
        }
        match self.workflow.as_ref().and_then(Workflow::request) {
            Some(Request::AssetData(_)) => Ok(Action::NeedAssetData),
            Some(Request::Signature(tbs)) => Ok(Action::NeedSignature(tbs)),
            None => Ok(Action::Continue),
        }
    }

    /// Hash the next chunk of the asset. Work is proportional to
    /// `chunk.len()`, so the caller bounds each step by its chunk size.
    /// Does not allocate or copy the chunk, and retains no reference to it.
    pub fn write_asset(&mut self, chunk: &[u8]) -> Result<(), SignError> {
        let Some(Request::AssetData(hasher)) =
            self.workflow.as_mut().and_then(Workflow::request_mut)
        else {
            return Err(self.wrong_phase("write_asset"));
        };
        hasher.update(chunk);
        self.progress.set(Progress {
            asset_bytes_hashed: hasher.bytes_hashed(),
            ..self.progress.get()
        });
        Ok(())
    }

    /// Signal end of asset input.
    pub fn end_asset(&mut self) -> Result<(), SignError> {
        if !matches!(
            self.workflow.as_ref().and_then(Workflow::request),
            Some(Request::AssetData(_))
        ) {
            return Err(self.wrong_phase("end_asset"));
        }
        let result = self.workflow.as_mut().unwrap().respond_with(|request| {
            let Request::AssetData(hasher) = request else {
                unreachable!("end_asset checked the request kind");
            };
            Response::AssetData(hasher)
        });
        if result.is_err() {
            return Err(self.wrong_phase("end_asset"));
        }
        self.advance()
    }

    /// Supply the signature over the bytes from [`Action::NeedSignature`].
    pub fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), SignError> {
        if !matches!(
            self.workflow.as_ref().and_then(Workflow::request),
            Some(Request::Signature(_))
        ) {
            return Err(self.wrong_phase("provide_signature"));
        }
        self.respond(Response::Signature(signature), "provide_signature")
    }

    /// Take the finished manifest store bytes.
    pub fn into_store_bytes(self) -> Result<Vec<u8>, SignError> {
        match self.output {
            Some(bytes) => Ok(bytes),
            None => Err(SignError::WrongPhase {
                called: "into_store_bytes",
                phase: self.progress.get().phase,
            }),
        }
    }

    fn wrong_phase(&self, called: &'static str) -> SignError {
        match self.progress().phase {
            Phase::Failed => SignError::Failed,
            _ => SignError::WrongPhase {
                called,
                phase: self.progress().phase,
            },
        }
    }

    fn respond(&mut self, response: Response, called: &'static str) -> Result<(), SignError> {
        let Some(workflow) = &mut self.workflow else {
            return Err(self.wrong_phase(called));
        };
        if workflow.respond(response).is_err() {
            return Err(self.wrong_phase(called));
        }
        self.advance()
    }

    fn advance(&mut self) -> Result<(), SignError> {
        let Some(workflow) = &mut self.workflow else {
            return Err(SignError::Failed);
        };
        workflow.step();
        if let Some(result) = workflow.take_output() {
            self.workflow = None;
            match result {
                Ok(bytes) => {
                    self.output = Some(bytes);
                    set_phase(&self.progress, Phase::Complete);
                }
                Err(error) => {
                    set_phase(&self.progress, Phase::Failed);
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

fn set_phase(progress: &Cell<Progress>, phase: Phase) {
    progress.set(Progress {
        phase,
        ..progress.get()
    });
}

async fn sign_workflow(
    cx: Context<Request, Response>,
    params: SignParams,
    hasher: DataHasher,
    progress: Rc<Cell<Progress>>,
) -> Result<Vec<u8>, SignError> {
    let Response::AssetData(hasher) = cx.request(Request::AssetData(Box::new(hasher))).await else {
        unreachable!("SignSession only accepts asset responses for asset requests");
    };
    if let Some(expected) = params.asset_len
        && expected != hasher.bytes_hashed()
    {
        return Err(SignError::AssetLengthMismatch {
            expected,
            actual: hasher.bytes_hashed(),
        });
    }

    let data_hash = hasher.finish();
    set_phase(&progress, Phase::AddingAssertions);
    cx.checkpoint().await;
    let mut builder = Builder::new(Vec::new(), &params.manifest_label)?;
    let cbor = data_hash.to_cbor().map_err(encode_err)?;
    let href = builder.add_cbor_assertion(DataHash::LABEL, None, &cbor)?;
    let mut hrefs = vec![hashed_uri(href)];
    cx.checkpoint().await;

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
    set_phase(&progress, Phase::BuildingClaim);
    cx.checkpoint().await;

    let mut claim = Claim::new(&params.manifest_label, params.instance_id, params.generator);
    claim.alg = Some(ASSERTION_HASH_ALG.to_string());
    for href in hrefs {
        claim.add_created_assertion(href);
    }
    let claim_cbor = claim.to_cbor().map_err(encode_err)?;
    builder.add_claim("c2pa.claim.v2", &claim_cbor)?;
    let x5chain = Value::Array(params.x5chain.into_iter().map(Value::Bytes).collect());
    let protected = HeaderBuilder::new()
        .algorithm(params.cose_alg)
        .value(COSE_HEADER_X5CHAIN, x5chain)
        .build();
    let mut sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(claim_cbor)
        .build();
    let tbs = sign1.tbs_data(&[]).map_err(encode_err)?;
    set_phase(&progress, Phase::AwaitingSignature);
    cx.checkpoint().await;

    let Response::Signature(signature) = cx.request(Request::Signature(tbs)).await else {
        unreachable!("SignSession only accepts signatures for signature requests");
    };
    sign1.signature = signature;
    sign1.payload = None;
    let signature_cbor = sign1.to_tagged_vec().map_err(encode_err)?;
    set_phase(&progress, Phase::Finalizing);
    cx.checkpoint().await;

    builder.add_signature(&signature_cbor)?;
    Ok(builder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_cbor::cose::CoseSign1;
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
        let mut sign1 = CoseSign1::from_tagged_slice(manifest.signature_cose().unwrap()).unwrap();
        assert_eq!(sign1.signature, vec![0xAB; 64]);
        assert!(sign1.payload.is_none(), "C2PA requires a detached payload");
        sign1.payload = Some(manifest.claim_cbor().unwrap().to_vec());
        assert_eq!(sign1.tbs_data(&[]).unwrap(), tbs_a);
    }

    #[test]
    fn borrowed_stream_buffer_can_be_overwritten_and_dropped_between_steps() {
        let mut s = SignSession::new(params(Some(ASSET.len() as u64))).unwrap();
        {
            let mut buffer = [0u8; 7];
            for chunk in ASSET.chunks(buffer.len()) {
                buffer[..chunk.len()].copy_from_slice(chunk);
                s.write_asset(&buffer[..chunk.len()]).unwrap();
                buffer.fill(0xFF);
                assert_eq!(s.poll().unwrap(), Action::NeedAssetData);
            }
            s.write_asset(&[]).unwrap();
        }
        assert_eq!(s.progress().asset_bytes_hashed, ASSET.len() as u64);
        s.end_asset().unwrap();
        loop {
            match s.poll().unwrap() {
                Action::Continue => {}
                Action::NeedSignature(_) => s.provide_signature(vec![0xAB; 64]).unwrap(),
                Action::Complete => break,
                other => panic!("unexpected action: {other:?}"),
            }
        }
        assert_eq!(s.into_store_bytes().unwrap(), run(7).0);
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

    #[test]
    fn requests_can_wait_and_completion_is_repeatable() {
        let mut s = SignSession::new(params(Some(0))).unwrap();
        for _ in 0..3 {
            assert_eq!(s.poll().unwrap(), Action::NeedAssetData);
            assert_eq!(s.progress().asset_bytes_hashed, 0);
        }
        s.end_asset().unwrap();
        let tbs = loop {
            match s.poll().unwrap() {
                Action::Continue => {}
                Action::NeedSignature(tbs) => break tbs.to_vec(),
                other => panic!("unexpected action: {other:?}"),
            }
        };
        for _ in 0..3 {
            assert_eq!(s.poll().unwrap(), Action::NeedSignature(&tbs));
        }
        assert!(matches!(s.end_asset(), Err(SignError::WrongPhase { .. })));
        s.provide_signature(vec![0xAB; 64]).unwrap();
        assert_eq!(s.progress().phase, Phase::Finalizing);
        assert!(matches!(
            s.provide_signature(vec![]),
            Err(SignError::WrongPhase { .. })
        ));
        assert_eq!(s.poll().unwrap(), Action::Complete);
        assert_eq!(s.progress().phase, Phase::Complete);
        assert_eq!(s.poll().unwrap(), Action::Complete);
        assert!(ManifestStore::parse(&s.into_store_bytes().unwrap()).is_ok());
    }
}
