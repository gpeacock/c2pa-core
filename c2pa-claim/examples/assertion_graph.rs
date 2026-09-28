//! Prototype: build a manifest's assertions as a dependency graph instead of
//! a flat, caller-ordered list.
//!
//! Usage: `cargo run --example assertion_graph`
//!
//! # The problem
//!
//! An assertion's `HashedUri` can only be computed from another assertion's
//! *finished* bytes, but some assertions embed hashed-URI references to other
//! assertions (an ingredient referencing its thumbnail, say). So there is a
//! real dependency order to respect, and an assertion may depend on zero or
//! more others.
//!
//! # The trick
//!
//! [`AssertionGraph::declare`] only accepts [`Handle`]s that were already
//! returned by an earlier `declare` call. That makes a forward reference
//! (and therefore a cycle) a compile-time impossibility: by the time a node
//! can name a dependency, that dependency's node already exists earlier in
//! `self.nodes`. So declaration order is *always* a valid topological order
//! for free — no sort, no cycle detection, no `Result` on `declare`.
//! [`AssertionGraph::resolve`] just walks `0..n` in order, building each
//! node's real bytes and its `HashedUri` (which happens to require no
//! machinery for it beyond a `Vec`), then plugs that into a real
//! [`c2pa_claim::Claim`] and a real `c2pa_store::BoxWriter` stream, and
//! finally re-parses the result with `ManifestStore::parse` and verifies
//! every hashed URI the normal way, to prove the model produces a
//! self-consistent store.

use std::process::ExitCode;

use c2pa_claim::{Claim, GeneratorInfo, HashedUri};
use c2pa_store::format::BOX_CBOR;
use c2pa_store::{uuids, BoxWriter, ManifestStore};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MANIFEST_LABEL: &str = "urn:c2pa:demo-manifest";
const ALG: &str = "sha256";

/// An opaque reference to a not-yet-built assertion. Only ever produced by
/// [`AssertionGraph::declare`], which is what makes forward references (and
/// hence cycles) impossible.
#[derive(Clone, Copy, Debug)]
struct Handle(usize);

/// Given the resolved `HashedUri`s of a node's dependencies (same order as
/// declared), produce that assertion's CBOR body.
type Build = Box<dyn FnOnce(&[HashedUri]) -> Vec<u8>>;

/// One assertion, declared before it is built.
struct Node {
    label: String,
    depends_on: Vec<Handle>,
    build: Build,
}

#[derive(Default)]
struct AssertionGraph {
    nodes: Vec<Node>,
}

impl AssertionGraph {
    /// Declare an assertion. `depends_on` may be empty (a leaf assertion) or
    /// name any number of earlier handles.
    fn declare(
        &mut self,
        label: impl Into<String>,
        depends_on: &[Handle],
        build: impl FnOnce(&[HashedUri]) -> Vec<u8> + 'static,
    ) -> Handle {
        let handle = Handle(self.nodes.len());
        self.nodes.push(Node {
            label: label.into(),
            depends_on: depends_on.to_vec(),
            build: Box::new(build),
        });
        handle
    }

    /// Build every node in declaration order (already a valid topological
    /// order, see module docs). Returns each node's finished, salted JUMBF
    /// assertion box, and its resolved `HashedUri`, both indexed by
    /// `Handle::0`.
    fn resolve(self) -> (Vec<Vec<u8>>, Vec<HashedUri>) {
        let mut resolved: Vec<HashedUri> = Vec::with_capacity(self.nodes.len());
        let mut boxes: Vec<Vec<u8>> = Vec::with_capacity(self.nodes.len());

        for (i, node) in self.nodes.into_iter().enumerate() {
            // Every dependency handle is `< i` by construction, so it's
            // already resolved.
            let deps: Vec<HashedUri> = node
                .depends_on
                .iter()
                .map(|h| resolved[h.0].clone())
                .collect();
            let body = (node.build)(&deps);

            // A real builder would draw a random salt per assertion; a fixed,
            // index-derived one is enough to demonstrate the shape.
            let salt = [i as u8; 16];
            let mut w = BoxWriter::new(Vec::<u8>::new());
            w.start_superbox(&uuids::CBOR, &node.label, Some(&salt))
                .unwrap();
            w.content_box(&BOX_CBOR, &body).unwrap();
            w.end_box().unwrap();
            let box_bytes = w.finish().unwrap();

            // The hashed span is the box payload: everything after the
            // 8-byte `jumb` header (matches c2pa-claim's verification side).
            let hash = Sha256::digest(&box_bytes[8..]).to_vec();
            let url = format!("self#jumbf=c2pa.assertions/{}", node.label);
            resolved.push(HashedUri::new(url, Some(ALG.to_string()), &hash));
            boxes.push(box_bytes);
        }

        (boxes, resolved)
    }
}

/// Build a standalone content box's bytes (header + data), for use as a
/// `superbox` child.
fn content_box(tbox: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut w = BoxWriter::new(Vec::<u8>::new());
    w.content_box(tbox, data).unwrap();
    w.finish().unwrap()
}

/// Wrap a superbox around already-serialized child boxes.
fn superbox(uuid: &[u8; 16], label: &str, children: &[Vec<u8>]) -> Vec<u8> {
    let mut w = BoxWriter::new(Vec::<u8>::new());
    w.start_superbox(uuid, label, None).unwrap();
    for child in children {
        w.write(child).unwrap();
    }
    w.end_box().unwrap();
    w.finish().unwrap()
}

fn main() -> ExitCode {
    let mut graph = AssertionGraph::default();

    // Two independent leaves: zero dependencies each.
    let icon = graph.declare("com.example.icon", &[], |_deps| {
        c2pa_cbor::to_vec_deterministic(&"<icon bytes go here>").unwrap()
    });
    let thumbnail = graph.declare("c2pa.thumbnail.ingredient", &[], |_deps| {
        c2pa_cbor::to_vec_deterministic(&"<thumbnail bytes go here>").unwrap()
    });

    // One dependency: embeds the thumbnail's *already-resolved* HashedUri in
    // its own body -- this only works because thumbnail was built first.
    #[derive(Serialize)]
    struct ToyIngredient<'a> {
        thumbnail: &'a HashedUri,
    }
    let ingredient = graph.declare("c2pa.ingredient.v3", &[thumbnail], |deps| {
        c2pa_cbor::to_vec_deterministic(&ToyIngredient {
            thumbnail: &deps[0],
        })
        .unwrap()
    });

    // Two dependencies, proving "zero or more": this one needs both the
    // ingredient and the icon resolved before it can be built.
    #[derive(Serialize)]
    struct ToyActions<'a> {
        ingredient: &'a HashedUri,
        icon: &'a HashedUri,
    }
    let actions = graph.declare("c2pa.actions.v2", &[ingredient, icon], |deps| {
        c2pa_cbor::to_vec_deterministic(&ToyActions {
            ingredient: &deps[0],
            icon: &deps[1],
        })
        .unwrap()
    });

    let (assertion_boxes, hrefs) = graph.resolve();

    let mut generator_info = GeneratorInfo::new("assertion-graph-demo");
    generator_info.icon = Some(hrefs[icon.0].clone());

    let mut claim = Claim::new(MANIFEST_LABEL, "xmp:iid:demo-instance", generator_info);
    claim.alg = Some(ALG.to_string());
    for h in [thumbnail, icon, ingredient, actions] {
        claim.add_created_assertion(hrefs[h.0].clone());
    }
    let claim_cbor = claim.to_cbor().unwrap();

    let assertions_box = superbox(&uuids::ASSERTION_STORE, "c2pa.assertions", &assertion_boxes);
    let claim_box = superbox(
        &uuids::CLAIM,
        "c2pa.claim.v2",
        &[content_box(&BOX_CBOR, &claim_cbor)],
    );
    let manifest_box = superbox(
        &uuids::MANIFEST,
        MANIFEST_LABEL,
        &[claim_box, assertions_box],
    );
    let store_bytes = superbox(&uuids::MANIFEST_STORE, "c2pa", &[manifest_box]);

    println!("built store: {} bytes", store_bytes.len());

    // Re-parse from scratch and verify every hashed URI the normal way, to
    // prove the graph-built store is self-consistent.
    let store = ManifestStore::parse(&store_bytes).unwrap();
    let manifest = store.active_manifest().unwrap();
    let claim = Claim::from_cbor(manifest.claim_cbor().unwrap()).unwrap();

    let mut failures = 0;
    for href in &claim.created_assertions {
        match href.verify(&store, &manifest, claim.alg.as_deref()) {
            Ok(()) => println!("ok   {}", href.url()),
            Err(e) => {
                println!("FAIL {} -> {e:?}", href.url());
                failures += 1;
            }
        }
    }
    if let Some(icon_href) = &claim.claim_generator_info.icon {
        match icon_href.verify(&store, &manifest, claim.alg.as_deref()) {
            Ok(()) => println!("ok   [generator icon] {}", icon_href.url()),
            Err(e) => {
                println!("FAIL [generator icon] {} -> {e:?}", icon_href.url());
                failures += 1;
            }
        }
    }

    if failures == 0 {
        println!("\nall hashed URIs verified -- graph-resolved order produced a valid store");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
