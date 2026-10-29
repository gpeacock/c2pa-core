//! Container access and size-stable embedding through asset-io.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use asset_io::{C2paBox, C2paHash, HandlerRegistry, NullSink, Structure, Updates};
use c2pa_claim::{AssetBox, BoxHash, DataHash, HardBinding, HashRange};
use c2pa_store::ManifestStore;
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tempfile::NamedTempFile;

use crate::{Result, TestSigner};

/// The hash algorithm for new bindings.
const ALG: &str = "sha256";

pub fn open(path: &Path) -> Result<(File, Structure)> {
    let mut file = File::open(path)?;
    let registry = HandlerRegistry::builtin();
    // Text formats and raw sidecars do not all implement content detection.
    let extension = path.extension().and_then(|extension| extension.to_str());
    let structure = match extension.filter(|extension| registry.handler(extension).is_some()) {
        Some(extension) => registry.parse(extension, &mut file),
        None => registry.parse_detect(&mut file),
    }
    .map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok((file, structure))
}

pub fn read_store(structure: &Structure, file: &mut File) -> Result<Vec<u8>> {
    let bytes = structure
        .c2pa_store(file)?
        .ok_or("no C2PA manifest store")?;
    ManifestStore::parse(&bytes)?;
    Ok(bytes)
}

/// The C2PA data-hash exclusions of the embedded manifest store, as the container
/// defines them. Containers without data-hash embedding rules are reported here.
pub fn exclusions(structure: &Structure, file: &mut File) -> Result<Vec<HashRange>> {
    let Some(item) = structure.c2pa_item(file)? else {
        return Ok(Vec::new());
    };
    let ranges = structure.c2pa_data_hash_exclusions(item).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            match e {
                asset_io::Error::UnsupportedFeature(_) => format!(
                    "{}: embedded signing/data-hash validation is not implemented ({e}); \
                     dump is supported",
                    structure.container_id()
                )
                .into(),
                e => e.into(),
            }
        },
    )?;
    Ok(ranges
        .into_iter()
        .map(|range| HashRange {
            start: range.offset(),
            length: range.len(),
        })
        .collect())
}

/// Hash every byte outside validated, ordered exclusion ranges, with bounded memory.
pub fn hash_asset(file: &mut File, total: u64, alg: &str, ranges: &[HashRange]) -> Result<Vec<u8>> {
    let mut hasher: Box<dyn DynDigest> = match alg {
        "sha256" => Box::new(Sha256::new()),
        "sha384" => Box::new(Sha384::new()),
        "sha512" => Box::new(Sha512::new()),
        _ => return Err(format!("unsupported asset hash algorithm: {alg}").into()),
    };
    let mut cursor = 0;
    let mut buffer = [0u8; 64 * 1024];
    for range in ranges.iter().cloned().chain(std::iter::once(HashRange {
        start: total,
        length: 0,
    })) {
        let end = range
            .start
            .checked_add(range.length)
            .ok_or("exclusion overflow")?;
        if range.start < cursor || end > total {
            return Err("asset exclusions overlap, are unordered, or exceed the file".into());
        }
        file.seek(SeekFrom::Start(cursor))?;
        let mut remaining = range.start - cursor;
        while remaining > 0 {
            let len = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..len])?;
            hasher.update(&buffer[..len]);
            remaining -= len as u64;
        }
        cursor = end;
    }
    Ok(hasher.finalize().into_vec())
}

pub fn ca_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".ca.pem");
    PathBuf::from(path)
}

fn temporary_for(path: &Path) -> Result<NamedTempFile> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(NamedTempFile::new_in(parent)?)
}

/// Which hard binding [`sign`] uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingChoice {
    /// The binding asset-io recommends for the container: a box hash where the
    /// container has meaningful boxes, else a data hash.
    #[default]
    Recommended,
    /// A data hash, where the container allows one.
    Data,
}

/// A hard binding being embedded: placeholder first, then filled in.
enum Binding {
    Data {
        binding: DataHash,
        exclusions: usize,
    },
    Boxes(BoxHash),
}

impl Binding {
    /// A placeholder sized for the planned output.
    fn placeholder(kind: C2paHash, planned: &Structure, source: &mut File) -> Result<Self> {
        Ok(match kind {
            C2paHash::Data => {
                let exclusions = exclusions(planned, source)?.len();
                let binding = DataHash::placeholder(ALG, exclusions).ok_or("unsupported hash")?;
                Self::Data {
                    binding,
                    exclusions,
                }
            }
            C2paHash::Box => {
                let boxes = planned.c2pa_boxes(source)?;
                let binding = BoxHash::placeholder(ALG, boxes.iter().map(|b| b.name.as_ref()))
                    .ok_or("unsupported hash")?;
                Self::Boxes(binding)
            }
            kind => return Err(format!("{kind:?} hard bindings are not implemented").into()),
        })
    }

    fn assertion(&self) -> &dyn HardBinding {
        match self {
            Self::Data { binding, .. } => binding,
            Self::Boxes(binding) => binding,
        }
    }

    /// Fill in the real values from the written asset; the binding keeps its size.
    fn fill(&mut self, written: &Structure, file: &mut File) -> Result<()> {
        match self {
            Self::Data {
                binding,
                exclusions: count,
            } => {
                let ranges = exclusions(written, file)?;
                if ranges.len() != *count {
                    return Err("exclusion count changed with the reserved store size".into());
                }
                let hash = hash_asset(file, written.total_size(), ALG, &ranges)?;
                binding.update(ranges, hash)?;
            }
            Self::Boxes(binding) => {
                let boxes = written.c2pa_boxes(file)?;
                binding.update(file, &asset_boxes(&boxes), Some(ALG))?;
            }
        }
        Ok(())
    }
}

/// asset-io's boxes, with the metadata they hold, as a box hash takes them.
pub fn asset_boxes(boxes: &[C2paBox]) -> Vec<AssetBox<'_>> {
    let range = |r: asset_io::ByteRange| HashRange {
        start: r.offset(),
        length: r.len(),
    };
    boxes
        .iter()
        .map(|b| AssetBox {
            name: &b.name,
            range: range(b.range),
            metadata: b.metadata.iter().copied().map(range).collect(),
        })
        .collect()
}

/// Preserve existing manifests and append a freshly signed test manifest.
/// Publish only after re-reading and verifying the final output.
pub fn sign(input: &Path, output: &Path, choice: BindingChoice) -> Result<()> {
    let ca = ca_path(output);
    if output.try_exists()? || ca.try_exists()? {
        return Err("output or CA file already exists; choose a new output path".into());
    }
    let (mut source, structure) = open(input)?;
    // asset-io says which hard binding the container calls for; the caller may
    // choose a data hash instead of a box hash.
    let kind = match (structure.c2pa_hash(), choice) {
        (Some(C2paHash::Box), BindingChoice::Data) => C2paHash::Data,
        (Some(kind @ (C2paHash::Box | C2paHash::Data)), _) => kind,
        (kind, _) => {
            return Err(format!(
                "{}: embedded signing with a {kind:?} hard binding is not implemented; \
                 dump is supported",
                structure.container_id()
            )
            .into());
        }
    };
    let previous = if structure.c2pa_item(&mut source)?.is_some() {
        Some(read_store(&structure, &mut source)?)
    } else {
        None
    };
    let signer = TestSigner::new()?;
    // Plan the placement once, so the binding can size a placeholder that its
    // real values fit into: a data hash needs the number of exclusions, a box
    // hash the names of the boxes.
    let probe = DataHash::placeholder(ALG, 0).ok_or("unsupported hash algorithm")?;
    let probe = signer.build_store(&probe, previous.as_deref())?;
    let planned = structure.plan(&mut source, &Updates::new().set_jumbf(probe))?;
    let mut binding = Binding::placeholder(kind, &planned, &mut source)?;
    let mut manifest = signer.placeholder(binding.assertion(), previous.as_deref())?;
    let mut temporary = temporary_for(output)?;
    structure.write(
        &mut source,
        temporary.as_file_mut(),
        &Updates::new().set_jumbf(manifest.store.clone()),
        &mut NullSink,
    )?;
    let written = structure.handler().clone().parse(temporary.as_file_mut())?;
    // The binding fills itself in at its placeholder's size; the store and claim
    // are then updated in place around it.
    binding.fill(&written, temporary.as_file_mut())?;
    signer.complete(&mut manifest, binding.assertion())?;
    let item = written
        .c2pa_item(temporary.as_file_mut())?
        .ok_or("written store is missing")?;
    written.patch_exact(temporary.as_file_mut(), item, &manifest.store)?;

    let reparsed = written.handler().clone().parse(temporary.as_file_mut())?;
    let final_store = read_store(&reparsed, temporary.as_file_mut())?;
    crate::validation::validate(&final_store, temporary.as_file_mut(), &reparsed, true)?;
    temporary.as_file_mut().sync_all()?;

    let mut ca_temp = temporary_for(&ca)?;
    ca_temp.write_all(signer.ca_pem().as_bytes())?;
    ca_temp.as_file_mut().sync_all()?;
    ca_temp.persist_noclobber(&ca)?;
    if let Err(error) = temporary.persist_noclobber(output) {
        std::fs::remove_file(&ca).map_err(|cleanup| {
            format!(
                "publish asset failed: {error}; removing newly created CA also failed: {cleanup}"
            )
        })?;
        return Err(error.into());
    }
    Ok(())
}
