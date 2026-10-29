use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_sign_sample::{Result, asset, dump, validation};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    about = "Experimental c2pa-core + asset-io CLI (not a trust verifier)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Display an expanded JUMBF/CBOR/JSON tree from a supported asset or sidecar.
    Dump { input: PathBuf },
    /// Check assertion hashes, Ed25519 signatures, and the active hard binding
    /// (data hash or box hash).
    /// Does NOT evaluate certificate trust, revocation, timestamps or ingredients.
    Validate {
        input: PathBuf,
        /// Original asset when INPUT is a raw .c2pa sidecar.
        #[arg(long)]
        asset: Option<PathBuf>,
    },
    /// Append an ephemeral test-signed manifest (JPEG, PNG, RIFF, SVG).
    /// Writes a new asset and OUTPUT.ca.pem; neither may already exist.
    /// Uses a box hash where the container has meaningful boxes, else a data hash.
    Sign {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Use a data hash even where a box hash is recommended.
        #[arg(long)]
        data_hash: bool,
    },
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Dump { input } => {
            let (mut file, structure) = asset::open(&input)?;
            let store = asset::read_store(&structure, &mut file)?;
            dump::dump(&mut std::io::stdout().lock(), &store)?;
        }
        Command::Validate {
            input,
            asset: original,
        } => {
            eprintln!(
                "Scope: integrity only; certificate trust, revocation, timestamps and ingredients NOT evaluated."
            );
            let (mut file, structure) = asset::open(&input)?;
            let store = asset::read_store(&structure, &mut file)?;
            let report = if structure.container_id() == "c2pa" {
                let original =
                    original.ok_or("raw .c2pa validation requires --asset <original-file>")?;
                let (mut file, structure) = asset::open(&original)?;
                validation::validate(&store, &mut file, &structure, false)?
            } else {
                if original.is_some() {
                    return Err("--asset is only supported with a raw .c2pa input".into());
                }
                validation::validate(&store, &mut file, &structure, true)?
            };
            println!(
                "integrity verified: {} manifest(s), {} assertion hash(es), {} Ed25519 signature(s), active {} binding",
                report.manifests, report.assertions, report.signatures, report.binding,
            );
            if report.additional_exclusions {
                println!(
                    "note: the binding excludes asset metadata or boxes besides the C2PA store \
                     (assertion.boxesHash.additionalExclusionsPresent)"
                );
            }
        }
        Command::Sign {
            input,
            output,
            data_hash,
        } => {
            eprintln!("WARNING: ephemeral test credentials; output is NOT trusted by default.");
            let choice = if data_hash {
                asset::BindingChoice::Data
            } else {
                asset::BindingChoice::Recommended
            };
            asset::sign(&input, &output, choice)?;
            println!("wrote {}", output.display());
            println!("test CA: {}", asset::ca_path(&output).display());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
