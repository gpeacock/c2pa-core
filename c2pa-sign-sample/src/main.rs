//! Create a test-signed raw sidecar; see `c2pa-asset` for embedded manifests.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_claim::DataHash;
use c2pa_sign_sample::{Result, TestSigner};

fn run() -> Result<()> {
    let path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: c2pa-sign-sample <path-to-file>")?,
    );
    let binding = DataHash::from_reader("sha256", BufReader::new(File::open(&path)?))?;
    let signer = TestSigner::new()?;
    let bytes = signer.build_store(&binding, None)?;
    let sidecar = path.with_extension("c2pa");
    let ca = path.with_extension("ca.pem");
    std::fs::write(&sidecar, &bytes)?;
    std::fs::write(&ca, signer.ca_pem())?;
    println!("wrote {} ({} bytes)", sidecar.display(), bytes.len());
    println!(
        "wrote {} -- ephemeral test CA, not trusted by default",
        ca.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
