//! Complete an endorsement certificate chain from a file, and print what it reaches.
//!
//! This is the half that cannot be tested from a specification: point it at a real leaf certificate and
//! it walks the authority-information-access extensions to the vendor root, which is the step that fails
//! on real machines for reasons no document predicts — an Intel leaf carries no AIA at all, and its
//! intermediates arrive concatenated inside one blob.
//!
//!   cargo run --release --example chain -- leaf.der
fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: chain <certificate.der>");
            std::process::exit(2);
        }
    };
    match posea_prover::chip::selftest_chain(&path) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}
