//! PoSEA prover — the TPM side, in Rust.
//!
//! The Python package beside this one is the VERIFIER's implementation: parsing, chain validation, the
//! per-device binding handle. This crate is the other half, the part that runs on the machine being
//! attested, and it exists because a verifier that nobody can produce a proof for is an unfinished idea.
//!
//! WHY A SECOND IMPLEMENTATION AT ALL. The prover has to run on whatever the owner already has —
//! typically Windows, frequently with no toolchain, no Python and no administrator rights — and it has
//! to talk to the chip directly. There is no TSS dependency and no tpm2-tools here: it is struct packing
//! and two platform transports, which is a smaller thing to audit than a stack, and it is the same
//! command bytes on both.
//!
//! Everything in it was driven against real silicon rather than a specification; `HARDWARE.md` records
//! what that silicon actually did, including the four places the endorsement certificate was NOT.
//!
//! ```text
//!   tpm      TPM 2.0 command encoding — templates, sessions, the commands an enrolment needs
//!   devtpm   Linux transport: /dev/tpmrm0, the kernel resource manager
//!   tbs      Windows transport: Tbsi_Context_Create / Tbsip_Submit_Command
//!   win      Windows certificate sources: the EKCertStore registry blob and the system stores
//!   chip     finding the endorsement certificate and assembling a chain that verifies
//!   http     fetching issuer certificates over AIA, without a TLS stack
//!   sha      SHA-256, because a hash should not pull in a dependency tree
//! ```

pub mod chip;
pub mod devtpm;
pub mod http;
pub mod sha;
// WINDOWS-ONLY, and gated so the crate still builds and links on Linux. Without the gate the crate
// compiles as an rlib and only fails when something finally links it — `unable to find library
// -lncrypt` from an example, long after "it builds" was believed.
#[cfg(windows)]
pub mod tbs;
pub mod tpm;
#[cfg(windows)]
pub mod win;

/// Fill `buf` with cryptographic randomness, straight from the OS generator on each platform.
///
/// ONE PLACE, BOTH PLATFORMS, NO DEPENDENCY — and no in-process seeding, because a predictable source
/// here would be a real weakness rather than a style question.
pub fn rand_bytes(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
        f.read_exact(buf).expect("read /dev/urandom");
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(h: *mut core::ffi::c_void, p: *mut u8, n: u32, f: u32) -> i32;
        }
        const USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        let rc = unsafe {
            BCryptGenRandom(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32,
                            USE_SYSTEM_PREFERRED_RNG)
        };
        assert!(rc == 0, "BCryptGenRandom failed: {rc:#x}");
    }
}
