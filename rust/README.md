# posea-prover — the TPM side, in Rust

The Python package in `../posea` is the **verifier's** implementation. This crate is the other half: the
part that runs on the machine being attested. A verifier nobody can produce a proof for is an unfinished
idea, and the prover is where the surprises live.

```bash
cargo build --release
cargo run --release --example chain -- some-ek-leaf.der     # complete a chain, print what it reaches
```

Cross-compiling for Windows, which is where most of these machines are:

```bash
cargo install cargo-xwin --locked
rustup target add x86_64-pc-windows-msvc
RUSTFLAGS="-C target-feature=+crt-static" cargo xwin build --release --target x86_64-pc-windows-msvc
```

Use the **MSVC** target rather than `x86_64-pc-windows-gnu`. Both are Rust — the triple selects the
linker and C runtime, not the language — but almost nothing legitimate on Windows ships MinGW-linked
binaries while malware cross-compiled from Linux routinely does, and Defender flagged the MinGW build on
a real user's machine. `+crt-static` also removes the VC++ redistributable dependency. None of this is a
substitute for Authenticode signing, which is the only thing that reliably clears SmartScreen.

## Why a second implementation exists

The prover runs on whatever the owner already has: usually Windows, often with no toolchain, no Python
and no administrator rights, and it has to talk to the chip directly. There is no TSS dependency and no
`tpm2-tools` here — it is struct packing plus two platform transports, which is a smaller thing to audit
than a stack, and the command bytes are identical on both.

| module | what it is |
|---|---|
| `tpm` | TPM 2.0 command encoding: templates, policy sessions, the commands an enrolment needs |
| `devtpm` | Linux transport — `/dev/tpmrm0`, the kernel resource manager |
| `tbs` | Windows transport — `Tbsi_Context_Create` / `Tbsip_Submit_Command` |
| `win` | Windows certificate sources: the `EKCertStore` registry blob and the system stores |
| `chip` | finding the endorsement certificate, and assembling a chain that actually verifies |
| `http` | fetching issuer certificates over AIA, without a TLS stack |
| `sha` | SHA-256, because a hash should not pull in a dependency tree |

## What the hardware actually does

Every claim here was measured rather than read from a specification; `../HARDWARE.md` has the detail and
the reproduction steps. The parts that cost the most time:

- **The endorsement certificate is often not in NV.** On an AMD fTPM both standard NV indices and all
  four platform-crypto-provider properties were empty; the certificate existed only as a Windows
  *serialized certificate* in the registry, which is a run of property records rather than a certificate.
- **A certificate store returns a set, not a chain.** Intel's ODCA delivers the ROM, Kernel and PTT
  intermediates **concatenated in one blob**, and an X.509 tool shows only the first without comment. A
  machine was refused as uncertified while the issuer of its leaf sat inside the bytes it had sent.
- **AIA points upward only.** An Intel CSME leaf carries no AIA extension at all, so a walk anchored on
  the leaf fetches nothing while the certificate above it points the whole rest of the way — and a
  missing link *below* you cannot be found by following pointers at all.
- **Intel publishes over `https`, AMD over `http`.** A fetcher that looks for one scheme silently never
  completes the other vendor's chain.
- **A CRL is also a DER `SEQUENCE`**, published beside the certificate it revokes, so "looks like DER"
  splices a revocation list into the chain and breaks it.
- **`TPM2_Create` under the endorsement key is refused** (`TPM_RC_HANDLE`) on an AMD fTPM, which
  forecloses on hardware a design that is independently unsound in theory.
- **`TPM2_ActivateCredential` against an `adminWithPolicy` EK costs nothing**: zero dictionary-attack
  attempts across four rounds, lockout counter unchanged at 0 of 32.

The Windows modules are `#[cfg(windows)]`, so the crate builds and **links** on Linux — without the gate
it compiles as an rlib and only fails when something finally links it.
