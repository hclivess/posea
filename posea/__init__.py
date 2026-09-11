"""PoSEA - Proof of Secure Element Attestation.

Sybil resistance priced in devices rather than in per-identity rules. See SPEC.md.

The floor is the price of one more device, and that is a real floor rather than a claim of scarcity:
a farm CAN buy a thousand phones, and buying them is exactly the cost this imposes. What it removes
is the free identity — the one a script mints — not the funded adversary.

Two halves, for two situations.

`_parse` is for devices whose PLATFORM already produces an attestation: parsing, validity spans,
and the per-device binding handle that makes "one device, one identity" enforceable. Extracted
from the NADO deployment (ops/device_attest.py), where chain signature verification runs in a
native kernel.

`tpm` and `enrolment` are for the machines where the platform produces NOTHING — a healthy TPM
whose vendor CA answers 404, or a Linux box where no attestation service has ever existed. They
prove a key lives in a vendor-certified chip with no certificate authority anywhere in the design,
using a commit-reveal whose security is carried by publication ORDER rather than by a signature.
See SPEC.md section 9.
"""

from ._parse import (
    cbor_decode,
    parse_auth_data,
    parse_attestation,
    cert_validity,
    device_binding_key,
)
from .tpm import (
    aik_name,
    credential_commitment,
    make_credential,
    pub_area_rsa,
    pub_area_spki,
    validate_aik_pub_area,
    verify_certify,
    verify_credential_reveal,
)
from . import enrolment
# PLATFORM LAYER. Import-safe on every OS: tpm_windows constructs nothing at import time, so a Linux
# verifier can import the package without ctypes.WinDLL, and a Windows prover gets TBS plus the registry
# EKCertStore reader that is the ONLY place an AMD fTPM's endorsement certificate was found (HARDWARE.md).
from . import tpm_windows

__all__ = [
    # platform attestation
    "cbor_decode",
    "parse_auth_data",
    "parse_attestation",
    "cert_validity",
    "device_binding_key",
    # CA-free TPM enrolment
    "aik_name",
    "credential_commitment",
    "make_credential",
    "pub_area_rsa",
    "pub_area_spki",
    "validate_aik_pub_area",
    "verify_certify",
    "verify_credential_reveal",
    "enrolment",
    "tpm_windows",
]
