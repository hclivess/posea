"""PoSEA - Proof of Secure Element Attestation.

Sybil resistance from hardware scarcity rather than hardware cost. See SPEC.md.

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
]
