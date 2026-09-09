"""PoSEA - Proof of Secure Element Attestation.

Sybil resistance from hardware scarcity rather than hardware cost. See SPEC.md.

The parsing core is extracted from the NADO deployment (ops/device_attest.py), where
certificate chain signature verification runs in a native kernel. What lives here is the
deterministic part: parsing, validity spans, and the per-device binding handle that makes
"one device, one identity" enforceable.
"""

from ._parse import (
    cbor_decode,
    parse_auth_data,
    parse_attestation,
    cert_validity,
    device_binding_key,
)

__all__ = [
    "cbor_decode",
    "parse_auth_data",
    "parse_attestation",
    "cert_validity",
    "device_binding_key",
]
