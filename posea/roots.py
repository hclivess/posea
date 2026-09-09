"""Pinned vendor attestation roots, as SHA-256 over DER.

Roots are constants. They are never fetched at validation time, never learned from a peer,
and change only by an explicit agreed update. See SPEC.md section 4.
"""

ROOT_FINGERPRINTS = frozenset((
    "0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29",  # Apple WebAuthn Root CA (2045)
    "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",  # Google Hardware Attestation Root (2042)
    "1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc",  # Google Hardware Attestation Root (2034)
    "ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a",  # Google Hardware Attestation Root (2036)
    "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",  # Google Key Attestation CA1 (2035)
    "870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da",  # Microsoft TPM Root CA 2014 (2039)
))

# Classes that yield a per-device handle and are therefore bindable to one identity.
BINDABLE_FORMATS = frozenset(("android-key", "tpm"))

# A genuine remotely-provisioned Android attestation certificate is short lived (~13 days
# observed). A pre-RKP batch certificate is multi-year and shared by up to 100k units, so it
# is rejected by validity span. See SPEC.md section 3.1.
MAX_DEVICE_CERT_SECS = 40 * 24 * 3600
