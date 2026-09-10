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


# --- ENDORSEMENT roots: the silicon vendors' word that a chip is genuine -------------------------------------
#
# SEPARATE FROM THE SET ABOVE, ON PURPOSE. Those roots answer "did a vendor sign this attestation statement".
# These answer "did a silicon vendor certify this chip". Conflating them would let an endorsement root
# validate a platform statement or the reverse, and neither vendor ever asserted the other thing.
#
# Each was fetched from the vendor's own PKI, confirmed self-signed with CA:TRUE, and — where a real
# endorsement certificate was available to walk — confirmed to be the root that certificate reaches.
#
# WHICH ROOTS ARE PINNED IS THE SYBIL DIAL, and it only reverses in the widening direction. A discrete TPM
# module is ~£15, so pinning the module makers prices an identity at the cost of a chip; a CPU-vendor fTPM
# implies a whole machine. Narrowing later strands everyone already enrolled under the wider set.
EK_ROOT_FINGERPRINTS = frozenset((
    "67bd2472a546751caca5f358a78f80727531671338960a9bcfdfbe6a34d0c6a1",  # AMD fTPM — CN=AMDTPM (2039)
    "beb40bb7507b33967226aa80e084749fbb6593893c642e818d682e9a8d07fc24",  # Intel PTT — OnDie CA Root (2049)
    "4aebe77a51ed29959a7f9f5e07a24a558dee8167f3985d724995a541c258dfda",  # Nuvoton TPM Root CA 2110 (2035)
    "cd8185ff8995ed09811970090a8c36fafab34ef87f47fa51fdb9ecf95c9c2e04",  # Nuvoton TPM Root CA 2111 (2037)
    "899e35474c9807eb4c7f2f7a12da0028fb250cd02154d0009fca7d9c66574f3b",  # Infineon OPTIGA RSA Root (2043)
    "cfeb02fecd55ad7a73c6e1d11985d4c47dee248ab63dcb66091a2489660443c3",  # Infineon OPTIGA ECC Root (2043)
    # STMicroelectronics is NOT pinned. The certificate published as "STM TPM EK Root CA" is cross-signed by
    # GlobalSign and is therefore an intermediate, not a root — pinning it would be a decision to trust
    # GlobalSign's Trusted Computing CA, which is a different assertion from "ST made this chip".
))

# How many independent challengers one enrolment needs (SPEC.md section 9.5). The residual attack on a CA-free
# enrolment is a challenger privately handing its secret to a prover with no chip; with k drawn challengers,
# forgery needs all k to collude. 3 is the smallest k where no single challenger can admit identities alone.
ENROL_CHALLENGERS = 3
