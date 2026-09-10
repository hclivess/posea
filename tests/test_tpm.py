"""The credential-protection primitives, and what each security property is actually for.

These are not sanity checks. Each one corresponds to a way the construction fails if it does not hold:
  - a credential sealed for one attestation key must not open for another   (else one chip mints many)
  - a credential sealed to one endorsement key must not open under another  (else no chip is proven)
  - an unrestricted key must not enrol                                      (else certify means nothing)
  - a PKCS#1 signature must be checked over the whole re-encoded block      (Bleichenbacher'06)

Run: python -m unittest discover -s tests -v
"""
import base64
import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posea import tpm                                                     # noqa: E402
from posea.roots import EK_ROOT_FINGERPRINTS                              # noqa: E402


def software_ek():
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    decrypt = lambda ct: key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                      algorithm=hashes.SHA256(), label=b"IDENTITY\x00"))
    return spki, decrypt


class TestCredentialProtection(unittest.TestCase):
    def setUp(self):
        self.spki, self.decrypt = software_ek()
        self.pub_area = os.urandom(312)
        self.name = tpm.aik_name(self.pub_area)
        self.secret = os.urandom(32)

    def test_name_is_namealg_plus_digest(self):
        self.assertEqual(self.name, b"\x00\x0b" + hashlib.sha256(self.pub_area).digest())

    def test_a_chip_holding_both_keys_recovers_the_secret(self):
        blob, enc = tpm.make_credential(self.spki, self.name, self.secret)
        self.assertEqual(tpm.activate_credential(self.decrypt, blob, enc, self.name), self.secret)

    def test_bound_to_the_attestation_key(self):
        """ONE CHIP MUST NOT MINT MANY IDENTITIES: a second key in the same chip cannot open the first's
        credential, because the credential is keyed and HMACed over the key's Name."""
        blob, enc = tpm.make_credential(self.spki, self.name, self.secret)
        with self.assertRaises(ValueError):
            tpm.activate_credential(self.decrypt, blob, enc, tpm.aik_name(os.urandom(312)))

    def test_bound_to_the_endorsement_key(self):
        """AND THE PROOF MUST MEAN A CHIP: without the endorsement private key the seed never unwraps."""
        other_spki, _ = software_ek()
        blob, enc = tpm.make_credential(other_spki, self.name, self.secret)
        with self.assertRaises(Exception):
            tpm.activate_credential(self.decrypt, blob, enc, self.name)

    def test_the_blob_is_deterministic_in_seed_name_secret(self):
        """THE PROPERTY THE WHOLE CA-FREE CONSTRUCTION RESTS ON. Only the wrapped seed is randomised, so a
        challenge issued once can be replayed by every verifier afterwards, forever, offline."""
        seed = os.urandom(32)
        a, enc_a = tpm.make_credential(self.spki, self.name, self.secret, seed=seed)
        b, enc_b = tpm.make_credential(self.spki, self.name, self.secret, seed=seed)
        self.assertEqual(a, b)
        self.assertNotEqual(enc_a, enc_b, "the wrapped seed must still be randomised")

    def test_reveal_verifies_and_both_halves_are_needed(self):
        seed = os.urandom(32)
        blob, _ = tpm.make_credential(self.spki, self.name, self.secret, seed=seed)
        commit = tpm.credential_commitment(self.secret)
        self.assertTrue(tpm.verify_credential_reveal(self.spki, self.name, self.secret, seed, blob, commit))
        self.assertFalse(tpm.verify_credential_reveal(self.spki, self.name, self.secret, os.urandom(32),
                                                      blob, commit))
        self.assertFalse(tpm.verify_credential_reveal(self.spki, self.name, self.secret, seed, blob,
                                                      tpm.credential_commitment(b"something else")))


class TestPublicArea(unittest.TestCase):
    @staticmethod
    def pub(attrs=0x00050472, scheme=0x0014, exponent=0, modulus=None):
        n = modulus if modulus is not None else (b"\xc0" + b"\x11" * 255)
        return (struct.pack(">HHI", 0x0001, 0x000B, attrs) + b"\x00\x00" + struct.pack(">H", 0x0010)
                + struct.pack(">HH", scheme, 0x000B) + struct.pack(">H", 2048)
                + struct.pack(">I", exponent) + struct.pack(">H", len(n)) + n)

    def test_a_restricted_signing_key_is_accepted(self):
        self.assertIn("restricted", tpm.validate_aik_pub_area(self.pub()))

    def test_an_unrestricted_key_is_refused(self):
        """Certify an unrestricted key and the chip will afterwards sign anything the host asks, including a
        forged TPMS_ATTEST for a key that never existed in it."""
        with self.assertRaises(ValueError):
            tpm.validate_aik_pub_area(self.pub(attrs=0x00050472 & ~0x00010000))

    def test_a_duplicable_key_is_refused(self):
        """Without fixedTPM/fixedParent the key can be duplicated to another chip, so one enrolment would
        licence every machine it is copied to."""
        for bit in (0x0000_0002, 0x0000_0010):
            with self.assertRaises(ValueError):
                tpm.validate_aik_pub_area(self.pub(attrs=0x00050472 & ~bit))

    def test_an_imported_key_is_refused(self):
        """Without sensitiveDataOrigin the private half could have been generated outside the chip."""
        with self.assertRaises(ValueError):
            tpm.validate_aik_pub_area(self.pub(attrs=0x00050472 & ~0x0000_0020))

    def test_a_null_scheme_is_refused(self):
        """A NULL scheme lets the caller pick one per signature, reopening the freedom `restricted` removes."""
        with self.assertRaises(ValueError):
            tpm.validate_aik_pub_area(self.pub(scheme=0x0010))

    def test_zero_exponent_reads_as_65537(self):
        """The TPM encodes the default exponent as 0. Reading it literally yields a key that verifies
        nothing — and it fails as a silent wrong answer, not as an error."""
        self.assertEqual(tpm.pub_area_rsa(self.pub(exponent=0))[1], 65537)
        self.assertEqual(tpm.pub_area_rsa(self.pub(exponent=3))[1], 3)

    def test_spki_matches_a_reference_encoder(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        want = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        n = key.public_key().public_numbers().n.to_bytes(256, "big")
        self.assertEqual(tpm.pub_area_spki(self.pub(modulus=n)), want)


class TestCertify(unittest.TestCase):
    """What an admission presents: the enrolled key signing a TPM-generated structure that answers a
    challenge bound to the moment. Built here with a software key; tests/test_swtpm.py drives a real TPM."""

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = self.key.public_key().public_numbers().n.to_bytes(256, "big")
        self.pub_area = TestPublicArea.pub(modulus=n)
        self.challenge = os.urandom(32)
        self.cert_info = self.attest(self.challenge, tpm.aik_name(self.pub_area))
        self.sig = self.key.sign(self.cert_info, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def attest(extra, certified_name):
        return (struct.pack(">IH", tpm.TPM_GENERATED, tpm.ST_ATTEST_CERTIFY)
                + struct.pack(">H", 4) + b"sign"               # qualifiedSigner
                + struct.pack(">H", len(extra)) + extra        # extraData
                + b"\x00" * 17 + b"\x00" * 8                   # clockInfo + firmwareVersion
                + struct.pack(">H", len(certified_name)) + certified_name)

    def test_a_good_certify_verifies(self):
        self.assertTrue(tpm.verify_certify(self.pub_area, self.cert_info, self.sig,
                                           self.challenge).startswith("certify by RSA-2048"))

    def test_a_stale_certify_is_refused(self):
        """extraData is where freshness lives: without this check any earlier certify replays forever."""
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.pub_area, self.cert_info, self.sig, os.urandom(32))

    def test_a_certify_of_a_different_object_is_refused(self):
        """Otherwise an enrolment licences whatever else the chip happens to hold."""
        info = self.attest(self.challenge, b"\x00\x0b" + hashlib.sha256(b"other").digest())
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        sig = self.key.sign(info, padding.PKCS1v15(), hashes.SHA256())
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.pub_area, info, sig, self.challenge)

    def test_a_structure_the_host_composed_is_refused(self):
        """No TPM_GENERATED magic means it did not come out of a chip."""
        forged = b"\x00\x00\x00\x00" + self.cert_info[4:]
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.pub_area, forged, self.sig, self.challenge)

    def test_a_quote_is_not_a_certify(self):
        """A different TPMS_ATTEST type puts different fields at these offsets, so accepting one would mean
        reading some other structure as if it were this one."""
        wrong = self.cert_info[:4] + struct.pack(">H", 0x8018) + self.cert_info[6:]
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.pub_area, wrong, self.sig, self.challenge)

    def test_tampering_is_refused(self):
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.pub_area, self.cert_info,
                               self.sig[:-1] + bytes([self.sig[-1] ^ 1]), self.challenge)

    def test_signature_must_fill_the_whole_padded_block(self):
        """Bleichenbacher'06: an implementation that SEARCHES for the digest inside the padding, rather than
        comparing the whole re-encoded block, accepts trivial forgeries against small exponents. Real
        libraries have shipped this bug more than once, so it is pinned here."""
        n, _ = tpm.pub_area_rsa(self.pub_area)
        k = 256
        digest = hashlib.sha256(b"forge me").digest()
        # a block with the DigestInfo present but the padding short — a searching verifier accepts it
        loose = (b"\x00\x01" + b"\xff" * 8 + b"\x00" + bytes.fromhex("3031300d060960864801650304020105000420")
                 + digest)
        loose = loose + b"\x00" * (k - len(loose))
        self.assertFalse(tpm.verify_rsassa_sha256(n, 3, b"forge me",
                                                  pow(int.from_bytes(loose, "big"), 1, n).to_bytes(k, "big")))


class TestEndorsementRoots(unittest.TestCase):
    """A pinned 'root' that is actually a cross-signed intermediate silently moves the trust decision to
    whoever cross-signed it, which is a different assertion from 'this vendor made this chip'. That is not a
    hypothetical: STMicroelectronics publishes its 'STM TPM EK Root CA' cross-signed by GlobalSign, and it is
    deliberately NOT in the pinned set for exactly this reason."""

    @staticmethod
    def issuer_and_subject(der):
        """(issuer DER, subject DER) of a certificate, by walking the TLVs. In a self-signed certificate they
        are byte-identical."""
        from posea._parse import _der_tlv
        tag, hl, ln = _der_tlv(der, 0)                      # Certificate ::= SEQUENCE
        tag, hl2, ln2 = _der_tlv(der, hl)                   # tbsCertificate ::= SEQUENCE
        pos = hl + hl2
        end = pos + ln2
        fields = []
        while pos < end and len(fields) < 6:
            t, h, l = _der_tlv(der, pos)
            fields.append((t, der[pos:pos + h + l]))
            pos += h + l
        # [0] version is optional (tag 0xA0); without it every field shifts down by one.
        base = 1 if fields[0][0] == 0xA0 else 0
        return fields[base + 2][1], fields[base + 4][1]

    def test_every_pinned_root_ships_and_is_self_signed(self):
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "roots", "ek")
        seen = set()
        for name in sorted(os.listdir(d)):
            with open(os.path.join(d, name)) as f:
                pem = f.read()
            der = base64.b64decode("".join(l.strip() for l in pem.splitlines()
                                           if l and not l.startswith("-----")))
            fp = hashlib.sha256(der).hexdigest()
            self.assertIn(fp, EK_ROOT_FINGERPRINTS, f"{name} is not pinned")
            issuer, subject = self.issuer_and_subject(der)
            self.assertEqual(issuer, subject, f"{name} is not self-signed — it is an intermediate")
            seen.add(fp)
        self.assertEqual(seen, set(EK_ROOT_FINGERPRINTS), "a pinned root has no PEM to verify against")


if __name__ == "__main__":
    unittest.main()
