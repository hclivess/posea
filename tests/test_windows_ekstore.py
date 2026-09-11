"""Reading an endorsement certificate out of the Windows EKCertStore blob.

These are not sanity checks. Each corresponds to something a real machine did that a naive reader gets
wrong, and getting it wrong refuses a chip that is perfectly good — see HARDWARE.md §1 and §2:

  - the registry value is a SERIALIZED CERTIFICATE, not a certificate. Handing the whole blob to an
    X.509 parser reports a corrupt certificate rather than a different structure, which sends the owner
    off to fix hardware that is fine.
  - there is NO TERMINATOR RECORD. The reference machine's blob ends at exactly 1322 bytes with the
    last record flush against the end, so a walker must treat "offset == length" as success.
  - the certificate is the record with propId 32, and it is NOT the first record. On the reference
    machine it follows a key-length record (92) and the thumbprint (3).
  - a blob whose records cannot be walked still contains the DER, and refusing the machine over a parse
    detail is the wrong outcome.

Run: python -m unittest discover -s tests -v
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posea.tpm_windows import der_from_serialized                         # noqa: E402

CERT_CERT_PROP_ID = 32


def record(prop_id, data, encoding_type=1):
    """One {propId, encodingType, length, data} property record, little-endian — the layout observed on
    the reference machine, where encodingType was 1 on every record."""
    return struct.pack("<III", prop_id, encoding_type, len(data)) + data


def fake_der(body_len=1262):
    """A DER-shaped SEQUENCE: 0x30, long form, two length bytes. Real leaf was 1262 bytes beginning
    30 82 04 EA, which is this shape."""
    return b"\x30\x82" + struct.pack(">H", body_len) + bytes(body_len)


class ReadsTheReferenceLayout(unittest.TestCase):

    def test_finds_the_certificate_after_other_records(self):
        """propId 32 is not the first record: on the reference machine it follows key length and the
        thumbprint. A reader that takes the first record, or assumes ordering, gets four bytes of key
        size and calls the machine broken."""
        der = fake_der()
        blob = (record(92, struct.pack("<I", 0x00080000))      # key length, 2048
                + record(3, bytes(20))                          # CERT_SHA1_HASH_PROP_ID
                + record(CERT_CERT_PROP_ID, der))
        self.assertEqual(der_from_serialized(blob), der)

    def test_last_record_flush_against_the_end_is_not_truncation(self):
        """THE BLOB HAS NO TERMINATOR. The reference blob is 1322 bytes and simply stops. A walker that
        requires a trailing record — or that treats a record ending exactly at the end as truncated —
        finds nothing on a perfectly well-formed blob."""
        der = fake_der()
        blob = record(92, struct.pack("<I", 0x00080000)) + record(CERT_CERT_PROP_ID, der)
        self.assertEqual(len(blob) % 1, 0)
        self.assertEqual(blob[-len(der):], der, "the certificate must end flush with the blob")
        self.assertEqual(der_from_serialized(blob), der)

    def test_ignores_a_non_certificate_record_of_the_same_size(self):
        """Matching on length or on 'looks big' rather than on propId 32 picks up whatever else the blob
        carries. Only the tagged record is the certificate."""
        der = fake_der()
        decoy = bytes([0x31]) + bytes(len(der) - 1)     # same size, not a SEQUENCE
        blob = record(99, decoy) + record(CERT_CERT_PROP_ID, der)
        self.assertEqual(der_from_serialized(blob), der)


class DegradesInsteadOfRefusing(unittest.TestCase):

    def test_finds_the_der_when_the_records_cannot_be_walked(self):
        """A blob we cannot walk still contains the certificate. Refusing a machine over a parse detail
        is the wrong outcome, so the fallback locates the DER by its own header."""
        der = fake_der()
        unwalkable = b"\xff" * 7 + der
        self.assertEqual(der_from_serialized(unwalkable), der)

    def test_no_certificate_is_an_answer_not_a_crash(self):
        """A machine with no endorsement certificate must read as 'none', not raise: 'this chip cannot
        attest' is a verdict the caller has to be able to act on."""
        self.assertIsNone(der_from_serialized(b"\x00" * 40))
        self.assertIsNone(der_from_serialized(b""))

    def test_a_length_running_past_the_end_does_not_read_out_of_bounds(self):
        """A truncated or hostile blob declares a length longer than what follows. It must stop, not
        slice past the end and hand back whatever it finds."""
        der = fake_der()
        truncated = struct.pack("<III", CERT_CERT_PROP_ID, 1, len(der) + 500) + der
        self.assertNotEqual(der_from_serialized(truncated), None)   # falls back to shape
        self.assertEqual(der_from_serialized(truncated), der)


class ImportsAnywhere(unittest.TestCase):

    def test_the_module_imports_off_windows(self):
        """The parser and the platform chooser must import on Linux — the verifier half of this project
        runs on servers, and a module that needs ctypes.WinDLL at import time makes the whole package
        unimportable there."""
        import posea.tpm_windows as tw
        self.assertTrue(callable(tw.der_from_serialized))
        self.assertTrue(callable(tw.open_tpm))
        self.assertTrue(callable(tw.ek_certificates_from_registry))


if __name__ == "__main__":
    unittest.main(verbosity=2)
