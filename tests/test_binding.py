"""Tests for the per-device binding handle.

The handle is what makes "one device, one identity" enforceable, so the properties that
matter are: bindable classes produce a stable handle, non-bindable classes are refused
outright, and a batch-attested Android device is refused by certificate validity span.

Run: python -m unittest discover -s tests -v
"""
import base64
import hashlib
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posea import device_binding_key  # noqa: E402
from posea.roots import BINDABLE_FORMATS, MAX_DEVICE_CERT_SECS  # noqa: E402


# --- minimal CBOR encoder, enough to build attestation objects for tests ---

def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    if n < 65536:
        return bytes([(major << 5) | 25, n >> 8, n & 0xFF])
    return bytes([(major << 5) | 26, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def cbor(obj):
    if isinstance(obj, bytes):
        return _head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return _head(3, len(b)) + b
    if isinstance(obj, list):
        return _head(4, len(obj)) + b"".join(cbor(x) for x in obj)
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    raise TypeError(type(obj))


def att_obj(fmt, x5c):
    """A statement carrying only what the binding handle reads."""
    return base64.b64encode(cbor({"fmt": fmt, "attStmt": {"x5c": list(x5c)}})).decode()


def der_cert(not_before, not_after, tag=b"\x00"):
    """A DER certificate whose only property under test is its validity window.

    SEQUENCE { SEQUENCE { [0] version, serial, SEQUENCE alg, SEQUENCE issuer,
                          SEQUENCE { UTCTime nb, UTCTime na } } }
    Only the validity SEQUENCE is parsed by cert_validity, but the surrounding shape has to
    be walkable, so this mirrors the real nesting rather than faking it.
    """
    def tlv(t, body):
        if len(body) < 128:
            return bytes([t, len(body)]) + body
        n = len(body)
        nb_ = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([t, 0x80 | len(nb_)]) + nb_ + body

    def utctime(ts):
        import time as _t
        s = _t.strftime("%y%m%d%H%M%SZ", _t.gmtime(ts)).encode()
        return tlv(0x17, s)

    validity = tlv(0x30, utctime(not_before) + utctime(not_after))
    version = tlv(0xA0, tlv(0x02, b"\x02"))
    serial = tlv(0x02, b"\x01" + tag)
    alg = tlv(0x30, b"")
    issuer = tlv(0x30, b"")
    tbs = tlv(0x30, version + serial + alg + issuer + validity)
    return tlv(0x30, tbs)


DAY = 24 * 3600


class TestNonBindableClassesRefused(unittest.TestCase):
    """A class with no per-device value cannot be bound, so it must be refused.

    FIDO2 issues one batch certificate per >=100k units and Apple passkeys carry no
    attestation at all. Accepting either would mean binding a handle shared by many
    devices, which locks out every other owner of the same model.
    """

    def test_fido2_packed_refused(self):
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("packed", [der_cert(0, 10 * DAY)])}, MAX_DEVICE_CERT_SECS)

    def test_apple_refused(self):
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("apple", [der_cert(0, 10 * DAY)])}, MAX_DEVICE_CERT_SECS)

    def test_unknown_format_refused(self):
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("definitely-not-a-format", [])}, MAX_DEVICE_CERT_SECS)

    def test_bindable_set_matches_implementation(self):
        self.assertEqual(BINDABLE_FORMATS, frozenset(("android-key", "tpm")))


class TestTpmBinding(unittest.TestCase):
    def test_handle_is_sha256_of_aik(self):
        aik = der_cert(0, 365 * DAY)
        got = device_binding_key({"att": att_obj("tpm", [aik])}, MAX_DEVICE_CERT_SECS)
        self.assertEqual(got, "tpm:" + hashlib.sha256(aik).hexdigest())

    def test_missing_aik_refused(self):
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("tpm", [])}, MAX_DEVICE_CERT_SECS)


class TestAndroidBinding(unittest.TestCase):
    """x5c[1] is the device certificate under remote key provisioning."""

    def _chain(self, span_secs):
        leaf = der_cert(0, 30 * DAY, b"\x01")
        device = der_cert(0, span_secs, b"\x02")
        root = der_cert(0, 3650 * DAY, b"\x03")
        return [leaf, device, root], device

    def test_rkp_device_cert_is_the_handle(self):
        chain, device = self._chain(13 * DAY)
        got = device_binding_key({"att": att_obj("android-key", chain)}, MAX_DEVICE_CERT_SECS)
        self.assertEqual(got, "android-key:" + hashlib.sha256(device).hexdigest())

    def test_batch_attested_device_refused_by_validity_span(self):
        """A pre-RKP certificate is multi-year and shared by up to 100k units."""
        chain, _ = self._chain(3 * 365 * DAY)
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("android-key", chain)}, MAX_DEVICE_CERT_SECS)

    def test_short_chain_refused(self):
        leaf = der_cert(0, 30 * DAY)
        with self.assertRaises(ValueError):
            device_binding_key({"att": att_obj("android-key", [leaf])}, MAX_DEVICE_CERT_SECS)

    def test_handle_is_stable_across_calls(self):
        """The same device must yield the same handle, or binding cannot be enforced."""
        chain, _ = self._chain(13 * DAY)
        a = device_binding_key({"att": att_obj("android-key", chain)}, MAX_DEVICE_CERT_SECS)
        b = device_binding_key({"att": att_obj("android-key", chain)}, MAX_DEVICE_CERT_SECS)
        self.assertEqual(a, b)

    def test_distinct_devices_yield_distinct_handles(self):
        c1, _ = self._chain(13 * DAY)
        c2 = [c1[0], der_cert(DAY, 14 * DAY, b"\x09"), c1[2]]
        a = device_binding_key({"att": att_obj("android-key", c1)}, MAX_DEVICE_CERT_SECS)
        b = device_binding_key({"att": att_obj("android-key", c2)}, MAX_DEVICE_CERT_SECS)
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
