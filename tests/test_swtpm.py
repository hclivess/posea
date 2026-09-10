"""THE WHOLE ENROLMENT, DRIVEN THROUGH A REAL TPM 2.0 IMPLEMENTATION.

Everything else here is checked against a software stand-in, which proves the arithmetic agrees with itself.
This drives an actual TPM: our command bytes in, its structures out, our verifier over what it produced. It is
the only place the byte LAYOUTS meet something that did not come out of this repository — TPMS_ATTEST field
offsets, the exponent-zero-means-65537 encoding, a credential blob a chip will genuinely accept.

Requires `swtpm` (Debian/Ubuntu: apt install swtpm). Skipped when it is absent.

WHAT THIS DOES NOT PROVE: that a particular vendor's silicon behaves this way. swtpm accepts templates an
fTPM may reject, and carries no endorsement certificate at all — so the one thing PoSEA's TPM path ultimately
rests on, the vendor signature, cannot be exercised here.

Run: python -m unittest discover -s tests -v
"""
import hashlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posea import enrolment as E                                                  # noqa: E402
from posea import tpm                                                             # noqa: E402
from posea.tpm_device import Tpm, ek_template, aik_template, RH_ENDORSEMENT       # noqa: E402
from posea.tpm_device import AIK_ATTRS, ALG_RSA, ALG_SHA256, ALG_NULL, ALG_RSASSA, tpm2b  # noqa: E402


class MsSim:
    """The simulator's TCP framing (TPM_SEND_COMMAND = 8): locality, length, command; back comes a length,
    the response, and a four-byte return code. Nothing TPM-specific — a transport, which is exactly why the
    command builders live apart from the device file they normally write to."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)

    def transmit(self, cmd: bytes) -> bytes:
        self.sock.sendall(struct.pack(">IBI", 8, 0, len(cmd)) + cmd)
        n = struct.unpack(">I", self._recv(4))[0]
        rsp = self._recv(n)
        self._recv(4)
        return rsp

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise IOError("simulator closed the connection")
            buf += chunk
        return buf

    def close(self):
        self.sock.close()


def second_key_template():
    """A second restricted signing key, identical to the attestation key except for `unique` — a primary is
    DERIVED from its whole template, so one differing byte yields a different key. The ATTRIBUTES are left
    alone: clearing userWithAuth to make it differ produces TPM_RC_AUTH_UNAVAILABLE (0x12f) on Certify, which
    says nothing about the property under test and everything about the template."""
    return (struct.pack(">HHI", ALG_RSA, ALG_SHA256, AIK_ATTRS)
            + tpm2b(b"") + struct.pack(">H", ALG_NULL)
            + struct.pack(">HH", ALG_RSASSA, ALG_SHA256) + struct.pack(">HI", 2048, 0)
            + tpm2b(b"\x01" * 256))


@unittest.skipUnless(shutil.which("swtpm"), "swtpm is not installed")
class TestAgainstARealTpm(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = tempfile.mkdtemp(prefix="swtpm-state-")
        port = cls._free_port()
        cls.proc = subprocess.Popen(
            ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={cls.state}",
             "--server", f"type=tcp,port={port}", "--ctrl", f"type=tcp,port={port + 1}",
             "--flags", "startup-clear", "--log", "level=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.sim = cls._wait(port)
        if cls.sim is None:
            cls.proc.terminate()
            raise unittest.SkipTest("swtpm did not come up")
        cls.tpm = Tpm.__new__(Tpm)                 # a transport swap, not a second TPM implementation
        cls.tpm.transmit = cls.sim.transmit
        cls.ek_h, cls.ek_pub, _ = cls.tpm.create_primary(RH_ENDORSEMENT, ek_template())
        cls.aik_h, cls.aik_pub, _ = cls.tpm.create_primary(RH_ENDORSEMENT, aik_template())
        cls.ek_spki = tpm.pub_area_spki(cls.ek_pub)
        cls.name = tpm.aik_name(cls.aik_pub)

    @classmethod
    def tearDownClass(cls):
        # A LEAKED TRANSIENT HANDLE WEDGES THE NEXT RUN with TPM_RC_OBJECT_MEMORY (0x902), which then looks
        # like a bug in whatever that run is doing rather than in what this one failed to clean up.
        for h in getattr(cls, "_handles", []) + [getattr(cls, "ek_h", None), getattr(cls, "aik_h", None)]:
            if h:
                cls.tpm.flush(h)
        cls.sim.close()
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        shutil.rmtree(cls.state, ignore_errors=True)

    _handles = []

    @staticmethod
    def _free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    @classmethod
    def _wait(cls, port):
        for _ in range(100):
            if cls.proc.poll() is not None:
                return None
            try:
                return MsSim(port)
            except OSError:
                time.sleep(0.05)
        return None

    # --- what the chip derives ----------------------------------------------------------------------------

    def test_the_tcg_ek_template_derives(self):
        self.assertEqual(len(self.ek_pub), 314, "the TCG EK Credential Profile L-1 public area")

    def test_the_attestation_key_is_restricted(self):
        self.assertIn("restricted", tpm.validate_aik_pub_area(self.aik_pub))

    def test_reading_the_key_out_of_the_chip(self):
        n, e = tpm.pub_area_rsa(self.aik_pub)
        self.assertEqual(e, 65537, "a zero exponent means 65537")
        self.assertEqual(n.bit_length(), 2048)

    # --- the enrolment ------------------------------------------------------------------------------------

    def test_the_chip_opens_a_credential_we_sealed(self):
        secret, seed = os.urandom(32), os.urandom(32)
        blob, enc = tpm.make_credential(self.ek_spki, self.name, secret, seed=seed)
        sess = self.tpm.start_policy_session()
        try:
            self.tpm.policy_secret_endorsement(sess)
            self.assertEqual(self.tpm.activate_credential(self.aik_h, self.ek_h, sess, blob, enc), secret)
        finally:
            self.tpm.flush(sess)
        # and a verifier that saw none of it re-derives the identical challenge
        self.assertEqual(tpm.make_credential(self.ek_spki, self.name, secret, seed=seed)[0], blob)

    def test_the_enrolment_reaches_proven_on_real_chip_output(self):
        secret, seed = os.urandom(32), os.urandom(32)
        blob, enc = tpm.make_credential(self.ek_spki, self.name, secret, seed=seed)
        ek_id = hashlib.sha256(self.ek_spki).hexdigest()
        rec = E.new_record(ek_id, self.ek_spki, self.name.hex(), self.aik_pub, "prover", 100, ["c1"])
        rec = E.apply_challenge(rec, "c1", blob, enc, 101)
        rec = E.apply_commit(rec, "prover", tpm.credential_commitment(secret), 102)
        rec = E.apply_reveal(rec, "c1", secret, seed, 103)
        self.assertEqual(rec["state"], E.STATE_PROVEN)

    # --- what an admission presents -----------------------------------------------------------------------

    def test_the_chips_certify_verifies(self):
        challenge = os.urandom(32)
        cert_info, sig = self.tpm.certify(self.aik_h, self.aik_h, challenge)
        self.assertTrue(tpm.verify_certify(self.aik_pub, cert_info, sig, challenge)
                        .startswith("certify by RSA-2048"))
        for label, args in (
                ("a different challenge", (self.aik_pub, cert_info, sig, os.urandom(32))),
                ("a tampered signature", (self.aik_pub, cert_info, sig[:-1] + bytes([sig[-1] ^ 1]), challenge)),
                ("tampered certInfo", (self.aik_pub, cert_info[:-1] + bytes([cert_info[-1] ^ 1]), sig, challenge))):
            with self.subTest(refuses=label), self.assertRaises(ValueError):
                tpm.verify_certify(*args)

    def test_another_key_in_the_same_chip_is_not_the_enrolled_one(self):
        """Otherwise one enrolment licences every key the machine ever creates, and a chip becomes a
        factory."""
        challenge = os.urandom(32)
        other_h, _, _ = self.tpm.create_primary(RH_ENDORSEMENT, second_key_template())
        type(self)._handles.append(other_h)
        cert_info, sig = self.tpm.certify(other_h, other_h, challenge)
        with self.assertRaises(ValueError):
            tpm.verify_certify(self.aik_pub, cert_info, sig, challenge)


if __name__ == "__main__":
    unittest.main()
