"""THE ORDERING IS THE PROOF, so the ordering is what these tests attack.

posea/tpm.py checks the arithmetic of one challenge, and the arithmetic is happily satisfied by a
fabrication: a prover with no chip at all picks a secret and a seed, computes the blob itself, and every
equation holds. What makes an enrolment mean something is that each message was published strictly after the
one it answers. Every case below is a real way to try to collapse that, and each must be refused.

Run: python -m unittest discover -s tests -v
"""
import hashlib
import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posea import enrolment as E                                          # noqa: E402
from posea.tpm import credential_commitment, make_credential              # noqa: E402


def aik_pub_area(unique=b"", restricted=True):
    """A minimal TPMT_PUBLIC for a restricted RSA-2048 signing key — what validate_aik_pub_area demands."""
    attrs = 0x00050472 if restricted else (0x00050472 & ~0x00010000)
    return (struct.pack(">HHI", 0x0001, 0x000B, attrs) + b"\x00\x00" + struct.pack(">H", 0x0010)
            + struct.pack(">HH", 0x0014, 0x000B) + struct.pack(">H", 2048) + struct.pack(">I", 0)
            + struct.pack(">H", len(unique)) + unique)


def software_ek():
    """A stand-in endorsement key. `cryptography` appears in the TESTS only: the library that generates a key
    here is the same one that refuses to parse a real AMD endorsement certificate, which is exactly why the
    module under test has no dependencies."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, spki


class TestEnrolmentId(unittest.TestCase):
    def setUp(self):
        _, self.spki = software_ek()
        self.ek = hashlib.sha256(self.spki).hexdigest()
        self.name = E.aik_name_hex(aik_pub_area())

    def test_derived_not_chosen(self):
        a = E.enrol_id("demo", self.ek, self.name)
        self.assertEqual(a, E.enrol_id("demo", self.ek, self.name))
        self.assertEqual(len(a), 32)

    def test_domain_separates_deployments(self):
        """A record captured from one deployment must not be a valid record in the next."""
        self.assertNotEqual(E.enrol_id("demo", self.ek, self.name),
                            E.enrol_id("other", self.ek, self.name))


class TestChallengerDraw(unittest.TestCase):
    def setUp(self):
        self.weights = {f"c{i:02d}": (i + 1) * 1000 for i in range(12)}
        self.eid = "a" * 32

    def test_k_distinct_challengers(self):
        picked = E.challenger_set(self.eid, self.weights, "beacon-a", 3)
        self.assertEqual(len(picked), 3)
        self.assertEqual(len(set(picked)), 3, "seating one challenger twice halves the collusion to forge")

    def test_deterministic(self):
        self.assertEqual(E.challenger_set(self.eid, self.weights, "beacon-a", 3),
                         E.challenger_set(self.eid, self.weights, "beacon-a", 3))

    def test_beacon_changes_the_set(self):
        """A prover that could wait for a beacon drawing a set it likes would choose its own challengers."""
        base = E.challenger_set(self.eid, self.weights, "beacon-a", 3)
        self.assertTrue(any(E.challenger_set(self.eid, self.weights, b, 3) != base
                            for b in ("beacon-b", "beacon-c", "beacon-d")))

    def test_enrolment_draws_independently(self):
        base = E.challenger_set(self.eid, self.weights, "beacon-a", 3)
        self.assertTrue(any(E.challenger_set(e, self.weights, "beacon-a", 3) != base
                            for e in ("b" * 32, "c" * 32, "d" * 32)))

    def test_short_pool_returns_short_set(self):
        """The caller refuses a short set; the draw must not silently seat someone twice to fill it."""
        self.assertEqual(E.challenger_set(self.eid, {}, "beacon-a", 3), [])
        self.assertEqual(len(E.challenger_set(self.eid, {"solo": 10}, "beacon-a", 3)), 1)

    def test_zero_weight_is_not_seated(self):
        self.assertNotIn("nobody", E.challenger_set(self.eid, dict(self.weights, nobody=0), "b", 3))


class EnrolmentFlow(unittest.TestCase):
    """One chip, three challengers, and every ordering an adversary would like to collapse."""

    def setUp(self):
        _, self.spki = software_ek()
        self.ek = hashlib.sha256(self.spki).hexdigest()
        self.pub = aik_pub_area()
        self.name = E.aik_name_hex(self.pub)
        self.picked = ["c1", "c2", "c3"]
        self.secrets = {c: os.urandom(32) for c in self.picked}
        self.seeds = {c: os.urandom(32) for c in self.picked}
        self.blobs = {c: make_credential(self.spki, bytes.fromhex(self.name), self.secrets[c],
                                         seed=self.seeds[c]) for c in self.picked}
        self.commitment = credential_commitment(
            b"".join(self.secrets[c] for c in sorted(self.picked)))

    def fresh(self):
        return E.new_record(self.ek, self.spki, self.name, self.pub, "prover", 100, self.picked)

    def challenged(self, at=(101, 102, 103)):
        rec = self.fresh()
        for c, h in zip(self.picked, at):
            rec = E.apply_challenge(rec, c, self.blobs[c][0], self.blobs[c][1], h)
        return rec

    def committed(self):
        return E.apply_commit(self.challenged(), "prover", self.commitment, 110)

    # --- the honest flow ---------------------------------------------------------------------------------

    def test_honest_enrolment_is_proven(self):
        rec = self.committed()
        for i, c in enumerate(self.picked):
            rec = E.apply_reveal(rec, c, self.secrets[c], self.seeds[c], 111 + i)
        self.assertEqual(rec["state"], E.STATE_PROVEN)
        self.assertEqual(E.proven_key(rec), f"{self.ek}:{self.name}")

    def test_publication_requires_a_restricted_key(self):
        self.assertIn("restricted", E.validate_publication(self.ek, self.pub))
        with self.assertRaises(ValueError):
            E.validate_publication(self.ek, aik_pub_area(restricted=False))

    # --- ordering ----------------------------------------------------------------------------------------

    def test_challenge_may_not_share_the_enrolment_height(self):
        with self.assertRaises(AssertionError):
            E.apply_challenge(self.fresh(), "c1", self.blobs["c1"][0], self.blobs["c1"][1], 100)

    def test_commit_may_not_share_the_last_challenge_height(self):
        with self.assertRaises(AssertionError):
            E.apply_commit(self.challenged(), "prover", self.commitment, 103)

    def test_commit_requires_every_challenger(self):
        rec = E.apply_challenge(self.fresh(), "c1", self.blobs["c1"][0], self.blobs["c1"][1], 101)
        with self.assertRaises(AssertionError):
            E.apply_commit(rec, "prover", self.commitment, 105)

    def test_reveal_may_not_share_the_commit_height(self):
        """THE ATTACK THE WHOLE DESIGN EXISTS TO STOP: a prover reading the secret and then committing."""
        with self.assertRaises(AssertionError):
            E.apply_reveal(self.committed(), "c1", self.secrets["c1"], self.seeds["c1"], 110)

    def test_no_challenge_after_the_commitment(self):
        with self.assertRaises(AssertionError):
            E.apply_challenge(self.committed(), "c1", b"x", b"y", 111)

    # --- who may speak -----------------------------------------------------------------------------------

    def test_only_drawn_challengers(self):
        with self.assertRaises(AssertionError):
            E.apply_challenge(self.fresh(), "outsider", self.blobs["c1"][0], self.blobs["c1"][1], 101)

    def test_a_prover_may_not_seal_its_own_challenge(self):
        """A prover can compute a perfectly valid blob for a secret it chose. The state machine refuses it
        because the prover is not a drawn challenger — the whole difference between a proof and an
        assertion."""
        s, r = os.urandom(32), os.urandom(32)
        blob, enc = make_credential(self.spki, bytes.fromhex(self.name), s, seed=r)
        with self.assertRaises(AssertionError):
            E.apply_challenge(self.fresh(), "prover", blob, enc, 101)

    def test_one_challenge_each(self):
        rec = E.apply_challenge(self.fresh(), "c1", self.blobs["c1"][0], self.blobs["c1"][1], 101)
        with self.assertRaises(AssertionError):
            E.apply_challenge(rec, "c1", self.blobs["c1"][0], self.blobs["c1"][1], 102)

    def test_only_the_owner_commits(self):
        with self.assertRaises(AssertionError):
            E.apply_commit(self.challenged(), "someone-else", self.commitment, 110)

    # --- a challenger is held to what it published -------------------------------------------------------

    def test_challenger_cannot_reveal_another_secret(self):
        with self.assertRaises(AssertionError):
            E.apply_reveal(self.committed(), "c1", os.urandom(32), self.seeds["c1"], 111)

    def test_challenger_cannot_reveal_another_seed(self):
        with self.assertRaises(AssertionError):
            E.apply_reveal(self.committed(), "c1", self.secrets["c1"], os.urandom(32), 111)

    def test_one_reveal_each(self):
        rec = E.apply_reveal(self.committed(), "c1", self.secrets["c1"], self.seeds["c1"], 111)
        with self.assertRaises(AssertionError):
            E.apply_reveal(rec, "c1", self.secrets["c1"], self.seeds["c1"], 112)

    # --- k-of-k must not dissolve into 1-of-k ------------------------------------------------------------

    def test_partial_recovery_is_refused(self):
        """A prover that opened only one challenge commits to that secret plus guesses. Every blob check
        passes; only the commitment over ALL the secrets catches it, at the last reveal."""
        bad = credential_commitment(b"".join(self.secrets[c] if c == "c1" else os.urandom(32)
                                             for c in sorted(self.picked)))
        rec = E.apply_commit(self.challenged(), "prover", bad, 110)
        for c in self.picked[:-1]:
            rec = E.apply_reveal(rec, c, self.secrets[c], self.seeds[c], 111)
        last = self.picked[-1]
        with self.assertRaises(AssertionError):
            E.apply_reveal(rec, last, self.secrets[last], self.seeds[last], 112)

    def test_incomplete_enrolment_yields_no_key(self):
        rec = E.apply_reveal(self.committed(), "c1", self.secrets["c1"], self.seeds["c1"], 111)
        self.assertEqual(rec["state"], E.STATE_COMMITTED)
        with self.assertRaises(AssertionError):
            E.proven_key(rec)


if __name__ == "__main__":
    unittest.main()
