"""THE FOUR-MESSAGE ENROLMENT: what turns a commit-reveal into a proof.

posea/tpm.py checks the arithmetic of one challenge. The arithmetic is happily satisfied by a fabrication: a
prover with no chip at all picks a secret and a seed, computes the blob itself, and every equation holds. What
makes an enrolment mean something is the ORDERING — that each message was published strictly after the one it
answers, on a record every verifier agrees on.

WHY FOUR MESSAGES, AND WHY NO ADJACENT PAIR CAN BE MERGED:

  1. publish    prover      the endorsement chain + the attestation key's public area.
                            The challengers cannot act before this: MakeCredential seals to a SPECIFIC key's
                            name, and the name is a digest of that public area.
  2. challenge  challenger  blob = MakeCredential(EKpub, aikName, S) and the wrapped seed. Only the chip can
                            open it. One message per drawn challenger.
  3. commit     prover      H(S_1 || ... || S_k), having run TPM2_ActivateCredential.
                            MUST be published strictly after every challenge: otherwise the prover is
                            committing to nothing and can pick its answer once the reveals arrive.
  4. reveal     challenger  (S_i, R_i). Every verifier recomputes the blob from them and checks it equals the
                            one published at step 2, then checks the commitment.
                            MUST be published strictly after the commit, or the prover reads S off the record
                            and never touches a TPM.

`height` below is whatever the deployment uses for agreed ordering — a block height in a replicated ledger, a
sequence number in a log. What it must NOT be is a wall clock or the prover's own claim. Note that same-height
is not "after": two messages in one block have no ordering that verifiers agree on, so the checks are strict.

WHO CHALLENGES. Not whoever the prover asks — a prover that picks its own challengers picks parties that will
leak S to it. The set is DRAWN from a weighted pool by an unpredictable beacon keyed on the enrolment id, and
the prover must recover EVERY drawn challenger's secret. Forgery then requires all k of them to collude, which
is a property the system can observe, rather than a key someone promises to guard.

WHAT AN ENROLMENT CONFERS. Nothing by itself. It records that a specific attestation key lives in a specific
vendor-certified chip. Admission still requires a FRESH TPM2_Certify under that key over a challenge bound to
the moment (posea.tpm.verify_certify), and the identity binds to the ENDORSEMENT key — so enrolling ten
attestation keys in one chip yields one identity, not ten.

See SPEC.md section 9.
"""
import hashlib

from .tpm import aik_name, credential_commitment, make_credential, validate_aik_pub_area


def _h(*parts: bytes) -> str:
    """Domain-separated SHA-256 over length-prefixed parts, hex. Length prefixes rather than concatenation:
    without them ("ab", "c") and ("a", "bc") hash alike, and an id or a draw that collides across differently
    split inputs is an attacker's degree of freedom."""
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.hexdigest()


STATE_OPEN = "open"          # published, waiting for its challengers
STATE_COMMITTED = "commit"   # the prover answered; waiting for the reveals
STATE_PROVEN = "proven"      # every secret reproduced its blob and the commitment holds


def enrol_id(domain: str, ek_identity: str, aik_name_hex: str) -> str:
    """The enrolment's key. Derived from its own public content, so it is the same for every verifier, cannot
    be chosen by the prover, and re-publishing the identical (chip, key) pair collides instead of opening a
    second enrolment.

    `domain` separates deployments — a system identifier, and in a chain that resets, its generation too. An
    enrolment from one deployment MUST NOT replay onto another; without a domain in the digest, the same chip
    and key yield the same id everywhere, and a record captured from one system is a valid record in the next.
    """
    return _h(b"posea/enrol-id", domain.encode(), bytes.fromhex(ek_identity),
              bytes.fromhex(aik_name_hex))[:32]


def challenger_set(enrol_id_hex: str, weights: dict, beacon: str, k: int) -> list:
    """The `k` challengers for one enrolment: a weighted draw WITHOUT replacement, keyed on the beacon and
    the enrolment id.

    `weights` is {challenger id: positive integer weight}. What the weight MEANS is the deployment's choice,
    but it must be something an adversary cannot manufacture cheaply — in the reference deployment it is
    bonded stake. An UNWEIGHTED draw over a permissionless set is the obvious mistake: cheap identities crowd
    the ballot, and the adversary who can mint them draws its own challengers, which is the entire attack.

    `beacon` must be unpredictable before the enrolment was published and agreed by every verifier. If the
    prover can predict or grind it, the prover chooses its own challengers.

    Without replacement, because the point is INDEPENDENT parties: seating one challenger twice lets it hold
    two of the k secrets and cuts the collusion it takes to forge.

    Returns fewer than k (possibly none) when the set cannot supply k distinct weighted entries. The caller
    MUST refuse an enrolment whose set is short — a smaller set is a weaker proof, and an adversary able to
    shrink the challenger pool must not thereby weaken what forgery costs.
    """
    cumulative, total = [], 0
    for address in sorted(weights):
        w = int(weights[address])
        if w > 0:
            total += w
            cumulative.append((total, address))
    if total == 0:
        return []
    picked, seen = [], set()
    # Bounded attempts: a heavily concentrated weight distribution re-draws the same large holder over and
    # over, and this must terminate identically for every verifier rather than loop until it happens to
    # succeed. Exhausting the attempts returns a short set, which the caller refuses.
    for i in range(k * 16):
        if len(picked) >= k:
            break
        draw = int(_h(b"posea/challenger", str(beacon).encode(),
                      f"{enrol_id_hex}:{i}".encode()), 16) % total
        lo, hi = 0, len(cumulative) - 1
        while lo < hi:                                   # first band with cumulative > draw
            mid = (lo + hi) // 2
            if draw < cumulative[mid][0]:
                hi = mid
            else:
                lo = mid + 1
        addr = cumulative[lo][1]
        if addr not in seen:
            seen.add(addr)
            picked.append(addr)
    return picked


def new_record(ek_identity: str, ek_spki: bytes, aik_name_hex: str, aik_pub: bytes, owner: str,
               height: int, challengers: list) -> dict:
    """The endorsement PUBLIC KEY is stored, not just its digest: every verifier has to re-derive the
    credential blob from the revealed (secret, seed) at step 4, and MakeCredential needs the key itself.
    Keeping it in the record also means the reveal check never re-parses a certificate — the chain was read
    once, when the vendor signature was verified, and every verifier reads the same bytes forever after."""
    return {"state": STATE_OPEN, "ek": str(ek_identity), "ekpub": ek_spki.hex(),
            "name": str(aik_name_hex),
            "pub": aik_pub.hex(), "owner": str(owner), "h": int(height),
            "challengers": sorted(str(a) for a in challengers),
            "blobs": [], "commit": "", "hc": -1, "reveals": [], "hp": -1}


def _pairs(rec: dict, field: str) -> dict:
    """Sorted pair LISTS are stored, never dicts. Most serialisers preserve insertion order, so a record two
    verifiers built with the same content in a different order is two different byte strings for one state —
    which anything that digests that state (a root, a snapshot, a signature over it) reads as disagreement.
    Sorted lists have exactly one encoding."""
    return {p[0]: p[1:] for p in rec.get(field) or []}


def apply_challenge(rec: dict, challenger: str, blob: bytes, enc_secret: bytes, height: int) -> dict:
    """Step 2. Refuses anyone not drawn, a second challenge from the same challenger, and any challenge not
    published strictly after the enrolment — the challenger must have SEEN the key's name to seal to it.
    Same height is not "after": messages sharing a height have no order that verifiers agree on."""
    assert rec.get("state") == STATE_OPEN, "enrolment is no longer accepting challenges"
    assert challenger in rec["challengers"], "not a drawn challenger for this enrolment"
    assert int(height) > int(rec["h"]), "a challenge must be published after the enrolment"
    have = _pairs(rec, "blobs")
    assert challenger not in have, "this challenger already challenged this enrolment"
    assert 0 < len(blob) <= 1024 and 0 < len(enc_secret) <= 1024, "credential sizes out of bounds"
    rec = dict(rec)
    rec["blobs"] = sorted(rec["blobs"] + [[challenger, blob.hex(), enc_secret.hex(), int(height)]])
    return rec


def apply_commit(rec: dict, sender: str, commitment: str, height: int) -> dict:
    """Step 3. The prover answers. EVERY drawn challenger must already have challenged, and this must be
    published strictly after the last of them — a commitment racing a challenge is a commitment to a secret
    the prover has not been asked for yet, which is worth nothing."""
    assert rec.get("state") == STATE_OPEN, "enrolment is not awaiting a commitment"
    assert sender == rec["owner"], "only the identity that opened an enrolment may answer it"
    blobs = _pairs(rec, "blobs")
    assert set(blobs) == set(rec["challengers"]), "not every drawn challenger has issued its challenge"
    assert int(height) > max(int(v[2]) for v in blobs.values()), \
        "the commitment must be published after every challenge"
    assert isinstance(commitment, str) and len(commitment) == 64 and _is_hex(commitment), "malformed commitment"
    rec = dict(rec)
    rec["state"], rec["commit"], rec["hc"] = STATE_COMMITTED, commitment.lower(), int(height)
    return rec


def apply_reveal(rec: dict, challenger: str, secret: bytes, seed: bytes, height: int) -> dict:
    """Step 4. A challenger opens its own challenge and every verifier re-derives the blob from (S, R). This
    is where the challenger is held to what it published: it cannot reveal a secret other than the one it
    sealed, because MakeCredential is deterministic in (seed, name, secret) and the blob is already on the
    record. When the last one lands, the commitment is checked and the enrolment is proven."""
    assert rec.get("state") == STATE_COMMITTED, "enrolment is not awaiting reveals"
    assert int(height) > int(rec["hc"]), \
        "a reveal must be published after the commitment — otherwise the prover reads the secret off the record"
    blobs = _pairs(rec, "blobs")
    assert challenger in blobs, "this challenger has nothing to reveal for this enrolment"
    assert challenger not in _pairs(rec, "reveals"), "this challenger already revealed"
    published = bytes.fromhex(blobs[challenger][0])
    name = bytes.fromhex(rec["name"])
    derived, _ = make_credential(bytes.fromhex(rec["ekpub"]), name, secret, seed=seed)
    assert derived == published, "the revealed secret and seed do not reproduce the published challenge"
    rec = dict(rec)
    rec["reveals"] = sorted(rec["reveals"] + [[challenger, secret.hex(), seed.hex(), int(height)]])
    if len(rec["reveals"]) == len(rec["challengers"]):
        # THE COMMITMENT IS OVER ALL THE SECRETS AT ONCE, in challenger order. One commitment per secret
        # would let a prover answer the challenges it managed to open and abandon the rest, which is exactly
        # the k-of-k requirement dissolving into 1-of-k.
        joined = b"".join(bytes.fromhex(r[1]) for r in rec["reveals"])
        assert credential_commitment(joined) == rec["commit"], \
            "the prover's commitment is not to the secrets its challengers sealed"
        rec["state"], rec["hp"] = STATE_PROVEN, int(height)
    return rec


def proven_key(rec: dict) -> str:
    """The attestation key this enrolment proved, as `<endorsement identity>:<attestation key name>`. Bind
    identity on the EK half — one chip, one identity, however many keys it enrols — and use the name half to
    find the public area a later certify must verify under."""
    assert rec.get("state") == STATE_PROVEN, "enrolment is not proven"
    return f"{rec['ek']}:{rec['name']}"


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def validate_publication(ek_identity: str, aik_pub: bytes) -> str:
    """Step 1's content check. The endorsement chain is verified separately, with a lenient X.509 parser (see
    the note in posea/tpm.py and SPEC.md section 9.3); what is left is the public area a chip is about to
    vouch for.

    ENROLLING AN UNRESTRICTED KEY WOULD END THE WHOLE SCHEME: such a key signs whatever the host hands it,
    including a forged TPMS_ATTEST for a key that never existed in any chip, and verify_certify would then
    accept that forgery under a genuinely enrolled name. `restricted` is the single attribute the whole design
    rests on — a restricted key signs ONLY structures the TPM itself generated."""
    assert isinstance(ek_identity, str) and len(ek_identity) == 64 and _is_hex(ek_identity), \
        "malformed endorsement identity"
    assert 0 < len(aik_pub) <= 2048, "attestation public area out of bounds"
    return validate_aik_pub_area(aik_pub)


def aik_name_hex(aik_pub: bytes) -> str:
    return aik_name(aik_pub).hex()
