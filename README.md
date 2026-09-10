# PoSEA — Proof of Secure Element Attestation

**Sybil resistance from hardware scarcity rather than hardware cost.**

A reference implementation and specification of PoSEA as a standalone primitive, extracted from
its deployment in [NADO](https://github.com/hclivess/nado) so that it can be read, criticised and
reused without adopting a blockchain.

---

## The problem it addresses

A permissionless system that rewards *participants* rather than *capital* has to decide who counts
as a participant. The usual defences are rules written per identity: a work proof at registration,
a waiting period, a per-address cap, a per-subnet budget, a probation window.

Every one of them fails for the same reason, and the reason is arithmetic rather than
implementation quality.

> Let a rule cost `c` per identity and reward `r` per identity. An adversary with `n` identities
> pays `nc` and earns `nr`. An honest participant with one identity pays `c` and earns `r`. The
> cost-to-reward ratio is `c/r` for both. Raising `c` does not disadvantage the adversary. It
> prices out the honest participant first, because the adversary amortises fixed setup across `n`
> and the honest participant does not.

If minting an identity is something a script can do, then a per-identity rule is a tax the honest
participant pays in full and the farm books as cost of goods.

This is not theoretical. It is the wall NANO hit with representative spam, Idena with its
validation ceremonies, and Nyzo with its cycle. In the NADO deployment it was measured: on
2026-09-06, roughly **1,000 of 1,191** registered mining identities belonged to two or three
operators running headless browser farms on rented servers, capturing about **42% of block
emission**.

## The idea

Stop trying to make identities *expensive*. Make them *scarce*.

Only two things resist replication by an adversary with money but no people: capital, and a
physically distinct object. PoSEA anchors identity in the second.

A device proves it is genuine hardware by generating a non-exportable key inside its secure
element and signing a challenge the verifier chose. The resulting attestation certificate chain
terminates at a vendor root. Where the device class exposes a per-device certificate, that
certificate is bound to one identity at a time.

Verification is **deterministic and offline**. No verifier ever contacts Google, Microsoft or any
vendor. Roots are pinned constants.

## What it proves, and what it does not

**Proves.** The registration was produced on genuine hardware of a stated class, by a key resident
in that hardware, over a challenge that could not be precomputed. On renewal, that the same device
key was present later.

**Does not prove personhood.** One human with one genuine device can create as many identities as
they physically tap, because WebAuthn requires user activation per signature. The security claim
is that an identity costs *non-automatable human work on genuine hardware* — not that identities
map one-to-one onto people.

**Rooting is not the loophole.** A rooted device is exactly what would automate the tap, and a
rooted device cannot attest: Android key attestation reports boot state from the secure element,
and the verifier requires `deviceLocked` and `verifiedBootState == Verified`.

## Device classes

| Class | Format | Per-device handle | Accepted |
|---|---|---|---|
| Android 12+, locked bootloader | `android-key` | `x5c[1]`, the remotely-provisioned attestation certificate (~2 week validity) | Yes |
| Windows, physical TPM 2.0 | `tpm` | AIK certificate, one per (TPM, account) | Yes |
| **Any TPM 2.0, no platform CA** | — | **endorsement key, one per chip** | **Yes** — see below |
| FIDO2 security key | `packed` | batch certificate, one per ≥100k units | No |
| Apple Secure Enclave | `apple` | passkeys return `fmt: none` | No |

FIDO2 batch certificates identify a *model*, not a *unit*, so one-identity-per-device is not
enforceable for them. Apple passkeys carry no attestation at all through a web page (confirmed
2026-09-07). Both are refused: what cannot be bound is not proof of anything.

## The machines no platform will certify

The third row is the largest single failure of the mechanism as first deployed, and it is not a
hardware fault. Measured over 664 admission attempts:

| | share |
|---|---|
| works today (phone / hardware wallet) | 47.9% |
| **TPM healthy, platform will not attest** | **26.8%** |
| user-fixable (a password manager took the ceremony) | 18.8% |
| works today (Windows Hello attests) | 6.5% |

A WebAuthn `tpm` statement needs `certInfo` signed by the key in `x5c[0]`, so the chip needs an
attestation-key **certificate** — which on Windows means Microsoft's AIK service. For a large
population of otherwise healthy machines that service has no authority registered for the chip's
KeyId and answers HTTP 404. Microsoft has confirmed this as service-side, with KeyIds
unregisterable by end users and no supported way to change their trust database. No client-side
change fixes it. On Linux there is no such service and there never has been a path.

Those machines carry a vendor-signed **endorsement certificate** — AMD's chains to `CN=AMDTPM`,
Intel's through the CSME issuing authorities the chip keeps in its own NV. The hardware evidence
exists and verifies offline. What is missing is one statement: *this attestation key lives in
that certified chip*.

### Two shortcuts that do not work

**"Just send the endorsement certificate."** It is public data — anyone who has seen a machine's
certificate can copy it. And the endorsement key **cannot sign**: TCG defines it as a restricted
decryption key, `Key Usage: critical, Key Encipherment`, no `digitalSignature`. It can never
occupy the `x5c[0]` slot.

**"Derive the challenge from public data, so it needs no round trip."** Anything every verifier
can recompute, the prover can recompute. The proof would prove nothing.

Proving possession of a decrypt-only key has exactly one shape: send it something only it can
decrypt and watch it come back. That is `TPM2_ActivateCredential`, and it is inherently
interactive — which is why TCG invented the AIK-plus-Privacy-CA model, and why the service that
is failing exists at all.

### Replacing the authority with an ordering

A CA turns the interactive proof into a durable artifact by signing it. That works, and it is
expensive in a way that has nothing to do with computation: a long-lived key able to assert any
endorsement identity is a key able to mint identities, guarded forever. In a permissionless
system it is also a single party the whole mechanism defers to — which is the objection the
mechanism exists to answer.

There is a cheaper way, and it rests on a property of the TPM command itself:

> **`TPM2_MakeCredential`'s `credentialBlob` is deterministic in `(seed, name, secret)`.** Only
> the OAEP-wrapped seed is randomised, and no verifier needs that half.

So a challenge issued once can be replayed by every verifier afterwards, offline, indefinitely.
The interactive proof does not need to be signed into an artifact; it needs only to be
**ordered** — and a ledger already orders things.

```
1. prover      publishes the endorsement chain + the attestation key's public area
2. challenger  publishes blob = MakeCredential(EKpub, aikName, S, seed=R)   ← one per drawn challenger
3. prover      publishes H(S₁ ‖ … ‖ S_k), having run TPM2_ActivateCredential
4. challenger  publishes (S, R); every verifier recomputes the blob and checks the commitment
```

Nothing is signed and no key persists. There is nothing to steal, rotate or guard.

### The ordering is the proof

The arithmetic above is satisfied by a fabrication: a prover with no chip picks a secret and a
seed, computes the blob itself, and every equation holds. Handed all four messages at once, a
verifier cannot tell the difference.

What separates them is that step 3 was published after every step 2 and before every step 4.
The prover can only learn `S` by holding the chip, and must commit before the reveal, so it
cannot read the answer off the record. Step 2 cannot precede step 1, because MakeCredential
seals to a specific key's Name, which is a digest of the public area published in step 1. Four
messages is minimal; no adjacent pair can be merged.

Two things are easy to get wrong. **Equal positions are not ordered** — two messages in one
block have no order verifiers agree on, so every comparison is strict. And the commitment must
be over **all k secrets jointly**: one commitment per secret would let a prover answer whichever
challenges it managed to open and abandon the rest, which is k-of-k dissolving into 1-of-k.

### Challengers are drawn, never chosen

The residual attack is a challenger privately leaking `S` to a prover with no chip. So the
prover must recover **every** one of `k` challengers' secrets, and the set is drawn — weighted by
something an adversary cannot manufacture cheaply, keyed on a beacon it cannot predict, without
replacement, and refused when short. Forgery then needs all `k` to collude, which is a property
the system can observe rather than a key someone promises to guard.

This is not refused if all k do collude, and we do not claim otherwise. `k = 3` is the smallest
value at which no single challenger can admit identities alone.

### What it costs

**The human tap is gone.** Enrolment and renewal are automatic — required for headless machines,
and also meaning a farm's chips cost nothing to keep running. Identity *count* is unchanged (one
chip, one identity, however many keys it enrols) but the argument shifts: where the WebAuthn path
prices an identity at non-automatable human work on genuine hardware, this path prices it at the
hardware alone.

**So the pinned root set becomes the whole dial**, and it only reverses in the widening
direction — narrowing later strands everyone already enrolled. A discrete TPM module is ~£15; a
CPU-vendor fTPM implies a whole machine. Choose deliberately and say so, rather than pinning
every root you can find.

## The costs, stated plainly

Two, and neither can be argued away.

**Vendor authority enters the trust path.** Verification trusts that Google's and Microsoft's
attestation roots sign only genuine hardware. That is a centralisation cost in a system whose
premise is that no such authority should be needed.

Every Sybil mechanism trusts something: Proof of Work trusts that no coalition holds a hash
majority, an assumption weakening empirically; Proof of Stake trusts that concentrated holders do
not collude. This trusts pinned vendor roots, verified offline, with no service able to revoke a
participant at validation time. That is a *different* trust assumption, not obviously a worse one,
and reasonable people disagree.

**Modified devices are excluded.** A phone whose owner unlocked its bootloader cannot attest. This
disproportionately excludes the people most committed to owning their own hardware — the
constituency most sympathetic to permissionless systems in the first place. There is no clean
answer to this, and a capital-gated fallback lane is not a substitute.

## The open problem

**We cannot bound the cost of extracting an attestation or endorsement key from a secure element,
or say whether that cost is per-model or generalises across a chip family.**

The question is not untouched. TPM-FAIL (USENIX Security 2020) recovered ECDSA private keys from
an Intel fTPM and an STMicroelectronics TPM by timing analysis. faulTPM (arXiv:2304.14717, 2023)
extracted secrets from AMD firmware TPMs by voltage fault injection against the AMD Secure
Processor — a vendor whose root we pin. Samsung's TrustZone keymaster was shown to permit
attestation-relevant key compromise by design error (USENIX Security 2022).

What those establish is that extraction is possible **with physical access to the target
machine**, which prices it per device and hands a remote adversary nothing. What they do not
establish — and what this design needs — is whether any of it generalises to a key producible
without possessing each chip. If extraction stays per-device and expensive, device scarcity holds
and an adversary must buy hardware. If one extraction generalises across a family, the adversary
gains an oracle for minting attestations and the construction degrades into the identity farm it
was built to prevent, having excluded honest modified devices in the meantime.

This bears harder on the CA-free path above, which has no human tap to slow an oracle down.

We are not aware of a satisfying public treatment at the granularity this design needs. If you
have data on it, that is the single most useful thing you could contribute here — including if it
shows the assumption fails.

## Repository contents

```
paper/posea.tex      the write-up, submission-formatted
SUBMISSION.md        how to compile and where to submit it
SPEC.md              normative specification (§9 is the CA-free enrolment)
posea/_parse.py      attestation parsing and the per-device binding handle
posea/tpm.py         credential protection, commit-reveal, certify verification
posea/enrolment.py   the four-message state machine and the challenger draw
posea/tpm_device.py  driving a TPM 2.0 from the prover's side
posea/roots.py       pinned fingerprints, both root sets
roots/               pinned vendor attestation roots (PEM)
roots/ek/            pinned silicon-vendor endorsement roots (PEM)
tests/               binding, credential protection, ordering, and a live TPM
```

`posea/tpm.py` and `posea/enrolment.py` have **no dependencies at all** — KDFa, AES-CFB, MGF1,
RSA-OAEP, PKCS#1 v1.5 and the DER encoding are written out. That is not minimalism for its own
sake: a verifier that must agree byte-for-byte with every other verifier is badly served by
whichever version of a library each host happens to have, and in the deployment this code runs
inside consensus on nodes with no crypto library at all. (`cryptography` appears in the tests, as
an oracle. It is also the library that refuses to parse a real AMD endorsement certificate.)

The parsing core is extracted from the NADO deployment (`ops/device_attest.py`), where chain
signature verification runs in a native kernel. Endorsement-chain verification is likewise not
included here and must use a **lenient** X.509 parser — see SPEC.md §9.3 for why, and for what it
must check.

## Tests

```
python -m unittest discover -s tests -v
```

63 tests. `tests/test_swtpm.py` drives a real TPM 2.0 through the `swtpm` simulator
(`apt install swtpm`) and is skipped when it is absent; it is the only place the byte layouts
meet something that did not come out of this repository. It does not prove any particular
vendor's silicon behaves the same way — a simulator accepts templates a firmware TPM may reject,
and carries no endorsement certificate at all.

## Status

The WebAuthn path is deployed on NADO's betanet since 2026-09-07. The CA-free enrolment is
proven end to end against a TPM 2.0 simulator and against a physical AMD fTPM, and is gated off
pending broader hardware validation. Pre-mainnet. There is no token, no sale and nothing
to purchase; this repository exists so the mechanism can be evaluated on its own terms.

## Licence

AGPL-3.0, matching the implementation it is extracted from.
