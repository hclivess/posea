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
| FIDO2 security key | `packed` | batch certificate, one per ≥100k units | No |
| Apple Secure Enclave | `apple` | passkeys return `fmt: none` | No |

FIDO2 batch certificates identify a *model*, not a *unit*, so one-identity-per-device is not
enforceable for them. Apple passkeys carry no attestation at all through a web page (confirmed
2026-09-07). Both are refused: what cannot be bound is not proof of anything.

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

**We cannot bound the cost of extracting an attestation key from a secure element, and whether that
cost is per-model or generalises across a chip family.**

If extraction is per-model and expensive, device scarcity holds and an adversary must buy devices.
If one extraction generalises across a family, the adversary gains an oracle for minting
attestations, and the construction degrades into the identity farm it was built to prevent — while
having excluded honest modified devices in the meantime.

We are not aware of a satisfying public treatment at the granularity this design needs. If you have
data on it, that is the single most useful thing you could contribute here, including if it shows
the assumption fails.

## Repository contents

```
paper/posea.tex     the write-up, submission-formatted
SUBMISSION.md       how to compile and where to submit it
SPEC.md             normative specification
posea/_parse.py     attestation parsing and the per-device binding handle
roots/              pinned vendor attestation roots (PEM)
tests/              binding-handle tests
```

The parsing core is extracted from the NADO deployment (`ops/device_attest.py`), where chain
signature verification runs in a native kernel. This repository carries the parsing, the binding
rule and the specification; it is a reference for the mechanism, not a drop-in validator.

## Status

Deployed on NADO's betanet since 2026-09-07. Pre-mainnet. There is no token, no sale and nothing
to purchase; this repository exists so the mechanism can be evaluated on its own terms.

## Licence

AGPL-3.0, matching the implementation it is extracted from.
