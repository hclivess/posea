# Cover note to editors

Sent with the submission. Kept in the repo so the claims in it stay in step with the paper — an earlier
draft of this note asserted an open problem the paper no longer has.

---

Dear editors,

A note on scope, since I think this paper sits near the boundary of the archive.

It does not propose a new cryptographic primitive. It makes a protocol observation and builds on it: that
`TPM2_MakeCredential`'s credential blob is a deterministic function of its (seed, object name, secret)
triple, so a challenge issued once can be recomputed offline by every verifier afterwards, indefinitely.
That turns an inherently interactive possession proof into an artifact anyone can re-derive, which means
the privacy certificate authority that TPM attestation has always required can be replaced by an agreed
publication *order* — four messages, with a commit–reveal across k challengers drawn by a public beacon.
Nothing is signed and no long-lived key exists anywhere in the construction.

The motivation is not theoretical. Across 664 device-attestation attempts on a live deployment, 26.8%
came from machines with healthy TPM 2.0 hardware that no platform will certify, because the vendor's
attestation service has no authority registered for the chip and returns HTTP 404; on Linux no such
service has ever existed. Those machines hold a vendor-signed endorsement certificate, so the hardware
evidence exists and verifies offline. What was missing was one statement, and the standard way to obtain
it is to ask an authority that is not answering.

The paper also argues a negative result about a class of defences: per-identity admission rules cannot
resist Sybil identity farming, because their cost is linear in the number of identities and therefore
neutral between an honest participant holding one and an adversary holding many. The measurements are
from deployment rather than simulation — approximately 1,000 of 1,191 registered identities belonged to
two or three operators running browser farms on rented servers, capturing roughly 42% of emission before
the change. I apply that argument to my own mechanism as well and state, in the paper, that hardware
admission does not escape it: a device costs money, n devices cost n times as much, and a device farm is
the ASIC of the scheme. What it changes is the constant, which in this case was the entire problem.

I have not claimed to resolve the residual security question, and I want to be exact about which one it
is, because an earlier version of this note named the wrong one. It is not secure-element key extraction:
extraction from a chip an adversary physically holds yields the one identity that chip already had, and a
technique generalising across a whole chip family still yields one identity per chip *obtained*, because
certifying a key the vendor never certified requires the vendor's own key. The assumption that actually
carries the construction is vendor certificate authority integrity — a compromised vendor signing key
mints unlimited distinct identities that no uniqueness rule can detect, silently. I state that as the
open problem and propose per-issuer issuance observability as the direction I think most likely to
address it. I would welcome the community's help with it.

If you judge this outside the archive's scope, I will accept that without argument. The implementation,
specification, pinned roots and tests are public at github.com/hclivess/posea, including an end-to-end
run against a TPM 2.0 simulator and a physical AMD firmware TPM.

Thank you for your time.

Jan Kučera
