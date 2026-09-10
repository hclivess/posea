# PoSEA specification

Normative description of the admission mechanism. Extracted from the NADO deployment
(`doc/device-attestation.md`), generalised so it does not depend on that chain.

Key words MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.

---

## 1. Roles

- **Verifier.** Any party validating an admission. In a replicated system, every node.
- **Prover.** A device seeking admission for an identity.
- **Beacon.** A source of values that are unpredictable in advance and agreed by all verifiers.

## 2. Admission

An identity is admitted for one lease period if a verifier accepts an attestation satisfying all
of:

1. **Hardware residency.** The credential key was generated inside a secure element and is
   non-exportable.
2. **Freshness.** The signed challenge is derived from a beacon value that the prover could not
   have predicted at key-generation time.
3. **Chain validity.** The attestation certificate chain terminates at a root in the pinned root
   set (§4), every signature verifies, and every certificate is within its validity window as
   evaluated at the anchor time (§5).
4. **Boot integrity.** For classes that report it, the attested state MUST indicate
   `deviceLocked` and `verifiedBootState == Verified`, and the key's security level MUST be
   TEE or StrongBox.
5. **Binding uniqueness.** If the class yields a per-device handle (§3), that handle MUST NOT be
   bound to a different identity with a live lease.

A prover failing any condition MUST be refused. There is no partial admission.

## 3. Per-device binding handle

The handle is the value that makes "one device, one identity" enforceable. It is derived purely
by parsing bytes whose signatures have already been verified, and MUST be deterministic.

| `fmt` | Handle | Rationale |
|---|---|---|
| `android-key` | `"android-key:" + SHA256(x5c[1])` | With remote key provisioning (Android 12+), `x5c[1]` is the device's attestation certificate, reused for every credential until rotation |
| `tpm` | `"tpm:" + SHA256(x5c[0])` | The AIK certificate is unique to (physical TPM, account) |
| anything else | REFUSED | No per-device value exists |

### 3.1 Rejecting batch-attested Android

A pre-RKP Android device carries a long-lived intermediate shared by up to 100,000 units. It is
distinguished from a per-device certificate by validity span: implementations MUST reject an
`android-key` statement whose `x5c[1]` validity span exceeds a configured maximum
(`max_cert_secs`; the reference deployment observes ~13 days for genuine RKP certificates).

A shared certificate bound to one identity would lock out every other owner of the same model.

### 3.2 Refused classes

- **FIDO2 (`packed`).** FIDO privacy rules mandate one batch certificate per ≥100,000 units.
  Identifies a model, not a unit.
- **Apple (`apple`).** Passkeys return `fmt: none` and carry no attestation through a web page
  (iOS 16+, macOS 13+). A native App Attest bridge is the only route to a per-device key.

## 4. Roots are constants

Verifiers MUST pin roots by SHA-256 over DER. Roots MUST NOT be fetched at validation time, MUST
NOT be learned from peers, and MUST change only by an explicit, agreed update.

Reference pinned set (SHA-256 over DER):

```
0915dd5c07a28db549d1f677bb5a75d4bfbe9561a773424327762e9e02f9bb29  Apple WebAuthn Root CA
cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc  Google HW Attestation Root (2042)
1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc  Google HW Attestation Root (2034)
ab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a  Google HW Attestation Root (2036)
6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0  Google Key Attestation CA1 (2035)
870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da  Microsoft TPM Root CA 2014
```

Where multiple vendors are accepted, each authenticator identifier MUST map to its own roots, so
that a device from one vendor can never present a chain claiming another's.

## 5. Determinism requirements

In a replicated setting, admission is consensus input and MUST be a pure function of agreed data.

- Certificate validity MUST be evaluated against an **agreed anchor time**, never wall clock.
- Revocation lists MUST NOT be consulted at validation time. They are network-dependent and would
  make validation non-deterministic. A compromised intermediate is handled as a root-set change.
- The parser MUST reject duplicate CBOR map keys. Permitting them allows a statement to verify as
  one chain and bind as another.
- A binding operation MUST occupy a per-device uniqueness key within its block, so that two
  provers cannot bind the same device in a single block by checking against parent state only.

Both parser requirements above correspond to holes found and closed in the reference deployment.

## 6. Leases and rotation

Bindings MUST be leased, not permanent, for any class whose attestation key rotates.

Android attestation keys rotate roughly every two weeks; TPM AIK certificates are per account. A
binding outliving the key would let one device bind a fresh identity on each rotation. Renewal
MUST re-attest.

A device MAY move to another identity. Implementations SHOULD make the move immediate and evict
the previous holder, rather than imposing a cooldown: whoever physically holds the device is the
legitimate owner, and a cooldown punishes a genuine transfer more than an adversary.

## 7. What is out of scope

PoSEA is an admission mechanism. It says who may participate. It does not say who wins.

Implementations SHOULD keep attestation weight out of any finality or fork-choice calculation. In
the reference deployment, attestation and presence determine draw weight and reward share only;
they are deliberately excluded from stake weight, fork choice and the finality quorum. Presence
earns reward and never purchases a say in what is final.

## 8. Security assumptions

1. Vendor attestation roots sign only genuine secure elements.
2. Extracting an attestation private key from a secure element is expensive, and that cost does
   not generalise across a hardware family.
3. WebAuthn user activation cannot be automated on a device that can attest.

Assumption 1 is a trust assumption and a centralisation cost. Assumption 3 holds because
automating the tap requires root, and a rooted device cannot attest.

**Assumption 2 is unproven.** See the open problem in `README.md`. If it fails, the construction
degrades to an identity farm with an oracle. Implementers MUST treat it as an open question, not
as an established result.

---

## 9. Attestation without a certificate authority

Sections 1–8 assume the platform produces an attestation. For a large class of machines it does not, and the
reason is not a defect in the hardware.

A WebAuthn `tpm` statement requires `certInfo` signed by the key in `x5c[0]`, so the chip needs an
attestation-key **certificate**. On Windows that means Microsoft's AIK service, which for many otherwise
healthy machines has no authority registered for the chip's KeyId and returns HTTP 404 — service-side, with
no supported client-side remedy. On Linux no such service has ever existed. In the reference deployment this
was **26.8% of every attestation attempt**: a healthy TPM 2.0 and no way to use it.

Those machines carry a vendor-signed **endorsement certificate**. The hardware evidence exists. What is
missing is one statement: *this attestation key lives in that certified chip*.

This section specifies how to obtain that statement with no certificate authority.

### 9.1 Why the shortcuts do not work

Two proposals recur, and both MUST be rejected.

**Sending the endorsement certificate as the proof.** It is public data; anyone who has seen a machine's
certificate can copy it. And the endorsement key **cannot sign**: TCG defines it as a restricted decryption
key (`Key Usage: critical, Key Encipherment`, no `digitalSignature`). It can never occupy the `x5c[0]` slot.

**Deriving the challenge from public data**, to avoid a round trip. Anything every verifier can recompute,
the prover can recompute. The proof would prove nothing.

Proving possession of a decrypt-only key has exactly one shape: send it something only it can decrypt and
observe it come back. That is `TPM2_ActivateCredential`, and it is inherently interactive — which is why TCG
specified the AIK-plus-Privacy-CA model, and why the failing service exists at all.

### 9.2 The construction

A CA turns the interactive proof into a durable artifact by signing it. That works, and it is expensive: a
long-lived key able to assert any endorsement identity is a key able to mint identities, guarded forever.

There is a cheaper way, resting on a property of the TPM command itself:

> **`TPM2_MakeCredential`'s `credentialBlob` is deterministic in `(seed, name, secret)`.** Only the
> OAEP-wrapped seed is randomised, and no verifier needs that half.

So a challenge issued once can be **replayed by every verifier afterwards, offline, forever**:

```
1. challenger  seals secret S under seed R:  blob = MakeCredential(EKpub, aikName, S, seed=R)
2. prover      TPM2_ActivateCredential recovers S      (possible only inside the chip)
               publishes H(S)                           <- commitment
3. challenger  reveals (S, R)
4. verifiers   recompute the blob from (S, R), check it equals the published blob,
               and check the commitment is to that S
```

The prover can only learn `S` by holding the chip, and MUST commit before the reveal, so it cannot read the
answer off the record. **Nothing is signed and no key persists** — nothing to steal, rotate or guard.

### 9.3 Verifying the endorsement chain

The vendor signature is the entire basis for trusting the hardware. A verifier MUST check that `chain[0]`:

1. reaches a root in the pinned **endorsement** root set (§9.7), every signature verifying, evaluated at the
   agreed anchor time (§5);
2. carries the `tcg-kp-EKCertificate` extended key usage (`2.23.133.8.1`);
3. is **not** a CA;
4. is **encipherment-only** — `keyEncipherment` set and `digitalSignature` clear. A certificate claiming
   signing capability is not an endorsement key, and treating one as such would undermine the reason the
   handshake in §9.2 exists.

Client-supplied intermediates are a routing hint. Every link is verified and only pinned roots are trust
input, so a hostile prover gains nothing by supplying its own.

> **Implementation note, and a real obstacle.** Real vendor endorsement certificates are **not strictly DER**.
> AMD encodes `critical: FALSE` explicitly where DER requires the default omitted, and Python's
> `cryptography` refuses the certificate outright with
> `ParseError { kind: EncodedDefault, [..., "Extension::critical"] }`. `openssl` and Rust's `x509-parser`
> accept it. An implementer reaching for the obvious library will conclude the hardware is broken. Use a
> lenient parser — and, in a replicated setting, ONE implementation shared by all verifiers rather than
> whichever library each host has installed.

The **endorsement identity** is `SHA-256` over the leaf certificate's `SubjectPublicKeyInfo`.

### 9.4 The public area a chip may vouch for

Before any challenge is issued, the attestation key's `TPMT_PUBLIC` MUST be checked. Required:
`restricted`, `sign`, NOT `decrypt`, `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, and a real signing
scheme rather than `TPM_ALG_NULL`.

`restricted` is the attribute the entire design rests on. A restricted key signs **only structures the TPM
itself generated**, which is what makes `TPM2_Certify` evidence rather than merely a signature. Enrol an
unrestricted key and that chip can afterwards sign anything its host asks — including a forged `TPMS_ATTEST`
for a key that never existed in any chip — and the verifier would accept the forgery under a genuinely
enrolled name.

The others close narrower holes: without `sensitiveDataOrigin` the private half could have been generated
outside and imported; without `fixedTPM`/`fixedParent` the key can be duplicated to another chip, so one
enrolment would licence every machine it is copied to.

### 9.5 The enrolment is four messages, and none may be merged

The arithmetic of §9.2 is satisfied by a fabrication: a prover with no chip picks a secret and a seed,
computes the blob itself, and every equation holds. **What makes it a proof is the publication order.**

| # | Message | Published by | Ordering requirement |
|---|---|---|---|
| 1 | endorsement chain + attestation public area | prover | — |
| 2 | `blob`, wrapped seed | each drawn challenger | strictly after 1 |
| 3 | `H(S_1 ‖ … ‖ S_k)` | prover | strictly after every 2 |
| 4 | `(S_i, R_i)` | each drawn challenger | strictly after 3 |

Message 2 cannot precede 1: `MakeCredential` seals to a specific key's Name, which is a digest of the public
area. Message 3 must follow every 2, or the prover commits to a secret it has not been asked for. Message 4
must follow 3, or the prover reads `S` off the record and never touches a TPM.

Verifiers MUST treat **equal ordering positions as not ordered**. Two messages in the same block have no
order that verifiers agree on, so each check MUST be strict.

The commitment MUST be over **all** the secrets at once, in a canonical challenger order. One commitment per
secret would let a prover answer the challenges it managed to open and abandon the rest — `k`-of-`k`
dissolving into 1-of-`k`.

An incomplete enrolment MUST expire. A proven one MUST NOT, and MUST NOT be collectable: deleting it would
let one chip enrol again for a second identity.

### 9.6 Challengers are drawn, never chosen

The residual attack is a challenger privately leaking `S` to a prover with no chip.

Therefore verifiers MUST require **`k` independent challengers**, and the prover MUST recover every one of
their secrets. Forgery then requires all `k` to collude — a property the system can observe, rather than a
key someone promises to protect.

The set MUST be **drawn**, not chosen by the prover:

- weighted by something an adversary cannot manufacture cheaply (in the reference deployment, bonded stake).
  An unweighted draw over a permissionless set is the obvious mistake: cheap identities crowd the ballot, and
  an adversary that can mint them draws its own challengers;
- keyed on a **beacon** unpredictable before the enrolment was published and agreed by all verifiers;
- **without replacement** — seating one challenger twice halves the collusion forgery requires;
- refused when short. A smaller set is a weaker proof, and an adversary able to shrink the challenger pool
  MUST NOT thereby weaken what forgery costs.

`k = 3` is the smallest value where no single challenger can admit identities alone.

### 9.7 Endorsement roots are a separate set

Endorsement roots answer *"did a silicon vendor certify this chip"*. The roots of §4 answer *"did a vendor
sign this attestation statement"*. These are different assertions and the sets MUST NOT be merged: no vendor
ever made the other claim.

```
67bd2472a546751caca5f358a78f80727531671338960a9bcfdfbe6a34d0c6a1  AMD fTPM — CN=AMDTPM (2039)
beb40bb7507b33967226aa80e084749fbb6593893c642e818d682e9a8d07fc24  Intel PTT — OnDie CA Root (2049)
4aebe77a51ed29959a7f9f5e07a24a558dee8167f3985d724995a541c258dfda  Nuvoton TPM Root CA 2110 (2035)
cd8185ff8995ed09811970090a8c36fafab34ef87f47fa51fdb9ecf95c9c2e04  Nuvoton TPM Root CA 2111 (2037)
899e35474c9807eb4c7f2f7a12da0028fb250cd02154d0009fca7d9c66574f3b  Infineon OPTIGA RSA Root (2043)
cfeb02fecd55ad7a73c6e1d11985d4c47dee248ab63dcb66091a2489660443c3  Infineon OPTIGA ECC Root (2043)
```

Each was fetched from the vendor's own PKI and confirmed self-signed. **STMicroelectronics is deliberately
absent:** the certificate published as "STM TPM EK Root CA" is cross-signed by GlobalSign and is therefore an
intermediate. Pinning it would be a decision to trust GlobalSign's Trusted Computing CA — a different
assertion from "ST made this chip". Verifiers MUST confirm a candidate root is self-signed before pinning it.

### 9.8 Admission still requires a fresh certify

An enrolment records that an attestation key lives in a certified chip. It says nothing about *when*, and a
proof from last year is not evidence the machine still exists.

Each admission MUST therefore present a fresh `TPM2_Certify` under the enrolled key, and verifiers MUST check:

1. `certInfo` begins with `TPM_GENERATED` (`0xFF544347`);
2. its type is `TPM_ST_ATTEST_CERTIFY` (`0x8017`) — a different type places different fields at these
   offsets, so accepting one would mean reading some other structure as if it were this one;
3. `extraData` equals the challenge bound to this admission (§2 freshness);
4. the certified object's Name is the **enrolled key's own**, not another object in the chip;
5. the signature verifies under the enrolled public area.

PKCS#1 v1.5 verification MUST compare the **entire re-encoded block**. An implementation that searches for
the digest inside the padding accepts trivial forgeries against small exponents (Bleichenbacher, 2006), a bug
real libraries have shipped more than once.

### 9.9 Binding, and what this costs

The binding handle is the **endorsement identity** (§9.3), never an attestation key. A chip holds unlimited
attestation keys, so binding to one would hand a single machine an identity per enrolment. Regenerating the
endorsement seed to fake a new chip changes the endorsement key, and the vendor's certificate no longer
matches it, so the fake cannot enrol at all.

Two costs, stated plainly:

**The human tap is gone.** §8 assumption 3 does not apply here: enrolment and renewal are automatic, which is
required for headless machines and also means a farm's chips cost nothing to keep running. Identity *count*
is unchanged — one chip, one identity — but the Sybil question collapses onto **the price of a chip**.

**Which roots are pinned therefore becomes the whole dial**, and it only reverses in the widening direction.
A discrete TPM module is ~£15; a CPU-vendor fTPM implies a whole machine. Narrowing the set later strands
everyone already enrolled under the wider one. Implementations SHOULD choose deliberately and document the
choice, rather than pinning every root they can find.

The open problem of §8 assumption 2 applies here unchanged, and with more force: extraction from one chip
family would be an admission oracle that no human tap slows down.
