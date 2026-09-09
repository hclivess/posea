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
