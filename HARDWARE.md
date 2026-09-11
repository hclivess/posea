# What a real TPM actually does

Everything here was measured on hardware, not read from a specification. Where a specification says one
thing and the chip does another, the chip is recorded and the specification is noted as wrong for this
part. Each item names how to reproduce it.

**Reference machine:** AMD fTPM 3.92.0.5, Windows 11. `ManufacturerIdTxt` `AMD`, `ManufacturerId`
1095582720. Measured 2026-09-11, across four independent enrolment runs.

---

## 1. The endorsement certificate is not where the profile says it is

The TCG EK Credential Profile puts the certificate in NV. On this machine NV is empty:

| source | result |
|---|---|
| `TPM2_NV_Read` 0x01C00002 (RSA EK cert) | empty |
| `TPM2_NV_Read` 0x01C0000A (ECC EK cert) | empty |
| NCrypt `PCP_EKCERT` | 8 bytes — empty |
| NCrypt `PCP_RSA_EKCERT` | 8 bytes — empty |
| NCrypt `PCP_EKNVCERT` | 8 bytes — empty |
| NCrypt `PCP_RSA_EKNVCERT` | 8 bytes — empty |
| **Windows registry `EKCertStore`** | **1322-byte blob — the certificate** |

```
HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates\<thumbprint>\Blob
```

On the reference machine the thumbprint is `766A04F0CD177832F2BD991A4B3697F14AFA0766`.

**Consequence for implementers.** A reader that consults only the NV indices — which is what the profile
tells you to do — concludes this machine has no endorsement certificate and refuses a perfectly good
chip. There is no Linux equivalent of this store; see §5.

## 2. The registry value is not a certificate

It is a Windows *serialized certificate*: a run of property records, little-endian.

```
{ propId u32 | encodingType u32 | length u32 | data[length] }
```

Observed layout on the reference machine, `encodingType` 1 on every record:

| propId | length | meaning |
|---|---|---|
| 92 | 4 | key length, `0x00080000` = 2048 |
| 3 | 20 | `CERT_SHA1_HASH_PROP_ID` — the thumbprint |
| **32** | **1262** | **the DER certificate**, beginning `30 82 04 EA` |

**There is no terminator record.** The blob simply ends — here at exactly 1322 bytes. A parser must
treat `offset == length` as success, not as a truncated record.

Handing the whole blob to an X.509 parser fails in a way that reads as *"this machine has a corrupt
certificate"* rather than *"this is a different structure"*, which is a misdiagnosis that sends the
owner to fix their hardware.

`posea/tpm_windows.py:der_from_serialized` walks the records and falls back to locating the DER by its
own header if the records cannot be walked — refusing a machine over a parse detail is the wrong
outcome.

## 3. The chain exists only over AIA

The certificate chains `EK → CN=PRG-RN, O=Advanced Micro Devices → CN=AMDTPM` (self-signed root).

Neither intermediate is in **any** Windows certificate store. Both `LocalMachine` and `CurrentUser` were
searched across `Root`, `CA`, `My`, `TrustedPeople`, `AuthRoot`, `Disallowed`, `SmartCardRoot`, `Trust`,
`EnterpriseTrust` and `TrustedPublisher`. They arrive only by fetching the AIA extension of the
certificate below:

```
leaf   → http://ftpm.amd.com/pki/aia/CC5AB663EE845CA9654A582121F50381   → PRG-RN
PRG-RN → http://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121   → AMDTPM root
CRL      http://ftpm.amd.com/pki/crl
OCSP     http://ftpm.amd.com/pki/ocsp
```

Walk each certificate's own AIA extension. Do not hardcode these paths: they are per-issuer, and the
leaf's URL is specific to this chip's issuing CA.

**Parse AIA by its declared length, not by scanning to a delimiter.** The URL is an IA5String; reading
"graphic characters until something that is not one" truncates real URLs and produces a fetch that 404s.

## 4. The root, pinned by three independent acquisitions

```
sha256 67bd2472a546751caca5f358a78f80727531671338960a9bcfdfbe6a34d0c6a1
SHA-1  E01AEF00737AB32F28F3374EB2EA72A682DE45C1
```

Three acquisitions agree byte for byte, and they are independent in a way worth stating because a pin
checked against itself proves nothing:

1. the reference machine's own Windows AIA cache, **dated 2026-09-04** — months before this work began;
2. a fresh AIA fetch on a different machine during this work;
3. the constant already compiled into the NADO deployment.

## 5. Linux has no equivalent, and this is a gap rather than parity

AIA yields **intermediates only**. The leaf certificate is published at no vendor URL — it exists on the
machine or not at all. So a Linux box whose NV indices are empty has no endorsement certificate and no
way to obtain one, and there is no `EKCertStore` to fall back to.

Supplying the certificate out of band (`ek.cer` beside the binary) is the only answer today. Do not
claim platform parity: Windows can recover a certificate that Linux cannot.

## 6. The endorsement key will not act as a storage parent

```
TPM2_Create under the EK → TPM_RC_HANDLE (0x0000008b)
```

Rejected at *handle validation*, before the template or the policy is examined. An AMD fTPM will not
parent a key under its endorsement key.

This is load-bearing: it forecloses the whole family of designs that try to prove an attestation key is
in the chip by *descent* from the EK — create the AIK as a child of the EK, certify the creation, and
hand over one self-contained blob. Such a design is also unsound for a separate and more fundamental
reason (see `SPEC.md` — `parentName` is a claim inside a structure signed by the claimant, so a software
key reproduces it), but on this hardware it does not even reach the point of being unsound. It is
refused.

## 7. ActivateCredential works against an adminWithPolicy EK, and costs nothing

The EK is `restricted | decrypt | adminWithPolicy`: it cannot sign, and it cannot be used with a
password session. The credential is opened through a `PolicySecret` session on the endorsement
hierarchy.

```
TPM2_StartAuthSession  → policy session
TPM2_PolicySecret(TPM_RH_ENDORSEMENT, session)
TPM2_ActivateCredential(activateHandle=AIK, keyHandle=EK, [pw, policy]) → the secret
```

**It works, and it consumes zero authorisation attempts.** `LockoutCount` was 0 of 32 before and after,
across four separate rounds in which three credentials were opened each time. `LockedOut` never became
true.

That cost could not be known in advance and it mattered: a dictionary-attack counter that advanced on
each attempt would put a hard ceiling on retries and make every failed enrolment expensive. It does not.

**Note on the second handle.** `TPM2_ActivateCredential` takes two handles, and only the *first* takes
authorisation. Supplying two sessions yields a session-2 handle error (`0x0000098b` family). The
authorisation area carries the password session for the AIK and the policy session for the EK.

## 8. Windows' own claim API is not a shortcut

`NCryptCreateClaim` looks like it should replace all of the above. It does not: it mints a fresh
per-call signer whose certificate no verifier has ever seen, so the output cannot be verified by anyone
who was not present when it was produced. The format is decoded at
<https://github.com/hclivess/windows-tpm-claim-format>.

## 9. Comparing an EK public key to a certificate

`Get-TpmEndorsementKeyInfo -Hash Sha256` reports a `PublicKeyHash`. It is the sha256 of the
certificate's **SubjectPublicKeyInfo BIT STRING contents** — the `RSAPublicKey` DER,
`SEQUENCE { modulus, exponent }`.

On the reference machine:

```
correct   sha256(SPKI BIT STRING contents) = 35ad3a003d3d176985dc78985fb5a0f73b720e3a95b4a530a42ba73c21ed8b82
wrong     sha256(bare modulus)             = 417e305a...
wrong     sha256(0x00 || modulus)          = b0089ce1...
```

Match this convention when comparing against `TPM2_ReadPublic`, or a correct chip looks like a mismatched
one.
