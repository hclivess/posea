"""The same TPM, reached the Windows way: TBS for commands, the registry for the endorsement certificate.

`tpm_device.Tpm` speaks TCG part 3 and only its `transmit` is transport, so Windows support is a subclass
and nothing else changes. What is NOT a subclass is finding the endorsement certificate, and that turned
out to be the harder half of the platform — see below.

MEASURED ON REAL SILICON (AMD fTPM 3.92.0.5, Windows 11, 2026-09-11). Every claim in this module is
something that machine did, not something a specification promised:

  * the endorsement certificate was in the registry EKCertStore and NOWHERE else. TPM2_NV_Read of the
    standard EK certificate indices returned nothing, and all four NCrypt PCP properties
    (PCP_EKNVCERT, PCP_EKCERT, PCP_RSA_EKNVCERT, PCP_RSA_EKCERT) came back empty. A reader that consults
    only the NV indices — which is what the TCG profile tells you to do — concludes the machine has no
    certificate and refuses a perfectly good chip.
  * the registry value is not a certificate. It is a Windows *serialized certificate*: a run of property
    records, with the DER in the one tagged propId 32. Feeding the whole blob to an X.509 parser fails in
    a way that reads as "this machine has a corrupt certificate" rather than "this is a different
    structure".
  * the certificate chains to the vendor root only by walking AIA. The leaf was published at no vendor
    URL; each issuer had to be fetched from the AIA extension of the certificate below it.
  * TPM2_Create under the endorsement key is REFUSED: TPM_RC_HANDLE (0x8b). The EK is
    restricted|decrypt|adminWithPolicy and this chip will not parent a key under it, which forecloses any
    design that tries to certify an attestation key by descent from the EK.
  * TPM2_ActivateCredential against that adminWithPolicy EK, via a PolicySecret session on the
    endorsement hierarchy, WORKS and consumes no authorisation attempts. Three credentials were opened in
    three separate runs with the chip's LockoutCount unchanged at 0 of 32 throughout. That cost mattered
    to know in advance and could only be established by doing it.

WHAT NOT TO USE. Windows' own NCryptCreateClaim looks like it should short-circuit all of this. It does
not: it mints a fresh per-call signer whose certificate no verifier has ever seen, so the output is
unverifiable by anyone who was not present when it was produced. That format is decoded at
https://github.com/hclivess/windows-tpm-claim-format if you need to confirm it for yourself.
"""
import ctypes
import threading

from .tpm_device import Tpm, TpmError

# Tbsi_Context_Create takes a TBS_CONTEXT_PARAMS2 whose version is 2 and whose flags request the
# TPM 2.0 interface. Version 1 exists and yields a TPM 1.2 context on a machine that has both.
_TBS_CONTEXT_VERSION_TWO = 2
_TBS_TPM_VERSION_20 = 2
_TBS_COMMAND_LOCALITY_ZERO = 0
_TBS_COMMAND_PRIORITY_NORMAL = 200
_TBS_SUCCESS = 0

# A response buffer must be big enough for the largest reply we ask for. TBS does not grow it: it fails
# with TBS_E_BUFFER_TOO_SMALL and the command is spent.
_MAX_RESPONSE = 4096

_EK_CERT_STORE = r"SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates"

# CERT_CERT_PROP_ID — the property record inside a serialized certificate blob that holds the DER.
_CERT_CERT_PROP_ID = 32


class _TbsContextParams2(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("flags", ctypes.c_uint32)]


class WindowsTpm(Tpm):
    """A TPM driven through TBS. Identical command bytes, different pipe.

    Deliberately does NOT call Tpm.__init__: that opens a character device, which is the one part of the
    base class that is Linux. Everything below `transmit` in tpm_device is shared."""

    def __init__(self):
        self.path = "TBS"
        self._lock = threading.Lock()
        self._tbs = ctypes.WinDLL("tbs.dll")
        params = _TbsContextParams2(_TBS_CONTEXT_VERSION_TWO, _TBS_TPM_VERSION_20)
        self._ctx = ctypes.c_void_p()
        rc = self._tbs.Tbsi_Context_Create(ctypes.byref(params), ctypes.byref(self._ctx))
        if rc != _TBS_SUCCESS:
            # 0x8028400F is TBS_E_TPM_NOT_FOUND, which on a desktop usually means fTPM/PTT is off in the
            # firmware rather than that the machine has no TPM at all.
            raise TpmError(rc, "Tbsi_Context_Create")

    @staticmethod
    def present() -> bool:
        """True when a TPM 2.0 context can actually be opened — not merely when tbs.dll exists, which it
        does on every Windows install including machines with the chip disabled in firmware."""
        try:
            tpm = WindowsTpm()
        except Exception:
            return False
        tpm.close()
        return True

    def close(self):
        try:
            if getattr(self, "_ctx", None):
                self._tbs.Tbsip_Context_Close(self._ctx)
                self._ctx = None
        except Exception:
            pass

    def transmit(self, cmd: bytes) -> bytes:
        with self._lock:
            out = ctypes.create_string_buffer(_MAX_RESPONSE)
            out_len = ctypes.c_uint32(_MAX_RESPONSE)
            rc = self._tbs.Tbsip_Submit_Command(
                self._ctx,
                ctypes.c_uint32(_TBS_COMMAND_LOCALITY_ZERO),
                ctypes.c_uint32(_TBS_COMMAND_PRIORITY_NORMAL),
                ctypes.c_char_p(cmd), ctypes.c_uint32(len(cmd)),
                out, ctypes.byref(out_len),
            )
            if rc != _TBS_SUCCESS:
                raise TpmError(rc, "Tbsip_Submit_Command")
            return out.raw[:out_len.value]


def der_from_serialized(blob: bytes):
    """The DER certificate inside a Windows serialized-certificate blob, or None.

    The blob is a run of {propId u32, encodingType u32, length u32, data[length]} records and the
    certificate is the one tagged propId 32."""
    off = 0
    while off + 12 <= len(blob):
        prop = int.from_bytes(blob[off:off + 4], "little")
        length = int.from_bytes(blob[off + 8:off + 12], "little")
        off += 12
        if off + length > len(blob):
            break
        if prop == _CERT_CERT_PROP_ID and length > 64 and blob[off] == 0x30:
            return blob[off:off + length]
        off += length
    # FALL BACK TO SHAPE. A blob whose records we could not walk still contains the certificate, and
    # refusing a machine over a parse detail is the wrong outcome: find the DER by its own header
    # (SEQUENCE, long form, two length bytes) and let the X.509 parser be the thing that rejects it.
    i = 0
    while i + 4 < len(blob):
        if blob[i] == 0x30 and blob[i + 1] == 0x82:
            n = int.from_bytes(blob[i + 2:i + 4], "big") + 4
            if n > 256 and i + n <= len(blob):
                return blob[i:i + n]
        i += 1
    return None


def ek_certificates_from_registry():
    """Every endorsement certificate Windows holds for this machine's TPM, as DER.

    This is the ONLY place an AMD fTPM's certificate was found: the NV indices the TCG profile names were
    empty, and so were all four NCrypt PCP properties. Read-only, needs no elevation, and returns [] on a
    machine that has none rather than raising — "no certificate" is an answer, not a failure."""
    import winreg
    out = []
    try:
        store = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _EK_CERT_STORE, 0, winreg.KEY_READ)
    except OSError:
        return out
    try:
        for index in range(64):
            try:
                name = winreg.EnumKey(store, index)
            except OSError:
                break
            try:
                with winreg.OpenKey(store, name, 0, winreg.KEY_READ) as child:
                    blob, _kind = winreg.QueryValueEx(child, "Blob")
            except OSError:
                continue
            der = der_from_serialized(bytes(blob))
            if der:
                out.append(der)
    finally:
        store.Close()
    return out


def open_tpm():
    """The platform's TPM, whichever platform this is. Import-safe on Linux: WindowsTpm is only
    constructed when we are actually on Windows, so this module can be imported anywhere."""
    import sys
    if sys.platform == "win32":
        return WindowsTpm()
    return Tpm()
