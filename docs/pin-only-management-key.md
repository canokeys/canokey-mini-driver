# PIN-Only Management Key Research

This note records the current understanding of YubiKey-style PIN-only PIV
management-key handling and the shape that would fit this minidriver.

## Summary

YubiKey PIN-only mode does not remove the PIV management key. It changes how
software obtains that key. After the normal PIV user PIN has been verified, the
software reads a PIN-protected data object from the card, recovers the stored
management key, and performs management-key authentication in the same logical
workflow. This lets enrollment, key generation, certificate import, and similar
management operations proceed after a normal Windows PIN prompt.

For CanoKey, the preferred boundary remains:

- The minidriver should not issue raw PC/SC/APDU operations.
- `canokey-pkcs11` should own PIV GET DATA / PUT DATA / GENERAL AUTHENTICATE.
- The minidriver should use PKCS#11 object APIs or CanoKey PKCS#11 extension
  APIs to recover the PIN-protected management key after `ROLE_USER`
  authentication.

## Source Findings

Yubico documents two PIN-only modes: PIN-protected and PIN-derived.
PIN-protected is the recommended mode. In that mode the SDK stores the
management key in the PRINTED data object and records mode information in ADMIN
DATA. When an operation later needs management-key authentication, the SDK
obtains the key from PRINTED after PIN verification and authenticates the
management key for that session. PIN-derived exists for compatibility and is
not the preferred model.

Yubico also documents an important security tradeoff: their SDK blocks the PUK
when setting PIN-only mode, so an administrator with only the PUK cannot reset
the user's PIN and then gain control of the PIN-protected management key. That
is a product/security-policy decision. For CanoKey development, do not block PUK
automatically until the behavior is intentionally designed and tested.

The Yubico .NET SDK `PinProtectedData` implementation stores its data in PIV
data tag `0x005FC109`, the PRINTED storage area. Its format is a Yubico-defined
TLV payload, not the standard PRINTED information layout:

```text
empty:
  53 00

with management key:
  53 len
    88 len
      89 len
        management-key bytes
```

The SDK accepts management key lengths of 16, 24, or 32 bytes. The current
CanoKey path uses a 24-byte 3DES management key.

Yubico ADMIN DATA records whether the PUK is blocked, whether the management
key is stored in a protected area, an optional salt for PIN-derived mode, and
an optional PIN-last-updated timestamp. The card does not set ADMIN DATA
automatically; the software that configures PIN-only mode must write consistent
ADMIN DATA and protected management-key data.

## Standards Context

NIST SP 800-73 lists PRINTED Information as PIV data tag `5FC109` and marks it
as PIN-or-OCC readable. It also describes standard PRINTED contents as printed
cardholder information. Yubico's PIN-protected management-key payload is
therefore an intentional overload of a PIN-protected data object rather than a
standard PRINTED information structure.

PC/SC is the lower-level transport API. On Windows, `SCardTransmit` sends a
service request/APDU to the card and returns the response. PC/SC does not know
about PKCS#11 objects, `CKO_DATA`, or `CKA_VALUE`.

PKCS#11 has a standard data-object class, `CKO_DATA`, and a standard value
attribute, `CKA_VALUE`. If `canokey-pkcs11` exposes PIV data objects as
PKCS#11 data objects, the minidriver can stay out of PC/SC and use
`C_FindObjects` plus `C_GetAttributeValue` to read the protected data.

## Current Codebase Gap

As of this note, `canokey-pkcs11` exposes PIV certificates, public keys,
private keys, and session secret keys. `C_FindObjectsInit` does not return
`CKO_DATA`, and `C_GetAttributeValue` has no object-class-specific handler for
PIV data objects. Therefore the minidriver cannot yet read `5FC109` through
standard PKCS#11 calls.

The minidriver should not work around this by calling `SCardTransmit` directly.
Doing so would split PIV APDU handling and sensitive-object parsing across two
layers.

## Proposed PKCS#11 Work

Model selected PIV data objects as `CKO_DATA`, but keep the writable surface
intentionally narrow. This is not meant to become a fully mutable generic PIV
object store.

- `C_FindObjects` should be able to find selected PIV data objects with
  `CKA_CLASS = CKO_DATA`.
- `CKA_APPLICATION` can identify the object family, for example `PIV`.
- `CKA_OBJECT_ID` should identify the raw PIV data tag, for example
  `{ 0x5F, 0xC1, 0x09 }` for PRINTED.
- `CKA_LABEL` can be a readable label such as `PIV data 5FC109`.
- `CKA_VALUE` should return the raw GET DATA payload.
- For PIN-protected tags such as `5FC109`, return a login/security error if
  the PIN has not been verified.
- `CKA_MODIFIABLE` should be `CK_FALSE`, because modification through
  `C_SetAttributeValue` is not supported.
- `CKA_DESTROYABLE` should be `CK_FALSE`, because `C_DestroyObject` does not
  currently delete PIV data objects.
- `CKA_COPYABLE` should be `CK_FALSE`, because `C_CopyObject` is not supported.

Writing should use `C_CreateObject(CKO_DATA)` only:

- The caller must be authenticated as SO.
- The template must include `CKA_CLASS = CKO_DATA`, the PIV object identifier,
  and `CKA_VALUE`.
- Internally this performs PIV PUT DATA.
- If the PIV data object already exists, overwrite it with the new value.

Keep `C_SetAttributeValue` simple: return `CKR_ATTRIBUTE_READ_ONLY` for PIV
token objects, including `CKO_DATA`. This matches the current direction of
YKCS11 more closely than pretending PIV objects are generally mutable PKCS#11
objects.

## Proposed Minidriver Work

After `CardAuthenticateEx(ROLE_USER)` succeeds:

1. Try to find a `CKO_DATA` object for PRINTED tag `5FC109`.
2. Read `CKA_VALUE` with `C_GetAttributeValue`.
3. Parse the Yubico-compatible TLV payload.
4. If a valid 24-byte management key is present, call `C_CNK_Login` with
   `CKU_SO` to authenticate the management key.
5. Mark `ROLE_ADMIN` authenticated only after `CKU_SO` succeeds.

Because PKCS#11 does not allow one session to be simultaneously logged in as
both user and SO, the exact login transition needs care. The current minidriver
has one PKCS#11 RW session per `CARD_DATA` context and already switches roles
by logging out the previous user type when `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`
is returned. A practical first version can read the PIN-protected object while
`ROLE_USER` is active, cache the recovered key only long enough to authenticate
`CKU_SO`, then zero it. After switching to SO, do not assume the PIV user PIN is
still verified.

The helper should be best-effort. If the PIN-protected object is missing,
malformed, or does not contain a supported management key, the minidriver
should fall back to the current explicit `ROLE_ADMIN`/management-key path.

## Provisioning Notes

Runtime support and provisioning are separate tasks.

Runtime support only needs to read a correctly configured PIN-protected
management key and authenticate it. Provisioning needs more:

- Verify the user's PIN.
- Authenticate the current management key.
- Optionally generate a new random management key.
- Change the on-card management key if the card supports that operation.
- Write the PIN-protected management-key payload to PRINTED.
- Write consistent ADMIN DATA.
- Decide whether to block PUK.

For development keys, it is acceptable to configure this with an external tool
first and keep the minidriver runtime path read-only. Production provisioning
needs a deliberate security design.

## References

- Yubico SDK manual, PIV PIN-only mode:
  https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html
- Yubico SDK manual, PIV GET and PUT DATA:
  https://docs.yubico.com/yesdk/users-manual/application-piv/get-and-put-data.html
- Yubico .NET SDK `PinProtectedData` source:
  https://github.com/Yubico/Yubico.NET.SDK/blob/90bb723f050e356469351fc9d87360b3d11d2ca1/Yubico.YubiKey/src/Yubico/YubiKey/Piv/Objects/PinProtectedData.cs
- Yubico .NET SDK `AdminData` API documentation:
  https://docs.yubico.com/yesdk/yubikey-api/Yubico.YubiKey.Piv.Objects.AdminData.html
- NIST SP 800-73 Part 1, PIV data model and PRINTED tag `5FC109`:
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf
- Microsoft `SCardTransmit` documentation:
  https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardtransmit
- OASIS PKCS#11 v3.1 specification:
  https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.pdf
