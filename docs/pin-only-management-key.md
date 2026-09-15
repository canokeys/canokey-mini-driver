# PIN-protected management keys

A provisioned card can authorize key creation and certificate writes after the
normal Windows USER PIN prompt. The management key stays on the card in
PIN-protected PRINTED storage and inside PKCS#11's credential cache; the
minidriver receives only the authentication result.

`ProtectManagement` defaults to `1` and enables the runtime probe. It does not
provision the card. Set it to `0` when an external solution owns management
provisioning. See [runtime configuration](development.md#runtime-configuration).

## Runtime contract

After USER authentication, `C_CNK_LoginPinManaged` verifies all of the following:

- ADMIN DATA (`5FFF00`) has both PIN-protected and PUK-blocked flags.
- Actual PUK metadata reports zero remaining retries.
- PRINTED (`5FC109`) contains a well-formed supported management key.
- Management challenge-response succeeds with the algorithm reported by 9B.

The backend strictly parses those objects through libcanokey and clears temporary
key material. Successful login retains USER and caches management authorization.
Missing configuration does not grant ADMIN. Malformed data, false blocking claims
and authentication failures remain distinct errors. The minidriver never parses
these TLVs or submits raw APDUs.

PUK recovery is disabled while PIN protection is configured, independently of
whether ADMIN DATA's PUK-blocked claim is true. Its policy read and attempted
reset share one PC/SC transaction. Ordinary PIN changes remain available with
the current PIN. Losing that PIN does not make the blocked PUK a recovery method.

## Representations

The current implementation accepts a 24-byte management key (3DES or AES-192
according to firmware metadata). The PRINTED GET DATA container is:

```text
53 length
  88 length
    89 18 <24 management-key bytes>
```

The standard PKCS#11 PRINTED data object uses `CKA_OBJECT_ID` containing ASN.1
OID content octets `60 86 48 01 65 03 07 02 30 01`; it does not use the raw
three-byte PIV tag. `CKA_VALUE` retains complete container framing. The narrow
`C_CNK_GetPivData` extension instead accepts the raw PIV tag. Data writes use
`C_CreateObject(CKO_DATA)` with management authorization; they do not make
persistent data objects generally mutable through `C_SetAttributeValue`.

## Provisioning and development tests

Provisioning must authenticate USER and the current management key, write the
protected key and consistent policy, block the actual PUK and confirm zero
retries. `C_CNK_FinalizePinManaged` completes an explicitly preconfigured setup;
it is not part of initialization or ordinary login. Do not infer blocking from
policy bits alone or silently try default credentials.

The companion `scripts/hardware-pin-managed-test.py` provides a narrow fixture
for an explicitly selected development reader/serial with confirmed default
PIN/PUK and empty protection objects. Run `check-reset` before `prepare` to prove
the recovery capability. Always run `restore` in the caller's `finally` block,
including after partial setup failure. It removes protection data and uses
explicit PIN-plus-management authorization to reset retries and credentials to
firmware defaults. This is a credential reset, not a counter-only operation.
The separate `clear-slot` mode deletes only an explicitly selected test key for
Windows enrollment testing; it is not a driver deletion API.

Production provisioning should use a deliberate credential/recovery policy.
[Yubico's PIN-only description](https://docs.yubico.com/yesdk/users-manual/application-piv/pin-only.html)
describes the compatible storage/security model; current CanoKey behavior is
specified by the backend contracts and verified firmware operations.
