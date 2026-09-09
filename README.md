# CanoKey Windows Minidriver

Use CanoKey PIV keys and certificates with Windows applications through
Microsoft Base Smart Card CSP and Microsoft Smart Card KSP. The driver supports
certificate discovery, RSA and ECDSA signatures, and certificate enrollment.
It uses [canokey-pkcs11](external/canokey-pkcs11) to communicate with the card.

This project is under development. The CI packages are development builds;
the generated INF does not include a signed catalog for production
installation. For local use, follow the
[registry-only setup](docs/development.md#registry-only-minidriver-loading).

## Supported features

| Feature | Support |
| --- | --- |
| Windows signing | RSA and NIST P-256, P-384, P-521 |
| Windows key slots | PIV 9A, 9C, 9D, 9E, 82, 83 |
| RSA decryption | RSA key in PIV 9D |
| Key generation and import | RSA and the three NIST curves above; requires card management authorization |
| Certificate enrollment | Microsoft Smart Card KSP and `certreq` |
| PIN management | User PIN change; PUK-based reset when PIN-managed recovery is not configured |
| Persistent container names | CanoKey firmware 3.1.0 or later, with an up-to-date driver |

An RSA key in 9D uses `AT_KEYEXCHANGE`, including for signing. Other exposed
signing keys use `AT_SIGNATURE`. Windows chooses a container when creating a
key; an enrollment request cannot select an arbitrary PIV slot. Occupied slots
are protected even when their key algorithm is not supported by Windows.

ECDH, Ed25519, X25519, SM2, secp256k1, and post-quantum algorithms are not
exposed through Windows CSP/KSP. Applications that need them must use
PKCS#11, subject to the card's firmware and algorithm support. See
[post-quantum support](docs/pqc.md) for ML-DSA and ML-KEM.

## Choose a Windows build

Download one complete CI artifact for the desired configuration and Visual
Studio version. Artifact names are `canokey-mini-driver-release-vs2022` or
`canokey-mini-driver-release-vs2026`; Debug variants are also available.
Keep files from the same artifact together.

| Windows environment | DLLs needed |
| --- | --- |
| x64 applications on x64 Windows | `canokey-minidriver-x64.dll` |
| 32-bit x86 applications | `canokey-minidriver-x86.dll`, with the corresponding 32-bit registry mapping |
| Native ARM64 and x64 applications on ARM64 Windows | `canokey-minidriver-arm64x.dll`, `canokey-minidriver-arm64.dll`, and `canokey-minidriver-x64.dll` together |

On ARM64 Windows, register the Arm64X DLL so native and x64-emulated
applications can share the same card mapping. A plain x64 DLL cannot serve
native Windows smart-card services. ARM32 is not supported.

See [deployment and architecture selection](docs/architecture-distribution.md)
for file layouts and registry mappings. Choose either registry-only deployment
or a properly packaged INF installation; mixing them can make Windows load a
different DLL than intended.

## Check that Windows can use the card

After configuring the driver, insert the CanoKey and run:

```powershell
certutil -scinfo "canokeys.org OpenPGP PIV OATH 0"
```

Replace the reader name if yours differs. Allow Windows to prompt for the
card PIN. Check that the intended certificates appear and Windows can match
them to their private keys. The results depend on which keys and certificates
are provisioned on your card.

For certificate enrollment, read [container names and firmware compatibility](docs/container-names.md).
Cards running firmware older than 3.1.0 need the
[legacy certreq procedure](docs/windows-certreq-legacy.md) when accepting a
certificate in a separate process.

Key creation and certificate writes require management authorization. A card
configured for [PIN-protected management](docs/pin-only-management-key.md) can
provide that authorization after the Windows user PIN prompt. This mode
permanently disables PUK recovery; ordinary PIN login alone does not configure
it.

## Build from source

Use Windows with Visual Studio 2022, Desktop development with C++, ClangCL,
CMake/Ninja, Python, and the
[Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

```powershell
git submodule update --init --recursive
python -m pip install -r external/canokey-pkcs11/cmake/tf-psa-crypto-generator-requirements.txt
.\build.ps1 -Arch x64 -Config Release
```

Build outputs are in `out/build/x64-Clang-Release/`. The build script only
builds files; it does not install or update the driver. Use `-Arch x86` or
`-Arch arm64` for those architectures.

For the shared ARM64/x64 deployment, build both implementations and then the
forwarder with the same configuration:

```powershell
.\build.ps1 -Arch x64 -Config Release
.\build.ps1 -Arch arm64 -Config Release
.\build.ps1 -Arch arm64x -Config Release
```

If CMake selects the wrong Python environment, pass
`-Python3Executable C:\Path\To\python.exe` to `build.ps1`.

## Troubleshooting

- **Card not detected:** check the reader name, reinsert the card, and verify
  the Calais mapping points to the DLL for your Windows architecture.
- **Certificate appears but its key cannot be opened:** check the container
  name and key specification. RSA 9D uses `AT_KEYEXCHANGE`. For older firmware,
  follow the [pending-request repair steps](docs/windows-certreq-legacy.md#option-b-repair-a-pending-request-after-new-key-enrollment).
- **Key creation fails:** check management authorization and slot occupancy.
  A key hidden from Windows still occupies its slot. Do not repeat key
  generation to fix a certificate association.
- **Certificate trust or revocation error:** check the issuing CA's trust
  chain and revocation endpoints. Container-name repair does not fix trust.
- **More diagnostic detail needed:** enable
  [logging](docs/development.md#logging). Logging is disabled by default;
  leave raw APDU logging off unless needed for diagnosis.

## Documentation for contributors

- [Development setup, configuration, and test commands](docs/development.md)
- [Architecture and ownership boundaries](docs/architecture.md)
- [Windows-to-PKCS#11 API mapping](docs/pkcs11-minidriver-mapping.md)
- [Review and validation requirements](docs/validation.md)
- [Fuzzing plan](docs/fuzzing-plan.md)
