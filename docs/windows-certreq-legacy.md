# certreq without a firmware upgrade

If your CanoKey runs firmware older than 3.1.0, use the steps below to request
and install a certificate without upgrading the firmware. With firmware 3.1.0
or later and an up-to-date minidriver, the extra repair step is unnecessary.

On older firmware, `certreq -new` may successfully create a private key and
certificate signing request (CSR), but `certreq -accept` later fails to find
that key. Windows saved a temporary key name such as `tq-...` with the request;
when it opens the card again, the driver reports a different name for the same
key. The key is still on the card.

If you already have a key, use Option A to request a certificate with its
current name. If you have already created a CSR and received a certificate,
use Option B to fix the saved name before installing the certificate.

Install an up-to-date minidriver from the `genkey` branch first; older driver
versions have additional certificate-request bugs. Run all commands as the
same Windows user, with the same card connected. These examples install the
certificate for that user. Let Windows prompt for the PIN; do not use `-q`
or `Silent=TRUE`.

## Option A: request a certificate for an existing card key

Use the name Windows currently reports for the key. This keeps the request
and the installed certificate pointing to the same card key.

1. List the card keys and their container names:

   ```powershell
   certutil -user -csp "Microsoft Smart Card Key Storage Provider" -key
   ```

   Find the intended CanoKey key and copy its container name from this output.
   This is usually a GUID such as `12345678-1234-1234-1234-123456789abc`.
   A slot number such as `9A` or a temporary name from an earlier request will
   not work here.

2. Save this as `existing-key.inf`, replacing the subject and container name:

   ```ini
   [Version]
   Signature="$Windows NT$"

   [NewRequest]
   Subject="CN=CanoKey enrollment test"
   RequestType=PKCS10
   ProviderName="Microsoft Smart Card Key Storage Provider"
   ProviderType=0
   KeyContainer="REPLACE_WITH_LIVE_CONTAINER_NAME"
   UseExistingKeySet=TRUE
   KeyAlgorithm=RSA
   KeySpec=AT_SIGNATURE
   HashAlgorithm=SHA256
   KeyUsage=0x80
   MachineKeySet=FALSE
   Silent=FALSE
   ```

   Set these two fields to match your key:

   | Existing key | KeyAlgorithm | KeySpec |
   | --- | --- | --- |
   | RSA signing container outside 9D | RSA | AT_SIGNATURE (2) |
   | RSA in PIV 9D, including CSR signing | RSA | AT_KEYEXCHANGE (1) |
   | ECDSA P-256 signing container | ECDSA_P256 | AT_SIGNATURE (2) |

   `KeyUsage=0x80` requests certificate digital-signature usage; it does not
   choose a PIV slot or override the provider's KeySpec. Adjust certificate
   subject, extensions and usage to the issuing CA's policy.

   With `UseExistingKeySet=TRUE`, omit `UserProtected`, `KeyProtection`,
   `Exportable`, and other key-creation policy options. Do not copy those
   options from a new-key INF; they can cause `ERROR_INVALID_DATA` at
   `UseExistingKeySet`. They cannot change an existing key's protection.

3. Create the CSR and have your CA issue its matching certificate:

   ```powershell
   certreq -user -new .\existing-key.inf .\existing-key.req
   certutil -dump .\existing-key.req
   # Optional independent verification if OpenSSL is installed:
   openssl req -in .\existing-key.req -verify -noout
   ```

   Submit `existing-key.req` through your CA's normal enrollment process.
   Save your issued certificate as `issued.cer`. Windows must trust the issuing
   CA and be able to reach its certificate and revocation-list URLs.

4. Accept the certificate and check its private-key association:

   ```powershell
   certreq -user -accept .\issued.cer
   certutil -user -store My
   certutil -scinfo "canokeys.org OpenPGP PIV OATH 0"
   ```

   Use the actual reader name if it differs. Verify the certificate matches
   the intended card key, then test signing and enumeration after reinsertion.
   Merely importing a CER into My does not prove that the certificate is on
   the card or that the private-key association is usable.

## Option B: repair a pending request after new-key enrollment

Use this when `certreq -new` already created the key and CSR, but the pending
Request entry still names a temporary container. Keep that key and CSR; do
not run new-key enrollment again to repair the name.

For a fresh RSA signing-key request, a minimal `new-key.inf` is:

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN=CanoKey enrollment test"
RequestType=PKCS10
ProviderName="Microsoft Smart Card Key Storage Provider"
ProviderType=0
KeyAlgorithm=RSA
KeyLength=2048
KeySpec=AT_SIGNATURE
KeyUsageProperty=2
HashAlgorithm=SHA256
KeyUsage=0x80
Exportable=FALSE
MachineKeySet=FALSE
Silent=FALSE
```

Skip this command if you already have the CSR. To create a new key, the card
must have an empty slot and already be configured to allow key creation:

```powershell
certreq -user -new .\new-key.inf .\new-key.req
```

Windows chooses the slot; this INF cannot select 9A or 9C directly. A slot
containing an SM2 or other unsupported key is still occupied, even if Windows
does not list it. The driver rejects attempts to overwrite it, so key creation
may fail even when another slot is empty.

After the CSR succeeds and the CA returns its matching `issued.cer`:

1. Inspect the pending requests and the card's live containers:

   ```powershell
   certutil -user -v -store Request
   certutil -user -csp "Microsoft Smart Card Key Storage Provider" -key
   certutil -dump .\new-key.req
   certutil -dump .\issued.cer
   ```

   Find the Request entry for this CSR by checking its public key and request
   details. Copy the SHA-1 certificate hash shown for that entry. This is
   **not** the issued leaf certificate's thumbprint or the CSR file's hash.
   Check that the CSR and issued certificate have the same public key. Do not
   select a request solely by subject name or a changing numeric store index.

2. Repair only that pending entry by matching its public key to the card key:

   ```powershell
   $requestId = "REPLACE_WITH_EXACT_REQUEST_ENTRY_SHA1"
   certutil -user -csp "Microsoft Smart Card Key Storage Provider" -repairstore Request $requestId
   certutil -user -v -store Request $requestId
   ```

   Check that the command succeeded and the Request entry now shows the card's
   current container name. If no matching key is found, check that you are using
   the correct card, Windows account and KeySpec. This command updates the key
   name saved by Windows; your CSR and private key stay unchanged.

3. Accept the already-issued certificate:

   ```powershell
   certreq -user -accept .\issued.cer
   certutil -scinfo "canokeys.org OpenPGP PIV OATH 0"
   ```

Repairing `My` instead of `Request` does not repair the pending request that
`certreq -accept` is trying to use. Broad store deletion is unnecessary.

## Troubleshooting

- `NTE_BAD_KEYSET` / `0x80090016`: compare the pending association with a fresh
  container enumeration; also check the user/machine store and KeySpec.
- `ERROR_INVALID_DATA` / `0x8007000D` at `UseExistingKeySet`: remove conflicting
  new-key protection options and use the minimal existing-key INF above.
- Chain or revocation errors require correcting CA trust or reachability;
  repairing a container name does not fix certificate trust.
- An occupied-slot rejection is intentional. Neither reissuing a certificate
  nor repairing a request requires replacing its private key.

## What has been tested

On Windows ARM64 with driver d064aa7, the Request repair procedure worked for
a new RSA key: certificate installation, automatic certificate discovery after
reinsertion, and signing all passed without a firmware upgrade. Creating CSRs
with existing RSA keys in 9A and 9D also passed.

The ECDSA example was tested on newer firmware only. The complete ECDSA flow
on older firmware and AD smart-card login have not been verified.
