# Container names and firmware compatibility

Windows identifies a smart-card key by its container name. That name must
remain the same when Windows reopens the card, including between creating a
certificate signing request (CSR) and installing the issued certificate.

## Firmware 3.1.0 and later

With an up-to-date minidriver, CanoKey saves Windows container names on the
card. A name assigned during key creation remains available to a later
`certreq -accept` process and after card reinsertion. No pending-request name
repair is needed for this workflow.

Existing keys without a saved name use a name derived from their public key.
Updating the driver does not require replacing those keys or certificates.

## Older firmware

Existing keys and certificates remain usable. However, a temporary name chosen
by Windows during enrollment cannot be saved on the card. A later
`certreq -accept` process may therefore fail to find the key, even though key
creation and the CSR succeeded.

Use either of the procedures in
[certreq without a firmware upgrade](windows-certreq-legacy.md):

- Request a certificate for an existing key using its live container name.
- If a CSR already exists, repair its exact pending Request-store association
  before accepting the matching certificate.

Do not generate another key just to repair a container name.

## If enrollment fails

Key creation and saving its name are separate card writes. An error can occur
after the key has already been created. Likewise, renaming several containers
can succeed for some names before another write fails.

Re-enumerate the card before retrying. Keep any existing CSR and compare its
public key with the card key and the issued certificate. The driver does not
automatically delete or regenerate keys to undo a naming failure.

On firmware that supports saved names, communication errors or invalid name
responses are reported as errors. The driver does not silently switch to a
different naming scheme.

## Slot selection

Windows exposes only PIV slots 9A, 9C, 9D, 9E, 82, and 83. Persistent names do
not expose additional slots or allow `certreq` to choose an arbitrary PIV slot.
A slot containing an unsupported key, such as SM2, remains occupied even when
Windows does not list it. Key creation can fail if Windows selects that slot.

For implementation details, see the
[enrollment and name-storage boundaries](architecture.md#persistent-container-names).
