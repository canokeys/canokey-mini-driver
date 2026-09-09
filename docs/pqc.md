# Post-Quantum Support Boundary

Current Windows CPDK headers do not define Smart Card Minidriver key types,
properties, or callbacks for ML-DSA or ML-KEM. The minidriver therefore does
not invent private algorithm identifiers or expose post-quantum PIV slots to
Microsoft Base Smart Card CSP or Microsoft Smart Card KSP. Those providers
continue to receive only the classic RSA and EC containers represented by the
documented `cardmod.h` contract.

Post-quantum access is provided by `external/canokey-pkcs11` through its
PKCS#11 3.2 interface:

- ML-DSA-65 key generation and single-part or multipart signing.
- ML-KEM-768 key generation, host-side encapsulation, and on-card
  decapsulation.
- Discovery across all 24 PIV key slots.

The PKCS#11 layer reads the firmware algorithm-extension configuration rather
than assuming the default PIV algorithm byte values. It uses the fast PIV
metadata directory only after confirming firmware 5.7 or newer; older firmware
falls back to individual metadata reads and does not advertise PQ mechanisms.

This separation keeps PQ key material usable without depending on an
unsupported Windows ABI. Native Smart Card KSP exposure should be added only
after a released CPDK defines the required algorithms and minidriver contract.
