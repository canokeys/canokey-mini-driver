#ifndef CAONKEY_H
#define CAONKEY_H

#include <pkcs11.h>
#include <stdint.h>

#define MAX_SLOT_ID 6

typedef struct {
  CK_BYTE modulus[512];
  CK_BYTE exponent[4];
  CK_ULONG modulusBits;
} RSA_PUB_KEY;

typedef struct {
  CK_BYTE x[66];
  CK_BYTE y[66];
} ECC_PUB_KEY;

typedef struct {
  CK_BYTE id;
  CK_BYTE pivId;
  CK_KEY_TYPE keyType;
  union {
    RSA_PUB_KEY rsa;
    ECC_PUB_KEY ecc;
    CK_BYTE ed[32];
    CK_BYTE data[0];
  };
  CK_BYTE cert[4096];
  CK_ULONG certLen;
} SLOT;

typedef struct {
  SLOT slots[MAX_SLOT_ID];
  CK_ULONG slotCount;
} CANOKEY;

CK_RV read_canokey(CK_SESSION_HANDLE session, CANOKEY *pCanokey);
void reverse_bytes(CK_BYTE *data, CK_ULONG len);

#endif // CANOKEY_H
