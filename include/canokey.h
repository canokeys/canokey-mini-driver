#ifndef CANOKEY_H
#define CANOKEY_H

#include <pkcs11.h>
#include <stdint.h>

#define MAX_SLOT_ID 24
#define CANOKEY_SLOT_CAP_SIGN 0x01
#define CANOKEY_SLOT_CAP_DECRYPT 0x02
#define CANOKEY_SLOT_CAP_DERIVE 0x04

#pragma pack(push, 1)
typedef struct {
  CK_BYTE modulus[512];
  CK_BYTE exponent[4];
  CK_ULONG modulusBits;
} RSA_PUB_KEY;

typedef struct {
  CK_BYTE _dummy;
  CK_BYTE x[66];
  CK_BYTE y[66];
  CK_ULONG cbPrivate;
} ECC_PUB_KEY;

typedef enum {
  CANOKEY_EC_CURVE_NONE = 0,
  CANOKEY_EC_CURVE_P256,
  CANOKEY_EC_CURVE_P384,
  CANOKEY_EC_CURVE_P521,
} CANOKEY_EC_CURVE;

typedef struct {
  CK_BBOOL present;
  CK_BYTE id;
  CK_BYTE pivId;
  CK_BYTE capabilities;
  CK_KEY_TYPE keyType;
  CANOKEY_EC_CURVE ecCurve;
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
#pragma pack(pop)

CK_RV read_canokey(CK_SESSION_HANDLE session, CANOKEY *pCanokey);
CK_BBOOL canokey_slot_has_key(const SLOT *slot);
CK_BBOOL canokey_slot_can_sign(const SLOT *slot);
CK_BBOOL canokey_slot_can_decrypt(const SLOT *slot);
CK_BBOOL canokey_slot_can_derive(const SLOT *slot);
CK_ULONG canokey_ec_curve_bits(const SLOT *slot);
CK_BYTE canokey_container_object_id(CK_BYTE containerIndex);
void reverse_bytes(CK_BYTE *data, CK_ULONG len);

#endif // CANOKEY_H
