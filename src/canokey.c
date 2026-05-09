#include "canokey.h"
#include "logging.h"
#include "pkcs11.h"

#include <pkcs11_canokey.h>

#include <stdio.h>
#include <string.h>

void reverse_bytes(CK_BYTE *data, CK_ULONG len) {
  for (CK_ULONG i = 0; i < len / 2; i++) {
    const CK_BYTE tmp = data[i];
    data[i] = data[len - 1 - i];
    data[len - 1 - i] = tmp;
  }
}

static CK_BYTE capabilities_for_piv_slot(CK_BYTE pivId) {
  switch (pivId) {
  case 0x9A:
  case 0x9C:
  case 0x9D:
  case 0x9E:
  case 0x82:
  case 0x83:
    return CANOKEY_SLOT_CAP_SIGN | CANOKEY_SLOT_CAP_DERIVE | (pivId == 0x9D ? CANOKEY_SLOT_CAP_DECRYPT : 0);
  default:
    return 0;
  }
}

CK_BBOOL canokey_slot_can_sign(const SLOT *slot) {
  return slot != NULL && (slot->capabilities & CANOKEY_SLOT_CAP_SIGN) != 0;
}

CK_BBOOL canokey_slot_can_decrypt(const SLOT *slot) {
  return slot != NULL && (slot->capabilities & CANOKEY_SLOT_CAP_DECRYPT) != 0;
}

CK_BBOOL canokey_slot_can_derive(const SLOT *slot) {
  return slot != NULL && (slot->capabilities & CANOKEY_SLOT_CAP_DERIVE) != 0 && slot->keyType == CKK_EC;
}

static CK_RV unpack_ec_point(SLOT *slot, CK_ULONG value_len) {
  if (value_len == CK_UNAVAILABLE_INFORMATION || value_len < 3 || value_len > sizeof(ECC_PUB_KEY)) {
    CMD_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Invalid EC point length");
  }

  CK_ULONG coordinate_len = value_len - 1;
  if (coordinate_len % 2 != 0 || coordinate_len / 2 > sizeof(slot->ecc.x)) {
    CMD_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Invalid EC coordinate length");
  }

  CK_BYTE point[sizeof(ECC_PUB_KEY)];
  memcpy(point, &slot->ecc, value_len);
  if (point[0] != 0x04) {
    CMD_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Only uncompressed EC points are supported");
  }

  slot->ecc.cbPrivate = coordinate_len / 2;
  memcpy(slot->ecc.x, point + 1, slot->ecc.cbPrivate);
  memcpy(slot->ecc.y, point + 1 + slot->ecc.cbPrivate, slot->ecc.cbPrivate);
  return CKR_OK;
}

/**
 * Function: read_canokey
 *
 * Purpose: Enumerate all slots, read all metadata and certificates,
 *          and generate container info and map files.
 *
 * Parameters:
 *   pSession - Pointer to the PKCS#11 session handle
 *   pCanokey - Pointer to the CANOKEY structure to be filled
 *
 * Returns:
 *   CK_RV - PKCS#11 return value
 */
CK_RV read_canokey(CK_SESSION_HANDLE session, CANOKEY *pCanokey) {
  CMD_ENSURE_NONNULL(pCanokey, CKR_ARGUMENTS_BAD);

  // Initialize the CANOKEY structure
  memset(pCanokey, 0, sizeof(CANOKEY));
  pCanokey->slotCount = 0;

  for (CK_BYTE i = 1; i <= MAX_SLOT_ID; i++) {
    CMD_DEBUG("Reading slot %d", i);

    CK_OBJECT_CLASS objectClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE templates[] = {
        {CKA_ID, &i, sizeof(i)},
        {CKA_CLASS, &objectClass, sizeof(objectClass)},
    };
    CK_RV rv = C_FindObjectsInit(session, templates, 2);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjectsInit failed");

    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount = 0;
    rv = C_FindObjects(session, &hObject, 1, &ulObjectCount);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjects failed");
    C_FindObjectsFinal(session);
    if (ulObjectCount == 0) {
      CMD_DEBUG("No public key found for slot %d", i);
      continue;
    }

    SLOT *slot = &pCanokey->slots[pCanokey->slotCount];
    slot->id = i;
    C_CNK_ObjIdToPivTag(i, &slot->pivId);
    slot->capabilities = capabilities_for_piv_slot(slot->pivId);
    if (!canokey_slot_can_sign(slot) && !canokey_slot_can_decrypt(slot) && !canokey_slot_can_derive(slot)) {
      CMD_DEBUG("Slot %d: PIV 0x%02x has no minidriver capability, skipping", i, slot->pivId);
      continue;
    }

    CK_ATTRIBUTE attr[] = {
        {CKA_KEY_TYPE, &slot->keyType, sizeof(slot->keyType)},
        {CKA_MODULUS, slot->rsa.modulus, sizeof(slot->rsa.modulus)},
        {CKA_MODULUS_BITS, &slot->rsa.modulusBits, sizeof(slot->rsa.modulusBits)},
        {CKA_EC_POINT, &slot->ecc, sizeof(slot->ecc)},
    };
    rv = C_GetAttributeValue(session, hObject, attr, 4);
    if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
      CMD_RETURN(rv, "C_GetAttributeValue failed");

    if (slot->keyType == CKK_RSA) {
      // RSA modulus is stored in big-endian, need to reverse
      reverse_bytes(slot->rsa.modulus, slot->rsa.modulusBits / 8);
      CMD_DEBUG("Slot %d: keyType = CKK_RSA, modulusBits = %d", i, slot->rsa.modulusBits);
    } else if (slot->keyType == CKK_EC) {
      rv = unpack_ec_point(slot, attr[3].ulValueLen);
      if (rv != CKR_OK)
        CMD_RETURN(rv, "Invalid EC point");
      CMD_DEBUG("Point:");
      CMD_PRINT_HEX(slot->ecc.x, slot->ecc.cbPrivate);
      CMD_PRINT_HEX(slot->ecc.y, slot->ecc.cbPrivate);
      CMD_DEBUG("Slot %d: keyType = CKK_EC, cbPrivate = %d", i, slot->ecc.cbPrivate);
    }

    objectClass = CKO_CERTIFICATE;
    rv = C_FindObjectsInit(session, templates, 2);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjectsInit failed");

    rv = C_FindObjects(session, &hObject, 1, &ulObjectCount);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjects failed");
    C_FindObjectsFinal(session);
    if (ulObjectCount == 0) {
      CMD_DEBUG("No certificate found for slot %d", i);
      if (!canokey_slot_can_decrypt(slot)) {
        continue;
      }
    } else {
      attr[0].type = CKA_VALUE;
      attr[0].pValue = slot->cert;
      attr[0].ulValueLen = sizeof(slot->cert);
      rv = C_GetAttributeValue(session, hObject, attr, 1);
      if (rv != CKR_OK)
        CMD_RETURN(rv, "C_GetAttributeValue failed");
      slot->certLen = attr[0].ulValueLen;
    }

    CMD_DEBUG("Slot %d: PIV 0x%02x, keyType = %d, certLen = %d, capabilities = 0x%02x", i, slot->pivId, slot->keyType,
              slot->certLen, slot->capabilities);

    pCanokey->slotCount++;
  }

  return CKR_OK;
}
