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
    return CANOKEY_SLOT_CAP_SIGN | (pivId == 0x9D ? CANOKEY_SLOT_CAP_DECRYPT : 0);
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
    if (!canokey_slot_can_sign(slot) && !canokey_slot_can_decrypt(slot)) {
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
      slot->ecc.cbPrivate = (attr[3].ulValueLen - 1) / 2;
      memcpy(slot->ecc.y, slot->ecc.x + slot->ecc.cbPrivate, slot->ecc.cbPrivate);
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
