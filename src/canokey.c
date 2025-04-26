#include "canokey.h"
#include "logging.h"

#include <stdio.h>
#include <string.h>

extern CK_RV cnk_obj_id_to_piv_tag(CK_BYTE obj_id, CK_BYTE *piv_tag);

void reverse_bytes(CK_BYTE *data, CK_ULONG len) {
  for (CK_ULONG i = 0; i < len / 2; i++) {
    const CK_BYTE tmp = data[i];
    data[i] = data[len - 1 - i];
    data[len - 1 - i] = tmp;
  }
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
    cnk_obj_id_to_piv_tag(i, &slot->pivId);

    CK_ATTRIBUTE attr[] = {
        {CKA_KEY_TYPE, &slot->keyType, sizeof(slot->keyType)},
        {CKA_MODULUS, slot->rsa.modulus, sizeof(slot->rsa.modulus)},
        {CKA_MODULUS_BITS, &slot->rsa.modulusBits, sizeof(slot->rsa.modulusBits)},
    };
    rv = C_GetAttributeValue(session, hObject, attr, 3);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_GetAttributeValue failed");

    // RSA modulus is stored in big-endian, need to reverse
    reverse_bytes(slot->rsa.modulus, slot->rsa.modulusBits / 8);

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
      continue;
    }

    attr[0].type = CKA_VALUE;
    attr[0].pValue = slot->cert;
    attr[0].ulValueLen = sizeof(slot->cert);
    rv = C_GetAttributeValue(session, hObject, attr, 1);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_GetAttributeValue failed");
    slot->certLen = attr[0].ulValueLen;

    CMD_DEBUG("Slot %d: keyType = %d, certLen = %d", i, slot->keyType, slot->certLen);

    pCanokey->slotCount++;
  }

  return CKR_OK;
}