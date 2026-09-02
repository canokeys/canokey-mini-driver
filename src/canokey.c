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
  case 0x84:
  case 0x85:
  case 0x86:
  case 0x87:
  case 0x88:
  case 0x89:
  case 0x8A:
  case 0x8B:
  case 0x8C:
  case 0x8D:
  case 0x8E:
  case 0x8F:
  case 0x90:
  case 0x91:
  case 0x92:
  case 0x93:
  case 0x94:
  case 0x95:
    return CANOKEY_SLOT_CAP_SIGN | CANOKEY_SLOT_CAP_DERIVE | (pivId == 0x9D ? CANOKEY_SLOT_CAP_DECRYPT : 0);
  default:
    return 0;
  }
}

CK_BBOOL canokey_slot_can_sign(const SLOT *slot) {
  return canokey_slot_has_key(slot) && (slot->capabilities & CANOKEY_SLOT_CAP_SIGN) != 0;
}

CK_BBOOL canokey_slot_can_decrypt(const SLOT *slot) {
  return canokey_slot_has_key(slot) && (slot->capabilities & CANOKEY_SLOT_CAP_DECRYPT) != 0;
}

CK_BBOOL canokey_slot_can_derive(const SLOT *slot) {
  return canokey_slot_has_key(slot) && (slot->capabilities & CANOKEY_SLOT_CAP_DERIVE) != 0 && slot->keyType == CKK_EC;
}

CK_BBOOL canokey_slot_has_key(const SLOT *slot) { return slot != NULL && slot->present; }

CK_ULONG canokey_ec_curve_bits(const SLOT *slot) {
  if (slot == NULL)
    return 0;
  switch (slot->ecCurve) {
  case CANOKEY_EC_CURVE_P256:
    return 256;
  case CANOKEY_EC_CURVE_P384:
    return 384;
  case CANOKEY_EC_CURVE_P521:
    return 521;
  default:
    return 0;
  }
}

CK_BYTE canokey_container_object_id(CK_BYTE containerIndex) { return (CK_BYTE)(containerIndex + 1); }

static CANOKEY_EC_CURVE ec_curve_from_params(const CK_BYTE *params, CK_ULONG paramsLen) {
  static const CK_BYTE p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static const CK_BYTE p384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
  static const CK_BYTE p521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};

  if (paramsLen == sizeof(p256) && memcmp(params, p256, sizeof(p256)) == 0)
    return CANOKEY_EC_CURVE_P256;
  if (paramsLen == sizeof(p384) && memcmp(params, p384, sizeof(p384)) == 0)
    return CANOKEY_EC_CURVE_P384;
  if (paramsLen == sizeof(p521) && memcmp(params, p521, sizeof(p521)) == 0)
    return CANOKEY_EC_CURVE_P521;
  return CANOKEY_EC_CURVE_NONE;
}

static CK_BBOOL is_supported_ec_coordinate_len(CK_ULONG coordinate_len) {
  switch (coordinate_len) {
  case 32:
  case 48:
  case 66:
    return CK_TRUE;
  default:
    return CK_FALSE;
  }
}

static CK_BBOOL decode_der_octet_string(const CK_BYTE *value, CK_ULONG value_len, const CK_BYTE **content,
                                        CK_ULONG *content_len) {
  if (value_len < 2 || value[0] != 0x04) {
    return CK_FALSE;
  }

  CK_BYTE length_byte = value[1];
  CK_ULONG length_size = 1;
  CK_ULONG payload_len = 0;
  if ((length_byte & 0x80) == 0) {
    payload_len = length_byte;
  } else {
    CK_ULONG encoded_length_size = length_byte & 0x7f;
    if (encoded_length_size == 0 || encoded_length_size > sizeof(CK_ULONG) || value_len < 2 + encoded_length_size) {
      return CK_FALSE;
    }
    length_size += encoded_length_size;
    for (CK_ULONG i = 0; i < encoded_length_size; i++) {
      payload_len = (payload_len << 8) | value[2 + i];
    }
  }

  if (value_len != 1 + length_size + payload_len) {
    return CK_FALSE;
  }

  *content = value + 1 + length_size;
  *content_len = payload_len;
  return CK_TRUE;
}

static CK_RV copy_uncompressed_ec_point(SLOT *slot, const CK_BYTE *point, CK_ULONG point_len) {
  if (point_len < 3 || point[0] != 0x04) {
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  CK_ULONG coordinate_bytes = point_len - 1;
  if (coordinate_bytes % 2 != 0) {
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  CK_ULONG coordinate_len = coordinate_bytes / 2;
  if (!is_supported_ec_coordinate_len(coordinate_len) || coordinate_len > sizeof(slot->ecc.x)) {
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  slot->ecc.cbPrivate = coordinate_len;
  memcpy(slot->ecc.x, point + 1, slot->ecc.cbPrivate);
  memcpy(slot->ecc.y, point + 1 + slot->ecc.cbPrivate, slot->ecc.cbPrivate);
  return CKR_OK;
}

static CK_RV unpack_ec_point(SLOT *slot, CK_ULONG value_len) {
  if (value_len == CK_UNAVAILABLE_INFORMATION || value_len < 3 || value_len > sizeof(ECC_PUB_KEY)) {
    CMD_RETURN(CKR_ATTRIBUTE_VALUE_INVALID, "Invalid EC point length");
  }

  CK_BYTE value[sizeof(ECC_PUB_KEY)];
  memcpy(value, &slot->ecc, value_len);

  const CK_BYTE *point = NULL;
  CK_ULONG point_len = 0;
  if (decode_der_octet_string(value, value_len, &point, &point_len)) {
    CK_RV rv = copy_uncompressed_ec_point(slot, point, point_len);
    if (rv == CKR_OK) {
      return rv;
    }
  }

  CK_RV rv = copy_uncompressed_ec_point(slot, value, value_len);
  if (rv != CKR_OK) {
    CMD_RETURN(rv, "Invalid EC point encoding");
  }
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
  pCanokey->slotCount = MAX_SLOT_ID;

  for (CK_BYTE i = 1; i <= MAX_SLOT_ID; i++) {
    CMD_DEBUG("Reading slot %d", i);

    SLOT *slot = &pCanokey->slots[i - 1];
    slot->id = i;
    C_CNK_ObjIdToPivTag(i, &slot->pivId);
    slot->capabilities = capabilities_for_piv_slot(slot->pivId);

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
    rv = C_FindObjectsFinal(session);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjectsFinal failed");
    if ((slot->capabilities & (CANOKEY_SLOT_CAP_SIGN | CANOKEY_SLOT_CAP_DECRYPT | CANOKEY_SLOT_CAP_DERIVE)) == 0) {
      CMD_DEBUG("Slot %d: PIV 0x%02x has no minidriver capability, skipping", i, slot->pivId);
      continue;
    }
    if (ulObjectCount == 0) {
      CMD_DEBUG("No public key found for slot %d", i);
      continue;
    }
    CK_ATTRIBUTE attr[] = {
        {CKA_KEY_TYPE, &slot->keyType, sizeof(slot->keyType)},
        {CKA_MODULUS, slot->rsa.modulus, sizeof(slot->rsa.modulus)},
        {CKA_MODULUS_BITS, &slot->rsa.modulusBits, sizeof(slot->rsa.modulusBits)},
        {CKA_EC_POINT, &slot->ecc, sizeof(slot->ecc)},
        {CKA_EC_PARAMS, NULL, 0},
    };
    CK_BYTE ecParams[16];
    attr[4].pValue = ecParams;
    attr[4].ulValueLen = sizeof(ecParams);
    rv = C_GetAttributeValue(session, hObject, attr, 5);
    if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID)
      CMD_RETURN(rv, "C_GetAttributeValue failed");

    if (slot->keyType == CKK_RSA) {
      // RSA modulus is stored in big-endian, need to reverse
      reverse_bytes(slot->rsa.modulus, slot->rsa.modulusBits / 8);
      CMD_DEBUG("Slot %d: keyType = CKK_RSA, modulusBits = %d", i, slot->rsa.modulusBits);
    } else if (slot->keyType == CKK_EC) {
      slot->ecCurve = ec_curve_from_params(ecParams, attr[4].ulValueLen);
      if (slot->ecCurve == CANOKEY_EC_CURVE_NONE) {
        // Windows cardmod/CNG has no compatible identifier for secp256k1 or
        // SM2. Coordinate length alone must never be used as curve identity.
        CMD_DEBUG("Slot %d: unsupported Windows EC parameters, skipping", i);
        continue;
      }
      rv = unpack_ec_point(slot, attr[3].ulValueLen);
      if (rv != CKR_OK)
        CMD_RETURN(rv, "Invalid EC point");
      if (slot->ecc.cbPrivate != (canokey_ec_curve_bits(slot) + 7) / 8) {
        CMD_DEBUG("Slot %d: EC point size does not match named curve, skipping", i);
        continue;
      }
      CMD_DEBUG("Point:");
      CMD_PRINT_HEX(slot->ecc.x, slot->ecc.cbPrivate);
      CMD_PRINT_HEX(slot->ecc.y, slot->ecc.cbPrivate);
      CMD_DEBUG("Slot %d: keyType = CKK_EC, curve = %d, cbPrivate = %d", i, slot->ecCurve, slot->ecc.cbPrivate);
    } else {
      // PKCS#11 exposes PQ and future algorithms, but current cardmod headers
      // cannot represent them. Keep the fixed Windows slot empty rather than
      // failing all classic container discovery.
      CMD_DEBUG("Slot %d: unsupported Windows key type 0x%lx, skipping", i, slot->keyType);
      continue;
    }
    slot->present = CK_TRUE;

    objectClass = CKO_CERTIFICATE;
    rv = C_FindObjectsInit(session, templates, 2);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjectsInit failed");

    rv = C_FindObjects(session, &hObject, 1, &ulObjectCount);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjects failed");
    rv = C_FindObjectsFinal(session);
    if (rv != CKR_OK)
      CMD_RETURN(rv, "C_FindObjectsFinal failed");
    if (ulObjectCount == 0) {
      CMD_DEBUG("No certificate found for slot %d", i);
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
  }

  return CKR_OK;
}
