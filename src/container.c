#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "config.h"
#include "logging.h"
#include "minidriver.h"

typedef struct {
  PUBLICKEYSTRUC publickeystruc;
  RSAPUBKEY rsapubkey;
} PUBRSAKEYSTRUCT_BASE;

#define MAX_RSA_CRT_COMPONENT_BYTES 256
#define RSA_CRT_COMPONENT_COUNT 5

static DWORD map_pkcs11_container_error(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
    return SCARD_S_SUCCESS;
  case CKR_USER_NOT_LOGGED_IN:
    return SCARD_W_SECURITY_VIOLATION;
  case CKR_SESSION_READ_ONLY:
    return SCARD_E_INVALID_PARAMETER;
  case CKR_PIN_INCORRECT:
  case CKR_PIN_INVALID:
  case CKR_PIN_LEN_RANGE:
  case CKR_PIN_EXPIRED:
    return SCARD_W_WRONG_CHV;
  case CKR_PIN_LOCKED:
    return SCARD_W_CHV_BLOCKED;
  case CKR_KEY_SIZE_RANGE:
  case CKR_MECHANISM_INVALID:
  case CKR_ATTRIBUTE_VALUE_INVALID:
  case CKR_TEMPLATE_INCONSISTENT:
    return SCARD_E_INVALID_PARAMETER;
  case CKR_HOST_MEMORY:
    return SCARD_E_NO_MEMORY;
  default:
    return SCARD_F_INTERNAL_ERROR;
  }
}

static CK_BYTE container_index_to_object_id(BYTE bContainerIndex) { return (CK_BYTE)(bContainerIndex + 1); }

static BOOL container_index_is_piv_9d(BYTE bContainerIndex) {
  CK_BYTE pivTag = 0;
  return C_CNK_ObjIdToPivTag(container_index_to_object_id(bContainerIndex), &pivTag) == CKR_OK && pivTag == 0x9D;
}

static DWORD validate_create_container_request(BYTE bContainerIndex, DWORD dwFlags, DWORD dwKeySpec, DWORD dwKeySize,
                                               PBYTE pbKeyData) {
  if (bContainerIndex >= MAX_SLOT_ID) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }
  if (dwFlags != CARD_CREATE_CONTAINER_KEY_GEN && dwFlags != CARD_CREATE_CONTAINER_KEY_IMPORT) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid container creation flags");
  }
  if (dwFlags == CARD_CREATE_CONTAINER_KEY_GEN && pbKeyData != NULL) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Key generation does not accept key data");
  }
  if (dwFlags == CARD_CREATE_CONTAINER_KEY_IMPORT && pbKeyData == NULL) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Key import requires key data");
  }

  switch (dwKeySpec) {
  case AT_SIGNATURE:
    if (dwKeySize != 2048 && dwKeySize != 3072 && dwKeySize != 4096) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported RSA key size");
    }
    CMD_RET_OK;
  case AT_KEYEXCHANGE:
    // Windows models RSA key exchange as the PIV key-management slot. Do not
    // silently expose a signature/authentication-slot RSA key as KSP decrypt.
    if (!container_index_is_piv_9d(bContainerIndex)) {
      CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "RSA key exchange is only supported by PIV 9D");
    }
    if (dwKeySize != 2048 && dwKeySize != 3072 && dwKeySize != 4096) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported RSA key size");
    }
    CMD_RET_OK;
  case AT_ECDSA_P256:
  case AT_ECDHE_P256:
    if (dwKeySize != 0 && dwKeySize != 256) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported P-256 key size");
    }
    CMD_RET_OK;
  case AT_ECDSA_P384:
  case AT_ECDHE_P384:
    if (dwKeySize != 0 && dwKeySize != 384) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported P-384 key size");
    }
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported key spec");
  }
}

static DWORD refresh_container_metadata(CMD_CONTEXT_PTR pContext) {
  CK_RV rv = read_canokey(pContext->session, &pContext->canokey);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_container_error(rv), "Failed to refresh CanoKey metadata");
  }
  return GenerateCardIdentifier(pContext);
}

static DWORD ec_params_for_key_spec(DWORD dwKeySpec, const CK_BYTE **ppParams, CK_ULONG *pParamsLen) {
  static const CK_BYTE p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static const CK_BYTE p384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};

  CMD_ENSURE_NONNULL(ppParams, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pParamsLen, SCARD_E_INVALID_PARAMETER);

  switch (dwKeySpec) {
  case AT_ECDSA_P256:
  case AT_ECDHE_P256:
    *ppParams = p256;
    *pParamsLen = sizeof(p256);
    CMD_RET_OK;
  case AT_ECDSA_P384:
  case AT_ECDHE_P384:
    *ppParams = p384;
    *pParamsLen = sizeof(p384);
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported EC key spec");
  }
}

static DWORD create_keypair(CMD_CONTEXT_PTR pContext, BYTE bContainerIndex, DWORD dwKeySpec, DWORD dwKeySize) {
  CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_BYTE objectId = container_index_to_object_id(bContainerIndex);
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL privateKey = CK_TRUE;
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE privateKeyHandle = CK_INVALID_HANDLE;
  CK_MECHANISM mechanism = {0};
  CK_ATTRIBUTE publicTemplate[5];
  CK_ULONG publicCount = 0;
  const CMD_CONFIG *config = cmd_get_config();
  touchPolicy = (CK_BYTE)config->new_key_touch_policy;

  CK_ATTRIBUTE privateTemplate[8];
  CK_ULONG privateCount = 0;

  publicTemplate[publicCount++] = (CK_ATTRIBUTE){CKA_CLASS, &publicClass, sizeof(publicClass)};
  publicTemplate[publicCount++] = (CK_ATTRIBUTE){CKA_ID, &objectId, sizeof(objectId)};
  publicTemplate[publicCount++] = (CK_ATTRIBUTE){CKA_TOKEN, &token, sizeof(token)};

  privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_CLASS, &privateClass, sizeof(privateClass)};
  privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_ID, &objectId, sizeof(objectId)};
  privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_TOKEN, &token, sizeof(token)};
  privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_PRIVATE, &privateKey, sizeof(privateKey)};
  if (config->has_new_key_pin_policy) {
    pinPolicy = (CK_BYTE)config->new_key_pin_policy;
    privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_CNK_PIV_PIN_POLICY, &pinPolicy, sizeof(pinPolicy)};
  }
  privateTemplate[privateCount++] = (CK_ATTRIBUTE){CKA_CNK_PIV_TOUCH_POLICY, &touchPolicy, sizeof(touchPolicy)};

  if (dwKeySpec == AT_SIGNATURE || dwKeySpec == AT_KEYEXCHANGE) {
    CK_ULONG modulusBits = dwKeySize;
    mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    publicTemplate[publicCount++] = (CK_ATTRIBUTE){CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)};
  } else {
    const CK_BYTE *ecParams = NULL;
    CK_ULONG ecParamsLen = 0;
    DWORD ret = ec_params_for_key_spec(dwKeySpec, &ecParams, &ecParamsLen);
    if (ret != SCARD_S_SUCCESS) {
      return ret;
    }
    mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
    publicTemplate[publicCount++] = (CK_ATTRIBUTE){CKA_EC_PARAMS, (CK_BYTE_PTR)ecParams, ecParamsLen};
  }

  CK_RV rv = C_GenerateKeyPair(pContext->session, &mechanism, publicTemplate, publicCount, privateTemplate,
                               privateCount, &publicKey, &privateKeyHandle);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_container_error(rv), "C_GenerateKeyPair failed");
  }

  return refresh_container_metadata(pContext);
}

static void reverse_copy(CK_BYTE *destination, const CK_BYTE *source, CK_ULONG length) {
  // CAPI PRIVATEKEYBLOB integer components are little-endian; PKCS#11 RSA
  // attributes and the PIV import TLV use fixed-width big-endian integers.
  for (CK_ULONG i = 0; i < length; i++) {
    destination[i] = source[length - 1 - i];
  }
}

static BOOL validate_rsa_private_blob(const BYTE *blob, DWORD blobLen) {
  // Let the Windows software provider validate CRT consistency before any
  // irreversible PIV slot overwrite is attempted.
  HCRYPTPROV provider = 0;
  HCRYPTKEY key = 0;
  BOOL valid = FALSE;
  if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
    valid = CryptImportKey(provider, blob, blobLen, 0, 0, &key);
  }
  if (key != 0) {
    CryptDestroyKey(key);
  }
  if (provider != 0) {
    CryptReleaseContext(provider, 0);
  }
  return valid;
}

static BOOL validate_ec_private_blob(DWORD dwKeySpec, const BYTE *blob, DWORD blobLen) {
  // BCrypt validates the point/scalar relationship and curve-specific magic;
  // the minidriver subsequently imports only the private scalar into PIV.
  BCRYPT_ALG_HANDLE provider = NULL;
  BCRYPT_KEY_HANDLE key = NULL;
  LPCWSTR algorithm =
      (dwKeySpec == AT_ECDHE_P256 || dwKeySpec == AT_ECDHE_P384) ? BCRYPT_ECDH_ALGORITHM : BCRYPT_ECDSA_ALGORITHM;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&provider, algorithm, NULL, 0);
  if (BCRYPT_SUCCESS(status)) {
    status = BCryptImportKeyPair(provider, NULL, BCRYPT_ECCPRIVATE_BLOB, &key, (PUCHAR)blob, blobLen, 0);
  }
  if (key != NULL) {
    BCryptDestroyKey(key);
  }
  if (provider != NULL) {
    BCryptCloseAlgorithmProvider(provider, 0);
  }
  return BCRYPT_SUCCESS(status);
}

static void append_import_policies(CK_ATTRIBUTE *templ, CK_ULONG *pCount, CK_BYTE *pPinPolicy, CK_BYTE *pTouchPolicy) {
  const CMD_CONFIG *config = cmd_get_config();
  *pTouchPolicy = (CK_BYTE)config->new_key_touch_policy;
  if (config->has_new_key_pin_policy) {
    *pPinPolicy = (CK_BYTE)config->new_key_pin_policy;
    templ[(*pCount)++] = (CK_ATTRIBUTE){CKA_CNK_PIV_PIN_POLICY, pPinPolicy, sizeof(*pPinPolicy)};
  }
  templ[(*pCount)++] = (CK_ATTRIBUTE){CKA_CNK_PIV_TOUCH_POLICY, pTouchPolicy, sizeof(*pTouchPolicy)};
}

static DWORD import_rsa_key(CMD_CONTEXT_PTR pContext, BYTE bContainerIndex, DWORD dwKeySpec, DWORD dwKeySize,
                            const BYTE *pbKeyData) {
  PUBRSAKEYSTRUCT_BASE header;
  memcpy(&header, pbKeyData, sizeof(header));

  ALG_ID expectedAlg = dwKeySpec == AT_KEYEXCHANGE ? CALG_RSA_KEYX : CALG_RSA_SIGN;
  if (header.publickeystruc.bType != PRIVATEKEYBLOB || header.publickeystruc.bVersion != CUR_BLOB_VERSION ||
      header.publickeystruc.reserved != 0 || header.publickeystruc.aiKeyAlg != expectedAlg ||
      header.rsapubkey.magic != 0x32415352 || header.rsapubkey.bitlen != dwKeySize ||
      header.rsapubkey.pubexp != 65537) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid RSA private key blob header");
  }

  CK_ULONG modulusLen = dwKeySize / 8;
  CK_ULONG componentLen = modulusLen / 2;
  if (componentLen == 0 || componentLen > MAX_RSA_CRT_COMPONENT_BYTES) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid RSA private key blob size");
  }
  DWORD blobLen = (DWORD)(sizeof(header) + modulusLen * 2 + componentLen * RSA_CRT_COMPONENT_COUNT);
  if (!validate_rsa_private_blob(pbKeyData, blobLen)) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "RSA private key blob validation failed");
  }

  const CK_BYTE *component = pbKeyData + sizeof(header) + modulusLen;
  // PRIVATEKEYBLOB order after the modulus is P, Q, dP, dQ, qInv. The modulus
  // and private exponent are not needed by CanoKey's CRT import format.
  CK_BYTE components[RSA_CRT_COMPONENT_COUNT][MAX_RSA_CRT_COMPONENT_BYTES] = {0};
  for (CK_ULONG i = 0; i < RSA_CRT_COMPONENT_COUNT; i++) {
    reverse_copy(components[i], component, componentLen);
    component += componentLen;
  }

  CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_BYTE objectId = container_index_to_object_id(bContainerIndex);
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL privateKey = CK_TRUE;
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_ATTRIBUTE templ[12];
  CK_ULONG count = 0;
  templ[count++] = (CK_ATTRIBUTE){CKA_CLASS, &objectClass, sizeof(objectClass)};
  templ[count++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
  templ[count++] = (CK_ATTRIBUTE){CKA_ID, &objectId, sizeof(objectId)};
  templ[count++] = (CK_ATTRIBUTE){CKA_TOKEN, &token, sizeof(token)};
  templ[count++] = (CK_ATTRIBUTE){CKA_PRIVATE, &privateKey, sizeof(privateKey)};
  templ[count++] = (CK_ATTRIBUTE){CKA_PRIME_1, components[0], componentLen};
  templ[count++] = (CK_ATTRIBUTE){CKA_PRIME_2, components[1], componentLen};
  templ[count++] = (CK_ATTRIBUTE){CKA_EXPONENT_1, components[2], componentLen};
  templ[count++] = (CK_ATTRIBUTE){CKA_EXPONENT_2, components[3], componentLen};
  templ[count++] = (CK_ATTRIBUTE){CKA_COEFFICIENT, components[4], componentLen};
  append_import_policies(templ, &count, &pinPolicy, &touchPolicy);

  CK_OBJECT_HANDLE privateKeyHandle = CK_INVALID_HANDLE;
  CK_RV rv = C_CreateObject(pContext->session, templ, count, &privateKeyHandle);
  SecureZeroMemory(components, sizeof(components));
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_container_error(rv), "C_CreateObject RSA import failed");
  }
  return refresh_container_metadata(pContext);
}

static DWORD ecc_private_magic_for_key_spec(DWORD dwKeySpec, ULONG *pMagic, ULONG *pKeyBytes) {
  CMD_ENSURE_NONNULL(pMagic, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pKeyBytes, SCARD_E_INVALID_PARAMETER);

  switch (dwKeySpec) {
  case AT_ECDSA_P256:
    *pMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    *pKeyBytes = 32;
    CMD_RET_OK;
  case AT_ECDHE_P256:
    *pMagic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
    *pKeyBytes = 32;
    CMD_RET_OK;
  case AT_ECDSA_P384:
    *pMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    *pKeyBytes = 48;
    CMD_RET_OK;
  case AT_ECDHE_P384:
    *pMagic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
    *pKeyBytes = 48;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported EC private key blob type");
  }
}

static DWORD import_ec_key(CMD_CONTEXT_PTR pContext, BYTE bContainerIndex, DWORD dwKeySpec, DWORD dwKeySize,
                           const BYTE *pbKeyData) {
  BCRYPT_ECCKEY_BLOB header;
  memcpy(&header, pbKeyData, sizeof(header));

  ULONG expectedMagic = 0;
  ULONG expectedKeyBytes = 0;
  DWORD ret = ecc_private_magic_for_key_spec(dwKeySpec, &expectedMagic, &expectedKeyBytes);
  if (ret != SCARD_S_SUCCESS) {
    return ret;
  }
  if (header.dwMagic != expectedMagic || header.cbKey != expectedKeyBytes ||
      (dwKeySize != 0 && dwKeySize != expectedKeyBytes * 8)) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid EC private key blob header");
  }
  DWORD blobLen = (DWORD)(sizeof(header) + expectedKeyBytes * 3);
  if (!validate_ec_private_blob(dwKeySpec, pbKeyData, blobLen)) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "EC private key blob validation failed");
  }

  const CK_BYTE *ecParams = NULL;
  CK_ULONG ecParamsLen = 0;
  ret = ec_params_for_key_spec(dwKeySpec, &ecParams, &ecParamsLen);
  if (ret != SCARD_S_SUCCESS) {
    return ret;
  }

  // BCRYPT_ECCPRIVATE_BLOB stores X || Y || d as big-endian fixed-width fields.
  CK_BYTE privateScalar[48] = {0};
  memcpy(privateScalar, pbKeyData + sizeof(header) + expectedKeyBytes * 2, expectedKeyBytes);

  CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_EC;
  CK_BYTE objectId = container_index_to_object_id(bContainerIndex);
  CK_BBOOL token = CK_TRUE;
  CK_BBOOL privateKey = CK_TRUE;
  CK_BYTE pinPolicy = 0;
  CK_BYTE touchPolicy = 0;
  CK_ATTRIBUTE templ[9];
  CK_ULONG count = 0;
  templ[count++] = (CK_ATTRIBUTE){CKA_CLASS, &objectClass, sizeof(objectClass)};
  templ[count++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
  templ[count++] = (CK_ATTRIBUTE){CKA_ID, &objectId, sizeof(objectId)};
  templ[count++] = (CK_ATTRIBUTE){CKA_TOKEN, &token, sizeof(token)};
  templ[count++] = (CK_ATTRIBUTE){CKA_PRIVATE, &privateKey, sizeof(privateKey)};
  templ[count++] = (CK_ATTRIBUTE){CKA_EC_PARAMS, (CK_BYTE_PTR)ecParams, ecParamsLen};
  templ[count++] = (CK_ATTRIBUTE){CKA_VALUE, privateScalar, expectedKeyBytes};
  append_import_policies(templ, &count, &pinPolicy, &touchPolicy);

  CK_OBJECT_HANDLE privateKeyHandle = CK_INVALID_HANDLE;
  CK_RV rv = C_CreateObject(pContext->session, templ, count, &privateKeyHandle);
  SecureZeroMemory(privateScalar, sizeof(privateScalar));
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_container_error(rv), "C_CreateObject EC import failed");
  }
  return refresh_container_metadata(pContext);
}

static DWORD import_key(CMD_CONTEXT_PTR pContext, BYTE bContainerIndex, DWORD dwKeySpec, DWORD dwKeySize,
                        const BYTE *pbKeyData) {
  if (dwKeySpec == AT_SIGNATURE || dwKeySpec == AT_KEYEXCHANGE) {
    return import_rsa_key(pContext, bContainerIndex, dwKeySpec, dwKeySize, pbKeyData);
  }
  return import_ec_key(pContext, bContainerIndex, dwKeySpec, dwKeySize, pbKeyData);
}

static DWORD AllocRsaPublicKeyBlob(const SLOT *slot, ALG_ID keyAlg, PBYTE *ppbKey, PDWORD pcbKey) {
  PUBRSAKEYSTRUCT_BASE keyHeader;
  DWORD modulusSize = slot->rsa.modulusBits / 8;
  DWORD totalSize = sizeof(PUBRSAKEYSTRUCT_BASE) + modulusSize;

  *ppbKey = (PBYTE)g_pfnCspAlloc(totalSize);
  CMD_ENSURE_NONNULL(*ppbKey, SCARD_E_NO_MEMORY);

  keyHeader.publickeystruc.bType = PUBLICKEYBLOB;
  keyHeader.publickeystruc.bVersion = CUR_BLOB_VERSION;
  keyHeader.publickeystruc.reserved = 0;
  keyHeader.publickeystruc.aiKeyAlg = keyAlg;

  keyHeader.rsapubkey.magic = 0x31415352;             // RSA1 in little-endian
  keyHeader.rsapubkey.bitlen = slot->rsa.modulusBits; // Key size in bits
  keyHeader.rsapubkey.pubexp = 65537;                 // Standard RSA exponent (0x10001)

  memcpy(*ppbKey, &keyHeader, sizeof(PUBRSAKEYSTRUCT_BASE));
  memcpy(*ppbKey + sizeof(PUBRSAKEYSTRUCT_BASE), slot->rsa.modulus, modulusSize);
  *pcbKey = totalSize;

  CMD_RET_OK;
}

static DWORD AllocEcPublicKeyBlob(const SLOT *slot, ULONG magic, PBYTE *ppbKey, PDWORD pcbKey) {
  DWORD totalSize = sizeof(BCRYPT_ECCKEY_BLOB) + (DWORD)slot->ecc.cbPrivate * 2;

  *ppbKey = (PBYTE)g_pfnCspAlloc(totalSize);
  CMD_ENSURE_NONNULL(*ppbKey, SCARD_E_NO_MEMORY);

  BCRYPT_ECCKEY_BLOB *keyHeader = (BCRYPT_ECCKEY_BLOB *)*ppbKey;
  keyHeader->dwMagic = magic;
  keyHeader->cbKey = (ULONG)slot->ecc.cbPrivate;
  memcpy(*ppbKey + sizeof(BCRYPT_ECCKEY_BLOB), slot->ecc.x, slot->ecc.cbPrivate);
  memcpy(*ppbKey + sizeof(BCRYPT_ECCKEY_BLOB) + slot->ecc.cbPrivate, slot->ecc.y, slot->ecc.cbPrivate);
  *pcbKey = totalSize;

  CMD_RET_OK;
}

static DWORD EcPublicKeyMagic(const SLOT *slot, BOOL derive, ULONG *pMagic) {
  CMD_ENSURE_NONNULL(pMagic, SCARD_E_INVALID_PARAMETER);

  switch (slot->ecc.cbPrivate) {
  case 32:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P256_MAGIC : BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    CMD_RET_OK;
  case 48:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P384_MAGIC : BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    CMD_RET_OK;
  case 66:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P521_MAGIC : BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Unsupported EC key size");
  }
}

DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
                                 __in DWORD dwKeySpec, __in DWORD dwKeySize, __in PBYTE pbKeyData) {
  CMD_LOG_FUNC("pCardData %p, bContainerIndex %d, dwFlags %x, dwKeySpec %x, dwKeySize %d, pbKeyData %p", pCardData,
               bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);

  CMD_NONNULL_PARAM(pCardData);

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  DWORD ret = validate_create_container_request(bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
  if (ret != SCARD_S_SUCCESS) {
    return ret;
  }

  if (dwFlags == CARD_CREATE_CONTAINER_KEY_IMPORT) {
    return import_key(pContext, bContainerIndex, dwKeySpec, dwKeySize, pbKeyData);
  }

  return create_keypair(pContext, bContainerIndex, dwKeySpec, dwKeySize);
}

DWORD WINAPI CardCreateContainerEx(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
                                   __in DWORD dwKeySpec, __in DWORD dwKeySize, __in PBYTE pbKeyData,
                                   __in PIN_ID PinId) {
  CMD_LOG_FUNC("pCardData %p, bContainerIndex %d, dwFlags %x, dwKeySpec %x, dwKeySize %d, pbKeyData %p, PinId %d",
               pCardData, bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData, PinId);

  if (PinId == ROLE_ADMIN) {
    CMD_RETURN(SCARD_W_SECURITY_VIOLATION, "Administrators cannot create user key containers");
  }
  if (PinId != ROLE_USER) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid PinId");
  }

  return CardCreateContainer(pCardData, bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
}

/*
 * Function: CardGetContainerInfo
 *
 * Purpose: Get information about a key container on the card.
 */
DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
                                  __inout PCONTAINER_INFO pContainerInfo) {
  CMD_LOG_FUNC("pCardData %p, bContainerIndex %d, dwFlags %x, dwVersion %d", pCardData, bContainerIndex, dwFlags,
               pContainerInfo->dwVersion);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pContainerInfo);

  INJECT_HANDLES();

  CMD_CHECK_DW_FLAGS;
  if (pContainerInfo->dwVersion > CONTAINER_INFO_CURRENT_VERSION)
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid container info version");

  CMD_GET_CTX(pCardData, pContext);

  if (bContainerIndex >= pContext->canokey.slotCount ||
      !canokey_slot_has_key(&pContext->canokey.slots[bContainerIndex])) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }

  pContainerInfo->cbSigPublicKey = 0;
  pContainerInfo->pbSigPublicKey = NULL;
  pContainerInfo->cbKeyExPublicKey = 0;
  pContainerInfo->pbKeyExPublicKey = NULL;

  SLOT *slot = &pContext->canokey.slots[bContainerIndex];
  if (!canokey_slot_can_sign(slot) && !canokey_slot_can_decrypt(slot) && !canokey_slot_can_derive(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no usable key");
  }

  if (slot->keyType == CKK_RSA) {
    if (canokey_slot_can_sign(slot)) {
      DWORD ret =
          AllocRsaPublicKeyBlob(slot, CALG_RSA_SIGN, &pContainerInfo->pbSigPublicKey, &pContainerInfo->cbSigPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate signature RSA public key blob");
      }
    }
    if (canokey_slot_can_decrypt(slot)) {
      DWORD ret = AllocRsaPublicKeyBlob(slot, CALG_RSA_KEYX, &pContainerInfo->pbKeyExPublicKey,
                                        &pContainerInfo->cbKeyExPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate key exchange RSA public key blob");
      }
    }

    CMD_DEBUG("pContainerInfo:");
    CMD_PRINT_HEX(pContainerInfo, sizeof(CONTAINER_INFO));
    if (pContainerInfo->pbSigPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey, pContainerInfo->cbSigPublicKey);
    }
    if (pContainerInfo->pbKeyExPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbKeyExPublicKey, pContainerInfo->cbKeyExPublicKey);
    }
  } else if (slot->keyType == CKK_EC) {
    if (!canokey_slot_can_sign(slot) && !canokey_slot_can_derive(slot)) {
      CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "EC container has no usable key");
    }

    if (canokey_slot_can_sign(slot)) {
      ULONG magic;
      DWORD ret = EcPublicKeyMagic(slot, FALSE, &magic);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to select signature EC public key magic");
      }
      ret = AllocEcPublicKeyBlob(slot, magic, &pContainerInfo->pbSigPublicKey, &pContainerInfo->cbSigPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate signature EC public key blob");
      }
    }

    if (canokey_slot_can_derive(slot)) {
      ULONG magic;
      DWORD ret = EcPublicKeyMagic(slot, TRUE, &magic);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to select ECDH public key magic");
      }
      ret = AllocEcPublicKeyBlob(slot, magic, &pContainerInfo->pbKeyExPublicKey, &pContainerInfo->cbKeyExPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate ECDH public key blob");
      }
    }

    CMD_DEBUG("pContainerInfo:");
    CMD_PRINT_HEX(pContainerInfo, sizeof(CONTAINER_INFO));
    if (pContainerInfo->pbSigPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey, pContainerInfo->cbSigPublicKey);
    }
    if (pContainerInfo->pbKeyExPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbKeyExPublicKey, pContainerInfo->cbKeyExPublicKey);
    }
  }

  CMD_RET_OK;
}
