#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"
#include "pkcs11.h"

static DWORD map_pkcs11_crypto_error(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
    return SCARD_S_SUCCESS;
  case CKR_USER_NOT_LOGGED_IN:
    return SCARD_W_SECURITY_VIOLATION;
  case CKR_PIN_INCORRECT:
    return SCARD_W_WRONG_CHV;
  case CKR_PIN_LOCKED:
    return SCARD_W_CHV_BLOCKED;
  case CKR_HOST_MEMORY:
    return SCARD_E_NO_MEMORY;
  case CKR_BUFFER_TOO_SMALL:
    return ERROR_INSUFFICIENT_BUFFER;
  default:
    return SCARD_F_INTERNAL_ERROR;
  }
}

static DWORD map_oaep_hash_alg(LPCWSTR pszAlgId, CK_MECHANISM_TYPE *pHashAlg, CK_RSA_PKCS_MGF_TYPE *pMgf) {
  CMD_ENSURE_NONNULL(pHashAlg, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pMgf, SCARD_E_INVALID_PARAMETER);

  if (pszAlgId == NULL || wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0) {
    *pHashAlg = CKM_SHA_1;
    *pMgf = CKG_MGF1_SHA1;
    CMD_RET_OK;
  }
  if (wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
    *pHashAlg = CKM_SHA256;
    *pMgf = CKG_MGF1_SHA256;
    CMD_RET_OK;
  }
  if (wcscmp(pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
    *pHashAlg = CKM_SHA384;
    *pMgf = CKG_MGF1_SHA384;
    CMD_RET_OK;
  }
  if (wcscmp(pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
    *pHashAlg = CKM_SHA512;
    *pMgf = CKG_MGF1_SHA512;
    CMD_RET_OK;
  }

  CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported OAEP hash algorithm");
}

/*
 * Function: CardSignData
 *
 * Purpose: Sign data using a key on the card.
 */
DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pCardSigningInfo) {
  CMD_LOG_FUNC("pCardData %p, pCardSigningInfo %p", pCardData, pCardSigningInfo);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pCardSigningInfo);

  INJECT_HANDLES();

  CMD_DEBUG("CardSigningInfo: dwVersion %d, bContainerIndex %d, dwKeySpec %d, dwSigningFlags %d, aiHashAlg %d, cbData "
            "%d, pbData %p, cbSignedData %d, pbSignedData %p",
            pCardSigningInfo->dwVersion, pCardSigningInfo->bContainerIndex, pCardSigningInfo->dwKeySpec,
            pCardSigningInfo->dwSigningFlags, pCardSigningInfo->aiHashAlg, pCardSigningInfo->cbData,
            pCardSigningInfo->pbData, pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);

  if (pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION &&
      pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");

  CMD_GET_CTX(pCardData, pContext);
  if (pCardSigningInfo->bContainerIndex >= pContext->canokey.slotCount)
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");

  SLOT *slot = &pContext->canokey.slots[pCardSigningInfo->bContainerIndex];
  if (!canokey_slot_can_sign(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no signature key");
  }

  if (pCardSigningInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY) {
    pCardSigningInfo->cbSignedData = slot->keyType == CKK_RSA ? slot->rsa.modulusBits / 8 : slot->ecc.cbPrivate * 2;
    CMD_RET_OK;
  }

  CMD_NONNULL_PARAM(pCardSigningInfo->pbData);

  if (slot->keyType == CKK_RSA) {
    if (pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
      CMD_DEBUG("Using legacy CARD_SIGNING_INFO basic RSA padding path");
    if ((pCardSigningInfo->dwSigningFlags & CARD_PADDING_INFO_PRESENT) &&
        pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
      CMD_RETURN(ERROR_REVISION_MISMATCH, "Padding info requires current signing info version");
    CMD_ENSURE_NONNULL(g_pfnCspPadData, SCARD_F_INTERNAL_ERROR);

    DWORD paddedLen = slot->rsa.modulusBits / 8;
    DWORD ret = g_pfnCspPadData(pCardSigningInfo, paddedLen, &paddedLen, &pCardSigningInfo->pbSignedData);
    if (ret != 0)
      CMD_RETURN(ret, "padding failed");

    // Windows stores raw data in small-endian, need to reverse
    reverse_bytes(pCardSigningInfo->pbSignedData, paddedLen);

    CMD_DEBUG("Padding data: %d bytes (@%p)", paddedLen, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, paddedLen);

    // Sign
    CK_MECHANISM mech = {CKM_RSA_X_509, NULL, 0};
    CK_OBJECT_HANDLE hKey = (CKO_PRIVATE_KEY << 8) | slot->id;
    CK_RV rv = C_SignInit(pContext->session, &mech, hKey);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_SignInit failed");

    pCardSigningInfo->cbSignedData = paddedLen;
    rv = C_Sign(pContext->session, pCardSigningInfo->pbSignedData, paddedLen, pCardSigningInfo->pbSignedData,
                &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_Sign failed");

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);

    // reverse the signature
    reverse_bytes(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  } else if (slot->keyType == CKK_EC) {
    CK_MECHANISM mech = {CKM_ECDSA, NULL, 0};
    CK_OBJECT_HANDLE hKey = (CKO_PRIVATE_KEY << 8) | slot->id;
    CK_RV rv = C_SignInit(pContext->session, &mech, hKey);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_SignInit failed");

    pCardSigningInfo->cbSignedData = slot->ecc.cbPrivate * 2;
    pCardSigningInfo->pbSignedData = (PBYTE)g_pfnCspAlloc(pCardSigningInfo->cbSignedData);
    CMD_ENSURE_NONNULL(pCardSigningInfo->pbSignedData, SCARD_E_NO_MEMORY);

    rv = C_Sign(pContext->session, pCardSigningInfo->pbData, pCardSigningInfo->cbData, pCardSigningInfo->pbSignedData,
                &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_Sign failed");

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  } else {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Unsupported key type");
  }

  CMD_RET_OK;
}

/*
 * Function: CardRSADecrypt
 *
 * Purpose: Decrypt data using a key exchange key on the card.
 */
DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData, __inout PCARD_RSA_DECRYPT_INFO pInfo) {
  CMD_LOG_FUNC("pCardData %p, pInfo %p", pCardData, pInfo);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pInfo);

  INJECT_HANDLES();

  CMD_DEBUG("CardRSADecrypt: dwVersion %d, bContainerIndex %d, dwKeySpec %d, pbData %p, cbData %d, pPaddingInfo %p, "
            "dwPaddingType %d",
            pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->pbData, pInfo->cbData,
            pInfo->pPaddingInfo, pInfo->dwPaddingType);

  if (pInfo->dwVersion != CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE &&
      pInfo->dwVersion != CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");

  CMD_GET_CTX(pCardData, pContext);
  if (pInfo->bContainerIndex >= pContext->canokey.slotCount)
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");

  SLOT *slot = &pContext->canokey.slots[pInfo->bContainerIndex];
  if (!canokey_slot_can_decrypt(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no key exchange key");
  }
  if (slot->keyType != CKK_RSA) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Key exchange key is not RSA");
  }
  if (pInfo->dwKeySpec != AT_KEYEXCHANGE) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only AT_KEYEXCHANGE is supported for RSA decrypt");
  }

  CMD_NONNULL_PARAM(pInfo->pbData);
  DWORD modulusSize = slot->rsa.modulusBits / 8;
  if (pInfo->cbData != modulusSize) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Encrypted data length does not match RSA modulus");
  }

  CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
  CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0};
  if (pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE || pInfo->dwPaddingType == 0 ||
      pInfo->dwPaddingType == CARD_PADDING_PKCS1) {
    mech.mechanism = CKM_RSA_PKCS;
  } else if (pInfo->dwPaddingType == CARD_PADDING_NONE) {
    mech.mechanism = CKM_RSA_X_509;
  } else if (pInfo->dwPaddingType == CARD_PADDING_OAEP) {
    CMD_ENSURE_NONNULL(pInfo->pPaddingInfo, SCARD_E_INVALID_PARAMETER);
    BCRYPT_OAEP_PADDING_INFO *paddingInfo = (BCRYPT_OAEP_PADDING_INFO *)pInfo->pPaddingInfo;
    DWORD ret = map_oaep_hash_alg(paddingInfo->pszAlgId, &oaepParams.hashAlg, &oaepParams.mgf);
    if (ret != SCARD_S_SUCCESS) {
      CMD_RETURN(ret, "Unsupported OAEP hash algorithm");
    }
    oaepParams.source = CKZ_DATA_SPECIFIED;
    oaepParams.pSourceData = paddingInfo->pbLabel;
    oaepParams.ulSourceDataLen = paddingInfo->cbLabel;

    mech.mechanism = CKM_RSA_PKCS_OAEP;
    mech.pParameter = &oaepParams;
    mech.ulParameterLen = sizeof(oaepParams);
  } else {
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported RSA decrypt padding type");
  }

  PBYTE encryptedData = (PBYTE)g_pfnCspAlloc(pInfo->cbData);
  CMD_ENSURE_NONNULL(encryptedData, SCARD_E_NO_MEMORY);
  memcpy(encryptedData, pInfo->pbData, pInfo->cbData);
  reverse_bytes(encryptedData, pInfo->cbData);

  CK_OBJECT_HANDLE hKey = (CKO_PRIVATE_KEY << 8) | slot->id;
  CK_RV rv = C_DecryptInit(pContext->session, &mech, hKey);
  if (rv != CKR_OK) {
    g_pfnCspFree(encryptedData);
    CMD_RETURN(map_pkcs11_crypto_error(rv), "C_DecryptInit failed");
  }

  CK_ULONG cbPlain = pInfo->cbData;
  rv = C_Decrypt(pContext->session, encryptedData, pInfo->cbData, pInfo->pbData, &cbPlain);
  g_pfnCspFree(encryptedData);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_crypto_error(rv), "C_Decrypt failed");
  }

  // CardRSADecrypt returns RSA data to Windows in little-endian order, even
  // when the PKCS#11 layer has already removed PKCS#1/OAEP padding.
  reverse_bytes(pInfo->pbData, cbPlain);
  pInfo->cbData = (DWORD)cbPlain;

  CMD_DEBUG("Decrypted data: %d bytes (@%p)", pInfo->cbData, pInfo->pbData);
  CMD_PRINT_HEX(pInfo->pbData, pInfo->cbData);

  CMD_RET_OK;
}

/*
 * Function: CardQueryKeySizes
 *
 * Purpose: Query the supported key sizes for a given algorithm.
 */
DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags,
                               __inout PCARD_KEY_SIZES pKeySizes) {
  CMD_LOG_FUNC("pCardData %p, dwKeySpec %x, dwFlags "
               "%x, pKeySizes %p",
               pCardData, dwKeySpec, dwFlags, pKeySizes);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pKeySizes);

  INJECT_HANDLES();

  CMD_RET_UNIMPL;
}
