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

static DWORD cancel_context_operation(CMD_CONTEXT_PTR pContext, CK_FLAGS flags, DWORD fallback) {
  CK_RV cancelRv = C_SessionCancel(pContext->session, flags);
  if (cancelRv != CKR_OK && cancelRv != CKR_OPERATION_NOT_INITIALIZED) {
    CMD_ERROR("C_SessionCancel failed for flags 0x%lx: 0x%lx", (unsigned long)flags, (unsigned long)cancelRv);
    return SCARD_F_INTERNAL_ERROR;
  }
  return fallback;
}

static CK_RV sign_with_context_pin(CMD_CONTEXT_PTR pContext, CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR signature,
                                   CK_ULONG_PTR signatureLen) {
  CK_RV rv = C_Sign(pContext->session, data, dataLen, signature, signatureLen);
  if (rv != CKR_USER_NOT_LOGGED_IN)
    return rv;

  // C_Sign keeps the PIN-always operation active on this error. Authenticate
  // once with the PIN captured by CardAuthenticateEx, then retry the same
  // operation. cmd_login_context_specific consumes and clears that PIN.
  CMD_DEBUG("C_Sign requires context-specific USER authentication; retrying once");
  CK_RV authRv = cmd_login_context_specific(pContext);
  if (authRv != CKR_OK) {
    CMD_DEBUG("C_Sign context-specific authentication failed: 0x%lx", authRv);
    return authRv == CKR_OPERATION_NOT_INITIALIZED ? CKR_USER_NOT_LOGGED_IN : authRv;
  }
  rv = C_Sign(pContext->session, data, dataLen, signature, signatureLen);
  CMD_DEBUG("C_Sign context-specific retry returned 0x%lx", rv);
  return rv;
}

static CK_RV decrypt_with_context_pin(CMD_CONTEXT_PTR pContext, CK_BYTE_PTR encryptedData, CK_ULONG encryptedLen,
                                      CK_BYTE_PTR plainData, CK_ULONG_PTR plainLen) {
  CK_RV rv = C_Decrypt(pContext->session, encryptedData, encryptedLen, plainData, plainLen);
  if (rv != CKR_USER_NOT_LOGGED_IN)
    return rv;

  CMD_DEBUG("C_Decrypt requires context-specific USER authentication; retrying once");
  CK_RV authRv = cmd_login_context_specific(pContext);
  if (authRv != CKR_OK) {
    CMD_DEBUG("C_Decrypt context-specific authentication failed: 0x%lx", authRv);
    return authRv == CKR_OPERATION_NOT_INITIALIZED ? CKR_USER_NOT_LOGGED_IN : authRv;
  }
  rv = C_Decrypt(pContext->session, encryptedData, encryptedLen, plainData, plainLen);
  CMD_DEBUG("C_Decrypt context-specific retry returned 0x%lx", rv);
  return rv;
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

static DWORD ec_key_spec_for_slot(const SLOT *slot, DWORD *pKeySpec) {
  CMD_ENSURE_NONNULL(slot, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pKeySpec, SCARD_E_INVALID_PARAMETER);

  switch (slot->ecCurve) {
  case CANOKEY_EC_CURVE_P256:
    *pKeySpec = AT_ECDHE_P256;
    CMD_RET_OK;
  case CANOKEY_EC_CURVE_P384:
    *pKeySpec = AT_ECDHE_P384;
    CMD_RET_OK;
  case CANOKEY_EC_CURVE_P521:
    *pKeySpec = AT_ECDHE_P521;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported EC key size");
  }
}

static DWORD expected_ecdh_public_magic(const SLOT *slot, ULONG *pMagic) {
  CMD_ENSURE_NONNULL(slot, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pMagic, SCARD_E_INVALID_PARAMETER);

  switch (slot->ecCurve) {
  case CANOKEY_EC_CURVE_P256:
    *pMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    CMD_RET_OK;
  case CANOKEY_EC_CURVE_P384:
    *pMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    CMD_RET_OK;
  case CANOKEY_EC_CURVE_P521:
    *pMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported ECDH public key size");
  }
}

static void clear_dh_agreement(CMD_DH_AGREEMENT *agreement) {
  if (agreement == NULL) {
    return;
  }
  SecureZeroMemory(agreement->secret, sizeof(agreement->secret));
  memset(agreement, 0, sizeof(*agreement));
}

static DWORD find_free_dh_agreement(CMD_CONTEXT_PTR pContext, BYTE *pAgreementIndex) {
  CMD_ENSURE_NONNULL(pContext, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pAgreementIndex, SCARD_E_INVALID_PARAMETER);

  for (BYTE i = 0; i < CMD_MAX_DH_AGREEMENTS; i++) {
    if (!pContext->dhAgreements[i].active) {
      *pAgreementIndex = (BYTE)(i + 1);
      CMD_RET_OK;
    }
  }

  CMD_RETURN(SCARD_E_NO_MEMORY, "No free DH agreement slot");
}

static DWORD get_dh_agreement(CMD_CONTEXT_PTR pContext, BYTE agreementIndex, CMD_DH_AGREEMENT **ppAgreement) {
  CMD_ENSURE_NONNULL(pContext, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(ppAgreement, SCARD_E_INVALID_PARAMETER);

  if (agreementIndex == 0 || agreementIndex > CMD_MAX_DH_AGREEMENTS) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid DH agreement index");
  }

  CMD_DH_AGREEMENT *agreement = &pContext->dhAgreements[agreementIndex - 1];
  if (!agreement->active) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "DH agreement index is not active");
  }

  *ppAgreement = agreement;
  CMD_RET_OK;
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

  CMD_CONTEXT_PTR userPinGuard CMD_USER_PIN_GUARD = pContext;

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
    CK_OBJECT_HANDLE hKey = CMD_MAKE_OBJECT_HANDLE(0, CKO_PRIVATE_KEY, slot->id);
    CK_RV rv = C_SignInit(pContext->session, &mech, hKey);
    if (rv != CKR_OK) {
      g_pfnCspFree(pCardSigningInfo->pbSignedData);
      pCardSigningInfo->pbSignedData = NULL;
      pCardSigningInfo->cbSignedData = 0;
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_SignInit failed");
    }

    pCardSigningInfo->cbSignedData = paddedLen;
    rv = sign_with_context_pin(pContext, pCardSigningInfo->pbSignedData, paddedLen, pCardSigningInfo->pbSignedData,
                               &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK) {
      DWORD cancelRet = cancel_context_operation(pContext, CKF_SIGN, map_pkcs11_crypto_error(rv));
      SecureZeroMemory(pCardSigningInfo->pbSignedData, paddedLen);
      g_pfnCspFree(pCardSigningInfo->pbSignedData);
      pCardSigningInfo->pbSignedData = NULL;
      pCardSigningInfo->cbSignedData = 0;
      CMD_RETURN(cancelRet, "C_Sign failed");
    }

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);

    // reverse the signature
    reverse_bytes(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  } else if (slot->keyType == CKK_EC) {
    CK_MECHANISM mech = {CKM_ECDSA, NULL, 0};
    CK_OBJECT_HANDLE hKey = CMD_MAKE_OBJECT_HANDLE(0, CKO_PRIVATE_KEY, slot->id);
    CK_RV rv = C_SignInit(pContext->session, &mech, hKey);
    if (rv != CKR_OK) {
      pCardSigningInfo->pbSignedData = NULL;
      pCardSigningInfo->cbSignedData = 0;
      CMD_RETURN(map_pkcs11_crypto_error(rv), "C_SignInit failed");
    }

    DWORD signatureCapacity = (DWORD)(slot->ecc.cbPrivate * 2);
    pCardSigningInfo->cbSignedData = signatureCapacity;
    pCardSigningInfo->pbSignedData = (PBYTE)g_pfnCspAlloc(signatureCapacity);
    if (pCardSigningInfo->pbSignedData == NULL) {
      DWORD cancelRet = cancel_context_operation(pContext, CKF_SIGN, SCARD_E_NO_MEMORY);
      CMD_RETURN(cancelRet, "signature output allocation failed");
    }

    rv = sign_with_context_pin(pContext, pCardSigningInfo->pbData, pCardSigningInfo->cbData,
                               pCardSigningInfo->pbSignedData, &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK) {
      DWORD cancelRet = cancel_context_operation(pContext, CKF_SIGN, map_pkcs11_crypto_error(rv));
      SecureZeroMemory(pCardSigningInfo->pbSignedData, signatureCapacity);
      g_pfnCspFree(pCardSigningInfo->pbSignedData);
      pCardSigningInfo->pbSignedData = NULL;
      pCardSigningInfo->cbSignedData = 0;
      CMD_RETURN(cancelRet, "C_Sign failed");
    }

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  } else {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Unsupported key type");
  }

  CMD_RET_OK;
}

/*
 * Function: CardConstructDHAgreement
 *
 * Purpose: Create an ECDH shared secret with a card EC private key and a peer
 *          public key.
 */
DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData, __inout PCARD_DH_AGREEMENT_INFO pAgreementInfo) {
  CMD_LOG_FUNC("pCardData %p, pAgreementInfo %p", pCardData, pAgreementInfo);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pAgreementInfo);

  INJECT_HANDLES();

  CMD_DEBUG("CardConstructDHAgreement: dwVersion %d, bContainerIndex %d, dwFlags %x, dwPublicKey %d, pbPublicKey %p, "
            "pbReserved %p, cbReserved %d",
            pAgreementInfo->dwVersion, pAgreementInfo->bContainerIndex, pAgreementInfo->dwFlags,
            pAgreementInfo->dwPublicKey, pAgreementInfo->pbPublicKey, pAgreementInfo->pbReserved,
            pAgreementInfo->cbReserved);

  if (pAgreementInfo->dwVersion != CARD_DH_AGREEMENT_INFO_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }
  if (pAgreementInfo->dwFlags != 0 || pAgreementInfo->pbReserved != NULL || pAgreementInfo->cbReserved != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported DH agreement flags or reserved fields");
  }
  CMD_NONNULL_PARAM(pAgreementInfo->pbPublicKey);

  CMD_GET_CTX(pCardData, pContext);
  if (pAgreementInfo->bContainerIndex >= pContext->canokey.slotCount) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }

  SLOT *slot = &pContext->canokey.slots[pAgreementInfo->bContainerIndex];
  if (!canokey_slot_can_derive(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no ECDH key");
  }

  DWORD keySpec;
  DWORD ret = ec_key_spec_for_slot(slot, &keySpec);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Unsupported ECDH key size");
  }

  ULONG expectedMagic;
  ret = expected_ecdh_public_magic(slot, &expectedMagic);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Unsupported ECDH public key size");
  }

  if (pAgreementInfo->dwPublicKey != sizeof(BCRYPT_ECCKEY_BLOB) + slot->ecc.cbPrivate * 2) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Peer public key blob length mismatch");
  }

  BCRYPT_ECCKEY_BLOB *peerKey = (BCRYPT_ECCKEY_BLOB *)pAgreementInfo->pbPublicKey;
  if (peerKey->dwMagic != expectedMagic || peerKey->cbKey != slot->ecc.cbPrivate) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Peer public key curve mismatch");
  }

  BYTE peerPoint[1 + CMD_MAX_DH_SECRET_LEN * 2] = {0};
  DWORD peerPointLen = 1 + (DWORD)slot->ecc.cbPrivate * 2;
  peerPoint[0] = 0x04;
  memcpy(peerPoint + 1, pAgreementInfo->pbPublicKey + sizeof(BCRYPT_ECCKEY_BLOB), slot->ecc.cbPrivate * 2);

  CK_ECDH1_DERIVE_PARAMS deriveParams = {
      .kdf = CKD_NULL,
      .pSharedData = NULL,
      .ulSharedDataLen = 0,
      .pPublicData = peerPoint,
      .ulPublicDataLen = peerPointLen,
  };
  CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &deriveParams, sizeof(deriveParams)};

  CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
  CK_KEY_TYPE secretType = CKK_GENERIC_SECRET;
  CK_ULONG secretLen = slot->ecc.cbPrivate;
  CK_BBOOL token = CK_FALSE;
  CK_BBOOL private = CK_TRUE;
  CK_BBOOL sensitive = CK_FALSE;
  CK_BBOOL extractable = CK_TRUE;
  CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &secretClass, sizeof(secretClass)},
      {CKA_KEY_TYPE, &secretType, sizeof(secretType)},
      {CKA_VALUE_LEN, &secretLen, sizeof(secretLen)},
      {CKA_TOKEN, &token, sizeof(token)},
      {CKA_PRIVATE, &private, sizeof(private)},
      {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
      {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
  };

  CK_OBJECT_HANDLE hBaseKey = CMD_MAKE_OBJECT_HANDLE(0, CKO_PRIVATE_KEY, slot->id);
  CK_OBJECT_HANDLE hSecret = 0;
  CMD_CONTEXT_PTR userPinGuard CMD_USER_PIN_GUARD = pContext;
  CK_RV rv =
      C_DeriveKey(pContext->session, &mech, hBaseKey, template, sizeof(template) / sizeof(template[0]), &hSecret);
  SecureZeroMemory(peerPoint, sizeof(peerPoint));
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_crypto_error(rv), "C_DeriveKey failed");
  }

  BYTE agreementIndex;
  ret = find_free_dh_agreement(pContext, &agreementIndex);
  if (ret != SCARD_S_SUCCESS) {
    CK_RV destroyRv = C_DestroyObject(pContext->session, hSecret);
    if (destroyRv != CKR_OK)
      CMD_WARN("C_DestroyObject for ECDH secret failed: 0x%lx", destroyRv);
    CMD_RETURN(ret, "No free DH agreement slot");
  }

  CMD_DH_AGREEMENT *agreement = &pContext->dhAgreements[agreementIndex - 1];
  clear_dh_agreement(agreement);
  CK_ATTRIBUTE valueAttr = {CKA_VALUE, agreement->secret, sizeof(agreement->secret)};
  rv = C_GetAttributeValue(pContext->session, hSecret, &valueAttr, 1);
  CK_RV destroyRv = C_DestroyObject(pContext->session, hSecret);
  if (destroyRv != CKR_OK) {
    clear_dh_agreement(agreement);
    CMD_RETURN(map_pkcs11_crypto_error(destroyRv), "C_DestroyObject for ECDH secret failed");
  }
  if (rv != CKR_OK) {
    clear_dh_agreement(agreement);
    CMD_RETURN(map_pkcs11_crypto_error(rv), "C_GetAttributeValue for ECDH secret failed");
  }
  if (valueAttr.ulValueLen == CK_UNAVAILABLE_INFORMATION || valueAttr.ulValueLen == 0 ||
      valueAttr.ulValueLen > sizeof(agreement->secret)) {
    clear_dh_agreement(agreement);
    CMD_RETURN(SCARD_F_INTERNAL_ERROR, "Invalid ECDH secret length");
  }

  agreement->active = TRUE;
  agreement->secretLen = (DWORD)valueAttr.ulValueLen;
  agreement->containerIndex = pAgreementInfo->bContainerIndex;
  agreement->keySpec = keySpec;
  pAgreementInfo->bSecretAgreementIndex = agreementIndex;

  CMD_DEBUG("Constructed DH agreement %u for container %u, secretLen %u", agreementIndex,
            pAgreementInfo->bContainerIndex, agreement->secretLen);
  CMD_RET_OK;
}

/*
 * Function: CardDeriveKey
 *
 * Purpose: Return raw ECDH secret bytes for a previously constructed DH
 *          agreement. Other KDFs are intentionally unsupported for now.
 */
DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData, __inout PCARD_DERIVE_KEY pAgreementInfo) {
  CMD_LOG_FUNC("pCardData %p, pAgreementInfo %p", pCardData, pAgreementInfo);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pAgreementInfo);

  INJECT_HANDLES();

  CMD_DEBUG("CardDeriveKey: dwVersion %d, dwFlags %x, pwszKDF %S, bSecretAgreementIndex %u, pParameterList %p, "
            "pbDerivedKey %p, cbDerivedKey %d, pwszAlgId %S, dwKeyLen %d, hKey %p",
            pAgreementInfo->dwVersion, pAgreementInfo->dwFlags, pAgreementInfo->pwszKDF,
            pAgreementInfo->bSecretAgreementIndex, pAgreementInfo->pParameterList, pAgreementInfo->pbDerivedKey,
            pAgreementInfo->cbDerivedKey, pAgreementInfo->pwszAlgId, pAgreementInfo->dwKeyLen,
            (void *)pAgreementInfo->hKey);

  if (pAgreementInfo->dwVersion != CARD_DERIVE_KEY_VERSION &&
      pAgreementInfo->dwVersion != CARD_DERIVE_KEY_VERSION_TWO) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }

  if (pAgreementInfo->dwFlags & CARD_RETURN_KEY_HANDLE) {
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Returning symmetric key handles is not supported");
  }
  if ((pAgreementInfo->dwFlags & ~(CARD_BUFFER_SIZE_ONLY | CARD_RETURN_KEY_HANDLE)) != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported derive key flags");
  }
  if (pAgreementInfo->pParameterList != NULL) {
    BCryptBufferDesc *params = (BCryptBufferDesc *)pAgreementInfo->pParameterList;
    if (params->ulVersion != BCRYPTBUFFER_VERSION || params->cBuffers != 0) {
      CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "KDF parameter lists are not supported");
    }
  }
  if (pAgreementInfo->pwszKDF != NULL && pAgreementInfo->pwszKDF[0] != L'\0' &&
      wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_RAW_SECRET) != 0) {
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Only raw secret KDF is supported");
  }
  if (pAgreementInfo->pwszAlgId != NULL) {
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Derived key algorithms are not supported");
  }

  CMD_GET_CTX(pCardData, pContext);
  CMD_DH_AGREEMENT *agreement = NULL;
  DWORD ret = get_dh_agreement(pContext, pAgreementInfo->bSecretAgreementIndex, &agreement);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Invalid DH agreement");
  }

  DWORD outputLen = agreement->secretLen;
  if (pAgreementInfo->dwKeyLen != 0) {
    DWORD requestedLen = (pAgreementInfo->dwKeyLen + 7) / 8;
    if (requestedLen == 0 || requestedLen > agreement->secretLen) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid requested raw secret length");
    }
    outputLen = requestedLen;
  }

  if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY) {
    pAgreementInfo->cbDerivedKey = outputLen;
    CMD_RET_OK;
  }

  if (pAgreementInfo->pbDerivedKey == NULL) {
    pAgreementInfo->pbDerivedKey = (PBYTE)g_pfnCspAlloc(outputLen);
    CMD_ENSURE_NONNULL(pAgreementInfo->pbDerivedKey, SCARD_E_NO_MEMORY);
  } else if (pAgreementInfo->cbDerivedKey < outputLen) {
    pAgreementInfo->cbDerivedKey = outputLen;
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "Derived key buffer is too small");
  }

  memcpy(pAgreementInfo->pbDerivedKey, agreement->secret, outputLen);
  reverse_bytes(pAgreementInfo->pbDerivedKey, outputLen);
  pAgreementInfo->cbDerivedKey = outputLen;

  CMD_DEBUG("Derived raw ECDH secret: %d bytes", pAgreementInfo->cbDerivedKey);
  CMD_RET_OK;
}

/*
 * Function: CardDestroyDHAgreement
 *
 * Purpose: Delete a cached DH shared secret.
 */
DWORD WINAPI CardDestroyDHAgreement(__in PCARD_DATA pCardData, __in BYTE bSecretAgreementIndex, __in DWORD dwFlags) {
  CMD_LOG_FUNC("pCardData %p, bSecretAgreementIndex %u, dwFlags %x", pCardData, bSecretAgreementIndex, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_CHECK_DW_FLAGS;

  INJECT_HANDLES();

  CMD_GET_CTX(pCardData, pContext);
  CMD_DH_AGREEMENT *agreement = NULL;
  DWORD ret = get_dh_agreement(pContext, bSecretAgreementIndex, &agreement);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Invalid DH agreement");
  }

  clear_dh_agreement(agreement);
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
  CMD_CONTEXT_PTR userPinGuard CMD_USER_PIN_GUARD = pContext;
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

  CK_OBJECT_HANDLE hKey = CMD_MAKE_OBJECT_HANDLE(0, CKO_PRIVATE_KEY, slot->id);
  CK_RV rv = C_DecryptInit(pContext->session, &mech, hKey);
  if (rv != CKR_OK) {
    g_pfnCspFree(encryptedData);
    CMD_RETURN(map_pkcs11_crypto_error(rv), "C_DecryptInit failed");
  }

  CK_ULONG cbPlain = pInfo->cbData;
  rv = decrypt_with_context_pin(pContext, encryptedData, pInfo->cbData, pInfo->pbData, &cbPlain);
  g_pfnCspFree(encryptedData);
  if (rv != CKR_OK) {
    DWORD cancelRet = cancel_context_operation(pContext, CKF_DECRYPT, map_pkcs11_crypto_error(rv));
    CMD_RETURN(cancelRet, "C_Decrypt failed");
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
DWORD FillCardKeySizes(DWORD dwKeySpec, PCARD_KEY_SIZES pKeySizes) {
  CMD_ENSURE_NONNULL(pKeySizes, SCARD_E_INVALID_PARAMETER);

  pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
  pKeySizes->dwIncrementalBitlen = 0;

  switch (dwKeySpec) {
  case AT_SIGNATURE:
  case AT_KEYEXCHANGE:
    pKeySizes->dwMinimumBitlen = 2048;
    pKeySizes->dwDefaultBitlen = 2048;
    pKeySizes->dwMaximumBitlen = 4096;
    pKeySizes->dwIncrementalBitlen = 1024;
    CMD_RET_OK;
  case AT_ECDSA_P256:
  case AT_ECDHE_P256:
    pKeySizes->dwMinimumBitlen = 256;
    pKeySizes->dwDefaultBitlen = 256;
    pKeySizes->dwMaximumBitlen = 256;
    CMD_RET_OK;
  case AT_ECDSA_P384:
  case AT_ECDHE_P384:
    pKeySizes->dwMinimumBitlen = 384;
    pKeySizes->dwDefaultBitlen = 384;
    pKeySizes->dwMaximumBitlen = 384;
    CMD_RET_OK;
  case AT_ECDSA_P521:
  case AT_ECDHE_P521:
    pKeySizes->dwMinimumBitlen = 521;
    pKeySizes->dwDefaultBitlen = 521;
    pKeySizes->dwMaximumBitlen = 521;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Unsupported key spec");
  }
}

DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags,
                               __inout PCARD_KEY_SIZES pKeySizes) {
  CMD_LOG_FUNC("pCardData %p, dwKeySpec %x, dwFlags "
               "%x, pKeySizes %p",
               pCardData, dwKeySpec, dwFlags, pKeySizes);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pKeySizes);

  INJECT_HANDLES();

  if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }
  CMD_CHECK_DW_FLAGS;

  return FillCardKeySizes(dwKeySpec, pKeySizes);
}
