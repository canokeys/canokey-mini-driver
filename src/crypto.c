#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"
#include "pkcs11.h"

static DWORD map_pkcs11_sign_error(CK_RV rv) {
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
            "%d, pbData %p, cbSignedData %d, pbSignedData %p, pPaddingInfo %p, dwPaddingType %d",
            pCardSigningInfo->dwVersion, pCardSigningInfo->bContainerIndex, pCardSigningInfo->dwKeySpec,
            pCardSigningInfo->dwSigningFlags, pCardSigningInfo->aiHashAlg, pCardSigningInfo->cbData,
            pCardSigningInfo->pbData, pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData,
            pCardSigningInfo->pPaddingInfo, pCardSigningInfo->dwPaddingType);

  if (pCardSigningInfo->dwVersion < CARD_SIGNING_INFO_CURRENT_VERSION &&
      pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");

  CMD_GET_CTX(pCardData, pContext);
  SLOT *slot = &pContext->canokey.slots[pCardSigningInfo->bContainerIndex];

  if (pCardSigningInfo->dwSigningFlags & CARD_PADDING_INFO_PRESENT) {
    if (pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
      CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");

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
      CMD_RETURN(map_pkcs11_sign_error(rv), "C_SignInit failed");

    pCardSigningInfo->cbSignedData = paddedLen;
    rv = C_Sign(pContext->session, pCardSigningInfo->pbSignedData, paddedLen, pCardSigningInfo->pbSignedData,
                &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_sign_error(rv), "C_Sign failed");

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);

    // reverse the signature
    reverse_bytes(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  } else {
    // if (pCardSigningInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION)
    //   CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
    // Sign
    CK_MECHANISM mech = {CKM_ECDSA, NULL, 0};
    CK_OBJECT_HANDLE hKey = (CKO_PRIVATE_KEY << 8) | slot->id;
    CK_RV rv = C_SignInit(pContext->session, &mech, hKey);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_sign_error(rv), "C_SignInit failed");

    pCardSigningInfo->cbSignedData = slot->ecc.cbPrivate * 2;
    pCardSigningInfo->pbSignedData = (PBYTE)g_pfnCspAlloc(pCardSigningInfo->cbSignedData);
    CMD_ENSURE_NONNULL(pCardSigningInfo->pbSignedData, SCARD_E_NO_MEMORY);

    rv = C_Sign(pContext->session, pCardSigningInfo->pbData, pCardSigningInfo->cbData, pCardSigningInfo->pbSignedData,
                &pCardSigningInfo->cbSignedData);
    if (rv != CKR_OK)
      CMD_RETURN(map_pkcs11_sign_error(rv), "C_Sign failed");

    CMD_DEBUG("Signed data: %d bytes (@%p)", pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData);
    CMD_PRINT_HEX(pCardSigningInfo->pbSignedData, pCardSigningInfo->cbSignedData);
  }

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
