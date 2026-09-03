#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "config.h"
#include "logging.h"
#include "minidriver.h"

static DWORD getCardFreeSpace(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(CARD_FREE_SPACE_INFO);
  if (cbData < sizeof(CARD_FREE_SPACE_INFO)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PCARD_FREE_SPACE_INFO p = (PCARD_FREE_SPACE_INFO)pbData;
  p->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
  FillCardFreeSpaceInfo(p);
  CMD_RET_OK;
}

static DWORD getCardCapabilities(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(CARD_CAPABILITIES);
  if (cbData < sizeof(CARD_CAPABILITIES)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PCARD_CAPABILITIES p = (PCARD_CAPABILITIES)pbData;
  p->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
  p->fCertificateCompression = TRUE;
  p->fKeyGen = TRUE;
  CMD_RET_OK;
}

static DWORD getCardKeysizes(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen, DWORD dwFlags) {
  (void)pCardData;

  *pdwDataLen = sizeof(CARD_KEY_SIZES);
  if (cbData < sizeof(CARD_KEY_SIZES)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PCARD_KEY_SIZES p = (PCARD_KEY_SIZES)pbData;
  DWORD ret = FillCardKeySizes(dwFlags, p);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Unsupported key size property request");
  }
  CMD_RET_OK;
}

static DWORD getCardReadOnly(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(BOOL);
  if (cbData < sizeof(BOOL)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(BOOL *)pbData = FALSE;
  CMD_RET_OK;
}

static DWORD getCardCacheMode(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(DWORD);
  if (cbData < sizeof(DWORD)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  // PIN changes have no durable freshness counter in PIV. Disable Base CSP
  // caching so Windows cannot reuse a stale authorization decision after an
  // external PKCS#11/PIV mutation. CardReadFile still bounds metadata reads.
  *(DWORD *)pbData = CP_CACHE_MODE_NO_CACHE;
  CMD_RET_OK;
}

static DWORD getCardSupportsWinX509Enrollment(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(BOOL);
  if (cbData < sizeof(BOOL)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(BOOL *)pbData = TRUE;
  CMD_RET_OK;
}

static DWORD getCardGuid(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  CMD_GET_CTX(pCardData, pContext);

  *pdwDataLen = sizeof(pContext->cardId);
  if (cbData < sizeof(pContext->cardId)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  memcpy(pbData, pContext->cardId, sizeof(pContext->cardId));
  CMD_RET_OK;
}

static DWORD getCardPinInfo(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen, DWORD dwFlags) {
  (void)pCardData;

  if (dwFlags != ROLE_USER && dwFlags != ROLE_ADMIN && dwFlags != CMD_ROLE_PUK) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "only ROLE_USER, ROLE_ADMIN, and CMD_ROLE_PUK are supported");
  }
  *pdwDataLen = sizeof(PIN_INFO);
  if (cbData < sizeof(PIN_INFO)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PPIN_INFO p = (PPIN_INFO)pbData;
  if (p->dwVersion != PIN_INFO_CURRENT_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }
  p->PinType = AlphaNumericPinType;
  p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
  if (dwFlags == ROLE_ADMIN) {
    p->PinPurpose = AdministratorPin;
    p->dwChangePermission = PIN_SET_NONE;
    p->dwUnblockPermission = PIN_SET_NONE;
    p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
    p->PinCachePolicy.dwPinCachePolicyInfo = 0;
  } else if (dwFlags == CMD_ROLE_PUK) {
    p->PinPurpose = UnblockOnlyPin;
    p->dwChangePermission = PIN_SET_NONE;
    p->dwUnblockPermission = PIN_SET_NONE;
    p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
    p->PinCachePolicy.dwPinCachePolicyInfo = 0;
  } else {
    p->PinPurpose = PrimaryCardPin;
    p->dwChangePermission = CREATE_PIN_SET(ROLE_USER);
    p->dwUnblockPermission = CREATE_PIN_SET(CMD_ROLE_PUK);
    const CMD_CONFIG *config = cmd_get_config();
    if (config->has_pin_cache_timeout) {
      p->PinCachePolicy.PinCachePolicyType = PinCacheTimed;
      p->PinCachePolicy.dwPinCachePolicyInfo = config->pin_cache_timeout;
    } else {
      p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
      p->PinCachePolicy.dwPinCachePolicyInfo = 0;
    }
  }
  CMD_RET_OK;
}

static DWORD getCardListPins(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  (void)pCardData;

  *pdwDataLen = sizeof(PIN_SET);
  if (cbData < sizeof(PIN_SET)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(PIN_SET *)pbData = CREATE_PIN_SET(ROLE_USER) | CREATE_PIN_SET(ROLE_ADMIN) | CREATE_PIN_SET(CMD_ROLE_PUK);
  CMD_RET_OK;
}

static DWORD getCardAuthenticatedState(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  CMD_GET_CTX(pCardData, pContext);

  *pdwDataLen = sizeof(PIN_SET);
  if (cbData < sizeof(PIN_SET)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(PIN_SET *)pbData = pContext->authenticatedPins;
  CMD_RET_OK;
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
                             __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                             __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardGetProperty pCardData %p, wszProperty \"%S\", pbData %p, cbData %d, pdwDataLen %p, dwFlags %x",
               pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(wszProperty);
  CMD_NONNULL_PARAM(pdwDataLen);
  *pdwDataLen = 0;
  if (cbData != 0) {
    CMD_NONNULL_PARAM(pbData);
  }

  INJECT_HANDLES();

  if (wcscmp(wszProperty, CP_CARD_FREE_SPACE) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardFreeSpace(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_CAPABILITIES) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardCapabilities(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_KEYSIZES) == 0) {
    return getCardKeysizes(pCardData, pbData, cbData, pdwDataLen, dwFlags);
  }
  if (wcscmp(wszProperty, CP_CARD_READ_ONLY) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardReadOnly(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_CACHE_MODE) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardCacheMode(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardSupportsWinX509Enrollment(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_GUID) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardGuid(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_PIN_INFO) == 0) {
    return getCardPinInfo(pCardData, pbData, cbData, pdwDataLen, dwFlags);
  }
  if (wcscmp(wszProperty, CP_CARD_LIST_PINS) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardListPins(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_AUTHENTICATED_STATE) == 0) {
    CMD_CHECK_DW_FLAGS;
    return getCardAuthenticatedState(pCardData, pbData, cbData, pdwDataLen);
  }
  if (wcscmp(wszProperty, CP_CARD_PIN_STRENGTH_VERIFY) == 0) {
    if (dwFlags != ROLE_USER && dwFlags != ROLE_ADMIN && dwFlags != CMD_ROLE_PUK) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "only ROLE_USER, ROLE_ADMIN, and CMD_ROLE_PUK are supported");
    }
    *pdwDataLen = sizeof(DWORD);
    if (cbData < sizeof(DWORD)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    // we do not support session PIN
    *(DWORD *)pbData = CARD_PIN_STRENGTH_PLAINTEXT;
    CMD_RET_OK;
  }
  CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Property not supported");
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbData) PBYTE pbData,
                             __in DWORD cbData, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardSetProperty pCardData %p, wszProperty %S, pbData %p, cbData %d, dwFlags %x", pCardData, wszProperty,
               pbData, cbData, dwFlags);
  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(wszProperty);
  CMD_NONNULL_PARAM(pbData);
  (void)cbData;
  (void)dwFlags;

  INJECT_HANDLES();

  CMD_RET_UNIMPL;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
                                      __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                                      __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardGetContainerProperty pCardData %p, bContainerIndex %d, wszProperty \"%S\", dwFlags %x", pCardData,
               bContainerIndex, wszProperty, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(wszProperty);
  CMD_NONNULL_PARAM(pdwDataLen);
  *pdwDataLen = 0;
  if (cbData != 0) {
    CMD_NONNULL_PARAM(pbData);
  }
  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);
  if (bContainerIndex >= WINDOWS_CONTAINER_COUNT || bContainerIndex >= pContext->canokey.slotCount) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }

  // cmapfile may contain empty entries. Do not advertise a PIN identifier for
  // an empty container: Windows treats the property as proof that a key exists.
  if (!canokey_slot_has_key(&pContext->canokey.slots[bContainerIndex])) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no key");
  }

  CMD_CHECK_DW_FLAGS;
  if (wcscmp(wszProperty, CCP_PIN_IDENTIFIER) == 0) {
    *pdwDataLen = sizeof(PIN_ID);
    if (cbData < sizeof(PIN_ID)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(PIN_ID *)pbData = ROLE_USER;
    *pdwDataLen = sizeof(PIN_ID);
    CMD_RET_OK;
  }
  CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid property");
}
