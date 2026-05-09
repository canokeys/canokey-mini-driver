#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

#define CMD_CHECK_DW_FLAGS                                                                                             \
  if (dwFlags != 0) {                                                                                                  \
    CMD_RETURN(ERROR_INVALID_PARAMETER, "dwFlags is not zero");                                                        \
  }

static DWORD getCardFreeSpace(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) { CMD_RET_UNIMPL; }

static DWORD getCardCapabilities(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  if (cbData < sizeof(CARD_CAPABILITIES)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PCARD_CAPABILITIES p = (PCARD_CAPABILITIES)pbData;
  p->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
  p->fCertificateCompression = TRUE;
  p->fKeyGen = FALSE;
  *pdwDataLen = sizeof(CARD_CAPABILITIES);
  CMD_RET_OK;
}

static DWORD getCardKeysizes(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen, DWORD dwFlags) {
  (void)pCardData;

  if (cbData < sizeof(CARD_KEY_SIZES)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PCARD_KEY_SIZES p = (PCARD_KEY_SIZES)pbData;
  DWORD ret = FillCardKeySizes(dwFlags, p);
  if (ret != SCARD_S_SUCCESS) {
    CMD_RETURN(ret, "Unsupported key size property request");
  }
  *pdwDataLen = sizeof(CARD_KEY_SIZES);
  CMD_RET_OK;
}

static DWORD getCardReadOnly(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  if (cbData < sizeof(BOOL)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(BOOL *)pbData = TRUE;
  *pdwDataLen = sizeof(BOOL);
  CMD_RET_OK;
}

static DWORD getCardCacheMode(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  if (cbData < sizeof(DWORD)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(DWORD *)pbData = CP_CACHE_MODE_NO_CACHE;
  *pdwDataLen = sizeof(DWORD);
  CMD_RET_OK;
}

static DWORD getCardSupportsWinX509Enrollment(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  if (cbData < sizeof(BOOL)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  *(BOOL *)pbData = FALSE;
  *pdwDataLen = sizeof(BOOL);
  CMD_RET_OK;
}

static DWORD getCardGuid(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen) {
  BYTE guid[16] = {0, 1, 2, 3, 4, 5, 6, 7};
  if (cbData < sizeof(guid)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  memcpy(pbData, guid, sizeof(guid));
  *pdwDataLen = sizeof(guid);
  CMD_RET_OK;
}

static DWORD getCardPinInfo(PCARD_DATA pCardData, PBYTE pbData, DWORD cbData, PDWORD pdwDataLen, DWORD dwFlags) {
  if ((dwFlags & ROLE_USER) == 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "only ROLE_USER is supported");
  }
  if (cbData < sizeof(PIN_INFO)) {
    CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
  }
  PPIN_INFO p = (PPIN_INFO)pbData;
  if (p->dwVersion != PIN_INFO_CURRENT_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }
  p->PinType = AlphaNumericPinType;
  p->PinPurpose = PrimaryCardPin;
  p->dwChangePermission = ROLE_ADMIN;  // TODO: check
  p->dwUnblockPermission = ROLE_ADMIN; // TODO: check
  p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
  p->PinCachePolicy.PinCachePolicyType = PinCacheNormal; // TODO: DO NOT cache in pkcs11 layer
  p->PinCachePolicy.dwPinCachePolicyInfo = 0;
  *pdwDataLen = sizeof(PIN_INFO);
  CMD_RET_OK;
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
                             __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                             __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardGetProperty pCardData %p, wszProperty \"%S\", pbData %p, cbData %d, pdwDataLen %p, dwFlags %x",
               pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

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
  if (wcscmp(wszProperty, CP_CARD_PIN_STRENGTH_VERIFY) == 0) {
    if ((dwFlags & ROLE_USER) == 0) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "only ROLE_USER is supported");
    }
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
  CMD_NONNULL_PARAM(pbData);
  CMD_NONNULL_PARAM(pdwDataLen);

  INJECT_HANDLES();

  if (dwFlags != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid dwFlags");
  }
  if (wcscmp(wszProperty, CCP_PIN_IDENTIFIER) == 0) {
    if (cbData < sizeof(PIN_ID)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(PIN_ID *)pbData = ROLE_USER;
    *pdwDataLen = sizeof(PIN_ID);
    CMD_RET_OK;
  }
  CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid property");
}
