#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"

#define CMD_CHECK_DW_FLAGS                                                                                             \
  if (dwFlags != 0) {                                                                                                  \
    CMD_RETURN(ERROR_INVALID_PARAMETER, "dwFlags is not zero");                                                        \
  }

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
                             __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                             __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardGetProperty pCardData %p, wszProperty %S, pbData %p, cbData %d, pdwDataLen %p, dwFlags %x",
               pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

  if (wcscmp(wszProperty, CP_CARD_FREE_SPACE) == 0) {
    CMD_CHECK_DW_FLAGS;
    CMD_RET_UNIMPL;
  } else if (wcscmp(wszProperty, CP_CARD_CAPABILITIES) == 0) {
    CMD_CHECK_DW_FLAGS;
    if (cbData < sizeof(CARD_CAPABILITIES)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    PCARD_CAPABILITIES p = (PCARD_CAPABILITIES)pbData;
    p->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
    p->fCertificateCompression = TRUE;
    p->fKeyGen = FALSE;
    *pdwDataLen = sizeof(CARD_CAPABILITIES);
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_KEYSIZES) == 0) {
    if (cbData < sizeof(CARD_KEY_SIZES)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    PCARD_KEY_SIZES p = (PCARD_KEY_SIZES)pbData;
    p->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
    p->dwMinimumBitlen = 2048;
    p->dwDefaultBitlen = 2048;
    p->dwMaximumBitlen = 4096;
    p->dwIncrementalBitlen = 1024;
    *pdwDataLen = sizeof(CARD_KEY_SIZES);
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_READ_ONLY) == 0) {
    CMD_CHECK_DW_FLAGS;
    if (cbData < sizeof(BOOL)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(BOOL *)pbData = TRUE;
    *pdwDataLen = sizeof(BOOL);
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_CACHE_MODE) == 0) {
    CMD_CHECK_DW_FLAGS;
    if (cbData < sizeof(DWORD)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(DWORD *)pbData = CP_CACHE_MODE_NO_CACHE;
    *pdwDataLen = sizeof(DWORD);
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0) {
    CMD_CHECK_DW_FLAGS;
    if (cbData < sizeof(BOOL)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(BOOL *)pbData = FALSE;
    *pdwDataLen = sizeof(BOOL);
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_GUID) == 0) {
    CMD_CHECK_DW_FLAGS;
    BYTE guid[16] = {0};
    if (cbData < sizeof(guid)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    memcpy(pbData, guid, sizeof(guid));
    *pdwDataLen = sizeof(guid);
    CMD_RET_OK;
  } else {
    CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Property not supported");
  }
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbData) PBYTE pbData,
                             __in DWORD cbData, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardSetProperty pCardData %p, wszProperty %S, pbData %p, cbData %d, dwFlags %x", pCardData, wszProperty,
               pbData, cbData, dwFlags);
  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(wszProperty);
  CMD_RET_UNIMPL;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
                                      __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                                      __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_LOG_FUNC("CardGetContainerProperty pCardData %p, bContainerIndex %d, wszProperty %S, dwFlags %x", pCardData,
               bContainerIndex, wszProperty, dwFlags);
  if (dwFlags != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid dwFlags");
  }
  if (wcscmp(wszProperty, CCP_PIN_IDENTIFIER) == 0) {
    if (cbData < sizeof(PIN_ID)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(PIN_ID *)pbData = ROLE_EVERYONE;
    *pdwDataLen = sizeof(PIN_ID);
    CMD_RET_OK;
  }
  CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid property");
}
