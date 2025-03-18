/*
 * CanoKey Smart Card Minidriver
 *
 * This file implements a smart card minidriver for CanoKey
 * based on the Windows Smart Card Minidriver specification.
 */

#include "cardmod.h"
#include "logging.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>
#include <winscard.h>

// Global function pointers for data caching mechanisms
PFN_CSP_CACHE_ADD_FILE g_pfnCspCacheAddFile = NULL;
PFN_CSP_CACHE_LOOKUP_FILE g_pfnCspCacheLookupFile = NULL;
PFN_CSP_CACHE_DELETE_FILE g_pfnCspCacheDeleteFile = NULL;

// Global function pointers for memory management
PFN_CSP_ALLOC g_pfnCspAlloc = NULL;
PFN_CSP_REALLOC g_pfnCspReAlloc = NULL;
PFN_CSP_FREE g_pfnCspFree = NULL;

// Global function pointer for padding removal
PFN_CSP_UNPAD_DATA g_pfnCspUnpadData = NULL;

static void init_logging_file(int level) {
  CreateDirectory("C:\\Logs", NULL); // ignore errors
  char log_file_name[64], time[16];
  SYSTEMTIME st;
  GetLocalTime(&st);
  sprintf_s(time, sizeof(time), "%04d%02d%02d_%02d%02d%02d", st.wYear,
            st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  sprintf_s(log_file_name, sizeof(log_file_name),
            "C:\\Logs\\canokey_minidriver_%s_%d.log", time,
            (int32_t)GetCurrentProcessId());
  cmd_init_logging(log_file_name, level);
  CMD_INFO("Start logging to file %s...\n", log_file_name);
}

// DllMain function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {

  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    // Initialize the DLL
    init_logging_file(CMD_LOG_LEVEL_DEBUG);
    CMD_INFO("CanoKey Smart Card Minidriver compiled at %s %s\n", __DATE__,
             __TIME__);
    CMD_INFO("DLL loaded with handle %p\n", hinstDLL);
    FUNC_TRACE(DisableThreadLibraryCalls(hinstDLL));
    break;
  case DLL_PROCESS_DETACH:
    // Clean up resources
    CMD_INFO("DLL unloaded with handle %p, stop logging...\n", hinstDLL);
    CMD_INFO("========================================\n");
    cmd_stop_logging();
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
    // No action needed
    break;
  }
  return TRUE;
}

/*
 * Function: CardAcquireContext
 *
 * Purpose: Initialize the CARD_DATA structure which will be used by
 *          the CSP to interact with a specific card.
 */
DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData,
                                __in DWORD dwFlags) {
  DWORD dwReturn = 0;

  CMD_DEBUG("CardAcquireContext called with pCardData %p, dwFlags %x\n",
            pCardData, dwFlags);
  // TODO: add function to print internal structure of CARD_DATA?

  // Check if pCardData is valid
  if (!pCardData) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "pCardData is NULL");
  }

  if (dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE) {
    // This flag is not supported
    CMD_RETURN(SCARD_E_INVALID_PARAMETER,
               "CARD_SECURE_KEY_INJECTION_NO_CARD_MODE");
  }

  // Check version
  if (pCardData->dwVersion < CARD_DATA_VERSION_FOUR) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion too old");
  }

  if (!pCardData->hSCardCtx || !pCardData->hScard) {
    CMD_RETURN(SCARD_E_INVALID_HANDLE, "No hSCardCtx or hScard");
  }

  if (!pCardData->pfnCspAlloc || !pCardData->pfnCspReAlloc ||
      !pCardData->pfnCspFree) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "No pfnCsp* allocators");
  }

  if (!pCardData->pbAtr || pCardData->cbAtr == 0) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "No pbAtr or cbAtr");
  }

  if (!pCardData->pwszCardName) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "No pwszCardName");
  }

  // TODO: check pbAtr content

  // Import the data caching functions
  g_pfnCspCacheAddFile = pCardData->pfnCspCacheAddFile;
  g_pfnCspCacheLookupFile = pCardData->pfnCspCacheLookupFile;
  g_pfnCspCacheDeleteFile = pCardData->pfnCspCacheDeleteFile;

  // Import the memory management functions
  g_pfnCspAlloc = pCardData->pfnCspAlloc;
  g_pfnCspReAlloc = pCardData->pfnCspReAlloc;
  g_pfnCspFree = pCardData->pfnCspFree;

  // Import the padding removal function
  if (pCardData->dwVersion >= CARD_DATA_VERSION_SEVEN) {
    g_pfnCspUnpadData = pCardData->pfnCspUnpadData;
  }

  // Set function pointers in pCardData
  pCardData->pfnCardDeleteContext = CardDeleteContext;
  pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
  pCardData->pfnCardGetProperty = CardGetProperty;
  pCardData->pfnCardSetProperty = CardSetProperty;
  pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
  pCardData->pfnCardReadFile = CardReadFile;
  pCardData->pfnCardGetFileInfo = CardGetFileInfo;
  pCardData->pfnCardEnumFiles = CardEnumFiles;
  pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
  pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
  pCardData->pfnCardSignData = CardSignData;
  pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;
  pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
  pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
  pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;

  CMD_RET_OK(SCARD_S_SUCCESS);
}

/*
 * Function: CardDeleteContext
 *
 * Purpose: Free resources consumed by the CARD_DATA structure.
 */
DWORD WINAPI CardDeleteContext(__inout PCARD_DATA pCardData) {
  CMD_DEBUG("CardDeleteContext called with pCardData %p\n", pCardData);
  if (!pCardData) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "pCardData is NULL");
  }

  // Free vendor specific data
  if (pCardData->pvVendorSpecific) {
    pCardData->pfnCspFree(pCardData->pvVendorSpecific);
    pCardData->pvVendorSpecific = NULL;
  }

  CMD_RET_OK(SCARD_S_SUCCESS);
}

/*
 * Function: CardGetProperty
 *
 * Purpose: Get card properties.
 */
DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData,
                             __in LPCWSTR wszProperty,
                             __out_bcount_part_opt(cbData, *pdwDataLen)
                                 PBYTE pbData,
                             __in DWORD cbData, __out PDWORD pdwDataLen,
                             __in DWORD dwFlags) {
  CMD_DEBUG("CardGetProperty called with pCardData %p, wszProperty %S, pbData "
            "%p, cbData %d, pdwDataLen %p, dwFlags %x\n",
            pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

  if (!pCardData || !wszProperty || !pdwDataLen) {
    return ERROR_INVALID_PARAMETER;
  }

  // Implementation for specific properties would go here
  // For now, return not supported
  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardSetProperty
 *
 * Purpose: Set card properties.
 */
DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData,
                             __in LPCWSTR wszProperty,
                             __in_bcount(cbData) PBYTE pbData,
                             __in DWORD cbData, __in DWORD dwFlags) {
  CMD_DEBUG("CardSetProperty called with pCardData %p, wszProperty %S, pbData "
            "%p, cbData %d, dwFlags %x\n",
            pCardData, wszProperty, pbData, cbData, dwFlags);

  if (!pCardData || !wszProperty) {
    return ERROR_INVALID_PARAMETER;
  }

  // Implementation for specific properties would go here
  // For now, return not supported
  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardAuthenticatePin
 *
 * Purpose: Authenticate the PIN.
 */
DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
                                 __in LPWSTR pwszUserId,
                                 __in_bcount(cbPin) PBYTE pbPin,
                                 __in DWORD cbPin,
                                 __out_opt PDWORD pcAttemptsRemaining) {
  CMD_DEBUG("CardAuthenticatePin called with pCardData %p, pwszUserId %S, "
            "pbPin %p, cbPin %d, pcAttemptsRemaining %p\n",
            pCardData, pwszUserId, pbPin, cbPin, pcAttemptsRemaining);

  if (!pCardData || !pwszUserId || !pbPin) {
    return ERROR_INVALID_PARAMETER;
  }

  // Implementation would go here
  // For now, return not supported
  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardReadFile
 *
 * Purpose: Read a file from the card.
 */
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData,
                          __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags,
                          __deref_out_bcount_opt(*pcbData) PBYTE *ppbData,
                          __out PDWORD pcbData) {
  CMD_DEBUG("CardReadFile called with pCardData %p, pszDirectoryName %s, "
            "pszFileName %s, dwFlags %x\n",
            pCardData, pszDirectoryName, pszFileName, dwFlags);

  if (!pCardData || !pszDirectoryName || !pszFileName || !ppbData || !pcbData) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardGetFileInfo
 *
 * Purpose: Get information about a file on the card.
 */
DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData,
                             __in LPSTR pszDirectoryName,
                             __in LPSTR pszFileName,
                             __in PCARD_FILE_INFO pCardFileInfo) {
  CMD_DEBUG("CardGetFileInfo called with pCardData %p, pszDirectoryName %s, "
            "pszFileName %s, pCardFileInfo %p\n",
            pCardData, pszDirectoryName, pszFileName, pCardFileInfo);

  if (!pCardData || !pszDirectoryName || !pszFileName || !pCardFileInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardEnumFiles
 *
 * Purpose: Enumerate files in a directory on the card.
 */
DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData,
                           __in_opt LPSTR pszDirectoryName,
                           __deref_out_ecount(*pdwcbFileName)
                               LPSTR *pmszFileNames,
                           __out LPDWORD pdwcbFileName, __in DWORD dwFlags) {
  CMD_DEBUG("CardEnumFiles called with pCardData %p, pszDirectoryName %s, "
            "pmszFileNames %p, pdwcbFileName %p, dwFlags %x\n",
            pCardData, pszDirectoryName, pmszFileNames, pdwcbFileName, dwFlags);

  if (!pCardData || !pdwcbFileName) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardQueryFreeSpace
 *
 * Purpose: Query the free space on the card.
 */
DWORD WINAPI
CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
                   __inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo) {
  CMD_DEBUG("CardQueryFreeSpace called with pCardData %p, dwFlags %x, "
            "pCardFreeSpaceInfo %p\n",
            pCardData, dwFlags, pCardFreeSpaceInfo);

  if (!pCardData || !pCardFreeSpaceInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}
/*
 * Function: CardQueryCapabilities
 *
 * Purpose: Query the capabilities of the card.
 */
DWORD WINAPI CardQueryCapabilities(
    __in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities) {
  CMD_DEBUG(
      "CardQueryCapabilities called with pCardData %p, pCardCapabilities %p\n",
      pCardData, pCardCapabilities);

  if (!pCardData || !pCardCapabilities) {
    return ERROR_INVALID_PARAMETER;
  }

  if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION) {
    return ERROR_REVISION_MISMATCH;
  }

  // Set capabilities
  pCardCapabilities->fCertificateCompression = FALSE;
  pCardCapabilities->fKeyGen = TRUE;

  return SCARD_S_SUCCESS;
}

/*
 * Function: CardGetContainerInfo
 *
 * Purpose: Get information about a key container on the card.
 */
DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData,
                                  __in BYTE bContainerIndex, __in DWORD dwFlags,
                                  __inout PCONTAINER_INFO pContainerInfo) {
  CMD_DEBUG("CardGetContainerInfo called with pCardData %p, bContainerIndex "
            "%d, dwFlags %x, pContainerInfo %p\n",
            pCardData, bContainerIndex, dwFlags, pContainerInfo);

  if (!pCardData || !pContainerInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardSignData
 *
 * Purpose: Sign data using a key on the card.
 */
DWORD WINAPI CardSignData(__in PCARD_DATA pCardData,
                          __in PCARD_SIGNING_INFO pCardSigningInfo) {
  CMD_DEBUG("CardSignData called with pCardData %p, pCardSigningInfo %p\n",
            pCardData, pCardSigningInfo);

  if (!pCardData || !pCardSigningInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardQueryKeySizes
 *
 * Purpose: Query the supported key sizes for a given algorithm.
 */
DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec,
                               __in DWORD dwFlags,
                               __inout PCARD_KEY_SIZES pKeySizes) {
  CMD_DEBUG("CardQueryKeySizes called with pCardData %p, dwKeySpec %x, dwFlags "
            "%x, pKeySizes %p\n",
            pCardData, dwKeySpec, dwFlags, pKeySizes);

  if (!pCardData || !pKeySizes) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardAuthenticateEx
 *
 * Purpose: Authenticate to the card with extended parameters.
 */
DWORD WINAPI CardAuthenticateEx(
    __in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags,
    __in_bcount(cbPinData) PBYTE pbPinData, __in DWORD cbPinData,
    __deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
    __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_DEBUG("CardAuthenticateEx called with pCardData %p, PinId %d, dwFlags "
            "%x, pbPinData %p, cbPinData %d\n",
            pCardData, PinId, dwFlags, pbPinData, cbPinData);

  if (!pCardData) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardDeauthenticateEx
 *
 * Purpose: Deauthenticate from the card with extended parameters.
 */
DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData, __in PIN_SET PinId,
                                  __in DWORD dwFlags) {
  CMD_DEBUG(
      "CardDeauthenticateEx called with pCardData %p, PinId %d, dwFlags %x\n",
      pCardData, PinId, dwFlags);

  if (!pCardData) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}

/*
 * Function: CardGetContainerProperty
 *
 * Purpose: Get a property of a key container on the card.
 */
DWORD WINAPI CardGetContainerProperty(
    __in PCARD_DATA pCardData, __in BYTE bContainerIndex,
    __in LPCWSTR wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
    __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_DEBUG("CardGetContainerProperty called with pCardData %p, "
            "bContainerIndex %d, wszProperty %S, dwFlags %x\n",
            pCardData, bContainerIndex, wszProperty, dwFlags);

  if (!pCardData || !wszProperty || !pdwDataLen) {
    return ERROR_INVALID_PARAMETER;
  }

  return SCARD_E_UNSUPPORTED_FEATURE;
}
