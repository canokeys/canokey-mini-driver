/*
 * CanoKey Smart Card Minidriver
 *
 * This file implements a smart card minidriver for CanoKey
 * based on the Windows Smart Card Minidriver specification.
 */

#include "cardmod.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
  sprintf_s(time, sizeof(time), "%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  sprintf_s(log_file_name, sizeof(log_file_name), "C:\\Logs\\canokey_minidriver_%s_%d.log", time, (int32_t) GetCurrentProcessId());
  cmd_init_logging(log_file_name, level);
  CMD_INFO("Start logging to file %s...\n", log_file_name);
}

// DllMain function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {

  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    // Initialize the DLL
    init_logging_file(CMD_LOG_LEVEL_DEBUG);
    CMD_INFO("CanoKey Smart Card Minidriver compiled at %s %s\n", __DATE__, __TIME__);
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

  CMD_DEBUG("CardAcquireContext called with pCardData %p, dwFlags %x\n", pCardData, dwFlags);
  // TODO: add function to print internal structure of CARD_DATA?

  if (dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE) {
    // This flag is not supported
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "CARD_SECURE_KEY_INJECTION_NO_CARD_MODE");
  }

  // Check if pCardData is valid
  if (!pCardData) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "pCardData is NULL");
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

  // Initialize other function pointers as needed
  // pCardData->pfnCardCreateContainer = CardCreateContainer;
  // pCardData->pfnCardDeleteContainer = CardDeleteContainer;
  // ... and so on for all the functions you'll implement


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
 * Function: CardQueryCapabilities
 *
 * Purpose: Query the capabilities of the card.
 */
DWORD WINAPI CardQueryCapabilities(
    __in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities) {
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
  if (!pCardData || !pwszUserId || !pbPin) {
    return ERROR_INVALID_PARAMETER;
  }

  // Implementation would go here
  // For now, return not supported
  return SCARD_E_UNSUPPORTED_FEATURE;
}
