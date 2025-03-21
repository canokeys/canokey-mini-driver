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

#include <windows.h>
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
  sprintf_s(time, sizeof(time), "%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
            st.wSecond);
  sprintf_s(log_file_name, sizeof(log_file_name), "C:\\Logs\\canokey_minidriver_%s_%d.log", time,
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

// clang-format off
// This is the list of functions required by the spec
// that we **do not want** to support.
// Please make sure any function is either listed here
// or has a concrete definition. Otherwise this mini driver
// would be silently ignored by CSP.
#define INVOKE_X_ON_NO_IMPL_FUNCS(X) \
X(CardDeleteContainer) \
X(CardCreateContainer) \
X(CardGetChallenge) \
X(CardAuthenticateChallenge) \
X(CardUnblockPin) \
X(CardChangeAuthenticator) \
X(CardDeauthenticate) \
X(CardCreateDirectory) \
X(CardDeleteDirectory) \
X(CardCreateFile) \
X(CardWriteFile) \
X(CardDeleteFile) \
X(CardSetContainerProperty) \
X(CardRSADecrypt) \
X(CardConstructDHAgreement) \
X(CardDeriveKey) \
X(CardDestroyDHAgreement) \
X(CardGetChallengeEx) \
X(CardChangeAuthenticatorEx) \
X(MDImportSessionKey) \
X(MDEncryptData) \
X(CardImportSessionKey) \
X(CardGetSharedKeyHandle) \
X(CardGetAlgorithmProperty) \
X(CardGetKeyProperty) \
X(CardSetKeyProperty) \
X(CardDestroyKey) \
X(CardProcessEncryptedData) \
X(CardCreateContainerEx)

#define CMD_NO_IMPL_FUNC_NAME(NAME) __cmd_noimpl__ ## NAME
#define CMD_GEN_NO_IMPL_FUNC(NAME) DWORD WINAPI CMD_NO_IMPL_FUNC_NAME(NAME)(__inout PCARD_DATA pCardData, ...) { \
  CMD_ERROR(#NAME " is not meant to be supported but called with pCardData %p\n", pCardData); \
  CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "not meant to be supported (generated by macro)"); \
}
INVOKE_X_ON_NO_IMPL_FUNCS(CMD_GEN_NO_IMPL_FUNC);
#undef CMD_GEN_NO_IMPL_FUNC
// clang-format on

/*
 * Function: CardAcquireContext
 *
 * Purpose: Initialize the CARD_DATA structure which will be used by
 *          the CSP to interact with a specific card.
 */
DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData, __in DWORD dwFlags) {
  DWORD dwReturn = 0;

  CMD_DEBUG("CardAcquireContext called with pCardData %p, dwFlags %x\n", pCardData, dwFlags);
  // TODO: add function to print internal structure of CARD_DATA?

  // Check if pCardData is valid
  if (!pCardData) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "pCardData is NULL");
  }

  if (dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE) {
    // This flag is not supported
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "CARD_SECURE_KEY_INJECTION_NO_CARD_MODE");
  }

  // Check version
  if (pCardData->dwVersion < CARD_DATA_VERSION_FOUR) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion too old");
  }
  CMD_DEBUG("dwVersion %d\n", pCardData->dwVersion);

  if (!pCardData->hSCardCtx || !pCardData->hScard) {
    CMD_RETURN(SCARD_E_INVALID_HANDLE, "No hSCardCtx or hScard");
  }

  CMD_DEBUG("hScardCtx %p, hScard %p\n", pCardData->hSCardCtx, pCardData->hScard);

  if (!pCardData->pfnCspAlloc || !pCardData->pfnCspReAlloc || !pCardData->pfnCspFree) {
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
  pCardData->pfnCardDeleteContext = CardDeleteContext;         // Yes
  pCardData->pfnCardQueryCapabilities = CardQueryCapabilities; // Yes
  pCardData->pfnCardDeleteContainer = NULL;                    // No
  pCardData->pfnCardCreateContainer = NULL;                    // No
  pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;   // Yes
  pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;     // Yes
  pCardData->pfnCardGetChallenge = NULL;                       // No (opt)
  pCardData->pfnCardAuthenticateChallenge = NULL;              // No (opt)
  pCardData->pfnCardUnblockPin = NULL;                         // No (opt)
  pCardData->pfnCardChangeAuthenticator = NULL;                // No (opt)
  pCardData->pfnCardDeauthenticate = NULL;                     // Yes (opt)
  pCardData->pfnCardCreateDirectory = NULL;                    // No
  pCardData->pfnCardDeleteDirectory = NULL;                    // No
  pCardData->pfnCardCreateFile = NULL;                         // No
  pCardData->pfnCardReadFile = CardReadFile;                   // Yes
  pCardData->pfnCardWriteFile = NULL;                          // No
  pCardData->pfnCardDeleteFile = NULL;                         // No
  pCardData->pfnCardEnumFiles = CardEnumFiles;                 // Yes
  pCardData->pfnCardGetFileInfo = CardGetFileInfo;             // Yes
  pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;       // Yes
  pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;         // Yes

  pCardData->pfnCardSignData = CardSignData;     // Yes
  pCardData->pfnCardRSADecrypt = NULL;           // Yes (opt)
  pCardData->pfnCardConstructDHAgreement = NULL; // Yes (opt)

  // New functions in version five.
  pCardData->pfnCardDeriveKey = NULL;          // Yes (opt)
  pCardData->pfnCardDestroyDHAgreement = NULL; // Yes (opt)
  // pCardData->pfnCspGetDHAgreement;

  // version 6 additions below here
  pCardData->pfnCardGetChallengeEx = NULL;                           // No (opt)
  pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;             // Yes
  pCardData->pfnCardChangeAuthenticatorEx = NULL;                    // No (opt)
  pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;         // Yes
  pCardData->pfnCardGetContainerProperty = CardGetContainerProperty; // Yes
  pCardData->pfnCardSetContainerProperty = NULL;                     // No
  pCardData->pfnCardGetProperty = CardGetProperty;                   // Yes
  pCardData->pfnCardSetProperty = CardSetProperty;                   // Yes

  // version 7 additions below here
  // pCardData->pfnCspUnpadData;
  pCardData->pfnMDImportSessionKey = NULL;       // No (opt)
  pCardData->pfnMDEncryptData = NULL;            // No (opt)
  pCardData->pfnCardImportSessionKey = NULL;     // No (opt)
  pCardData->pfnCardGetSharedKeyHandle = NULL;   // No (opt)
  pCardData->pfnCardGetAlgorithmProperty = NULL; // No (opt)
  pCardData->pfnCardGetKeyProperty = NULL;       // No (opt)
  pCardData->pfnCardSetKeyProperty = NULL;       // No (opt)
  pCardData->pfnCardDestroyKey = NULL;           // No (opt)
  pCardData->pfnCardProcessEncryptedData = NULL; // No (opt)
  pCardData->pfnCardCreateContainerEx = NULL;    // No (opt)

  // fill in generated stubs
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

  // clang-format off
#define CMD_SET_CARD_DATA_PFN(NAME) do { \
  if (pCardData->pfn##NAME != NULL) { \
    CMD_ERROR("pCardData->pfn%s (set to %p) overridden by generated stub\n", #NAME, pCardData->pfn##NAME); \
  } \
  pCardData->pfn##NAME = (void *) CMD_NO_IMPL_FUNC_NAME(NAME); \
} while (0);
INVOKE_X_ON_NO_IMPL_FUNCS(CMD_SET_CARD_DATA_PFN);
#undef CMD_SET_CARD_DATA_PFN
#undef CMD_NO_IMPL_FUNC_NAME
  // clang-format on

  // check whether pCardData is fully filled
  uintptr_t *begin = (uintptr_t *)&pCardData->pfnCardDeleteContext;
  uintptr_t *end = (uintptr_t *)&pCardData->pfnCardCreateContainerEx;
  for (uintptr_t *p = begin; p <= end; p++) {
    if (*p == 0 && !(p == &pCardData->pvUnused3 || p == &pCardData->pvUnused4 ||
                     p == &pCardData->pfnCspGetDHAgreement || p == &pCardData->pfnCspUnpadData)) {
      CMD_ERROR("pCardData has NULL entry point at offset %lld to pfnCardDeleteContext, check CardAcquireContext!\n",
                p - begin);
    }
  }

#pragma clang diagnostic pop

  CMD_RET_OK;
}

#undef INVOKE_X_ON_NO_IMPL_FUNCS

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

  CMD_RET_OK;
}

/*
 * Function: CardGetProperty
 *
 * Purpose: Get card properties.
 */
DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
                             __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                             __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_DEBUG("CardGetProperty called with pCardData: %p, wszProperty: %S, pbData: %p, cbData: %d, pdwDataLen: %p, "
            "dwFlags: %x\n",
            pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

  if (!pCardData || !wszProperty || !pdwDataLen) {
    CMD_RETURN(ERROR_INVALID_PARAMETER, "pCardData, wszProperty, or pdwDataLen is NULL");
  }

  // Handle different property requests
  if (wcscmp(wszProperty, CP_CARD_GUID) == 0) {
    // Card GUID - TODO should be the same as cardid, currently a placeholder
    BYTE cardGuid[16] = {0};
    *pdwDataLen = sizeof(cardGuid);
    if (cbData < sizeof(cardGuid)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    memcpy(pbData, cardGuid, sizeof(cardGuid));
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_READ_ONLY) == 0) {
    // Card read-only property
    *pdwDataLen = sizeof(BOOL);
    if (cbData < sizeof(BOOL)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(BOOL *)pbData = TRUE; // TODO
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_CACHE_MODE) == 0) {
    // Card cache mode property
    *pdwDataLen = sizeof(DWORD);
    if (cbData < sizeof(DWORD)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(DWORD *)pbData = CP_CACHE_MODE_NO_CACHE;
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0) {
    // Support for Windows x.509 enrollment
    *pdwDataLen = sizeof(BOOL);
    if (cbData < sizeof(BOOL)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }
    *(BOOL *)pbData = FALSE;
    CMD_RET_OK;
  } else if (wcscmp(wszProperty, CP_CARD_PIN_INFO) == 0) {
    // Card PIN info property
    PPIN_INFO p = (PPIN_INFO)pbData;

#ifdef CMD_VERBOSE
    CMD_DEBUG("Card PIN info property requested with dwVersion: %X, PinType: %d, PinPurpose: %d, dwChangePermission: "
              "%d, dwUnblockPermission: %d, PinCachePolicy: %d, dwFlags: %d\n",
              p->dwVersion, p->PinType, p->PinPurpose, p->dwChangePermission, p->dwUnblockPermission, p->PinCachePolicy,
              p->dwFlags);
#endif

    *pdwDataLen = sizeof(PIN_INFO);
    if (cbData < sizeof(PIN_INFO)) {
      CMD_RETURN(ERROR_INSUFFICIENT_BUFFER, "cbData is too small");
    }

    if (p->dwVersion != PIN_INFO_CURRENT_VERSION) {
      CMD_RETURN(ERROR_REVISION_MISMATCH, "Invalid PIN_INFO version");
    }

    CMD_RET_OK;
  }

  // Property not supported
  CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "Property not supported");
}

/*
 * Function: CardSetProperty
 *
 * Purpose: Set card properties.
 */
DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbData) PBYTE pbData,
                             __in DWORD cbData, __in DWORD dwFlags) {
  CMD_DEBUG("CardSetProperty called with pCardData %p, wszProperty %S, pbData "
            "%p, cbData %d, dwFlags %x\n",
            pCardData, wszProperty, pbData, cbData, dwFlags);

  if (!pCardData || !wszProperty) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardAuthenticatePin
 *
 * Purpose: Authenticate the PIN.
 */
DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin,
                                 __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_DEBUG("CardAuthenticatePin called with pCardData %p, pwszUserId %S, "
            "pbPin %p, cbPin %d, pcAttemptsRemaining %p\n",
            pCardData, pwszUserId, pbPin, cbPin, pcAttemptsRemaining);

  if (!pCardData || !pwszUserId || !pbPin) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardReadFile
 *
 * Purpose: Read a file from the card.
 */
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData) {
  CMD_DEBUG("CardReadFile called with pCardData %p, pszDirectoryName %s, pszFileName %s, dwFlags %x\n", pCardData,
            pszDirectoryName, pszFileName, dwFlags);

  if (pszDirectoryName == NULL) { // Root directory
    if (strcmp(pszFileName, szCACHE_FILE) == 0) {
      // TODO: Return cached data
      // now we return 6 bytes of zeros
      *ppbData = (PBYTE)g_pfnCspAlloc(6);
      if (*ppbData == NULL) {
        CMD_RETURN(ERROR_OUTOFMEMORY, "Failed to allocate memory");
      }
      memset(*ppbData, 0, 6);
      *pcbData = 6;
      CMD_RET_OK;
    }
  } else if (strcmp(pszDirectoryName, szBASE_CSP_DIR) == 0) {
    if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      // TODO: Return container map
      *ppbData = NULL;
      *pcbData = 0;
      CMD_RET_OK;
    }
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardGetFileInfo
 *
 * Purpose: Get information about a file on the card.
 */
DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                             __in PCARD_FILE_INFO pCardFileInfo) {
  CMD_DEBUG("CardGetFileInfo called with pCardData %p, pszDirectoryName %s, "
            "pszFileName %s, pCardFileInfo %p\n",
            pCardData, pszDirectoryName, pszFileName, pCardFileInfo);

  if (!pCardData || !pszDirectoryName || !pszFileName || !pCardFileInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardEnumFiles
 *
 * Purpose: Enumerate files in a directory on the card.
 */
DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData, __in_opt LPSTR pszDirectoryName,
                           __deref_out_ecount(*pdwcbFileName) LPSTR *pmszFileNames, __out LPDWORD pdwcbFileName,
                           __in DWORD dwFlags) {
  CMD_DEBUG("CardEnumFiles called with pCardData %p, pszDirectoryName %s, "
            "pmszFileNames %p, pdwcbFileName %p, dwFlags %x\n",
            pCardData, pszDirectoryName, pmszFileNames, pdwcbFileName, dwFlags);

  if (!pCardData || !pdwcbFileName) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardQueryFreeSpace
 *
 * Purpose: Query the free space on the card.
 */
DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
                                __inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo) {
  CMD_DEBUG("CardQueryFreeSpace called with pCardData %p, dwFlags %x, "
            "pCardFreeSpaceInfo %p\n",
            pCardData, dwFlags, pCardFreeSpaceInfo);

  if (!pCardData || !pCardFreeSpaceInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}
/*
 * Function: CardQueryCapabilities
 *
 * Purpose: Query the capabilities of the card.
 */
DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities) {
  CMD_DEBUG("CardQueryCapabilities called with pCardData %p, pCardCapabilities %p\n", pCardData, pCardCapabilities);

  if (!pCardData || !pCardCapabilities) {
    return ERROR_INVALID_PARAMETER;
  }

  if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION) {
    return ERROR_REVISION_MISMATCH;
  }

  // Set capabilities
  pCardCapabilities->fCertificateCompression = FALSE;
  pCardCapabilities->fKeyGen = TRUE;

  CMD_RET_OK;
}

/*
 * Function: CardGetContainerInfo
 *
 * Purpose: Get information about a key container on the card.
 */
DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
                                  __inout PCONTAINER_INFO pContainerInfo) {
  CMD_DEBUG("CardGetContainerInfo called with pCardData %p, bContainerIndex "
            "%d, dwFlags %x, pContainerInfo %p\n",
            pCardData, bContainerIndex, dwFlags, pContainerInfo);

  if (!pCardData || !pContainerInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardSignData
 *
 * Purpose: Sign data using a key on the card.
 */
DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pCardSigningInfo) {
  CMD_DEBUG("CardSignData called with pCardData %p, pCardSigningInfo %p\n", pCardData, pCardSigningInfo);

  if (!pCardData || !pCardSigningInfo) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardQueryKeySizes
 *
 * Purpose: Query the supported key sizes for a given algorithm.
 */
DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags,
                               __inout PCARD_KEY_SIZES pKeySizes) {
  CMD_DEBUG("CardQueryKeySizes called with pCardData %p, dwKeySpec %x, dwFlags "
            "%x, pKeySizes %p\n",
            pCardData, dwKeySpec, dwFlags, pKeySizes);

  if (!pCardData || !pKeySizes) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardAuthenticateEx
 *
 * Purpose: Authenticate to the card with extended parameters.
 */
DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags,
                                __in_bcount(cbPinData) PBYTE pbPinData, __in DWORD cbPinData,
                                __deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
                                __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_DEBUG("CardAuthenticateEx called with pCardData %p, PinId %d, dwFlags "
            "%x, pbPinData %p, cbPinData %d\n",
            pCardData, PinId, dwFlags, pbPinData, cbPinData);

  if (!pCardData) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardDeauthenticateEx
 *
 * Purpose: Deauthenticate from the card with extended parameters.
 */
DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData, __in PIN_SET PinId, __in DWORD dwFlags) {
  CMD_DEBUG("CardDeauthenticateEx called with pCardData %p, PinId %d, dwFlags %x\n", pCardData, PinId, dwFlags);

  if (!pCardData) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}

/*
 * Function: CardGetContainerProperty
 *
 * Purpose: Get a property of a key container on the card.
 */
DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
                                      __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData,
                                      __out PDWORD pdwDataLen, __in DWORD dwFlags) {
  CMD_DEBUG("CardGetContainerProperty called with pCardData %p, "
            "bContainerIndex %d, wszProperty %S, dwFlags %x\n",
            pCardData, bContainerIndex, wszProperty, dwFlags);

  if (!pCardData || !wszProperty || !pdwDataLen) {
    return ERROR_INVALID_PARAMETER;
  }

  CMD_RET_UNIMPL;
}
