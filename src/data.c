#include <string.h>
#include <wchar.h>

#include <Windows.h>

#include <pkcs11.h>
#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

/*
 * Function: CardReadFile
 *
 * Purpose: Read a file from the card.
 */
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData) {
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pszFileName %s, dwFlags %x", pCardData, pszDirectoryName,
               pszFileName, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pszFileName);

  if (pszDirectoryName == NULL) { // Root directory
    if (strcmp(pszFileName, szCACHE_FILE) == 0) {
      *ppbData = (PBYTE)g_pfnCspAlloc(6);
      CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);
      memset(*ppbData, 0, 6);
      *pcbData = 6;
      CMD_RET_OK;
    }
  } else if (strcmp(pszDirectoryName, szBASE_CSP_DIR) == 0) {
    if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
      *pcbData = 0;
      CMD_RET_OK;
    } else if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      *ppbData = (PBYTE)g_pfnCspAlloc(sizeof(CONTAINER_MAP_RECORD));
      CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);

      PCONTAINER_MAP_RECORD p = (PCONTAINER_MAP_RECORD)*ppbData;
      memset(p, 0, sizeof(CONTAINER_MAP_RECORD));
      wcscpy(p->wszGuid, L"22b5b6d5-4495-52c7-c8g9-6g4b8g58de94");
      p->bFlags = CONTAINER_MAP_VALID_CONTAINER;
      p->wSigKeySizeBits = 2048;

      *pcbData = sizeof(CONTAINER_MAP_RECORD);
      CMD_RET_OK;
    } else if (strcmp(pszFileName, "ksc00") == 0) {
      CK_SESSION_HANDLE_PTR pSession = pCardData->pvVendorSpecific;
      CK_RV rv;
      CK_OBJECT_HANDLE hObject;
      CK_BYTE key_id = 2;
      CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
      CK_ATTRIBUTE templ[] = {{CKA_ID, &key_id, sizeof(key_id)}, {CKA_CLASS, &keyClass, sizeof(keyClass)}};
      rv = C_FindObjectsInit(*pSession, templ, 2);
      if (rv != CKR_OK) {
        CMD_RETURN(SCARD_F_INTERNAL_ERROR, "Failed to initialize search");
      }
      CK_ULONG foundCount = 0;
      rv = C_FindObjects(*pSession, &hObject, 1, &foundCount);
      if (rv != CKR_OK) {
        CMD_RETURN(SCARD_F_INTERNAL_ERROR, "Failed to find object");
      }
      if (foundCount == 0) {
        CMD_RETURN(SCARD_F_INTERNAL_ERROR, "find no objects");
      }
      CK_ATTRIBUTE value[] = {{CKA_VALUE, NULL, 0}};
      rv = C_GetAttributeValue(*pSession, hObject, value, 1);
      if (rv != CKR_OK) {
        CMD_RETURN(SCARD_F_INTERNAL_ERROR, "Failed to get attribute value");
      }
      *ppbData = (PBYTE)g_pfnCspAlloc(value[0].ulValueLen);
      CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);
      rv = C_GetAttributeValue(*pSession, hObject, value, 1);
      if (rv != CKR_OK) {
        CMD_RETURN(SCARD_F_INTERNAL_ERROR, "Failed to get attribute value");
      }
      memcpy(*ppbData, value[0].pValue, value[0].ulValueLen);
      *pcbData = value[0].ulValueLen;

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
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pszFileName %s, pCardFileInfo %p", pCardData, pszDirectoryName,
               pszFileName, pCardFileInfo);
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
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pmszFileNames %p, pdwcbFileName %p, dwFlags %x", pCardData,
               pszDirectoryName, pmszFileNames, pdwcbFileName, dwFlags);
  CMD_RET_UNIMPL;
}

/*
 * Function: CardQueryFreeSpace
 *
 * Purpose: Query the free space on the card.
 */
DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
                                __inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo) {
  CMD_LOG_FUNC("pCardData %p, dwFlags %x, pCardFreeSpaceInfo %p", pCardData, dwFlags, pCardFreeSpaceInfo);
  CMD_RET_UNIMPL;
}
