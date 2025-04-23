#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <Windows.h>

#include <pkcs11.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

static DWORD GenerateContainerMapFile(CK_SESSION_HANDLE_PTR pSession, PBYTE *ppbData, PDWORD pcbData);

static BOOL cmapCached = FALSE;
static BYTE cmap[1024];
static DWORD cmapSize = 0;

// The CardReadFile function reads the entire file at the specified location into the user-supplied buffer.
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData) {
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pszFileName %s, dwFlags %x", pCardData, pszDirectoryName,
               pszFileName, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pszFileName);

  INJECT_HANDLES();

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
    }

    if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      CK_SESSION_HANDLE_PTR pSession = pCardData->pvVendorSpecific;
      DWORD res = GenerateContainerMapFile(pSession, ppbData, pcbData);
      if (res != SCARD_S_SUCCESS) {
        CMD_RETURN(res, "Generate container map failed");
      }
      CMD_RET_OK;
    }

    if (strcmp(pszFileName, "ksc00") == 0) {
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

// Generate the container map file content by enumerating all private keys,
// hashing public key data to produce a GUID, and marking CKA_ID==2 as default.
static DWORD GenerateContainerMapFile(CK_SESSION_HANDLE_PTR pSession, PBYTE *ppbData, PDWORD pcbData) {
  CMD_LOG_FUNC(" pSession %p, ppbData %p, pcbData %p", pSession, ppbData, pcbData);

  if (cmapCached) {
    CMD_DEBUG("cmap is cached");
    *ppbData = (PBYTE)g_pfnCspAlloc(cmapSize);
    if (!*ppbData)
      return SCARD_E_NO_MEMORY;
    memcpy(*ppbData, cmap, cmapSize);
    *pcbData = cmapSize;
    CMD_DEBUG("return cached container map, size: %d", cmapSize);
    CMD_RET_OK;
  }

  const CK_SESSION_HANDLE hSession = *pSession;
  const CK_ULONG maxObjects = 64;

  CK_ULONG foundCount = 0;
  CK_OBJECT_HANDLE objects[64];

  // Search for public key objects
  CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE searchTpl[] = {{CKA_CLASS, &pubClass, sizeof(pubClass)}};
  CK_RV rv = C_FindObjectsInit(hSession, searchTpl, 1);
  if (rv != CKR_OK)
    return SCARD_F_INTERNAL_ERROR;
  rv = C_FindObjects(hSession, objects, maxObjects, &foundCount);
  C_FindObjectsFinal(hSession);
  if (rv != CKR_OK)
    return SCARD_F_INTERNAL_ERROR;

  CMD_DEBUG("Found %d public keys", foundCount);

  // Allocate output buffer for all records
  const size_t total = foundCount * sizeof(CONTAINER_MAP_RECORD);
  *ppbData = (PBYTE)g_pfnCspAlloc(total);
  if (!*ppbData)
    return SCARD_E_NO_MEMORY;
  PCONTAINER_MAP_RECORD recs = (PCONTAINER_MAP_RECORD)*ppbData;
  memset(recs, 0, total);

  // Setup SHA-1 digest
  CK_MECHANISM mech = {CKM_SHA_1, NULL, 0};
  for (CK_ULONG i = 0; i < foundCount; i++) {
    PCONTAINER_MAP_RECORD rec = &recs[i];
    // Get public key modulus (assume RSA)
    CK_ATTRIBUTE pubAttr = {CKA_MODULUS, NULL, 0};
    rv = C_GetAttributeValue(hSession, objects[i], &pubAttr, 1);
    if (rv != CKR_OK || pubAttr.ulValueLen == 0)
      continue;
    CK_BYTE *modulus = g_pfnCspAlloc(pubAttr.ulValueLen);
    if (!modulus)
      continue;
    pubAttr.pValue = modulus;
    rv = C_GetAttributeValue(hSession, objects[i], &pubAttr, 1);
    if (rv != CKR_OK) {
      g_pfnCspFree(modulus);
      continue;
    }

    // Compute SHA-1 digest of modulus
    CK_BYTE digest[20];
    CK_ULONG digLen = sizeof(digest);
    rv = C_DigestInit(hSession, &mech);
    if (rv != CKR_OK) {
      g_pfnCspFree(modulus);
      continue;
    }
    rv = C_Digest(hSession, modulus, pubAttr.ulValueLen, digest, &digLen);
    g_pfnCspFree(modulus);
    if (rv != CKR_OK)
      continue;

    // Format first 16 bytes of digest as GUID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    unsigned char *b = digest;
    swprintf_s(rec->wszGuid, 37, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
               b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

    // Set flags
    rec->bFlags = CONTAINER_MAP_VALID_CONTAINER;
    // if (idAttr.ulValueLen == 1 && idBuf[0] == 2) {
    //   rec->bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
    // }
    // Set signature key size bits
    rec->wSigKeySizeBits = (WORD)(pubAttr.ulValueLen * 8);
    CMD_DEBUG("Container %d: %ls, wSigKeySizeBits: %d", i, rec->wszGuid, rec->wSigKeySizeBits);
  }
  CMD_PRINT_HEX(recs, total);
  *pcbData = (DWORD)total;

  cmapCached = TRUE;
  cmapSize = (DWORD)total;
  memcpy(cmap, recs, total);
  CMD_DEBUG("Container map generated, size: %d", total);

  CMD_RET_OK;
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
