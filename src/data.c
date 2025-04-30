#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <Windows.h>

#include <pkcs11.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

static DWORD GenerateContainerMapFile(CMD_CONTEXT_PTR pContext, PBYTE *ppbData, PDWORD pcbData);

// The CardReadFile function reads the entire file at the specified location into the user-supplied buffer.
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData) {
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pszFileName %s, dwFlags %x", pCardData, pszDirectoryName,
               pszFileName, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pszFileName);

  INJECT_HANDLES();

  CMD_GET_CTX(pCardData, pContext);

  if (pszDirectoryName == NULL) { // Root directory
    if (strcmp(pszFileName, szCACHE_FILE) == 0) {
      *ppbData = (PBYTE)g_pfnCspAlloc(6);
      CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);
      memset(*ppbData, 0, 6);
      *pcbData = 6;
      CMD_RET_OK;
    }
    CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
  }

  if (strcmp(pszDirectoryName, szBASE_CSP_DIR) == 0) {
    if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
      *pcbData = 0;
      CMD_RET_OK;
    }

    if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      DWORD res = GenerateContainerMapFile(pContext, ppbData, pcbData);
      if (res != SCARD_S_SUCCESS) {
        CMD_RETURN(res, "Generate container map failed");
      }
      CMD_RET_OK;
    }

    if (strncmp(pszFileName, szUSER_SIGNATURE_CERT_PREFIX, 3) == 0 ||
        strncmp(pszFileName, szUSER_KEYEXCHANGE_CERT_PREFIX, 3) == 0) {

      BYTE slotIndex = pszFileName[4] - '0';
      if (slotIndex >= pContext->canokey.slotCount)
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
      SLOT *slot = &pContext->canokey.slots[slotIndex];

      *ppbData = (PBYTE)g_pfnCspAlloc(slot->certLen);
      CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);

      memcpy(*ppbData, slot->cert, slot->certLen);
      *pcbData = slot->certLen;

      CMD_RET_OK;
    }

    CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
  }

  CMD_RETURN(SCARD_E_DIR_NOT_FOUND, "Directory not found");
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

static DWORD GenerateContainerMapFile(CMD_CONTEXT_PTR pContext, PBYTE *ppbData, PDWORD pcbData) {
  CMD_LOG_FUNC("pContext %p, ppbData %p, pcbData %p", pContext, ppbData, pcbData);

  CANOKEY *pCanokey = &pContext->canokey;

  // Allocate output buffer for all records
  const size_t total = pCanokey->slotCount * sizeof(CONTAINER_MAP_RECORD);
  *ppbData = (PBYTE)g_pfnCspAlloc(total);
  if (!*ppbData)
    return SCARD_E_NO_MEMORY;
  PCONTAINER_MAP_RECORD recs = (PCONTAINER_MAP_RECORD)*ppbData;
  memset(recs, 0, total);

  // Setup SHA-1 digest
  CK_MECHANISM mech = {CKM_SHA_1, NULL, 0};
  for (CK_ULONG i = 0; i < pCanokey->slotCount; i++) {
    SLOT *slot = &pCanokey->slots[i];
    PCONTAINER_MAP_RECORD rec = &recs[i];

    // Compute SHA-1 digest of modulus
    CK_BYTE digest[20];
    CK_ULONG digLen = sizeof(digest);
    CK_RV rv = C_DigestInit(pContext->session, &mech);
    if (rv != CKR_OK) {
      continue;
    }
    rv = C_Digest(pContext->session, slot->rsa.modulus, slot->rsa.modulusBits / 8, digest, &digLen);
    if (rv != CKR_OK)
      continue;

    // Format first 16 bytes of digest as GUID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    unsigned char *b = digest;
    swprintf_s(rec->wszGuid, 37, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
               b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

    // Set flags
    rec->bFlags = CONTAINER_MAP_VALID_CONTAINER;
    // Set signature key size bits
    rec->wSigKeySizeBits = (WORD)(slot->rsa.modulusBits);
    CMD_DEBUG("Container %d: %ls, wSigKeySizeBits: %d", i, rec->wszGuid, rec->wSigKeySizeBits);
  }
  *pcbData = (DWORD)total;
  CMD_DEBUG("Container map generated, size: %d", total);
  CMD_PRINT_HEX(*ppbData, total);

  CMD_RET_OK;
}