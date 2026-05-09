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

static DWORD AllocCopy(const void *data, DWORD cbData, PBYTE *ppbData, PDWORD pcbData) {
  CMD_ENSURE_NONNULL(ppbData, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pcbData, SCARD_E_INVALID_PARAMETER);

  *ppbData = NULL;
  *pcbData = cbData;
  if (cbData == 0) {
    CMD_RET_OK;
  }

  *ppbData = (PBYTE)g_pfnCspAlloc(cbData);
  CMD_ENSURE_NONNULL(*ppbData, SCARD_E_NO_MEMORY);
  memcpy(*ppbData, data, cbData);
  CMD_RET_OK;
}

static CK_RV DigestUpdateSlotPublicKey(CK_SESSION_HANDLE session, const SLOT *slot) {
  if (slot->keyType == CKK_RSA) {
    return C_DigestUpdate(session, (CK_BYTE_PTR)slot->rsa.modulus, slot->rsa.modulusBits / 8);
  }
  if (slot->keyType == CKK_EC) {
    CK_RV rv = C_DigestUpdate(session, (CK_BYTE_PTR)slot->ecc.x, slot->ecc.cbPrivate);
    if (rv != CKR_OK) {
      return rv;
    }
    return C_DigestUpdate(session, (CK_BYTE_PTR)slot->ecc.y, slot->ecc.cbPrivate);
  }
  return CKR_KEY_TYPE_INCONSISTENT;
}

DWORD GenerateCardIdentifier(CMD_CONTEXT_PTR pContext) {
  CMD_ENSURE_NONNULL(pContext, SCARD_E_INVALID_PARAMETER);

  CK_MECHANISM mech = {CKM_SHA_1, NULL, 0};
  CK_BYTE digest[20];
  CK_ULONG digestLen = sizeof(digest);
  CK_RV rv = C_DigestInit(pContext->session, &mech);
  if (rv != CKR_OK) {
    CMD_RETURN(SCARD_F_INTERNAL_ERROR, "C_DigestInit failed");
  }

  for (CK_ULONG i = 0; i < pContext->canokey.slotCount; i++) {
    rv = DigestUpdateSlotPublicKey(pContext->session, &pContext->canokey.slots[i]);
    if (rv != CKR_OK) {
      CMD_RETURN(SCARD_F_INTERNAL_ERROR, "C_DigestUpdate failed");
    }
  }

  rv = C_DigestFinal(pContext->session, digest, &digestLen);
  if (rv != CKR_OK || digestLen < sizeof(pContext->cardId)) {
    CMD_RETURN(SCARD_F_INTERNAL_ERROR, "C_DigestFinal failed");
  }

  memcpy(pContext->cardId, digest, sizeof(pContext->cardId));
  CMD_RET_OK;
}

static BYTE GetFileContainerIndex(LPCSTR pszFileName) {
  LPCSTR digits = pszFileName + 3;
  if (*digits == '\0') {
    return 0xff;
  }

  unsigned long value = 0;
  while (*digits != '\0') {
    if (*digits < '0' || *digits > '9') {
      return 0xff;
    }
    value = value * 10 + (unsigned long)(*digits - '0');
    if (value > MAX_SLOT_ID) {
      return 0xff;
    }
    digits++;
  }

  return (BYTE)value;
}

// The CardReadFile function reads the entire file at the specified location into the user-supplied buffer.
DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName,
                          __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData) {
  CMD_LOG_FUNC("pCardData %p, pszDirectoryName %s, pszFileName %s, dwFlags %x", pCardData, pszDirectoryName,
               pszFileName, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pszFileName);
  CMD_NONNULL_PARAM(ppbData);
  CMD_NONNULL_PARAM(pcbData);

  CMD_CHECK_DW_FLAGS;

  *ppbData = NULL;
  *pcbData = 0;

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
    if (strcmp(pszFileName, szCARD_IDENTIFIER_FILE) == 0) {
      return AllocCopy(pContext->cardId, sizeof(pContext->cardId), ppbData, pcbData);
    }
    CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
  }

  if (strcmp(pszDirectoryName, szBASE_CSP_DIR) == 0) {
    if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
      return AllocCopy(NULL, 0, ppbData, pcbData);
    }

    if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      DWORD res = GenerateContainerMapFile(pContext, ppbData, pcbData);
      if (res != SCARD_S_SUCCESS) {
        CMD_RETURN(res, "Generate container map failed");
      }
      CMD_RET_OK;
    }

    if (strncmp(pszFileName, szUSER_KEYEXCHANGE_CERT_PREFIX, 3) == 0) {
      BYTE slotIndex = GetFileContainerIndex(pszFileName);
      if (slotIndex >= pContext->canokey.slotCount)
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
      SLOT *slot = &pContext->canokey.slots[slotIndex];
      if (!canokey_slot_can_decrypt(slot) && !canokey_slot_can_derive(slot)) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Key exchange certificate not found");
      }
      if (slot->certLen == 0) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Key exchange certificate is absent");
      }

      return AllocCopy(slot->cert, (DWORD)slot->certLen, ppbData, pcbData);
    }

    if (strncmp(pszFileName, szUSER_SIGNATURE_CERT_PREFIX, 3) == 0) {
      BYTE slotIndex = GetFileContainerIndex(pszFileName);
      if (slotIndex >= pContext->canokey.slotCount)
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
      SLOT *slot = &pContext->canokey.slots[slotIndex];
      if (!canokey_slot_can_sign(slot)) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Signature certificate not found");
      }
      if (slot->certLen == 0) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Signature certificate is absent");
      }

      return AllocCopy(slot->cert, (DWORD)slot->certLen, ppbData, pcbData);
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
  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pszFileName);
  CMD_NONNULL_PARAM(pCardFileInfo);

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }

  pCardFileInfo->cbFileSize = 0;
  pCardFileInfo->AccessCondition = EveryoneReadAdminWriteAc;

  if (pszDirectoryName == NULL) {
    if (strcmp(pszFileName, szCACHE_FILE) == 0) {
      pCardFileInfo->cbFileSize = 6;
      CMD_RET_OK;
    }
    if (strcmp(pszFileName, szCARD_IDENTIFIER_FILE) == 0) {
      pCardFileInfo->cbFileSize = sizeof(pContext->cardId);
      CMD_RET_OK;
    }
    CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
  }

  if (strcmp(pszDirectoryName, szBASE_CSP_DIR) == 0) {
    pCardFileInfo->AccessCondition = EveryoneReadUserWriteAc;
    if (strcmp(pszFileName, szROOT_STORE_FILE) == 0) {
      pCardFileInfo->cbFileSize = 0;
      CMD_RET_OK;
    }
    if (strcmp(pszFileName, szCONTAINER_MAP_FILE) == 0) {
      pCardFileInfo->cbFileSize = (DWORD)(pContext->canokey.slotCount * sizeof(CONTAINER_MAP_RECORD));
      CMD_RET_OK;
    }
    if (strncmp(pszFileName, szUSER_KEYEXCHANGE_CERT_PREFIX, 3) == 0) {
      BYTE slotIndex = GetFileContainerIndex(pszFileName);
      if (slotIndex >= pContext->canokey.slotCount) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
      }
      SLOT *slot = &pContext->canokey.slots[slotIndex];
      if ((!canokey_slot_can_decrypt(slot) && !canokey_slot_can_derive(slot)) || slot->certLen == 0) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Key exchange certificate not found");
      }
      pCardFileInfo->cbFileSize = (DWORD)slot->certLen;
      CMD_RET_OK;
    }
    if (strncmp(pszFileName, szUSER_SIGNATURE_CERT_PREFIX, 3) == 0) {
      BYTE slotIndex = GetFileContainerIndex(pszFileName);
      if (slotIndex >= pContext->canokey.slotCount) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
      }
      SLOT *slot = &pContext->canokey.slots[slotIndex];
      if (!canokey_slot_can_sign(slot) || slot->certLen == 0) {
        CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "Signature certificate not found");
      }
      pCardFileInfo->cbFileSize = (DWORD)slot->certLen;
      CMD_RET_OK;
    }
    CMD_RETURN(SCARD_E_FILE_NOT_FOUND, "File not found");
  }

  CMD_RETURN(SCARD_E_DIR_NOT_FOUND, "Directory not found");
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
  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pmszFileNames);
  CMD_NONNULL_PARAM(pdwcbFileName);

  CMD_CHECK_DW_FLAGS;

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  *pmszFileNames = NULL;
  *pdwcbFileName = 0;

  if (pszDirectoryName == NULL) {
    const char rootFiles[] = szCACHE_FILE "\0" szCARD_IDENTIFIER_FILE "\0";
    return AllocCopy(rootFiles, sizeof(rootFiles), (PBYTE *)pmszFileNames, pdwcbFileName);
  }

  if (strcmp(pszDirectoryName, szBASE_CSP_DIR) != 0) {
    CMD_RETURN(SCARD_E_DIR_NOT_FOUND, "Directory not found");
  }

  DWORD total = sizeof(szROOT_STORE_FILE) + sizeof(szCONTAINER_MAP_FILE);
  for (CK_ULONG i = 0; i < pContext->canokey.slotCount; i++) {
    SLOT *slot = &pContext->canokey.slots[i];
    if (slot->certLen == 0) {
      continue;
    }
    if (canokey_slot_can_sign(slot)) {
      total += (DWORD)snprintf(NULL, 0, "%s%lu", szUSER_SIGNATURE_CERT_PREFIX, (unsigned long)i) + 1;
    }
    if (canokey_slot_can_decrypt(slot) || canokey_slot_can_derive(slot)) {
      total += (DWORD)snprintf(NULL, 0, "%s%lu", szUSER_KEYEXCHANGE_CERT_PREFIX, (unsigned long)i) + 1;
    }
  }
  total += 1;

  LPSTR files = (LPSTR)g_pfnCspAlloc(total);
  CMD_ENSURE_NONNULL(files, SCARD_E_NO_MEMORY);
  LPSTR cursor = files;
  DWORD remaining = total;

  int written = snprintf(cursor, remaining, "%s", szROOT_STORE_FILE);
  cursor += written + 1;
  remaining -= (DWORD)written + 1;
  written = snprintf(cursor, remaining, "%s", szCONTAINER_MAP_FILE);
  cursor += written + 1;
  remaining -= (DWORD)written + 1;

  for (CK_ULONG i = 0; i < pContext->canokey.slotCount; i++) {
    SLOT *slot = &pContext->canokey.slots[i];
    if (slot->certLen == 0) {
      continue;
    }
    if (canokey_slot_can_sign(slot)) {
      written = snprintf(cursor, remaining, "%s%lu", szUSER_SIGNATURE_CERT_PREFIX, (unsigned long)i);
      cursor += written + 1;
      remaining -= (DWORD)written + 1;
    }
    if (canokey_slot_can_decrypt(slot) || canokey_slot_can_derive(slot)) {
      written = snprintf(cursor, remaining, "%s%lu", szUSER_KEYEXCHANGE_CERT_PREFIX, (unsigned long)i);
      cursor += written + 1;
      remaining -= (DWORD)written + 1;
    }
  }
  *cursor = '\0';

  *pmszFileNames = files;
  *pdwcbFileName = total;
  CMD_RET_OK;
}

/*
 * Function: CardQueryFreeSpace
 *
 * Purpose: Query the free space on the card.
 */
DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
                                __inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo) {
  CMD_LOG_FUNC("pCardData %p, dwFlags %x, pCardFreeSpaceInfo %p", pCardData, dwFlags, pCardFreeSpaceInfo);
  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pCardFreeSpaceInfo);

  INJECT_HANDLES();

  CMD_CHECK_DW_FLAGS;
  if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION) {
    CMD_RETURN(ERROR_REVISION_MISMATCH, "dwVersion mismatch");
  }

  pCardFreeSpaceInfo->dwBytesAvailable = 0;
  pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
  pCardFreeSpaceInfo->dwMaxKeyContainers = MAX_SLOT_ID;
  CMD_RET_OK;
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
    if (slot->keyType == CKK_RSA) {
      rv = C_Digest(pContext->session, slot->rsa.modulus, slot->rsa.modulusBits / 8, digest, &digLen);
    } else if (slot->keyType == CKK_EC) {
      rv = C_Digest(pContext->session, slot->ecc.x, slot->ecc.cbPrivate * 2, digest, &digLen);
    }
    if (rv != CKR_OK)
      continue;

    // Format first 16 bytes of digest as GUID XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    unsigned char *b = digest;
    swprintf_s(rec->wszGuid, 37, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
               b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);

    // Set flags
    rec->bFlags = CONTAINER_MAP_VALID_CONTAINER;
    if (i == 0) {
      rec->bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
    }
    // Set signature key size bits
    if (canokey_slot_can_sign(slot)) {
      rec->wSigKeySizeBits = (WORD)(slot->keyType == CKK_RSA ? slot->rsa.modulusBits : slot->ecc.cbPrivate * 8);
    }
    if (canokey_slot_can_decrypt(slot) && slot->keyType == CKK_RSA) {
      rec->wKeyExchangeKeySizeBits = (WORD)slot->rsa.modulusBits;
    } else if (canokey_slot_can_derive(slot) && slot->keyType == CKK_EC) {
      rec->wKeyExchangeKeySizeBits = (WORD)(slot->ecc.cbPrivate * 8);
    }
    CMD_DEBUG("Container %d: %ls, flags: %d, wSigKeySizeBits: %d, wKeyExchangeKeySizeBits: %d", i, rec->wszGuid,
              rec->bFlags, rec->wSigKeySizeBits, rec->wKeyExchangeKeySizeBits);
  }
  *pcbData = (DWORD)total;
  CMD_DEBUG("Container map generated, size: %d", total);
  CMD_PRINT_HEX(*ppbData, total);

  CMD_RET_OK;
}
