#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

typedef struct {
  PUBLICKEYSTRUC publickeystruc;
  RSAPUBKEY rsapubkey;
} PUBRSAKEYSTRUCT_BASE;

/*
 * Function: CardGetContainerInfo
 *
 * Purpose: Get information about a key container on the card.
 */
DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
                                  __inout PCONTAINER_INFO pContainerInfo) {
  CMD_LOG_FUNC("pCardData %p, bContainerIndex %d, dwFlags %x, dwVersion %d", pCardData, bContainerIndex, dwFlags,
               pContainerInfo->dwVersion);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pContainerInfo);

  INJECT_HANDLES();

  if (pContainerInfo->dwVersion > CONTAINER_INFO_CURRENT_VERSION) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid container info version");
  }

  if (bContainerIndex != 0) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }

  // Create a properly formatted RSA public key structure
  PUBRSAKEYSTRUCT_BASE keyHeader;
  DWORD modulusSize = 256; // 2048 bits = 256 bytes
  DWORD exponentSize = 4;  // Standard RSA exponent size
  DWORD totalSize = sizeof(PUBRSAKEYSTRUCT_BASE) + modulusSize;

  // Allocate memory for the complete key structure
  pContainerInfo->cbSigPublicKey = totalSize;
  pContainerInfo->pbSigPublicKey = (PBYTE)g_pfnCspAlloc(totalSize);
  CMD_ENSURE_NONNULL(pContainerInfo->pbSigPublicKey, SCARD_E_NO_MEMORY);

  // Initialize the key header
  keyHeader.publickeystruc.bType = PUBLICKEYBLOB;
  keyHeader.publickeystruc.bVersion = CUR_BLOB_VERSION;
  keyHeader.publickeystruc.reserved = 0;
  keyHeader.publickeystruc.aiKeyAlg = CALG_RSA_SIGN;

  keyHeader.rsapubkey.magic = 0x31415352; // RSA1 in little-endian
  keyHeader.rsapubkey.bitlen = 2048;      // Key size in bits
  keyHeader.rsapubkey.pubexp = 65537;     // Standard RSA exponent (0x10001)

  // Copy the key header to the allocated memory
  memcpy(pContainerInfo->pbSigPublicKey, &keyHeader, sizeof(PUBRSAKEYSTRUCT_BASE));

  CK_SESSION_HANDLE_PTR pSession = pCardData->pvVendorSpecific;
  CK_OBJECT_HANDLE hObject;
  CK_BYTE key_id = 2;
  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE templates[] = {{CKA_ID, &key_id, sizeof(key_id)}, {CKA_CLASS, &keyClass, sizeof(keyClass)}};

  CK_RV rv = C_FindObjectsInit(*pSession, templates, 2);
  if (rv != CKR_OK) {
    CMD_RETURN(rv, "C_FindObjectsInit failed");
  }

  CK_ULONG ulObjectCount = 0;
  rv = C_FindObjects(*pSession, &hObject, 1, &ulObjectCount);
  if (rv != CKR_OK || ulObjectCount == 0) {
    CMD_RETURN(rv, "C_FindObjects failed");
  }

  rv = C_FindObjectsFinal(*pSession);
  if (rv != CKR_OK) {
    CMD_RETURN(rv, "C_FindObjectsFinal failed");
  }

  templates[0].type = CKA_MODULUS;
  templates[0].pValue = pContainerInfo->pbSigPublicKey + sizeof(PUBRSAKEYSTRUCT_BASE);
  templates[0].ulValueLen = modulusSize;
  rv = C_GetAttributeValue(*pSession, hObject, &templates[0], 1);
  if (rv != CKR_OK) {
    CMD_RETURN(rv, "C_GetAttributeValue failed");
  }

  reverse_bytes(pContainerInfo->pbSigPublicKey + sizeof(PUBRSAKEYSTRUCT_BASE), modulusSize);

  CMD_DEBUG("Modulus: ");
  CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey + sizeof(PUBRSAKEYSTRUCT_BASE), modulusSize);

  // No key exchange key in this implementation
  pContainerInfo->cbKeyExPublicKey = 0;
  pContainerInfo->pbKeyExPublicKey = NULL;

  CMD_RET_OK;
}
