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

  if (pContainerInfo->dwVersion > CONTAINER_INFO_CURRENT_VERSION)
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid container info version");

  CMD_GET_CTX(pCardData, pContext);

  if (bContainerIndex >= pContext->canokey.slotCount) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
  }

  pContainerInfo->cbSigPublicKey = 0;
  pContainerInfo->pbSigPublicKey = NULL;
  pContainerInfo->cbKeyExPublicKey = 0;
  pContainerInfo->pbKeyExPublicKey = NULL;

  SLOT *slot = &pContext->canokey.slots[bContainerIndex];
  if (!canokey_slot_can_sign(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no signature key");
  }

  if (slot->keyType == CKK_RSA) {
    // Create a properly formatted RSA public key structure
    PUBRSAKEYSTRUCT_BASE keyHeader;
    DWORD modulusSize = slot->rsa.modulusBits / 8;
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

    keyHeader.rsapubkey.magic = 0x31415352;             // RSA1 in little-endian
    keyHeader.rsapubkey.bitlen = slot->rsa.modulusBits; // Key size in bits
    keyHeader.rsapubkey.pubexp = 65537;                 // Standard RSA exponent (0x10001)

    // Copy the key header to the allocated memory
    memcpy(pContainerInfo->pbSigPublicKey, &keyHeader, sizeof(PUBRSAKEYSTRUCT_BASE));
    memcpy(pContainerInfo->pbSigPublicKey + sizeof(PUBRSAKEYSTRUCT_BASE), slot->rsa.modulus, modulusSize);

    CMD_DEBUG("pContainerInfo:");
    CMD_PRINT_HEX(pContainerInfo, sizeof(CONTAINER_INFO));
    CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey, sizeof(PUBRSAKEYSTRUCT_BASE) + modulusSize);
  } else if (slot->keyType == CKK_EC) {
    DWORD totalSize = sizeof(BCRYPT_ECCKEY_BLOB) + slot->ecc.cbPrivate * 2;

    // Allocate memory for the complete key structure
    pContainerInfo->cbSigPublicKey = totalSize;
    pContainerInfo->pbSigPublicKey = (PBYTE)g_pfnCspAlloc(totalSize);
    CMD_ENSURE_NONNULL(pContainerInfo->pbSigPublicKey, SCARD_E_NO_MEMORY);

    // Initialize the key header
    BCRYPT_ECCKEY_BLOB *keyHeader = (BCRYPT_ECCKEY_BLOB *)pContainerInfo->pbSigPublicKey;
    switch (slot->ecc.cbPrivate) {
    case 32:
      keyHeader->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
      break;
    case 48:
      keyHeader->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
      break;
    default:
      CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Invalid container index");
    }
    keyHeader->cbKey = slot->ecc.cbPrivate;
    memcpy(pContainerInfo->pbSigPublicKey + sizeof(BCRYPT_ECCKEY_BLOB), slot->ecc.x, slot->ecc.cbPrivate);
    memcpy(pContainerInfo->pbSigPublicKey + sizeof(BCRYPT_ECCKEY_BLOB) + slot->ecc.cbPrivate, slot->ecc.y,
           slot->ecc.cbPrivate);

    CMD_DEBUG("pContainerInfo:");
    CMD_PRINT_HEX(pContainerInfo, sizeof(CONTAINER_INFO));
    CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey, totalSize);
  }

  CMD_RET_OK;
}
