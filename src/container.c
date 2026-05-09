#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

typedef struct {
  PUBLICKEYSTRUC publickeystruc;
  RSAPUBKEY rsapubkey;
} PUBRSAKEYSTRUCT_BASE;

static DWORD AllocRsaPublicKeyBlob(const SLOT *slot, ALG_ID keyAlg, PBYTE *ppbKey, PDWORD pcbKey) {
  PUBRSAKEYSTRUCT_BASE keyHeader;
  DWORD modulusSize = slot->rsa.modulusBits / 8;
  DWORD totalSize = sizeof(PUBRSAKEYSTRUCT_BASE) + modulusSize;

  *ppbKey = (PBYTE)g_pfnCspAlloc(totalSize);
  CMD_ENSURE_NONNULL(*ppbKey, SCARD_E_NO_MEMORY);

  keyHeader.publickeystruc.bType = PUBLICKEYBLOB;
  keyHeader.publickeystruc.bVersion = CUR_BLOB_VERSION;
  keyHeader.publickeystruc.reserved = 0;
  keyHeader.publickeystruc.aiKeyAlg = keyAlg;

  keyHeader.rsapubkey.magic = 0x31415352;             // RSA1 in little-endian
  keyHeader.rsapubkey.bitlen = slot->rsa.modulusBits; // Key size in bits
  keyHeader.rsapubkey.pubexp = 65537;                 // Standard RSA exponent (0x10001)

  memcpy(*ppbKey, &keyHeader, sizeof(PUBRSAKEYSTRUCT_BASE));
  memcpy(*ppbKey + sizeof(PUBRSAKEYSTRUCT_BASE), slot->rsa.modulus, modulusSize);
  *pcbKey = totalSize;

  CMD_RET_OK;
}

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
  if (!canokey_slot_can_sign(slot) && !canokey_slot_can_decrypt(slot)) {
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Container has no usable key");
  }

  if (slot->keyType == CKK_RSA) {
    if (canokey_slot_can_sign(slot)) {
      DWORD ret =
          AllocRsaPublicKeyBlob(slot, CALG_RSA_SIGN, &pContainerInfo->pbSigPublicKey, &pContainerInfo->cbSigPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate signature RSA public key blob");
      }
    }
    if (canokey_slot_can_decrypt(slot)) {
      DWORD ret = AllocRsaPublicKeyBlob(slot, CALG_RSA_KEYX, &pContainerInfo->pbKeyExPublicKey,
                                        &pContainerInfo->cbKeyExPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate key exchange RSA public key blob");
      }
    }

    CMD_DEBUG("pContainerInfo:");
    CMD_PRINT_HEX(pContainerInfo, sizeof(CONTAINER_INFO));
    if (pContainerInfo->pbSigPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbSigPublicKey, pContainerInfo->cbSigPublicKey);
    }
    if (pContainerInfo->pbKeyExPublicKey != NULL) {
      CMD_PRINT_HEX(pContainerInfo->pbKeyExPublicKey, pContainerInfo->cbKeyExPublicKey);
    }
  } else if (slot->keyType == CKK_EC) {
    if (!canokey_slot_can_sign(slot)) {
      CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "EC container has no signature key");
    }

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
