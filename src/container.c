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

static DWORD AllocEcPublicKeyBlob(const SLOT *slot, ULONG magic, PBYTE *ppbKey, PDWORD pcbKey) {
  DWORD totalSize = sizeof(BCRYPT_ECCKEY_BLOB) + (DWORD)slot->ecc.cbPrivate * 2;

  *ppbKey = (PBYTE)g_pfnCspAlloc(totalSize);
  CMD_ENSURE_NONNULL(*ppbKey, SCARD_E_NO_MEMORY);

  BCRYPT_ECCKEY_BLOB *keyHeader = (BCRYPT_ECCKEY_BLOB *)*ppbKey;
  keyHeader->dwMagic = magic;
  keyHeader->cbKey = (ULONG)slot->ecc.cbPrivate;
  memcpy(*ppbKey + sizeof(BCRYPT_ECCKEY_BLOB), slot->ecc.x, slot->ecc.cbPrivate);
  memcpy(*ppbKey + sizeof(BCRYPT_ECCKEY_BLOB) + slot->ecc.cbPrivate, slot->ecc.y, slot->ecc.cbPrivate);
  *pcbKey = totalSize;

  CMD_RET_OK;
}

static DWORD EcPublicKeyMagic(const SLOT *slot, BOOL derive, ULONG *pMagic) {
  CMD_ENSURE_NONNULL(pMagic, SCARD_E_INVALID_PARAMETER);

  switch (slot->ecc.cbPrivate) {
  case 32:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P256_MAGIC : BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    CMD_RET_OK;
  case 48:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P384_MAGIC : BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    CMD_RET_OK;
  case 66:
    *pMagic = derive ? BCRYPT_ECDH_PUBLIC_P521_MAGIC : BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
    CMD_RET_OK;
  default:
    CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "Unsupported EC key size");
  }
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

  CMD_CHECK_DW_FLAGS;
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
  if (!canokey_slot_can_sign(slot) && !canokey_slot_can_decrypt(slot) && !canokey_slot_can_derive(slot)) {
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
    if (!canokey_slot_can_sign(slot) && !canokey_slot_can_derive(slot)) {
      CMD_RETURN(SCARD_E_NO_KEY_CONTAINER, "EC container has no usable key");
    }

    if (canokey_slot_can_sign(slot)) {
      ULONG magic;
      DWORD ret = EcPublicKeyMagic(slot, FALSE, &magic);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to select signature EC public key magic");
      }
      ret = AllocEcPublicKeyBlob(slot, magic, &pContainerInfo->pbSigPublicKey, &pContainerInfo->cbSigPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate signature EC public key blob");
      }
    }

    if (canokey_slot_can_derive(slot)) {
      ULONG magic;
      DWORD ret = EcPublicKeyMagic(slot, TRUE, &magic);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to select ECDH public key magic");
      }
      ret = AllocEcPublicKeyBlob(slot, magic, &pContainerInfo->pbKeyExPublicKey, &pContainerInfo->cbKeyExPublicKey);
      if (ret != SCARD_S_SUCCESS) {
        CMD_RETURN(ret, "Failed to allocate ECDH public key blob");
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
  }

  CMD_RET_OK;
}
