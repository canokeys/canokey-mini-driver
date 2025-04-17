#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

/*
 * Function: CardSignData
 *
 * Purpose: Sign data using a key on the card.
 */
DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pCardSigningInfo) {
  CMD_LOG_FUNC("pCardData %p, pCardSigningInfo %p", pCardData, pCardSigningInfo);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pCardSigningInfo);

  CMD_DEBUG("CardSigningInfo: dwVersion %d, bContainerIndex %d, dwKeySpec %d, dwSigningFlags %d, aiHashAlg %d, cbData "
            "%d, pbData %p, cbSignedData %d, pbSignedData %p, pPaddingInfo %p, dwPaddingType %d",
            pCardSigningInfo->dwVersion, pCardSigningInfo->bContainerIndex, pCardSigningInfo->dwKeySpec,
            pCardSigningInfo->dwSigningFlags, pCardSigningInfo->aiHashAlg, pCardSigningInfo->cbData,
            pCardSigningInfo->pbData, pCardSigningInfo->cbSignedData, pCardSigningInfo->pbSignedData,
            pCardSigningInfo->pPaddingInfo, pCardSigningInfo->dwPaddingType);

  pCardSigningInfo->pbSignedData = (PBYTE)g_pfnCspAlloc(256);

  // TODO

  CMD_RET_OK;
}

/*
 * Function: CardQueryKeySizes
 *
 * Purpose: Query the supported key sizes for a given algorithm.
 */
DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags,
                               __inout PCARD_KEY_SIZES pKeySizes) {
  CMD_LOG_FUNC("pCardData %p, dwKeySpec %x, dwFlags "
               "%x, pKeySizes %p",
               pCardData, dwKeySpec, dwFlags, pKeySizes);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pKeySizes);

  CMD_RET_UNIMPL;
}
