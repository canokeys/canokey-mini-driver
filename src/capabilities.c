#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"

/*
 * Function: CardQueryCapabilities
 *
 * Purpose: Query the capabilities of the card.
 */
DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities) {
  CMD_LOG_FUNC("pCardData %p, pCardCapabilities %p", pCardData, pCardCapabilities);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pCardCapabilities);

  if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION) {
    return ERROR_REVISION_MISMATCH;
  }

  // Set capabilities
  pCardCapabilities->fCertificateCompression = FALSE;
  pCardCapabilities->fKeyGen = TRUE;

  CMD_RET_OK;
}
