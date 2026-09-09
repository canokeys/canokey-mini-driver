#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

/*
 * Function: CardQueryCapabilities
 *
 * Purpose: Query the capabilities of the card.
 */
DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities) {
  CMD_LOG_FUNC("pCardData %p, pCardCapabilities %p", pCardData, pCardCapabilities);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pCardCapabilities);

  INJECT_HANDLES();

  if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION) {
    return ERROR_REVISION_MISMATCH;
  }

  // Set capabilities
  // The minidriver owns the PIV-to-DER certificate representation. Tell Base
  // CSP/KSP not to apply its card-file compression layer to CardReadFile data.
  pCardCapabilities->fCertificateCompression = TRUE;
  pCardCapabilities->fKeyGen = TRUE;

  CMD_RET_OK;
}
