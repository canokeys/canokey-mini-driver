#include <string.h>
#include <wchar.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

/*
 * Function: CardAuthenticatePin
 *
 * Purpose: Authenticate the PIN.
 */
DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin,
                                 __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_LOG_FUNC("pCardData %p, pwszUserId %S, "
               "pbPin %p, cbPin %d, pcAttemptsRemaining %p",
               pCardData, pwszUserId, pbPin, cbPin, pcAttemptsRemaining);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pwszUserId);
  CMD_NONNULL_PARAM(pbPin);

  INJECT_HANDLES();

  CMD_RET_UNIMPL;
}

/*
 * Function: CardAuthenticateEx
 *
 * Purpose: Authenticate to the card with extended parameters.
 */
DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags,
                                __in_bcount(cbPinData) PBYTE pbPinData, __in DWORD cbPinData,
                                __deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
                                __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_LOG_FUNC("pCardData %p, PinId %d, dwFlags "
               "%x, pbPinData %p, cbPinData %d",
               pCardData, PinId, dwFlags, pbPinData, cbPinData);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pbPinData);

  INJECT_HANDLES();

  CMD_RET_UNIMPL;
}

/*
 * Function: CardDeauthenticateEx
 *
 * Purpose: Deauthenticate from the card with extended parameters.
 */
DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData, __in PIN_SET PinId, __in DWORD dwFlags) {
  CMD_LOG_FUNC("pCardData %p, PinId %d, dwFlags %x", pCardData, PinId, dwFlags);

  CMD_NONNULL_PARAM(pCardData);

  INJECT_HANDLES();

  CMD_RET_UNIMPL;
}
