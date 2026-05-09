#include <string.h>
#include <wchar.h>

#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

/*
 * Function: CardAuthenticatePin
 *
 * Purpose: Authenticate the PIN. Deprecated by CardAuthenticateEx.
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

  if (wcscmp(pwszUserId, wszCARD_USER_USER) != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid user id");
  }

  return CardAuthenticateEx(pCardData, ROLE_USER, 0, pbPin, cbPin, NULL, NULL, pcAttemptsRemaining);
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
  CMD_GET_CTX(pCardData, pContext);

  INJECT_HANDLES();

  // The allowed values for PinId are ROLE_USER, ROLE_ADMIN or 3 through 7
  // TODO: currently we only support ROLE_USER
  if (PinId != ROLE_USER) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid PinId");
  }

  if (dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Session PIN not supported");
  }

  // if (cbPinData < sizeof(PIN_INFO)) {
  //   CMD_RETURN(SCARD_E_INVALID_PARAMETER, "cbPinData is too small");
  // }

  // PPIN_INFO pPinInfo = (PPIN_INFO)pbPinData;

  BYTE pinTries = 0;
  CK_RV rv = C_CNK_Login(pContext->session, CKU_USER, pbPinData, cbPinData, &pinTries);
  CMD_DEBUG("Remaining pinTries: %d", pinTries);

  if (rv == CKR_USER_ALREADY_LOGGED_IN) {
    CMD_RET_OK;
  }

  // TODO: For all attempts beyond the allowed number,
  // the function returns SCARD_W_CHV_BLOCKED and the pcAttemptsRemaining parameter returns zero.
  if (pcAttemptsRemaining) {
    *pcAttemptsRemaining = pinTries;
  }

  if (rv != CKR_OK) {
    // If the card minidriver returns a nonzero value from this function,
    // the Base CSP/KSP resets the card
    CMD_RETURN(pinTries > 0 ? SCARD_W_WRONG_CHV : SCARD_W_CHV_BLOCKED, "C_Login failed");
  } else {
    CMD_RET_OK;
  }
}

/*
 * Function: CardDeauthenticateEx
 *
 * Purpose: Deauthenticate from the card with extended parameters.
 */
DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData, __in PIN_SET PinId, __in DWORD dwFlags) {
  CMD_LOG_FUNC("pCardData %p, PinId %d, dwFlags %x", pCardData, PinId, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_GET_CTX(pCardData, pContext);

  INJECT_HANDLES();

  // TODO: PinId is not used
  CK_RV rv = C_Logout(pContext->session);
  if (rv == CKR_USER_NOT_LOGGED_IN) {
    CMD_RET_OK;
  }
  if (rv != CKR_OK) {
    // If the card minidriver returns a nonzero value from this function,
    // the Base CSP/KSP resets the card
    CMD_RETURN(rv, "C_Logout failed");
  } else {
    CMD_RET_OK;
  }
}
