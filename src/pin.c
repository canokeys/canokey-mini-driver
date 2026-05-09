#include <string.h>
#include <wchar.h>

#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "logging.h"
#include "minidriver.h"

#define CMD_MANAGEMENT_KEY_LEN 24

static DWORD map_pkcs11_pin_error(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
  case CKR_USER_NOT_LOGGED_IN:
    return SCARD_S_SUCCESS;
  case CKR_USER_PIN_NOT_INITIALIZED:
  case CKR_PIN_INCORRECT:
  case CKR_PIN_INVALID:
  case CKR_PIN_LEN_RANGE:
  case CKR_PIN_EXPIRED:
    return SCARD_W_WRONG_CHV;
  case CKR_PIN_LOCKED:
    return SCARD_W_CHV_BLOCKED;
  case CKR_SESSION_HANDLE_INVALID:
  case CKR_CRYPTOKI_NOT_INITIALIZED:
    return SCARD_E_INVALID_HANDLE;
  case CKR_HOST_MEMORY:
    return SCARD_E_NO_MEMORY;
  default:
    return SCARD_F_INTERNAL_ERROR;
  }
}

static DWORD map_pkcs11_login_error(CK_RV rv, BYTE pinTries) {
  if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_INVALID || rv == CKR_PIN_LEN_RANGE || rv == CKR_PIN_EXPIRED ||
      rv == CKR_USER_PIN_NOT_INITIALIZED) {
    return pinTries > 0 ? SCARD_W_WRONG_CHV : SCARD_W_CHV_BLOCKED;
  }
  if (rv == CKR_USER_NOT_LOGGED_IN) {
    return SCARD_F_INTERNAL_ERROR;
  }
  return map_pkcs11_pin_error(rv);
}

static int hex_digit_value(BYTE ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

static DWORD decode_management_key(PBYTE pbPinData, DWORD cbPinData, BYTE managementKey[CMD_MANAGEMENT_KEY_LEN],
                                   CK_ULONG *pManagementKeyLen) {
  CMD_ENSURE_NONNULL(pbPinData, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(managementKey, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pManagementKeyLen, SCARD_E_INVALID_PARAMETER);

  if (cbPinData == CMD_MANAGEMENT_KEY_LEN) {
    memcpy(managementKey, pbPinData, CMD_MANAGEMENT_KEY_LEN);
    *pManagementKeyLen = CMD_MANAGEMENT_KEY_LEN;
    CMD_RET_OK;
  }

  BYTE decoded[CMD_MANAGEMENT_KEY_LEN];
  DWORD decodedLen = 0;
  int highNibble = -1;
  for (DWORD i = 0; i < cbPinData; i++) {
    BYTE ch = pbPinData[i];
    if (ch == ':' || ch == '-' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
      continue;
    }

    int value = hex_digit_value(ch);
    if (value < 0) {
      SecureZeroMemory(decoded, sizeof(decoded));
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Management key is neither raw bytes nor hex");
    }

    if (highNibble < 0) {
      highNibble = value;
      continue;
    }

    if (decodedLen >= CMD_MANAGEMENT_KEY_LEN) {
      SecureZeroMemory(decoded, sizeof(decoded));
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Management key hex is too long");
    }
    decoded[decodedLen++] = (BYTE)((highNibble << 4) | value);
    highNibble = -1;
  }

  if (highNibble >= 0 || decodedLen != CMD_MANAGEMENT_KEY_LEN) {
    SecureZeroMemory(decoded, sizeof(decoded));
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid management key length");
  }

  memcpy(managementKey, decoded, CMD_MANAGEMENT_KEY_LEN);
  SecureZeroMemory(decoded, sizeof(decoded));
  *pManagementKeyLen = CMD_MANAGEMENT_KEY_LEN;
  CMD_RET_OK;
}

static CK_RV login_with_role(CMD_CONTEXT_PTR pContext, CK_USER_TYPE userType, PBYTE loginData, CK_ULONG loginDataLen,
                             BYTE *pPinTries) {
  CK_RV rv = C_CNK_Login(pContext->session, userType, loginData, loginDataLen, pPinTries);
  if (rv != CKR_USER_ANOTHER_ALREADY_LOGGED_IN) {
    return rv;
  }

  rv = C_Logout(pContext->session);
  if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
    return rv;
  }
  pContext->authenticatedPins = PIN_SET_NONE;
  return C_CNK_Login(pContext->session, userType, loginData, loginDataLen, pPinTries);
}

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

  PIN_ID pinId = ROLE_EVERYONE;
  if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0) {
    pinId = ROLE_USER;
  } else if (wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0) {
    pinId = ROLE_ADMIN;
  } else {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid user id");
  }

  return CardAuthenticateEx(pCardData, pinId, 0, pbPin, cbPin, NULL, NULL, pcAttemptsRemaining);
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
  (void)ppbSessionPin;
  (void)pcbSessionPin;

  INJECT_HANDLES();

  if (PinId != ROLE_USER && PinId != ROLE_ADMIN) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid PinId");
  }

  if ((dwFlags & ~(CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN | CARD_PIN_SILENT_CONTEXT)) !=
      0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid dwFlags");
  }
  if ((dwFlags & (CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN)) != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Session PIN not supported");
  }

  // if (cbPinData < sizeof(PIN_INFO)) {
  //   CMD_RETURN(SCARD_E_INVALID_PARAMETER, "cbPinData is too small");
  // }

  // PPIN_INFO pPinInfo = (PPIN_INFO)pbPinData;

  BYTE pinTries = 0;
  BYTE managementKey[CMD_MANAGEMENT_KEY_LEN];
  PBYTE loginData = pbPinData;
  CK_ULONG loginDataLen = cbPinData;
  CK_USER_TYPE userType = CKU_USER;

  if (PinId == ROLE_ADMIN) {
    DWORD ret = decode_management_key(pbPinData, cbPinData, managementKey, &loginDataLen);
    if (ret != SCARD_S_SUCCESS) {
      return ret;
    }
    loginData = managementKey;
    userType = CKU_SO;
  }

  CK_RV rv = login_with_role(pContext, userType, loginData, loginDataLen, &pinTries);
  SecureZeroMemory(managementKey, sizeof(managementKey));
  if (PinId == ROLE_USER) {
    CMD_DEBUG("Remaining pinTries: %d", pinTries);
  }

  if (rv == CKR_USER_ALREADY_LOGGED_IN) {
    SET_PIN(pContext->authenticatedPins, PinId);
    CMD_RET_OK;
  }
  if (rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN) {
    CMD_RETURN(SCARD_W_SECURITY_VIOLATION, "Another user type is already logged in");
  }

  // TODO: For all attempts beyond the allowed number,
  // the function returns SCARD_W_CHV_BLOCKED and the pcAttemptsRemaining parameter returns zero.
  if (pcAttemptsRemaining && PinId == ROLE_USER) {
    *pcAttemptsRemaining = pinTries;
  }

  if (rv != CKR_OK) {
    // If the card minidriver returns a nonzero value from this function,
    // the Base CSP/KSP resets the card
    CMD_RETURN(map_pkcs11_login_error(rv, pinTries), "C_Login failed");
  } else {
    SET_PIN(pContext->authenticatedPins, PinId);
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

  CMD_CHECK_DW_FLAGS;
  if (!IS_PIN_SET(PinId, ROLE_USER) && !IS_PIN_SET(PinId, ROLE_ADMIN)) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid PinId");
  }

  CK_RV rv = C_Logout(pContext->session);
  if (rv == CKR_USER_NOT_LOGGED_IN) {
    pContext->authenticatedPins = PIN_SET_NONE;
    CMD_RET_OK;
  }
  if (rv != CKR_OK) {
    // If the card minidriver returns a nonzero value from this function,
    // the Base CSP/KSP resets the card
    CMD_RETURN(map_pkcs11_pin_error(rv), "C_Logout failed");
  } else {
    pContext->authenticatedPins = PIN_SET_NONE;
    CMD_RET_OK;
  }
}
