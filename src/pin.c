#include <string.h>
#include <wchar.h>

#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "config.h"
#include "logging.h"
#include "minidriver.h"

#define CMD_MANAGEMENT_KEY_LEN 24

static CK_RV login_with_role(CMD_CONTEXT_PTR pContext, CK_USER_TYPE userType, PBYTE loginData, CK_ULONG loginDataLen,
                             BYTE *pPinTries);

void cmd_clear_user_pin(CMD_CONTEXT_PTR pContext) {
  if (pContext == NULL)
    return;
  SecureZeroMemory(pContext->userPin, sizeof(pContext->userPin));
  pContext->userPinLen = 0;
  pContext->userPinValid = FALSE;
}

void cmd_store_user_pin(CMD_CONTEXT_PTR pContext, const BYTE *pin, DWORD pinLen) {
  if (pContext == NULL)
    return;
  cmd_clear_user_pin(pContext);
  if (pin == NULL || pinLen == 0 || pinLen > CMD_MAX_USER_PIN_LEN) {
    // The Windows callback owns the original PIN buffer. Keep only values
    // that fit the bounded per-context retry bridge; never log the PIN bytes.
    if (pin != NULL && pinLen > CMD_MAX_USER_PIN_LEN)
      CMD_WARN("USER PIN length %lu cannot be retained for context-specific operations", (unsigned long)pinLen);
    return;
  }
  memcpy(pContext->userPin, pin, pinLen);
  pContext->userPinLen = pinLen;
  pContext->userPinValid = TRUE;
  CMD_DEBUG("Retained USER PIN of length %lu for one context-specific retry", (unsigned long)pinLen);
}

CK_RV cmd_login_context_specific(CMD_CONTEXT_PTR pContext) {
  if (pContext == NULL || !pContext->userPinValid || pContext->userPinLen == 0 ||
      pContext->userPinLen > sizeof(pContext->userPin))
    return CKR_USER_NOT_LOGGED_IN;

  BYTE pin[CMD_MAX_USER_PIN_LEN] = {0};
  DWORD pinLen = pContext->userPinLen;
  memcpy(pin, pContext->userPin, pinLen);
  // This is a one-shot credential. Clear the context copy before the card call
  // returns, regardless of whether context-specific verification succeeds.
  cmd_clear_user_pin(pContext);
  CMD_DEBUG("Attempting context-specific USER authentication with PIN length %lu", (unsigned long)pinLen);
  CK_RV rv = C_CNK_Login(pContext->session, CKU_CONTEXT_SPECIFIC, pin, pinLen, NULL);
  SecureZeroMemory(pin, sizeof(pin));
  CMD_DEBUG("Context-specific USER authentication returned 0x%lx", rv);
  return rv;
}

static void try_login_pin_protected_management_key(CMD_CONTEXT_PTR pContext, PBYTE pin, CK_ULONG pinLen) {
  // USER authentication already supplied Windows with the retry count. This
  // best-effort extension keeps ADMIN DATA parsing and raw key bytes entirely
  // inside PKCS#11, and only elevates the minidriver role after verification.
  CK_RV rv = C_CNK_LoginPinManaged(pContext->session, pin, pinLen);

  if (rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN) {
    SET_PIN(pContext->authenticatedPins, ROLE_ADMIN);
    pContext->pinManagedAdmin = TRUE;
    CMD_DEBUG("PIN-protected PIV management key is available for this session");
  } else if (rv != CKR_DATA_INVALID && rv != CKR_OBJECT_HANDLE_INVALID) {
    CMD_WARN("PIN-protected PIV management key is unavailable: PKCS#11 error 0x%lx", rv);
  }
}

static DWORD map_pkcs11_pin_error(CK_RV rv) {
  switch (rv) {
  case CKR_OK:
    return SCARD_S_SUCCESS;
  case CKR_USER_NOT_LOGGED_IN:
    return SCARD_W_SECURITY_VIOLATION;
  case CKR_USER_PIN_NOT_INITIALIZED:
  case CKR_PIN_INCORRECT:
  case CKR_PIN_INVALID:
  case CKR_PIN_LEN_RANGE:
  case CKR_PIN_EXPIRED:
    return SCARD_W_WRONG_CHV;
  case CKR_PIN_LOCKED:
    return SCARD_W_CHV_BLOCKED;
  case CKR_ACTION_PROHIBITED:
    return SCARD_W_SECURITY_VIOLATION;
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

static void maybe_set_attempts_remaining(PDWORD pcAttemptsRemaining, BYTE pinTries) {
  if (pcAttemptsRemaining != NULL) {
    *pcAttemptsRemaining = pinTries;
  }
}

static void set_attempts_unknown(PDWORD pcAttemptsRemaining) {
  if (pcAttemptsRemaining != NULL) {
    *pcAttemptsRemaining = (DWORD)-1;
  }
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

static DWORD logout_after_pin_update(CMD_CONTEXT_PTR pContext) {
  CK_RV rv = C_Logout(pContext->session);
  cmd_clear_all_user_pins();
  pContext->authenticatedPins = PIN_SET_NONE;
  if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
    CMD_RETURN(map_pkcs11_pin_error(rv), "C_Logout after PIN update failed");
  }
  CMD_RET_OK;
}

static DWORD change_user_pin(CMD_CONTEXT_PTR pContext, PBYTE pbOldPin, DWORD cbOldPin, PBYTE pbNewPin, DWORD cbNewPin,
                             PDWORD pcAttemptsRemaining) {
  CMD_ENSURE_NONNULL(pbOldPin, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pbNewPin, SCARD_E_INVALID_PARAMETER);
  set_attempts_unknown(pcAttemptsRemaining);

  BYTE pinTries = 0;
  CK_RV rv = C_CNK_SetPIN(pContext->session, CNK_PIV_PIN_TYPE_PIN, pbOldPin, cbOldPin, pbNewPin, cbNewPin, &pinTries);
  maybe_set_attempts_remaining(pcAttemptsRemaining, pinTries);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_pin_error(rv), "C_CNK_SetPIN failed");
  }

  // The old PIN is no longer valid on the card. Clear every context copy
  // before re-authenticating, then retain the new PIN only after success.
  cmd_clear_all_user_pins();
  rv = login_with_role(pContext, CKU_USER, pbNewPin, cbNewPin, &pinTries);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_login_error(rv, pinTries), "C_CNK_Login after C_SetPIN failed");
  }
  maybe_set_attempts_remaining(pcAttemptsRemaining, pinTries);
  cmd_store_user_pin(pContext, pbNewPin, cbNewPin);
  SET_PIN(pContext->authenticatedPins, ROLE_USER);
  CMD_RET_OK;
}

static DWORD unblock_user_pin(CMD_CONTEXT_PTR pContext, PBYTE pbPuk, DWORD cbPuk, PBYTE pbNewPin, DWORD cbNewPin,
                              PDWORD pcAttemptsRemaining) {
  CMD_ENSURE_NONNULL(pbPuk, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pbNewPin, SCARD_E_INVALID_PARAMETER);

  BYTE pinTries = 0;
  CK_RV rv = C_CNK_UnblockPIN(pContext->session, pbPuk, cbPuk, pbNewPin, cbNewPin, &pinTries);
  maybe_set_attempts_remaining(pcAttemptsRemaining, pinTries);
  if (rv != CKR_OK) {
    CMD_RETURN(map_pkcs11_login_error(rv, pinTries), "C_CNK_UnblockPIN failed");
  }

  return logout_after_pin_update(pContext);
}

static DWORD decode_management_key(PBYTE pbPinData, DWORD cbPinData, BYTE managementKey[CMD_MANAGEMENT_KEY_LEN],
                                   CK_ULONG *pManagementKeyLen) {
  CMD_ENSURE_NONNULL(pbPinData, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(managementKey, SCARD_E_INVALID_PARAMETER);
  CMD_ENSURE_NONNULL(pManagementKeyLen, SCARD_E_INVALID_PARAMETER);

  if (cbPinData == CMD_MANAGEMENT_KEY_LEN) {
    // A 24-byte value is treated as raw key material; hexadecimal input must
    // contain 48 hex characters plus optional separators.
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
  // An already-logged-in result does not validate the supplied credential.
  // Log out and retry so callers cannot turn a stale role bit into successful
  // authentication with an arbitrary PIN or management key.
  if (rv != CKR_USER_ANOTHER_ALREADY_LOGGED_IN && rv != CKR_USER_ALREADY_LOGGED_IN) {
    return rv;
  }

  rv = C_Logout(pContext->session);
  if (rv != CKR_OK && rv != CKR_USER_NOT_LOGGED_IN) {
    return rv;
  }
  cmd_clear_all_user_pins();
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
  (void)ppbSessionPin;
  (void)pcbSessionPin;

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  // A fresh USER authentication attempt supersedes any cached credential,
  // including when Windows submits an incorrect PIN or revalidation fails.
  if (PinId == ROLE_USER)
    cmd_clear_user_pin(pContext);

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
  set_attempts_unknown(pcAttemptsRemaining);
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

  if (rv == CKR_USER_ALREADY_LOGGED_IN)
    CMD_RETURN(SCARD_W_SECURITY_VIOLATION, "Credential could not be revalidated");
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
    if (PinId == ROLE_USER) {
      SET_PIN(pContext->authenticatedPins, PinId);
      cmd_store_user_pin(pContext, pbPinData, cbPinData);
    } else {
      // SO authentication changes the token-wide login state and invalidates
      // any USER PIN retained by another CARD_DATA context.
      cmd_clear_all_user_pins();
      pContext->pinManagedAdmin = FALSE;
      SET_PIN(pContext->authenticatedPins, PinId);
    }
    if (PinId == ROLE_USER) {
      if (cmd_get_config()->protect_management) {
        try_login_pin_protected_management_key(pContext, pbPinData, cbPinData);
      } else {
        CMD_DEBUG("ProtectManagement is disabled; skipping management-key probe");
      }
    }
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

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  CMD_CHECK_DW_FLAGS;
  if (!IS_PIN_SET(PinId, ROLE_USER) && !IS_PIN_SET(PinId, ROLE_ADMIN)) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Invalid PinId");
  }
  // PKCS#11 logout is token-wide. Reject a subset request when another role
  // is also authenticated instead of claiming that only one role was cleared.
  if ((IS_PIN_SET(pContext->authenticatedPins, ROLE_USER) && !IS_PIN_SET(PinId, ROLE_USER)) ||
      (IS_PIN_SET(pContext->authenticatedPins, ROLE_ADMIN) && !pContext->pinManagedAdmin &&
       !IS_PIN_SET(PinId, ROLE_ADMIN))) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Token-wide logout cannot honor a role subset");
  }

  CK_RV rv = C_Logout(pContext->session);
  cmd_clear_all_user_pins();
  if (rv == CKR_USER_NOT_LOGGED_IN) {
    pContext->authenticatedPins = PIN_SET_NONE;
    pContext->pinManagedAdmin = FALSE;
    CMD_RET_OK;
  }
  if (rv != CKR_OK) {
    // If the card minidriver returns a nonzero value from this function,
    // the Base CSP/KSP resets the card
    CMD_RETURN(map_pkcs11_pin_error(rv), "C_Logout failed");
  } else {
    pContext->authenticatedPins = PIN_SET_NONE;
    pContext->pinManagedAdmin = FALSE;
    CMD_RET_OK;
  }
}

/*
 * Function: CardUnblockPin
 *
 * Purpose: Unblock or reset the user PIN using the PIV PUK.
 */
DWORD WINAPI CardUnblockPin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId,
                            __in_bcount(cbAuthenticationData) PBYTE pbAuthenticationData,
                            __in DWORD cbAuthenticationData, __in_bcount(cbNewPinData) PBYTE pbNewPinData,
                            __in DWORD cbNewPinData, __in DWORD cRetryCount, __in DWORD dwFlags) {
  CMD_LOG_FUNC("pCardData %p, pwszUserId %S, pbAuthenticationData %p, cbAuthenticationData %d, pbNewPinData %p, "
               "cbNewPinData %d, cRetryCount %d, dwFlags %x",
               pCardData, pwszUserId, pbAuthenticationData, cbAuthenticationData, pbNewPinData, cbNewPinData,
               cRetryCount, dwFlags);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pwszUserId);
  (void)cRetryCount;

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  if (dwFlags != CARD_AUTHENTICATE_PIN_PIN) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only PIN-based unblock is supported");
  }
  if (cRetryCount != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Changing retry count is not supported");
  }

  if (wcscmp(pwszUserId, wszCARD_USER_USER) != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only user PIN unblock is supported");
  }

  return unblock_user_pin(pContext, pbAuthenticationData, cbAuthenticationData, pbNewPinData, cbNewPinData, NULL);
}

/*
 * Function: CardChangeAuthenticator
 *
 * Purpose: Change the user PIN using the current user PIN.
 */
DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId,
                                     __in_bcount(cbCurrentAuthenticator) PBYTE pbCurrentAuthenticator,
                                     __in DWORD cbCurrentAuthenticator,
                                     __in_bcount(cbNewAuthenticator) PBYTE pbNewAuthenticator,
                                     __in DWORD cbNewAuthenticator, __in DWORD cRetryCount, __in DWORD dwFlags,
                                     __out_opt PDWORD pcAttemptsRemaining) {
  CMD_LOG_FUNC("pCardData %p, pwszUserId %S, pbCurrentAuthenticator %p, cbCurrentAuthenticator %d, "
               "pbNewAuthenticator %p, cbNewAuthenticator %d, cRetryCount %d, dwFlags %x, pcAttemptsRemaining %p",
               pCardData, pwszUserId, pbCurrentAuthenticator, cbCurrentAuthenticator, pbNewAuthenticator,
               cbNewAuthenticator, cRetryCount, dwFlags, pcAttemptsRemaining);

  CMD_NONNULL_PARAM(pCardData);
  CMD_NONNULL_PARAM(pwszUserId);
  (void)cRetryCount;

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  if (dwFlags != CARD_AUTHENTICATE_PIN_PIN) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only PIN-based change is supported");
  }
  if (cRetryCount != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Changing retry count is not supported");
  }

  if (wcscmp(pwszUserId, wszCARD_USER_USER) != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only user PIN change is supported");
  }

  return change_user_pin(pContext, pbCurrentAuthenticator, cbCurrentAuthenticator, pbNewAuthenticator,
                         cbNewAuthenticator, pcAttemptsRemaining);
}

/*
 * Function: CardChangeAuthenticatorEx
 *
 * Purpose: Change the user PIN or unblock it with the PIV PUK.
 */
DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData, __in DWORD dwFlags, __in PIN_ID dwAuthenticatingPinId,
                                       __in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
                                       __in DWORD cbAuthenticatingPinData, __in PIN_ID dwTargetPinId,
                                       __in_bcount(cbTargetData) PBYTE pbTargetData, __in DWORD cbTargetData,
                                       __in DWORD cRetryCount, __out_opt PDWORD pcAttemptsRemaining) {
  CMD_LOG_FUNC("pCardData %p, dwFlags %x, dwAuthenticatingPinId %d, pbAuthenticatingPinData %p, "
               "cbAuthenticatingPinData %d, dwTargetPinId %d, pbTargetData %p, cbTargetData %d, cRetryCount %d, "
               "pcAttemptsRemaining %p",
               pCardData, dwFlags, dwAuthenticatingPinId, pbAuthenticatingPinData, cbAuthenticatingPinData,
               dwTargetPinId, pbTargetData, cbTargetData, cRetryCount, pcAttemptsRemaining);

  CMD_NONNULL_PARAM(pCardData);
  (void)cRetryCount;

  INJECT_HANDLES();
  CMD_GET_CTX(pCardData, pContext);

  if (cRetryCount != 0) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Changing retry count is not supported");
  }

  if (dwTargetPinId != ROLE_USER) {
    CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Only user PIN target is supported");
  }

  if (dwFlags == PIN_CHANGE_FLAG_CHANGEPIN) {
    if (dwAuthenticatingPinId != ROLE_USER) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "User PIN change requires ROLE_USER authentication data");
    }
    return change_user_pin(pContext, pbAuthenticatingPinData, cbAuthenticatingPinData, pbTargetData, cbTargetData,
                           pcAttemptsRemaining);
  }

  if (dwFlags == PIN_CHANGE_FLAG_UNBLOCK) {
    if (dwAuthenticatingPinId != CMD_ROLE_PUK) {
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "User PIN unblock requires CMD_ROLE_PUK authentication data");
    }
    return unblock_user_pin(pContext, pbAuthenticatingPinData, cbAuthenticatingPinData, pbTargetData, cbTargetData,
                            pcAttemptsRemaining);
  }

  CMD_RETURN(SCARD_E_INVALID_PARAMETER, "Unsupported PIN change flags");
}
