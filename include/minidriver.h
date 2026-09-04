#ifndef MINIDRIVER_H
#define MINIDRIVER_H

#include "canokey.h"
#include "cardmod.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

#include <Windows.h>

#define CMD_ROLE_PUK 3

// Global function pointers for memory management
extern PFN_CSP_ALLOC g_pfnCspAlloc;
extern PFN_CSP_FREE g_pfnCspFree;

// Global function pointer for padding
extern PFN_CSP_PAD_DATA g_pfnCspPadData;
extern SRWLOCK g_cmd_context_lock;
extern volatile LONG g_cmd_metadata_generation;

typedef struct CMD_CONTEXT CMD_CONTEXT;
typedef CMD_CONTEXT *CMD_CONTEXT_PTR;

DWORD RefreshCardMetadata(CMD_CONTEXT_PTR pContext);

static __attribute__((unused)) void cmd_release_context_lock(PSRWLOCK *lock) {
  if (lock != NULL && *lock != NULL)
    ReleaseSRWLockExclusive(*lock);
}

#define CMD_CONTEXT_LOCK_GUARD __attribute__((cleanup(cmd_release_context_lock)))

static __attribute__((unused)) void cmd_release_context_state_lock(CMD_CONTEXT_PTR *context);

#define CMD_CONTEXT_STATE_GUARD __attribute__((cleanup(cmd_release_context_state_lock)))

#define INJECT_HANDLES()                                                                                               \
  AcquireSRWLockExclusive(&g_cmd_context_lock);                                                                        \
  PSRWLOCK _cmd_context_lock CMD_CONTEXT_LOCK_GUARD = &g_cmd_context_lock;                                             \
  CNK_MANAGED_MODE_INIT_ARGS _cmd_managed_args = {.malloc_func = (CNK_MALLOC_FUNC)g_pfnCspAlloc,                       \
                                                  .free_func = (CNK_FREE_FUNC)g_pfnCspFree,                            \
                                                  .hSCardCtx = pCardData->hSCardCtx,                                   \
                                                  .hScard = pCardData->hScard};                                        \
  CK_RV _cmd_managed_ret = C_CNK_EnableManagedMode(&_cmd_managed_args);                                                \
  if (_cmd_managed_ret != CKR_OK && _cmd_managed_ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)                              \
    CMD_RETURN(SCARD_F_INTERNAL_ERROR, "cannot enable managed mode");                                                  \
  /* Returned buffers use this CARD_DATA allocator; PKCS#11 core allocations stay on its process heap. */              \
  g_pfnCspAlloc = pCardData->pfnCspAlloc;                                                                              \
  g_pfnCspFree = pCardData->pfnCspFree;                                                                                \
  g_pfnCspPadData = pCardData->pfnCspPadData;                                                                          \
  CMD_CONTEXT_PTR _cmd_state_guard CMD_CONTEXT_STATE_GUARD = NULL;                                                     \
  /* Keep per-CARD_DATA role bits consistent with token-wide PKCS#11 logout. */                                        \
  if (pCardData->pvVendorSpecific != NULL) {                                                                           \
    CMD_CONTEXT_PTR _cmd_context = (CMD_CONTEXT_PTR)pCardData->pvVendorSpecific;                                       \
    AcquireSRWLockExclusive(&_cmd_context->state_lock);                                                                \
    _cmd_state_guard = _cmd_context;                                                                                   \
    if (_cmd_context->card_handle != pCardData->hScard) {                                                              \
      _cmd_context->card_handle = pCardData->hScard;                                                                   \
      cmd_clear_user_pin(_cmd_context);                                                                                \
    }                                                                                                                  \
    LONG _cmd_generation = InterlockedCompareExchange(&g_cmd_metadata_generation, 0, 0);                               \
    if (_cmd_context->metadataGeneration != _cmd_generation) {                                                         \
      DWORD _cmd_refresh_ret = RefreshCardMetadata(_cmd_context);                                                      \
      if (_cmd_refresh_ret != SCARD_S_SUCCESS)                                                                         \
        CMD_RETURN(_cmd_refresh_ret, "cannot refresh card metadata");                                                  \
    }                                                                                                                  \
    CK_SESSION_INFO _cmd_session_info;                                                                                 \
    /* Public sessions have no cached authentication in either access mode. */                                         \
    if (C_GetSessionInfo(_cmd_context->session, &_cmd_session_info) == CKR_OK &&                                       \
        (_cmd_session_info.state == CKS_RO_PUBLIC_SESSION || _cmd_session_info.state == CKS_RW_PUBLIC_SESSION)) {      \
      _cmd_context->authenticatedPins = PIN_SET_NONE;                                                                  \
      cmd_clear_user_pin(_cmd_context);                                                                                \
    }                                                                                                                  \
  }

#define CMD_MAX_DH_AGREEMENTS 8
#define CMD_MAX_DH_SECRET_LEN 66
#define CMD_MAX_USER_PIN_LEN 8
#define CMD_MAKE_OBJECT_HANDLE(SLOT_ID, OBJECT_CLASS, OBJECT_ID)                                                       \
  ((((CK_OBJECT_HANDLE)(SLOT_ID)) << 16) | (((CK_OBJECT_HANDLE)(OBJECT_CLASS)) << 8) | ((CK_OBJECT_HANDLE)(OBJECT_ID)))

typedef struct {
  BOOL active;
  BYTE secret[CMD_MAX_DH_SECRET_LEN];
  DWORD secretLen;
  BYTE containerIndex;
  DWORD keySpec;
} CMD_DH_AGREEMENT;

struct CMD_CONTEXT {
  CK_SESSION_HANDLE session;
  SRWLOCK state_lock;
  SCARDCONTEXT card_context;
  SCARDHANDLE card_handle;
  CMD_CONTEXT_PTR managed_next;
  LONG metadataGeneration;
  CANOKEY canokey;
  BYTE cardId[16];
  ULONGLONG last_metadata_refresh_ms;
  BOOL metadata_refresh_valid;
  PIN_SET authenticatedPins;
  BOOL pinManagedAdmin;
  // A USER PIN is retained only to satisfy one pending PIN-always operation
  // in this CARD_DATA context. It is never shared through the Windows
  // session-PIN mechanism and is cleared on operation/context teardown.
  BYTE userPin[CMD_MAX_USER_PIN_LEN];
  DWORD userPinLen;
  BOOL userPinValid;
  CMD_DH_AGREEMENT dhAgreements[CMD_MAX_DH_AGREEMENTS];
};

static __attribute__((unused)) void cmd_release_context_state_lock(CMD_CONTEXT_PTR *context) {
  if (context != NULL && *context != NULL)
    ReleaseSRWLockExclusive(&(*context)->state_lock);
}

DWORD FillCardKeySizes(DWORD dwKeySpec, PCARD_KEY_SIZES pKeySizes);
void FillCardFreeSpaceInfo(PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo);
DWORD GenerateCardIdentifier(CMD_CONTEXT_PTR pContext);
void cmd_clear_user_pin(CMD_CONTEXT_PTR pContext);
void cmd_clear_all_user_pins(void);
void cmd_store_user_pin(CMD_CONTEXT_PTR pContext, const BYTE *pin, DWORD pinLen);
CK_RV cmd_login_context_specific(CMD_CONTEXT_PTR pContext);

static __attribute__((unused)) void cmd_release_user_pin(CMD_CONTEXT_PTR *pContext) {
  if (pContext != NULL && *pContext != NULL)
    cmd_clear_user_pin(*pContext);
}

#define CMD_USER_PIN_GUARD __attribute__((cleanup(cmd_release_user_pin)))

#endif // MINIDRIVER_H
