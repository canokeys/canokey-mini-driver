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

static __attribute__((unused)) void cmd_release_shared_context_lock(PSRWLOCK *lock) {
  if (lock != NULL && *lock != NULL)
    ReleaseSRWLockShared(*lock);
}

#define CMD_CONTEXT_SHARED_GUARD __attribute__((cleanup(cmd_release_shared_context_lock)))

#define INJECT_HANDLES()                                                                                               \
  AcquireSRWLockShared(&g_cmd_context_lock);                                                                           \
  PSRWLOCK _cmd_context_lock CMD_CONTEXT_SHARED_GUARD = &g_cmd_context_lock;                                           \
  CNK_MANAGED_MODE_INIT_ARGS _cmd_managed_args = {.malloc_func = (CNK_MALLOC_FUNC)g_pfnCspAlloc,                       \
                                                  .free_func = g_pfnCspFree,                                           \
                                                  .hSCardCtx = pCardData->hSCardCtx,                                   \
                                                  .hScard = pCardData->hScard};                                        \
  CK_RV _cmd_managed_ret = C_CNK_EnableManagedMode(&_cmd_managed_args);                                                \
  if (_cmd_managed_ret != CKR_OK && _cmd_managed_ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)                              \
    CMD_RETURN(SCARD_F_INTERNAL_ERROR, "cannot enable managed mode");                                                  \
  /* Keep per-CARD_DATA role bits consistent with token-wide PKCS#11 logout. */                                        \
  if (pCardData->pvVendorSpecific != NULL) {                                                                           \
    CMD_CONTEXT_PTR _cmd_context = (CMD_CONTEXT_PTR)pCardData->pvVendorSpecific;                                       \
    CK_SESSION_INFO _cmd_session_info;                                                                                 \
    /* The private PKCS#11 SessionState enum assigns 0 and 2 to public states. */                                      \
    if (C_GetSessionInfo(_cmd_context->session, &_cmd_session_info) == CKR_OK &&                                       \
        (_cmd_session_info.state == 0 || _cmd_session_info.state == 2))                                                \
      _cmd_context->authenticatedPins = PIN_SET_NONE;                                                                  \
  }

#define CMD_MAX_DH_AGREEMENTS 8
#define CMD_MAX_DH_SECRET_LEN 66
#define CMD_MAKE_OBJECT_HANDLE(SLOT_ID, OBJECT_CLASS, OBJECT_ID)                                                       \
  ((((CK_OBJECT_HANDLE)(SLOT_ID)) << 16) | (((CK_OBJECT_HANDLE)(OBJECT_CLASS)) << 8) | ((CK_OBJECT_HANDLE)(OBJECT_ID)))

typedef struct {
  BOOL active;
  BYTE secret[CMD_MAX_DH_SECRET_LEN];
  DWORD secretLen;
  BYTE containerIndex;
  DWORD keySpec;
} CMD_DH_AGREEMENT;

typedef struct {
  CK_SESSION_HANDLE session;
  CANOKEY canokey;
  BYTE cardId[16];
  PIN_SET authenticatedPins;
  CMD_DH_AGREEMENT dhAgreements[CMD_MAX_DH_AGREEMENTS];
} CMD_CONTEXT;

typedef CMD_CONTEXT *CMD_CONTEXT_PTR;

DWORD FillCardKeySizes(DWORD dwKeySpec, PCARD_KEY_SIZES pKeySizes);
void FillCardFreeSpaceInfo(PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo);
DWORD GenerateCardIdentifier(CMD_CONTEXT_PTR pContext);
DWORD RefreshCardMetadata(CMD_CONTEXT_PTR pContext);

#endif // MINIDRIVER_H
