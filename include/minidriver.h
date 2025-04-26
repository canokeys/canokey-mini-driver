#ifndef MINIDRIVER_H
#define MINIDRIVER_H

#include "canokey.h"
#include "cardmod.h"
#include "pkcs11.h"
#include "pkcs11_canokey.h"

// Global function pointers for data caching mechanisms
extern PFN_CSP_CACHE_ADD_FILE g_pfnCspCacheAddFile;
extern PFN_CSP_CACHE_LOOKUP_FILE g_pfnCspCacheLookupFile;
extern PFN_CSP_CACHE_DELETE_FILE g_pfnCspCacheDeleteFile;

// Global function pointers for memory management
extern PFN_CSP_ALLOC g_pfnCspAlloc;
extern PFN_CSP_REALLOC g_pfnCspReAlloc;
extern PFN_CSP_FREE g_pfnCspFree;

// Global function pointer for padding
extern PFN_CSP_PAD_DATA g_pfnCspPadData;

// Global function pointer for padding removal
extern PFN_CSP_UNPAD_DATA g_pfnCspUnpadData;

#define INJECT_HANDLES()                                                                                               \
  do {                                                                                                                 \
    CNK_MANAGED_MODE_INIT_ARGS args = {.malloc_func = (CNK_MALLOC_FUNC)g_pfnCspAlloc,                                  \
                                       .free_func = g_pfnCspFree,                                                      \
                                       .hSCardCtx = pCardData->hSCardCtx,                                              \
                                       .hScard = pCardData->hScard};                                                   \
    CK_RV ret = C_CNK_EnableManagedMode(&args);                                                                        \
    if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {                                                    \
      CMD_RETURN(SCARD_F_INTERNAL_ERROR, "cannot enable managed mode");                                                \
    }                                                                                                                  \
  } while (0);

typedef struct {
  CK_SESSION_HANDLE session;
  CANOKEY canokey;
} CMD_CONTEXT;

typedef CMD_CONTEXT *CMD_CONTEXT_PTR;

#endif // MINIDRIVER_H
