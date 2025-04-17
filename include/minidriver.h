#ifndef MINIDRIVER_H
#define MINIDRIVER_H

#include <cardmod.h>

// Global function pointers for data caching mechanisms
extern PFN_CSP_CACHE_ADD_FILE g_pfnCspCacheAddFile;
extern PFN_CSP_CACHE_LOOKUP_FILE g_pfnCspCacheLookupFile;
extern PFN_CSP_CACHE_DELETE_FILE g_pfnCspCacheDeleteFile;

// Global function pointers for memory management
extern PFN_CSP_ALLOC g_pfnCspAlloc;
extern PFN_CSP_REALLOC g_pfnCspReAlloc;
extern PFN_CSP_FREE g_pfnCspFree;

// Global function pointer for padding removal
extern PFN_CSP_UNPAD_DATA g_pfnCspUnpadData;

#endif //MINIDRIVER_H
