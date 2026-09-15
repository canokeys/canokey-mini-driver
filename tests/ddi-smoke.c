// Real-card DDI regression for the documented development-card containers.
// No driver installation: load the chosen DLL directly and use a process-local
// registry fixture to verify both log modes without exposing credentials.
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#define WIN32_LEAN_AND_MEAN
#include "cardmod.h"
#include <bcrypt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <windows.h>
#include <winscard.h>

static LPVOID WINAPI allocate(SIZE_T n) { return malloc(n); }
static LPVOID WINAPI reallocate(LPVOID p, SIZE_T n) { return realloc(p, n); }
static void WINAPI release(LPVOID p) { free(p); }
static int result(DWORD status, const char *operation) {
  printf("%s: 0x%08lx\n", operation, status);
  fflush(stdout);
  return status == SCARD_S_SUCCESS;
}
static int rewrite_certificate(CARD_DATA *data, const char *fileName, const BYTE *certificate, DWORD certificateLen,
                               const wchar_t *directory) {
  wchar_t backup[MAX_PATH];
  swprintf_s(backup, MAX_PATH, L"%ls/backup-%hs.der", directory, fileName);
  FILE *stream = _wfopen(backup, L"wb");
  if (!stream)
    return 0;
  int saved = fwrite(certificate, 1, certificateLen, stream) == certificateLen;
  if (fclose(stream) != 0 || !saved)
    return 0;
  DWORD status = data->pfnCardWriteFile(data, "mscp", (LPSTR)fileName, 0, (PBYTE)certificate, certificateLen);
  PBYTE actual = NULL;
  DWORD actualLen = 0;
  if (status == SCARD_S_SUCCESS)
    status = data->pfnCardReadFile(data, "mscp", (LPSTR)fileName, 0, &actual, &actualLen);
  int equal =
      status == SCARD_S_SUCCESS && actualLen == certificateLen && memcmp(actual, certificate, certificateLen) == 0;
  release(actual);
  if (!equal) {
    // A failed write/readback can leave a partial certificate. The test retains
    // its original bytes and live ADMIN context through an explicit restoration.
    result(data->pfnCardWriteFile(data, "mscp", (LPSTR)fileName, 0, (PBYTE)certificate, certificateLen),
           "Restore original certificate (backup retained)");
    result(status, "Certificate write/readback");
    return 0;
  }
  printf("%s: ADMIN write/readback preserved the original DER bytes\n", fileName);
  return 1;
}

static int derive_secret(CARD_DATA *data, BYTE index, const char *pin) {
  CONTAINER_INFO info = {.dwVersion = CONTAINER_INFO_CURRENT_VERSION};
  BCRYPT_ALG_HANDLE algorithm = NULL;
  BCRYPT_KEY_HANDLE cardKey = NULL, peerKey = NULL;
  BCRYPT_SECRET_HANDLE softwareSecret = NULL;
  CARD_DH_AGREEMENT_INFO agreement = {.dwVersion = CARD_DH_AGREEMENT_INFO_VERSION, .bContainerIndex = index};
  BYTE cardBlob[sizeof(BCRYPT_ECCKEY_BLOB) + 132], peerBlob[sizeof(cardBlob)], expected[66] = {0};
  PBYTE actual = NULL;
  DWORD actualLength = 0;
  int passed = 0;
  if (!result(data->pfnCardGetContainerInfo(data, index, 0, &info), "ECDH CardGetContainerInfo"))
    goto cleanup;
  if (!info.pbSigPublicKey || info.cbSigPublicKey < sizeof(BCRYPT_ECCKEY_BLOB) ||
      info.cbSigPublicKey > sizeof(cardBlob) || info.pbKeyExPublicKey || info.cbKeyExPublicKey)
    goto cleanup;
  memcpy(cardBlob, info.pbSigPublicKey, info.cbSigPublicKey);
  BCRYPT_ECCKEY_BLOB header;
  memcpy(&header, cardBlob, sizeof(header));
  LPCWSTR name;
  ULONG bits;
  switch (header.dwMagic) {
  case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
    name = BCRYPT_ECDH_P256_ALGORITHM;
    bits = 256;
    header.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    break;
  case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
    name = BCRYPT_ECDH_P384_ALGORITHM;
    bits = 384;
    header.dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    break;
  case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
    name = BCRYPT_ECDH_P521_ALGORITHM;
    bits = 521;
    header.dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
    break;
  default:
    goto cleanup;
  }
  // Interpret the explicit Windows curve magic, not coordinate length alone.
  if (header.cbKey != (bits + 7) / 8 || info.cbSigPublicKey != sizeof(header) + 2 * header.cbKey)
    goto cleanup;
  memcpy(cardBlob, &header, sizeof(header));
  ULONG peerLength = 0, expectedLength = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, name, NULL, 0) < 0 ||
      BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &cardKey, cardBlob, info.cbSigPublicKey, 0) < 0 ||
      BCryptGenerateKeyPair(algorithm, &peerKey, bits, 0) < 0 || BCryptFinalizeKeyPair(peerKey, 0) < 0 ||
      BCryptExportKey(peerKey, NULL, BCRYPT_ECCPUBLIC_BLOB, peerBlob, sizeof(peerBlob), &peerLength, 0) < 0 ||
      BCryptSecretAgreement(peerKey, cardKey, &softwareSecret, 0) < 0 ||
      BCryptDeriveKey(softwareSecret, BCRYPT_KDF_RAW_SECRET, NULL, expected, sizeof(expected), &expectedLength, 0) < 0)
    goto cleanup;
  DWORD tries = 0;
  if (!result(data->pfnCardAuthenticateEx(data, ROLE_USER, 0, (PBYTE)pin, (DWORD)strlen(pin), NULL, NULL, &tries),
              "ECDH CardAuthenticateEx(USER)"))
    goto cleanup;
  agreement.pbPublicKey = peerBlob;
  agreement.dwPublicKey = peerLength;
  if (!result(data->pfnCardConstructDHAgreement(data, &agreement), "CardConstructDHAgreement"))
    goto cleanup;
  CARD_DERIVE_KEY derived = {.dwVersion = CARD_DERIVE_KEY_CURRENT_VERSION,
                             .dwFlags = CARD_BUFFER_SIZE_ONLY,
                             .pwszKDF = BCRYPT_KDF_RAW_SECRET,
                             .bSecretAgreementIndex = agreement.bSecretAgreementIndex};
  if (!result(data->pfnCardDeriveKey(data, &derived), "CardDeriveKey(size)") || derived.cbDerivedKey != expectedLength)
    goto cleanup;
  BYTE sentinel = 0xcc;
  derived.dwFlags = 0;
  derived.pbDerivedKey = &sentinel;
  derived.cbDerivedKey = 1;
  if (data->pfnCardDeriveKey(data, &derived) != ERROR_INSUFFICIENT_BUFFER || derived.cbDerivedKey != expectedLength ||
      sentinel != 0xcc)
    goto cleanup;
  derived.pbDerivedKey = NULL;
  derived.cbDerivedKey = 0;
  DWORD status = data->pfnCardDeriveKey(data, &derived);
  actual = derived.pbDerivedKey;
  actualLength = derived.cbDerivedKey;
  if (!result(status, "CardDeriveKey(raw)") || !actual || actualLength != expectedLength ||
      memcmp(actual, expected, expectedLength))
    goto cleanup;
  if (!result(data->pfnCardDestroyDHAgreement(data, agreement.bSecretAgreementIndex, 0), "CardDestroyDHAgreement"))
    goto cleanup;
  agreement.bSecretAgreementIndex = 0;
  derived.dwFlags = CARD_BUFFER_SIZE_ONLY;
  if (data->pfnCardDeriveKey(data, &derived) == SCARD_S_SUCCESS)
    goto cleanup;
  printf("Container %u ECDH raw secret matched Windows BCrypt; retries and destruction verified\n", index);
  passed = 1;
cleanup:
  if (agreement.bSecretAgreementIndex)
    if (!result(data->pfnCardDestroyDHAgreement(data, agreement.bSecretAgreementIndex, 0), "Cleanup DH agreement"))
      passed = 0;
  if (actual) {
    SecureZeroMemory(actual, actualLength);
    release(actual);
  }
  SecureZeroMemory(expected, sizeof(expected));
  if (softwareSecret)
    BCryptDestroySecret(softwareSecret);
  if (peerKey)
    BCryptDestroyKey(peerKey);
  if (cardKey)
    BCryptDestroyKey(cardKey);
  if (algorithm)
    BCryptCloseAlgorithmProvider(algorithm, 0);
  release(info.pbSigPublicKey);
  release(info.pbKeyExPublicKey);
  return passed;
}

static int pin_contract(CARD_DATA *data, const char *pin, BOOL skipPuk) {
  const char *temporary = getenv("CNK_PIV_TEST_PIN"), *puk = getenv("CNK_PIV_PUK");
  if (!pin || !temporary || !strcmp(pin, temporary) || (!skipPuk && !puk))
    return 0;
  DWORD length = 0, attempts = 0;
  PIN_SET pins = 0;
  if (!result(data->pfnCardGetProperty(data, CP_CARD_LIST_PINS, (PBYTE)&pins, sizeof(pins), &length, 0), "PIN list") ||
      length != sizeof(pins))
    return 0;
  for (PIN_ID role = ROLE_USER; role <= 3; role++) {
    PIN_INFO info = {.dwVersion = PIN_INFO_CURRENT_VERSION};
    DWORD strength = 0;
    if (!result(data->pfnCardGetProperty(data, CP_CARD_PIN_INFO, (PBYTE)&info, sizeof(info), &length, role),
                "PIN info") ||
        length != sizeof(info) ||
        !result(data->pfnCardGetProperty(data, CP_CARD_PIN_STRENGTH_VERIFY, (PBYTE)&strength, sizeof(strength), &length,
                                         role),
                "PIN strength"))
      return 0;
  }
  if (!result(data->pfnCardAuthenticateEx(data, ROLE_USER, 0, (PBYTE)pin, (DWORD)strlen(pin), NULL, NULL, &attempts),
              "USER login"))
    return 0;
  BOOL policyBlocked = FALSE;
  for (unsigned round = 0; round < (skipPuk ? 1u : 2u); round++) {
    DWORD status =
        round == 0
            ? data->pfnCardChangeAuthenticator(data, L"user", (PBYTE)pin, (DWORD)strlen(pin), (PBYTE)temporary,
                                               (DWORD)strlen(temporary), 0, CARD_AUTHENTICATE_PIN_PIN, &attempts)
            : data->pfnCardChangeAuthenticatorEx(data, PIN_CHANGE_FLAG_UNBLOCK, 3, (PBYTE)puk, (DWORD)strlen(puk),
                                                 ROLE_USER, (PBYTE)temporary, (DWORD)strlen(temporary), 0, &attempts);
    if (round && status == SCARD_W_SECURITY_VIOLATION) {
      policyBlocked = TRUE;
      continue;
    }
    // Do not guess credentials after a transport failure with ambiguous mutation.
    if (!result(status, "Set temporary PIN")) {
      fputs("PIN mutation outcome is uncertain; inspect card state before retrying.\n", stderr);
      return 0;
    }
    if (!result(data->pfnCardChangeAuthenticator(data, L"user", (PBYTE)temporary, (DWORD)strlen(temporary), (PBYTE)pin,
                                                 (DWORD)strlen(pin), 0, CARD_AUTHENTICATE_PIN_PIN, &attempts),
                "Restore PIN")) {
      fputs("PIN restoration failed; do not assume the original PIN.\n", stderr);
      return 0;
    }
  }
  if (!result(data->pfnCardAuthenticateEx(data, ROLE_USER, 0, (PBYTE)pin, (DWORD)strlen(pin), NULL, NULL, &attempts),
              "Verify restored PIN"))
    return 0;
  printf("{\"PinSet\":%lu,\"PukResetTested\":%s,\"PukResetBlockedByPolicy\":%s}\n", pins,
         !skipPuk && !policyBlocked ? "true" : "false", policyBlocked ? "true" : "false");
  return 1;
}

static int provision_contract(CARD_DATA *data, PFN_CARD_ACQUIRE_CONTEXT acquire, const char *pin, DWORD index,
                              DWORD spec, DWORD bits, BOOL import) {
  HCRYPTPROV provider = 0;
  HCRYPTKEY rsa = 0;
  BCRYPT_ALG_HANDLE algorithm = NULL;
  BCRYPT_KEY_HANDLE ec = NULL;
  BYTE privateBlob[4096] = {0}, publicBlob[1024], before[16], after[16];
  DWORD privateLength = sizeof(privateBlob), publicLength = sizeof(publicBlob), length = 0, roles = 0, attempts = 0;
  CONTAINER_INFO info = {.dwVersion = CONTAINER_INFO_CURRENT_VERSION};
  int passed = 0;
  if (!pin || index > 5 || spec < AT_KEYEXCHANGE || spec > AT_ECDSA_P521 ||
      (spec <= AT_SIGNATURE ? (bits != 2048 && bits != 3072 && bits != 4096)
                            : bits != (spec == AT_ECDSA_P256   ? 256u
                                       : spec == AT_ECDSA_P384 ? 384u
                                                               : 521u)))
    goto cleanup;
  if (import) {
    if (spec <= AT_SIGNATURE) {
      if (!CryptAcquireContextW(&provider, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
          !CryptGenKey(provider, spec == AT_SIGNATURE ? CALG_RSA_SIGN : CALG_RSA_KEYX, (bits << 16) | CRYPT_EXPORTABLE,
                       &rsa) ||
          !CryptExportKey(rsa, 0, PRIVATEKEYBLOB, 0, privateBlob, &privateLength) ||
          !CryptExportKey(rsa, 0, PUBLICKEYBLOB, 0, publicBlob, &publicLength))
        goto cleanup;
    } else {
      LPCWSTR name = bits == 256   ? BCRYPT_ECDSA_P256_ALGORITHM
                     : bits == 384 ? BCRYPT_ECDSA_P384_ALGORITHM
                                   : BCRYPT_ECDSA_P521_ALGORITHM;
      if (BCryptOpenAlgorithmProvider(&algorithm, name, NULL, 0) < 0 ||
          BCryptGenerateKeyPair(algorithm, &ec, bits, 0) < 0 || BCryptFinalizeKeyPair(ec, 0) < 0 ||
          BCryptExportKey(ec, NULL, BCRYPT_ECCPRIVATE_BLOB, privateBlob, sizeof(privateBlob), &privateLength, 0) < 0 ||
          BCryptExportKey(ec, NULL, BCRYPT_ECCPUBLIC_BLOB, publicBlob, sizeof(publicBlob), &publicLength, 0) < 0)
        goto cleanup;
    }
  }
  if (!result(data->pfnCardGetProperty(data, CP_CARD_GUID, before, sizeof(before), &length, 0), "Card GUID before") ||
      length != sizeof(before) ||
      !result(data->pfnCardAuthenticateEx(data, ROLE_USER, 0, (PBYTE)pin, (DWORD)strlen(pin), NULL, NULL, &attempts),
              "USER protected-management login") ||
      !result(data->pfnCardGetProperty(data, CP_CARD_AUTHENTICATED_STATE, (PBYTE)&roles, sizeof(roles), &length, 0),
              "Authenticated roles") ||
      (roles & ((1u << ROLE_USER) | (1u << ROLE_ADMIN))) != ((1u << ROLE_USER) | (1u << ROLE_ADMIN)))
    goto cleanup;
  DWORD flags = import ? CARD_CREATE_CONTAINER_KEY_IMPORT : CARD_CREATE_CONTAINER_KEY_GEN;
  DWORD requestBits = !import && spec >= AT_ECDSA_P256 ? 0 : bits;
  if (data->pfnCardCreateContainerEx(data, index, flags, spec, requestBits, import ? privateBlob : NULL, ROLE_ADMIN) !=
      SCARD_W_SECURITY_VIOLATION)
    goto cleanup;
  if (!result(
          data->pfnCardCreateContainerEx(data, index, flags, spec, requestBits, import ? privateBlob : NULL, ROLE_USER),
          "CardCreateContainerEx") ||
      !result(data->pfnCardGetProperty(data, CP_CARD_GUID, after, sizeof(after), &length, 0), "Card GUID after") ||
      length != sizeof(after) || memcmp(before, after, sizeof(before)) ||
      !result(data->pfnCardGetContainerInfo(data, index, 0, &info), "Created public key"))
    goto cleanup;
  PBYTE actual = spec == AT_KEYEXCHANGE ? info.pbKeyExPublicKey : info.pbSigPublicKey;
  DWORD actualLength = spec == AT_KEYEXCHANGE ? info.cbKeyExPublicKey : info.cbSigPublicKey;
  if (!actual || !actualLength ||
      (import && (actualLength != publicLength || memcmp(actual, publicBlob, publicLength))))
    goto cleanup;
  if (!result(data->pfnCardDeleteContext(data), "Delete before reacquire") || !result(acquire(data, 0), "Reacquire") ||
      !result(data->pfnCardGetProperty(data, CP_CARD_GUID, after, sizeof(after), &length, 0), "Card GUID reacquired") ||
      length != sizeof(after) || memcmp(before, after, sizeof(before)))
    goto cleanup;
  printf("{\"Operation\":\"%s\",\"ContainerIndex\":%lu,\"KeySpec\":%lu,\"KeySize\":%lu,\"PublicKeyMatches\":true}\n",
         import ? "Import" : "Generate", index, spec, bits);
  passed = 1;
cleanup:
  SecureZeroMemory(privateBlob, sizeof(privateBlob));
  release(info.pbSigPublicKey);
  release(info.pbKeyExPublicKey);
  if (rsa)
    CryptDestroyKey(rsa);
  if (provider)
    CryptReleaseContext(provider, 0);
  if (ec)
    BCryptDestroyKey(ec);
  if (algorithm)
    BCryptCloseAlgorithmProvider(algorithm, 0);
  return passed;
}

static int check_logs(const wchar_t *directory, BOOL raw, unsigned expectedCycles) {
  wchar_t pattern[MAX_PATH], path[MAX_PATH];
  swprintf_s(pattern, MAX_PATH, L"%ls/*_%lu_*.log", directory, GetCurrentProcessId());
  WIN32_FIND_DATAW found;
  HANDLE search = FindFirstFileW(pattern, &found);
  if (search == INVALID_HANDLE_VALUE)
    return 0;
  unsigned cycles = 0, starts = 0, commands = 0, responses = 0;
  BOOL valid = TRUE, active = FALSE;
  do {
    swprintf_s(path, MAX_PATH, L"%ls/%ls", directory, found.cFileName);
    FILE *file = _wfopen(path, L"r");
    if (!file) {
      valid = FALSE;
      break;
    }
    char line[8192];
    while (fgets(line, sizeof(line), file)) {
      if (strstr(line, "C_Initialize completed: CK_RV=0x0")) {
        if (active)
          valid = FALSE;
        active = TRUE;
        starts = 0;
      }
      if (active && strstr(line, "cnk_operation_start completed: status=0x0"))
        starts++;
      if (strstr(line, "C_Finalize completed: CK_RV=0x0")) {
        if (!active || !starts)
          valid = FALSE;
        active = FALSE;
        cycles++;
      }
      commands += strstr(line, "APDU Command:") != NULL;
      responses += strstr(line, "APDU Response:") != NULL;
      // cmd_print_hex emits unprefixed pairs; ordinary timestamped lines have a colon.
      if (!raw && isxdigit((unsigned char)line[0]) && isxdigit((unsigned char)line[1]) && line[2] == ' ')
        valid = FALSE;
    }
    if (ferror(file))
      valid = FALSE;
    fclose(file);
  } while (FindNextFileW(search, &found));
  FindClose(search);
  valid = valid && !active && cycles == expectedCycles && (raw ? commands && responses : !commands && !responses);
  printf("Log assertions: %u complete contexts, %u commands, %u responses: %s\n", cycles, commands, responses,
         valid ? "PASS" : "FAIL");
  return valid;
}

int wmain(int argc, wchar_t **argv) {
  BOOL provision = argc == 7 && (!wcscmp(argv[3], L"generate") || !wcscmp(argv[3], L"import"));
  BOOL pinMode = argc == 4 && (!wcscmp(argv[3], L"pin") || !wcscmp(argv[3], L"pin-only"));
  BOOL raw = argc == 4 && !wcscmp(argv[3], L"raw");
  BOOL write = argc == 4 && !wcscmp(argv[3], L"write");
  if (argc != 3 && !provision && !pinMode && !raw && !write) {
    fputs("Usage: ddi-smoke <dll> <log-dir> [raw|write|pin|pin-only|generate|import [index spec bits]]\n", stderr);
    return 2;
  }
  if (provision) {
    for (unsigned i = 4; i < 7; i++)
      if (!argv[i][0] || wcsspn(argv[i], L"0123456789") != wcslen(argv[i]) || wcslen(argv[i]) > 4)
        return 2;
  }
  const char *managementKey = write ? getenv("CNK_PIV_MANAGEMENT_KEY") : NULL;
  if (write && !managementKey) {
    puts("CNK_PIV_MANAGEMENT_KEY is required for certificate writes");
    return 2;
  }
  SCARDCONTEXT context = 0;
  SCARDHANDLE card = 0;
  DWORD protocol = 0;
  HMODULE module = NULL;
  CARD_DATA data = {0};
  int passed = 0;
  HKEY testRoot = NULL, testConfig = NULL;
  wchar_t testKey[160];
  swprintf_s(testKey, 160, L"Software\\Canokeys\\CodexValidation\\%lu-%llu", GetCurrentProcessId(), GetTickCount64());
  wchar_t logPath[MAX_PATH];
  DWORD pathLength = GetFullPathNameW(argv[2], MAX_PATH, logPath, NULL);
  if (pathLength == 0 || pathLength >= MAX_PATH)
    goto cleanup;
  if (!CreateDirectoryW(logPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    goto cleanup;
  // A private HKCU fixture redirects only this process's DLL-load configuration.
  // The machine's Calais mapping and minidriver settings are never changed.
  if (RegCreateKeyExW(HKEY_CURRENT_USER, testKey, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &testRoot, NULL))
    goto cleanup;
  if (RegCreateKeyExW(testRoot, L"SOFTWARE\\Canokeys\\ckmd", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL,
                      &testConfig, NULL))
    goto cleanup;
  DWORD sensitive = raw ? 1 : 0;
  if (RegSetValueExW(testConfig, L"LogPath", 0, REG_SZ, (BYTE *)logPath,
                     (DWORD)((wcslen(logPath) + 1) * sizeof(wchar_t))) ||
      RegSetValueExW(testConfig, L"LogLevel", 0, REG_SZ, (BYTE *)L"DEBUG", sizeof(L"DEBUG")) ||
      RegSetValueExW(testConfig, L"LogSensitiveData", 0, REG_DWORD, (BYTE *)&sensitive, sizeof(sensitive)))
    goto cleanup;
  BYTE atr[64];
  DWORD atrLen = sizeof(atr), state = 0, readerLen = 512;
  wchar_t reader[512];
  if (!result(SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context), "SCardEstablishContext"))
    goto cleanup;
  wchar_t selectedReader[512] = L"canokeys.org OpenPGP PIV OATH 0";
  GetEnvironmentVariableW(L"CNK_PIV_READER", selectedReader, 512);
  if (!result(SCardConnectW(context, selectedReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
                            &protocol),
              "SCardConnect"))
    goto cleanup;
  if (!result(SCardStatusW(card, reader, &readerLen, &state, &protocol, atr, &atrLen), "SCardStatus"))
    goto cleanup;
  if (RegOverridePredefKey(HKEY_LOCAL_MACHINE, testRoot))
    goto cleanup;
  module = LoadLibraryW(argv[1]);
  RegOverridePredefKey(HKEY_LOCAL_MACHINE, NULL);
  if (!module) {
    printf("LoadLibrary: %lu\n", GetLastError());
    goto cleanup;
  }
  PFN_CARD_ACQUIRE_CONTEXT acquire = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(module, "CardAcquireContext");
  if (!acquire)
    goto cleanup;
  data.dwVersion = CARD_DATA_CURRENT_VERSION;
  data.pbAtr = atr;
  data.cbAtr = atrLen;
  data.pwszCardName = L"CanoKey";
  data.pfnCspAlloc = allocate;
  data.pfnCspReAlloc = reallocate;
  data.pfnCspFree = release;
  data.hSCardCtx = context;
  data.hScard = card;
  if (pinMode || provision) {
    if (!result(acquire(&data, 0), "CardAcquireContext"))
      goto cleanup;
    passed = pinMode ? pin_contract(&data, getenv("CNK_PIV_PIN"), !wcscmp(argv[3], L"pin-only"))
                     : provision_contract(&data, acquire, getenv("CNK_PIV_PIN"), (DWORD)_wtoi(argv[4]),
                                          (DWORD)_wtoi(argv[5]), (DWORD)_wtoi(argv[6]), !wcscmp(argv[3], L"import"));
    goto cleanup;
  }
  for (unsigned cycle = 0; cycle < 2; cycle++) {
    printf("Context cycle %u\n", cycle + 1);
    if (!result(acquire(&data, 0), "CardAcquireContext"))
      goto cleanup;
    PBYTE file = NULL;
    DWORD len = 0;
    if (!result(data.pfnCardReadFile(&data, "mscp", "cmapfile", 0, &file, &len), "CardReadFile(cmapfile)"))
      goto cleanup;
    printf("cmapfile bytes: %lu\n", len);
    release(file);
    if (!raw) {
      const char *certFiles[] = {"ksc00", "ksc01", "kxc02", "ksc03", "ksc04", "ksc05"};
      for (unsigned i = 0; i < sizeof(certFiles) / sizeof(certFiles[0]); i++) {
        PBYTE certificate = NULL;
        DWORD certificateLen = 0;
        if (!result(data.pfnCardReadFile(&data, "mscp", (LPSTR)certFiles[i], 0, &certificate, &certificateLen),
                    "CardReadFile(certificate)"))
          goto cleanup;
        PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, certificate, certificateLen);
        if (!cert) {
          release(certificate);
          printf("Certificate DER parsing failed: %lu\n", GetLastError());
          goto cleanup;
        }
        CertFreeCertificateContext(cert);
        int writePassed = 1;
        if (write) {
          if (i == 0) {
            DWORD denied = data.pfnCardWriteFile(&data, "mscp", (LPSTR)certFiles[i], 0, certificate, certificateLen);
            if (denied != SCARD_W_SECURITY_VIOLATION) {
              release(certificate);
              puts("Public certificate write did not require ADMIN");
              goto cleanup;
            }
            DWORD tries = 0;
            DWORD auth = data.pfnCardAuthenticateEx(&data, ROLE_ADMIN, 0, (PBYTE)managementKey,
                                                    (DWORD)strlen(managementKey), NULL, NULL, &tries);
            if (!result(auth, "CardAuthenticateEx(ADMIN)")) {
              release(certificate);
              goto cleanup;
            }
          }
          writePassed = rewrite_certificate(&data, certFiles[i], certificate, certificateLen, logPath);
        }
        release(certificate);
        if (!writePassed)
          goto cleanup;
      }
      if (write &&
          !result(data.pfnCardDeauthenticateEx(&data, CREATE_PIN_SET(ROLE_ADMIN), 0), "CardDeauthenticateEx(ADMIN)"))
        goto cleanup;
      const BYTE indexes[] = {0, 1, 4, 5};
      const DWORD specs[] = {AT_ECDSA_P256, AT_ECDSA_P256, AT_ECDSA_P384, AT_ECDSA_P521};
      const LPCWSTR algorithms[] = {BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_P256_ALGORITHM,
                                    BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM};
      const char *pin = getenv("CNK_PIV_PIN");
      if (!pin) {
        puts("CNK_PIV_PIN is required");
        goto cleanup;
      }
      for (unsigned i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
        CONTAINER_INFO info = {0};
        info.dwVersion = CONTAINER_INFO_CURRENT_VERSION;
        if (!result(data.pfnCardGetContainerInfo(&data, indexes[i], 0, &info), "CardGetContainerInfo"))
          goto cleanup;
        BCRYPT_ALG_HANDLE algorithm = NULL;
        BCRYPT_KEY_HANDLE key = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, algorithms[i], NULL, 0);
        if (status >= 0)
          status = BCryptImportKeyPair(algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB, &key, info.pbSigPublicKey,
                                       info.cbSigPublicKey, 0);
        release(info.pbSigPublicKey);
        release(info.pbKeyExPublicKey);
        if (status < 0) {
          printf("BCryptImportKeyPair: 0x%08lx\n", status);
          if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
          goto cleanup;
        }
        DWORD tries = 0;
        DWORD authStatus =
            data.pfnCardAuthenticateEx(&data, ROLE_USER, 0, (PBYTE)pin, (DWORD)strlen(pin), NULL, NULL, &tries);
        if (!result(authStatus, "CardAuthenticateEx(USER)")) {
          BCryptDestroyKey(key);
          BCryptCloseAlgorithmProvider(algorithm, 0);
          goto cleanup;
        }
        BYTE digest[32] = {0x42, 0x19, 0x83};
        CARD_SIGNING_INFO signing = {0};
        signing.dwVersion = CARD_SIGNING_INFO_CURRENT_VERSION;
        signing.bContainerIndex = indexes[i];
        signing.dwKeySpec = specs[i];
        signing.aiHashAlg = CALG_SHA_256;
        signing.pbData = digest;
        signing.cbData = sizeof(digest);
        signing.dwSigningFlags = CARD_BUFFER_SIZE_ONLY;
        DWORD signStatus = data.pfnCardSignData(&data, &signing);
        if (signStatus == SCARD_S_SUCCESS) {
          signing.dwSigningFlags = 0;
          signStatus = data.pfnCardSignData(&data, &signing);
        }
        if (signStatus == SCARD_S_SUCCESS)
          status =
              BCryptVerifySignature(key, NULL, digest, sizeof(digest), signing.pbSignedData, signing.cbSignedData, 0);
        release(signing.pbSignedData);
        BCryptDestroyKey(key);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (!result(signStatus, "CardSignData") || status < 0) {
          printf("BCryptVerifySignature: 0x%08lx\n", status);
          goto cleanup;
        }
        printf("Container %u signature verified with Windows BCrypt\n", indexes[i]);
        if (!derive_secret(&data, indexes[i], pin))
          goto cleanup;
      }
    }
    if (!result(data.pfnCardDeleteContext(&data), "CardDeleteContext(cycle)"))
      goto cleanup;
  }
  passed = 1;
cleanup:
  if (data.pvVendorSpecific && data.pfnCardDeleteContext)
    if (!result(data.pfnCardDeleteContext(&data), "CardDeleteContext"))
      passed = 0;
  if (module && !data.pvVendorSpecific) {
    if (!FreeLibrary(module))
      passed = 0;
    if (passed && !check_logs(logPath, raw, pinMode ? 1 : 2))
      passed = 0;
  }
  if (card)
    SCardDisconnect(card, SCARD_LEAVE_CARD);
  if (context)
    SCardReleaseContext(context);
  if (testConfig)
    RegCloseKey(testConfig);
  if (testRoot) {
    RegCloseKey(testRoot);
    RegDeleteTreeW(HKEY_CURRENT_USER, testKey);
  }
  return passed ? 0 : 1;
}
