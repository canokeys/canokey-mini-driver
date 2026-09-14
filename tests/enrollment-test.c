#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "minidriver.h"

#define CHECK(expr)                                                                                                    \
  do {                                                                                                                 \
    if (!(expr)) {                                                                                                     \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr);                                                       \
      exit(1);                                                                                                         \
    }                                                                                                                  \
  } while (0)

// Deterministic backend: no session, PIN, key or certificate reaches a card.
PFN_CSP_ALLOC g_pfnCspAlloc;
PFN_CSP_FREE g_pfnCspFree;
PFN_CSP_PAD_DATA g_pfnCspPadData;
SRWLOCK g_cmd_context_lock = SRWLOCK_INIT;
volatile LONG g_cmd_metadata_generation = 1;
static DWORD identityResult;
static BOOL differentCard;
static unsigned identityCalls, callbackCalls;
static CK_RV nameReadResult, nameWriteResult;
static unsigned nameReads, nameWrites;
static WCHAR cardName[40];
CK_RV C_CNK_GetContainerName(CK_SESSION_HANDLE session, CK_BYTE slot, CK_BYTE_PTR name, CK_ULONG_PTR len) {
  (void)session;
  CHECK(slot == 0x9D);
  nameReads++;
  if (nameReadResult != CKR_OK)
    return nameReadResult;
  *len = (CK_ULONG)(wcslen(cardName) * 2);
  memcpy(name, cardName, *len);
  return CKR_OK;
}
CK_RV C_CNK_SetContainerName(CK_SESSION_HANDLE session, CK_BYTE slot, CK_BYTE_PTR name, CK_ULONG len) {
  (void)session;
  CHECK(slot == 0x9D);
  nameWrites++;
  if (nameWriteResult == CKR_OK) {
    memset(cardName, 0, sizeof(cardName));
    memcpy(cardName, name, len);
  }
  return nameWriteResult;
}

bool cmd_should_log(const int level) {
  (void)level;
  return false;
}
void cmd_printlogf(const int level, const char *function, const char *file, const int line, const char *format, ...) {
  (void)level;
  (void)function;
  (void)file;
  (void)line;
  (void)format;
}
void cmd_print_stack(void) {}
CK_BBOOL canokey_slot_has_key(const SLOT *slot) { return slot != NULL && slot->present; }
CK_BBOOL canokey_slot_can_sign(const SLOT *slot) {
  return canokey_slot_has_key(slot) && (slot->capabilities & CANOKEY_SLOT_CAP_SIGN);
}
CK_BBOOL canokey_slot_can_decrypt(const SLOT *slot) {
  return canokey_slot_has_key(slot) && (slot->capabilities & CANOKEY_SLOT_CAP_DECRYPT);
}
CK_BYTE canokey_container_object_id(CK_BYTE index) { return index + 1; }
CK_RV C_CNK_ObjIdToPivTag(CK_BYTE id, CK_BYTE *tag) {
  static const CK_BYTE tags[] = {0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x83};
  if (id == 0 || id > sizeof(tags))
    return CKR_OBJECT_HANDLE_INVALID;
  *tag = tags[id - 1];
  return CKR_OK;
}
DWORD GenerateCardIdentifier(CMD_CONTEXT_PTR context) {
  identityCalls++;
  if (differentCard)
    context->cardId[0] ^= 1;
  return identityResult;
}
CK_RV C_CNK_EnableManagedMode(CNK_MANAGED_MODE_INIT_ARGS_PTR args) {
  (void)args;
  return CKR_OK;
}
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info) {
  (void)session;
  memset(info, 0, sizeof(*info));
  return CKR_OK;
}
void cmd_clear_user_pin(CMD_CONTEXT_PTR context) { (void)context; }
DWORD RefreshCardMetadata(CMD_CONTEXT_PTR context) {
  (void)context;
  return SCARD_S_SUCCESS;
}

static DWORD callback(PCARD_DATA pCardData) {
  INJECT_HANDLES();
  callbackCalls++;
  return SCARD_S_SUCCESS;
}

static void init(CMD_CONTEXT *context, CONTAINER_MAP_RECORD *records) {
  memset(context, 0, sizeof(*context));
  memset(records, 0, sizeof(CONTAINER_MAP_RECORD) * WINDOWS_CONTAINER_COUNT);
  context->canokey.slotCount = WINDOWS_CONTAINER_COUNT;
  context->metadataGeneration = 1;
  context->card_handle = 1;
  cmd_clear_enrollment_container_map(context);
  records[0].wszGuid[0] = L'A';
  records[0].bFlags = CONTAINER_MAP_VALID_CONTAINER;
  records[0].wKeyExchangeKeySizeBits = 2048;
  identityResult = SCARD_S_SUCCESS;
  differentCard = FALSE;
}

static void stage(CMD_CONTEXT *context, CONTAINER_MAP_RECORD *records) {
  CHECK(cmd_stage_enrollment_container_map(context, (const BYTE *)records,
                                           sizeof(CONTAINER_MAP_RECORD) * WINDOWS_CONTAINER_COUNT) == SCARD_S_SUCCESS);
}

static void generated(CMD_CONTEXT *context) {
  SLOT *slot = &context->canokey.slots[2];
  slot->keyPresent = TRUE;
  slot->present = TRUE;
  slot->pivId = 0x9D;
  slot->keyType = CKK_RSA;
  slot->capabilities = CANOKEY_SLOT_CAP_SIGN | CANOKEY_SLOT_CAP_DECRYPT;
  slot->rsa.modulusBits = 2048;
  slot->rsa.modulus[0] = 0x91;
  slot->rsa.exponent[0] = 3;
  cmd_capture_enrollment_alias_key(context, 0);
}

int main(void) {
  CMD_CONTEXT context;
  CONTAINER_MAP_RECORD records[WINDOWS_CONTAINER_COUNT];
  // An unsupported key must block both the target and the provisional source
  // of an enrollment alias, even though neither has a Windows key view.
  for (unsigned occupied = 0; occupied <= 2; occupied += 2) {
    init(&context, records);
    context.canokey.slots[occupied].keyPresent = TRUE;
    CHECK(!canokey_slot_has_key(&context.canokey.slots[occupied]));
    stage(&context, records);
    CHECK(cmd_resolve_container_index(&context, 0) == 0);
  }
  init(&context, records);
  stage(&context, records);
  CHECK(cmd_resolve_container_index(&context, 0) == 2);
  stage(&context, records); // pre-generation rewrite
  CHECK(cmd_resolve_container_index(&context, 0) == 2);
  generated(&context);
  records[0].bFlags |= CONTAINER_MAP_DEFAULT_CONTAINER;
  CHECK(cmd_certificate_container_index(&context, 2) == 0);
  CHECK(cmd_resolve_container_index(&context, cmd_certificate_container_index(&context, 2)) == 2);
  stage(&context, records);
  stage(&context, records);
  CHECK(cmd_resolve_container_index(&context, 0) == 2);
  CHECK(cmd_stage_enrollment_container_map(&context, (const BYTE *)records, 1) == SCARD_E_INVALID_PARAMETER);
  CHECK(cmd_resolve_container_index(&context, 0) == 2);
  CHECK(cmd_stage_enrollment_container_map(&context, NULL, sizeof(records)) == SCARD_E_INVALID_PARAMETER);
  CHECK(cmd_resolve_container_index(&context, 0) == 2);

  records[0].wszGuid[0] = L'B';
  stage(&context, records);
  CHECK(cmd_resolve_container_index(&context, 0) == 0);
  CHECK(cmd_certificate_container_index(&context, 2) == 2);
  for (unsigned variant = 0; variant < 6; variant++) {
    init(&context, records);
    stage(&context, records);
    generated(&context);
    switch (variant) {
    case 0:
      context.canokey.slots[2].rsa.modulus[0] ^= 1;
      break;
    case 1:
      records[0].wKeyExchangeKeySizeBits = 4096;
      break;
    case 2:
      records[0].bFlags = 0;
      break;
    case 3:
      records[2].bFlags = CONTAINER_MAP_VALID_CONTAINER;
      records[2].wszGuid[0] = L'C';
      break;
    case 4:
      records[0].wSigKeySizeBits = 2048;
      break;
    case 5:
      context.canokey.slots[2].rsa.exponent[0] ^= 1;
      break;
    }
    stage(&context, records);
    CHECK(cmd_resolve_container_index(&context, 0) == 0);
  }
  init(&context, records);
  generated(&context);
  stage(&context, records);
  CHECK(cmd_resolve_container_index(&context, 0) == 0); // never alias an existing key by name alone
  CHECK(cmd_stage_enrollment_container_map(&context, NULL, 0) == SCARD_S_SUCCESS);
  CHECK(context.enrollmentContainerMapSize == 0);

  init(&context, records);
  stage(&context, records);
  generated(&context);
  CARD_DATA card = {0};
  card.pvVendorSpecific = &context;
  card.hScard = 2;
  CHECK(callback(&card) == SCARD_S_SUCCESS);
  CHECK(context.card_handle == 2 && cmd_resolve_container_index(&context, 0) == 2);
  for (unsigned failure = 0; failure < 2; failure++) {
    init(&context, records);
    stage(&context, records);
    differentCard = failure == 0;
    identityResult = failure == 0 ? SCARD_S_SUCCESS : SCARD_E_COMM_DATA_LOST;
    DWORD expected = failure == 0 ? SCARD_E_UNKNOWN_CARD : identityResult;
    unsigned callbacksBefore = callbackCalls;
    CHECK(callback(&card) == expected);
    CHECK(context.cardId[0] == 0 && context.card_handle == 1);
    unsigned callsBefore = identityCalls;
    CHECK(callback(&card) == expected); // identical new handle must not bypass failure
    cmd_clear_enrollment_container_map(&context);
    CHECK(callback(&card) == expected);
    CHECK(cmd_revalidate_enrollment_card(&context) == expected);
    CHECK(identityCalls == callsBefore && callbackCalls == callbacksBefore);
    CHECK(cmd_stage_enrollment_container_map(&context, (const BYTE *)records, sizeof(records)) == expected);
  }

  init(&context, records);
  generated(&context);
  SLOT *slot = &context.canokey.slots[2];
  CHECK(cmd_slot_has_key_exchange_view(slot) && !cmd_slot_has_signature_view(slot));
  CHECK(canokey_slot_can_sign(slot)); // AT_KEYEXCHANGE remains sign-capable
  slot->keyType = CKK_EC;
  CHECK(!cmd_slot_has_key_exchange_view(slot) && cmd_slot_has_signature_view(slot));
  slot->keyType = CKK_RSA;
  slot->pivId = 0x9A;
  slot->capabilities = CANOKEY_SLOT_CAP_SIGN;
  CHECK(!cmd_slot_has_key_exchange_view(slot) && cmd_slot_has_signature_view(slot));
  slot->present = FALSE;
  CHECK(!cmd_slot_has_key_exchange_view(slot) && !cmd_slot_has_signature_view(slot));
  init(&context, records);
  stage(&context, records);
  nameReads = nameWrites = 0;
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) == SCARD_S_SUCCESS);
  CHECK(nameReads == 0 && nameWrites == 0); // empty slot: stage only
  generated(&context);
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) == SCARD_S_SUCCESS);
  CHECK(nameWrites == 1 && wcscmp(cardName, L"A") == 0);
  CHECK(context.canokey.slots[2].containerName[0] == L'A');
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) == SCARD_S_SUCCESS);
  CHECK(nameWrites == 1); // exact repeat requires no write
  nameReadResult = CKR_DEVICE_ERROR;
  CHECK(cmd_persist_enrollment_name(&context, 0, L"A") == SCARD_S_SUCCESS);
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) != SCARD_S_SUCCESS);
  nameReadResult = CKR_FUNCTION_NOT_SUPPORTED;
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) == SCARD_S_SUCCESS);
  CHECK(nameWrites == 1); // old firmware, no attempted persistent mutation
  nameReadResult = CKR_OK;
  cardName[0] = 0;
  nameWriteResult = CKR_USER_NOT_LOGGED_IN;
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) == SCARD_W_SECURITY_VIOLATION);
  nameWriteResult = CKR_DEVICE_ERROR;
  CHECK(cmd_persist_enrollment_name(&context, 0, NULL) != SCARD_S_SUCCESS);
  CHECK(cardName[0] == 0);
  memset(records[0].wszGuid, 'X', sizeof(records[0].wszGuid));
  CHECK(cmd_stage_enrollment_container_map(&context, (BYTE *)records, sizeof(records)) == SCARD_E_INVALID_PARAMETER);
  CHECK(context.enrollmentContainerMap[0].wszGuid[0] == L'A');
  puts("Enrollment regression tests passed (no hardware I/O).");
  return 0;
}
