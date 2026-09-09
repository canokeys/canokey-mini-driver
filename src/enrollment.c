#include <string.h>

#include "logging.h"
#include "minidriver.h"

void cmd_clear_enrollment_container_map(CMD_CONTEXT_PTR pContext) {
  if (pContext == NULL)
    return;
  SecureZeroMemory(pContext->enrollmentContainerMap, sizeof(pContext->enrollmentContainerMap));
  memset(pContext->enrollmentContainerAliases, 0xff, sizeof(pContext->enrollmentContainerAliases));
  SecureZeroMemory(pContext->enrollmentAliasKeys, sizeof(pContext->enrollmentAliasKeys));
  SecureZeroMemory(pContext->enrollmentAliasKeyValid, sizeof(pContext->enrollmentAliasKeyValid));
  pContext->enrollmentContainerMapSize = 0;
  pContext->enrollmentContainerMapValid = FALSE;
}

BYTE cmd_resolve_container_index(CMD_CONTEXT_PTR pContext, BYTE containerIndex) {
  if (pContext == NULL || !pContext->enrollmentContainerMapValid || containerIndex >= WINDOWS_CONTAINER_COUNT)
    return containerIndex;
  BYTE physicalIndex = pContext->enrollmentContainerAliases[containerIndex];
  return physicalIndex < WINDOWS_CONTAINER_COUNT ? physicalIndex : containerIndex;
}

BYTE cmd_certificate_container_index(CMD_CONTEXT_PTR pContext, BYTE physicalIndex) {
  if (pContext->enrollmentContainerMapValid) {
    for (BYTE i = 0; i < WINDOWS_CONTAINER_COUNT; i++) {
      if (pContext->enrollmentContainerAliases[i] == physicalIndex)
        return i;
    }
  }
  return physicalIndex;
}

DWORD cmd_revalidate_enrollment_card(CMD_CONTEXT_PTR pContext) {
  if (pContext->cardIdentityError != SCARD_S_SUCCESS)
    return pContext->cardIdentityError;
  if (!pContext->enrollmentContainerMapValid)
    return SCARD_S_SUCCESS;
  // KSP reconnects between its self-test and CSR signature. A new PC/SC
  // handle does not end CARD_DATA ownership of the provisional container.
  BYTE expectedCardId[sizeof(pContext->cardId)];
  memcpy(expectedCardId, pContext->cardId, sizeof(expectedCardId));
  DWORD ret = GenerateCardIdentifier(pContext);
  BOOL sameCard = ret == SCARD_S_SUCCESS && memcmp(expectedCardId, pContext->cardId, sizeof(expectedCardId)) == 0;
  memcpy(pContext->cardId, expectedCardId, sizeof(expectedCardId));
  if (!sameCard) {
    cmd_clear_enrollment_container_map(pContext);
    pContext->cardIdentityError = ret == SCARD_S_SUCCESS ? SCARD_E_UNKNOWN_CARD : ret;
    return pContext->cardIdentityError;
  }
  CMD_DEBUG("Preserved enrollment container map across same-card handle change");
  return SCARD_S_SUCCESS;
}

static void ConfigureEnrollmentContainerAliases(CMD_CONTEXT_PTR pContext, PCONTAINER_MAP_RECORD records,
                                                DWORD recordCount, BYTE *aliases) {
  DWORD keyExchangeIndex = recordCount;
  for (DWORD i = 0; i < recordCount; i++) {
    CK_BYTE pivTag = 0;
    if (C_CNK_ObjIdToPivTag(canokey_container_object_id((CK_BYTE)i), &pivTag) == CKR_OK && pivTag == 0x9D) {
      keyExchangeIndex = i;
      break;
    }
  }
  if (keyExchangeIndex == recordCount || keyExchangeIndex >= pContext->canokey.slotCount ||
      pContext->canokey.slots[keyExchangeIndex].keyPresent ||
      (records[keyExchangeIndex].bFlags & CONTAINER_MAP_VALID_CONTAINER) != 0) {
    return;
  }

  DWORD provisionalIndex = recordCount;
  for (DWORD i = 0; i < recordCount; i++) {
    if (i == keyExchangeIndex || (records[i].bFlags & CONTAINER_MAP_VALID_CONTAINER) == 0 ||
        records[i].wKeyExchangeKeySizeBits == 0 ||
        (i < pContext->canokey.slotCount && pContext->canokey.slots[i].keyPresent)) {
      continue;
    }
    if (provisionalIndex != recordCount) {
      CMD_WARN("Multiple provisional key-exchange records prevent PIV 9D aliasing");
      return;
    }
    provisionalIndex = i;
  }
  if (provisionalIndex == recordCount)
    return;

  aliases[provisionalIndex] = (BYTE)keyExchangeIndex;
  CMD_DEBUG("Aliased provisional key-exchange container index %lu to PIV 9D index %lu", (unsigned long)provisionalIndex,
            (unsigned long)keyExchangeIndex);
}

void cmd_capture_enrollment_alias_key(CMD_CONTEXT_PTR pContext, BYTE containerIndex) {
  BYTE physicalIndex = cmd_resolve_container_index(pContext, containerIndex);
  if (physicalIndex == containerIndex || containerIndex >= WINDOWS_CONTAINER_COUNT ||
      physicalIndex >= pContext->canokey.slotCount)
    return;
  const SLOT *slot = &pContext->canokey.slots[physicalIndex];
  if (cmd_slot_has_key_exchange_view(slot)) {
    pContext->enrollmentAliasKeys[containerIndex] = slot->rsa;
    pContext->enrollmentAliasKeyValid[containerIndex] = TRUE;
  }
}

DWORD cmd_stage_enrollment_container_map(CMD_CONTEXT_PTR pContext, const BYTE *data, DWORD size) {
  if ((data == NULL && size != 0) || size % sizeof(CONTAINER_MAP_RECORD) != 0 ||
      size > sizeof(pContext->enrollmentContainerMap))
    return SCARD_E_INVALID_PARAMETER;
  if (pContext->cardIdentityError != SCARD_S_SUCCESS)
    return pContext->cardIdentityError;
  CONTAINER_MAP_RECORD records[WINDOWS_CONTAINER_COUNT] = {0};
  BYTE aliases[WINDOWS_CONTAINER_COUNT];
  BOOL retainKey[WINDOWS_CONTAINER_COUNT] = {0};
  memset(aliases, 0xff, sizeof(aliases));
  if (size != 0)
    memcpy(records, data, size);
  DWORD count = size / sizeof(CONTAINER_MAP_RECORD);
  // Validate the complete input before any card mutation or overlay replacement.
  for (DWORD i = 0; i < count; i++) {
    if (!(records[i].bFlags & CONTAINER_MAP_VALID_CONTAINER))
      continue;
    size_t len = wcsnlen(records[i].wszGuid, ARRAYSIZE(records[i].wszGuid));
    if (len == 0 || len * sizeof(WCHAR) > CNK_PIV_CONTAINER_NAME_MAX_BYTES)
      return SCARD_E_INVALID_PARAMETER;
    for (size_t j = 0; j < len; j++) {
      WCHAR unit = records[i].wszGuid[j];
      if (unit == L'\\' || (unit >= 0xDC00 && unit <= 0xDFFF))
        return SCARD_E_INVALID_PARAMETER;
      if (unit >= 0xD800 && unit <= 0xDBFF) {
        if (++j >= len || records[i].wszGuid[j] < 0xDC00 || records[i].wszGuid[j] > 0xDFFF)
          return SCARD_E_INVALID_PARAMETER;
      }
    }
    for (DWORD j = 0; j < i; j++) {
      if ((records[j].bFlags & CONTAINER_MAP_VALID_CONTAINER) && wcscmp(records[i].wszGuid, records[j].wszGuid) == 0)
        return SCARD_E_INVALID_PARAMETER;
    }
  }
  ConfigureEnrollmentContainerAliases(pContext, records, count, aliases);

  // Default flags may change during enrollment. Preserve only the same valid
  // name/spec/size, backed by the exact public key captured after creation.
  DWORD oldCount = pContext->enrollmentContainerMapSize / sizeof(CONTAINER_MAP_RECORD);
  for (DWORD i = 0; pContext->enrollmentContainerMapValid && i < count && i < oldCount; i++) {
    BYTE target = pContext->enrollmentContainerAliases[i];
    const CONTAINER_MAP_RECORD *old = &pContext->enrollmentContainerMap[i];
    const CONTAINER_MAP_RECORD *next = &records[i];
    if (target >= count || target >= pContext->canokey.slotCount || target == i ||
        !pContext->enrollmentAliasKeyValid[i] || !(old->bFlags & next->bFlags & CONTAINER_MAP_VALID_CONTAINER) ||
        (records[target].bFlags & CONTAINER_MAP_VALID_CONTAINER) ||
        memcmp(old->wszGuid, next->wszGuid, sizeof(old->wszGuid)) != 0 ||
        old->wSigKeySizeBits != next->wSigKeySizeBits || old->wKeyExchangeKeySizeBits != next->wKeyExchangeKeySizeBits)
      continue;
    const SLOT *slot = &pContext->canokey.slots[target];
    if (!cmd_slot_has_key_exchange_view(slot) ||
        memcmp(&pContext->enrollmentAliasKeys[i], &slot->rsa, sizeof(slot->rsa)) != 0)
      continue;
    aliases[i] = target;
    retainKey[i] = TRUE;
  }

  // No borrowed pointers survive this call. The caller holds the context lock;
  // invalid writes return before changing either the map or its aliases.
  memcpy(pContext->enrollmentContainerMap, records, sizeof(records));
  memcpy(pContext->enrollmentContainerAliases, aliases, sizeof(aliases));
  for (DWORD i = 0; i < WINDOWS_CONTAINER_COUNT; i++) {
    if (!retainKey[i]) {
      SecureZeroMemory(&pContext->enrollmentAliasKeys[i], sizeof(pContext->enrollmentAliasKeys[i]));
      pContext->enrollmentAliasKeyValid[i] = FALSE;
    }
  }
  pContext->enrollmentContainerMapSize = size;
  pContext->enrollmentContainerMapValid = TRUE;
  return SCARD_S_SUCCESS;
}

DWORD cmd_persist_enrollment_name(CMD_CONTEXT_PTR context, BYTE index, const WCHAR *liveName) {
  if (!context->enrollmentContainerMapValid ||
      index >= context->enrollmentContainerMapSize / sizeof(CONTAINER_MAP_RECORD))
    return SCARD_S_SUCCESS;
  const CONTAINER_MAP_RECORD *record = &context->enrollmentContainerMap[index];
  BYTE physical = cmd_resolve_container_index(context, index);
  if (!(record->bFlags & CONTAINER_MAP_VALID_CONTAINER) || physical >= context->canokey.slotCount ||
      !canokey_slot_has_key(&context->canokey.slots[physical]))
    return SCARD_S_SUCCESS; // Before generation, only stage the provisional name.
  if (liveName && wcscmp(liveName, record->wszGuid) == 0)
    return SCARD_S_SUCCESS; // Default/size-only map writes need no management login.
  SLOT *slot = &context->canokey.slots[physical];
  WCHAR current[40] = {0};
  CK_ULONG currentLen = CNK_PIV_CONTAINER_NAME_MAX_BYTES;
  CK_RV rv = C_CNK_GetContainerName(context->session, slot->pivId, (CK_BYTE_PTR)current, &currentLen);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    CMD_WARN("Firmware has no F5 container names; enrollment name remains context-local");
    return SCARD_S_SUCCESS;
  }
  if (rv == CKR_OK && wcscmp(current, record->wszGuid) != 0) {
    // The key can already be committed. Any later failure is reported without
    // regenerating it; invalidate other contexts even if the response is lost.
    InterlockedIncrement(&g_cmd_metadata_generation);
    context->metadata_refresh_valid = FALSE;
    rv = C_CNK_SetContainerName(context->session, slot->pivId, (CK_BYTE_PTR)record->wszGuid,
                                (CK_ULONG)(wcslen(record->wszGuid) * sizeof(WCHAR)));
  }
  if (rv != CKR_OK) {
    CMD_ERROR("Persistent container name failed after possible key/name commit: 0x%lx", rv);
    if (rv == CKR_USER_NOT_LOGGED_IN)
      return SCARD_W_SECURITY_VIOLATION;
    if (rv == CKR_DATA_INVALID || rv == CKR_ARGUMENTS_BAD)
      return SCARD_E_INVALID_PARAMETER;
    if (rv == CKR_FUNCTION_NOT_SUPPORTED)
      return SCARD_E_UNSUPPORTED_FEATURE;
    return SCARD_F_COMM_ERROR;
  }
  memset(slot->containerName, 0, sizeof(slot->containerName));
  memcpy(slot->containerName, record->wszGuid, wcslen(record->wszGuid) * sizeof(WCHAR));
  return SCARD_S_SUCCESS;
}
