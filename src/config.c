#include "config.h"

#include <string.h>

static CMD_CONFIG g_config;

const CMD_CONFIG *cmd_get_config(void) { return &g_config; }

static bool read_registry_string(HKEY key, const char *name, char *buffer, DWORD buffer_len) {
  DWORD type = 0;
  DWORD cb_data = buffer_len;
  LSTATUS status = RegGetValueA(key, NULL, name, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, &type, buffer, &cb_data);
  if (status != ERROR_SUCCESS || cb_data == 0) {
    return false;
  }

  buffer[buffer_len - 1] = '\0';
  if (type == REG_EXPAND_SZ) {
    char expanded[CMD_CONFIG_MAX_PATH];
    DWORD expanded_len = ExpandEnvironmentStringsA(buffer, expanded, CMD_CONFIG_MAX_PATH);
    if (expanded_len > 0 && expanded_len <= CMD_CONFIG_MAX_PATH) {
      memcpy(buffer, expanded, expanded_len);
      buffer[buffer_len - 1] = '\0';
    }
  }

  return buffer[0] != '\0';
}

static bool read_registry_dword(HKEY key, const char *name, DWORD *value) {
  DWORD type = 0;
  DWORD cb_data = sizeof(*value);
  return RegGetValueA(key, NULL, name, RRF_RT_REG_DWORD, &type, value, &cb_data) == ERROR_SUCCESS;
}

static bool read_registry_bool(HKEY key, const char *name, bool *value) {
  DWORD dword_value = 0;
  if (read_registry_dword(key, name, &dword_value)) {
    *value = dword_value != 0;
    return true;
  }

  char string_value[16];
  if (read_registry_string(key, name, string_value, sizeof(string_value))) {
    return cmd_parse_bool(string_value, value);
  }

  return false;
}

void cmd_load_config(CMD_CONFIG *config) {
  CMD_CONFIG local = {
      .has_log_path = false,
      .log_path = {0},
      .logging =
          {
              .level = CMD_LOG_LEVEL_NONE,
              .unsafe_log_apdu = false,
          },
      .protect_management = true,
      .refresh_device_keys = true,
      .refresh_window_seconds = 60,
      .new_key_touch_policy = CNK_PIV_TOUCH_POLICY_NEVER,
      .has_new_key_pin_policy = false,
      .new_key_pin_policy = CNK_PIV_PIN_POLICY_ONCE,
      .has_pin_cache_timeout = false,
      .pin_cache_timeout = 0,
  };

  HKEY key = NULL;
  LSTATUS status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, CMD_CONFIG_REGISTRY_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &key);
  if (status == ERROR_SUCCESS) {
    local.has_log_path = read_registry_string(key, "LogPath", local.log_path, sizeof(local.log_path));
    if (local.has_log_path) {
      char log_level[16];
      int level = CMD_LOG_LEVEL_WARN;
      if (read_registry_string(key, "LogLevel", log_level, sizeof(log_level)) &&
          cmd_parse_log_level(log_level, &level)) {
        local.logging.level = level;
      } else {
        local.logging.level = CMD_LOG_LEVEL_WARN;
      }
      read_registry_bool(key, "LogSensitiveData", &local.logging.unsafe_log_apdu);
    }

    // Match YubiKey Minidriver semantics: disabling this delegates
    // PIN-managed management-key provisioning to an external solution.
    read_registry_bool(key, "ProtectManagement", &local.protect_management);
    read_registry_bool(key, "RefreshDeviceKeys", &local.refresh_device_keys);
    read_registry_dword(key, "RefreshWindow", &local.refresh_window_seconds);

    DWORD new_key_touch_policy = 0;
    if (read_registry_dword(key, "NewKeyTouchPolicy", &new_key_touch_policy) &&
        new_key_touch_policy >= CNK_PIV_TOUCH_POLICY_NEVER && new_key_touch_policy <= CNK_PIV_TOUCH_POLICY_CACHED) {
      local.new_key_touch_policy = new_key_touch_policy;
    }
    DWORD new_key_pin_policy = 0;
    if (read_registry_dword(key, "NewKeyPinPolicy", &new_key_pin_policy) &&
        new_key_pin_policy >= CNK_PIV_PIN_POLICY_NEVER && new_key_pin_policy <= CNK_PIV_PIN_POLICY_ALWAYS) {
      local.has_new_key_pin_policy = true;
      local.new_key_pin_policy = new_key_pin_policy;
    }
    if (read_registry_dword(key, "PinCacheTimeout", &local.pin_cache_timeout)) {
      local.has_pin_cache_timeout = true;
    }

    RegCloseKey(key);
  }

  g_config = local;
  if (config != NULL) {
    *config = local;
  }
}
