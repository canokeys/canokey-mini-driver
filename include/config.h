#pragma once
#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#include <Windows.h>

#include "logging.h"
#include "pkcs11_canokey.h"

#define CMD_CONFIG_REGISTRY_KEY "SOFTWARE\\Canokeys\\ckmd"
#define CMD_CONFIG_MAX_PATH 512

typedef struct {
  bool has_log_path;
  char log_path[CMD_CONFIG_MAX_PATH];
  CMD_LOG_CONFIG logging;
  bool protect_management;
  bool refresh_device_keys;
  DWORD refresh_window_seconds;
  DWORD new_key_touch_policy;
  bool has_new_key_pin_policy;
  DWORD new_key_pin_policy;
  bool has_pin_cache_timeout;
  DWORD pin_cache_timeout;
} CMD_CONFIG;

extern const CMD_CONFIG *cmd_get_config(void);
extern void cmd_load_config(CMD_CONFIG *config);

#endif // CONFIG_H
