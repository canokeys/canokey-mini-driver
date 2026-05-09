#include <Windows.h>

#include <DbgHelp.h>
#include <Psapi.h>
#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "config.h"
#include "logging.h"

static void init_logging_file(const CMD_CONFIG *config) {
  if (config == NULL || !config->has_log_path) {
    cmd_init_logging(NULL, config == NULL ? (CMD_LOG_CONFIG){.level = CMD_LOG_LEVEL_NONE, .unsafe_log_apdu = false}
                                          : config->logging);
    return;
  }

  CreateDirectory(config->log_path, NULL); // ignore errors
  char log_file_name[CMD_CONFIG_MAX_PATH + MAX_PATH + 128], time[16];
  SYSTEMTIME st;
  GetLocalTime(&st);
  sprintf_s(time, sizeof(time), "%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
            st.wSecond);
  HANDLE process = GetCurrentProcess();
  char exe_name[MAX_PATH] = {'\0'};
  GetModuleBaseName(process, NULL, exe_name, MAX_PATH);
  if (sprintf_s(log_file_name, sizeof(log_file_name), "%s\\canokey_minidriver_%s_%s_%d_%d.log", config->log_path, time,
                exe_name, (int32_t)GetCurrentProcessId(), (int32_t)GetCurrentThreadId()) < 0) {
    cmd_init_logging(NULL, (CMD_LOG_CONFIG){.level = CMD_LOG_LEVEL_NONE, .unsafe_log_apdu = false});
    return;
  }
  cmd_init_logging(log_file_name, config->logging);
  CMD_INFO("Start logging to file %s...", log_file_name);
#ifdef CMD_VERBOSE
  if (!cmd_should_log(CMD_LOG_LEVEL_DEBUG)) {
    return;
  }
  char exe_path[MAX_PATH] = {'\0'};
  GetModuleFileNameEx(process, NULL, exe_path, MAX_PATH);
  if (!SymInitialize(process, exe_path, TRUE)) {
    CMD_WARN("SymInitialize returned error: 0x%lx", GetLastError());
  }
#endif
}

static void configure_pkcs11_logging(const CMD_CONFIG *config) {
  FILE *log_file = cmd_get_log_file();
  int level = log_file == NULL ? CMD_LOG_LEVEL_NONE : config->logging.level;
  C_CNK_ConfigLogging(level, log_file, config->logging.unsafe_log_apdu ? CK_TRUE : CK_FALSE);
}

// DllMain function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  (void)lpvReserved;
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH: {
    // Initialize the DLL
    CMD_CONFIG config;
    cmd_load_config(&config);
    init_logging_file(&config);
    configure_pkcs11_logging(&config);
    CMD_INFO("CanoKey Smart Card Minidriver compiled at %s %s", __DATE__, __TIME__);
    CMD_INFO("DLL loaded with handle %p", hinstDLL);
    DisableThreadLibraryCalls(hinstDLL);
    break;
  }
  case DLL_PROCESS_DETACH:
    // Clean up resources
    CMD_INFO("DLL unloaded with handle %p, stop logging...", hinstDLL);
    CMD_INFO("========================================");
#ifdef CMD_VERBOSE
    if (cmd_should_log(CMD_LOG_LEVEL_DEBUG)) {
      SymCleanup(GetCurrentProcess());
    }
#endif
    C_CNK_ConfigLogging(CMD_LOG_LEVEL_NONE, NULL, CK_FALSE);
    cmd_stop_logging();
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  default:
    // No action needed
    break;
  }
  return TRUE;
}
