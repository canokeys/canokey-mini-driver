#include <Windows.h>

#include <DbgHelp.h>
#include <Psapi.h>
#include <pkcs11_canokey.h>

#include "cardmod.h"
#include "logging.h"

static void init_logging_file(int level) {
  CreateDirectory("C:\\Logs", NULL); // ignore errors
  char log_file_name[256], time[16];
  SYSTEMTIME st;
  GetLocalTime(&st);
  sprintf_s(time, sizeof(time), "%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
            st.wSecond);
  HANDLE process = GetCurrentProcess();
  char exe_name[MAX_PATH] = {'\0'};
  GetModuleBaseName(process, NULL, exe_name, MAX_PATH);
  sprintf_s(log_file_name, sizeof(log_file_name), "C:\\Logs\\canokey_minidriver_%s_%s_%d_%d.log", time, exe_name,
            (int32_t)GetCurrentProcessId(), (int32_t)GetCurrentThreadId());
  cmd_init_logging(log_file_name, level);
  CMD_INFO("Start logging to file %s...", log_file_name);
#ifdef CMD_VERBOSE
  char exe_path[MAX_PATH] = {'\0'};
  GetModuleFileNameEx(process, NULL, exe_path, MAX_PATH);
  if (!SymInitialize(process, exe_path, TRUE)) {
    CMD_WARN("SymInitialize returned error: 0x%lx", GetLastError());
  }
#endif
}

// DllMain function
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  (void)lpvReserved;
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    // Initialize the DLL
    init_logging_file(CMD_LOG_LEVEL_DEBUG);
    C_CNK_ConfigLogging(CMD_LOG_LEVEL_DEBUG, g_log_fp);
    CMD_INFO("CanoKey Smart Card Minidriver compiled at %s %s", __DATE__, __TIME__);
    CMD_INFO("DLL loaded with handle %p", hinstDLL);
    DisableThreadLibraryCalls(hinstDLL);
    break;
  case DLL_PROCESS_DETACH:
    // Clean up resources
    CMD_INFO("DLL unloaded with handle %p, stop logging...", hinstDLL);
    CMD_INFO("========================================");
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
