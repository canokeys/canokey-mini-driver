#include "logging.h"

// clang-format off
#include <Windows.h>
#include <assert.h>
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>
#include <DbgHelp.h>
// clang-format on

const char *g_log_level_name[CMD_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

// default values
int g_log_level = CMD_LOG_LEVEL_NONE;

int cmd_init_logging(const char *log_file, const int log_level) {
  static bool is_initialized = false;
  static int log_fd;

  if (is_initialized || log_file == NULL) {
    return 0;
  }

  // create log file in shared mode
  HANDLE hFile = CreateFile(log_file, FILE_APPEND_DATA | FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  // convert file handle to fd
  assert(hFile != INVALID_HANDLE_VALUE);
  log_fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_APPEND | _O_BINARY);
  assert(log_fd != -1);

  // redirect stderr to log file
  FILE *old_stderr;
  // stderr might be already closed - open it first
  assert(freopen_s(&old_stderr, "NUL", "w", stderr) == 0);
  assert(_dup2(log_fd, _fileno(stderr)) != -1);
  assert(_close(log_fd) == 0);

  // set global log level
  if (log_level >= 0 && log_level < CMD_LOG_LEVEL_SIZE) {
    g_log_level = log_level;
  } else {
    g_log_level = CMD_LOG_LEVEL_INFO;
  }
  is_initialized = true;

  return 0;
}

int cmd_stop_logging() { fclose(stderr); }

void cmd_fprintf(const int level, FILE *const out, const char *const format, ...) {
  if (level < g_log_level) {
    return;
  }
  // print current time at the beginning of the log line
  char time[16];
  SYSTEMTIME st;
  GetLocalTime(&st);
  sprintf_s(time, sizeof(time), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
  fprintf(out, "%s - ", time);
  // print the log line
  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fflush(out);
}

void cmd_print_stack() {
#ifdef CMD_VERBOSE

  const int maxStackFrames = 64;
  HANDLE process = GetCurrentProcess();
  DWORD pid = GetCurrentProcessId();
  DWORD tid = GetCurrentThreadId();
  CMD_DEBUG("Stack trace begin for process %d thread %d...\n", pid, tid);
  if (!SymInitialize(process, NULL, TRUE)) {
    fprintf(stderr, "SymInitialize returned error: 0x%lx\n", GetLastError());
    return;
  }

  void *stack[maxStackFrames];
  WORD frames = CaptureStackBackTrace(0, maxStackFrames, stack, NULL);

  // skip the first frame (this function)
  for (WORD i = 1; i < frames; ++i) {
    DWORD64 address = (DWORD64)stack[i];
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];

    if (i >= 2 && address == (DWORD64)stack[i - 1]) {
      fprintf(stderr, "\t[%02d] (repeated frame) @ %p\n", i, (PVOID)address);
    }

    // get module name
    char module[MAX_SYM_NAME];
    HMODULE hModule = NULL;
    lstrcpyA(module, "");
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                      (LPCTSTR)address, &hModule);
    if (hModule != NULL) {
      GetModuleFileNameA(hModule, module, MAX_SYM_NAME);
    } else {
      lstrcpyA(module, "unknown module");
    }

    // get symbol name
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacementSym = 0;
    BOOL symbolFound = SymFromAddr(process, address, &displacementSym, pSymbol);
    if (!symbolFound) {
      fprintf(stderr, "\t[%02d] SymFromAddr64 returned error for %s!%p: error 0x%lx\n", i, module, (PVOID)address,
              GetLastError());
      continue;
    }
    DWORD64 offset = address - pSymbol->Address;
    fprintf(stderr, "\t[%02d] at %s!%s+0x%llx @ %p, in ", i, module, pSymbol->Name, offset, (PVOID)address);

    // get line info
    IMAGEHLP_LINE64 line;
    DWORD displacementLine = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    BOOL lineFound = SymGetLineFromAddr64(process, address, &displacementLine, &line);
    if (lineFound) {
      fprintf(stderr, "%s:%lu\n", line.FileName, line.LineNumber);
    } else {
      fprintf(stderr, "unknown line\n");
    }
  }
  CMD_DEBUG("Stack trace end.\n");
#else
  CMD_WARN("Stack trace is disabled in non-debug mode.\n");
#endif
}
