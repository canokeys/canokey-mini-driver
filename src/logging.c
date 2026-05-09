#include "logging.h"

#include <time.h>

// clang-format off
#include <Windows.h>
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
FILE *g_log_fp = NULL;

int cmd_init_logging(const char *log_file, const int log_level) {
  static bool is_initialized = false;

  if (is_initialized || log_file == NULL) {
    return 0;
  }

  // create log file in shared mode
  HANDLE hFile = CreateFile(log_file, FILE_APPEND_DATA | FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    g_log_level = CMD_LOG_LEVEL_NONE;
    return (int)GetLastError();
  }

  // convert file handle to fd
  int log_fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_APPEND | _O_BINARY);
  if (log_fd == -1) {
    CloseHandle(hFile);
    g_log_level = CMD_LOG_LEVEL_NONE;
    return EINVAL;
  }
  FILE *fp = _fdopen(log_fd, "a");
  if (fp == NULL) {
    _close(log_fd);
    g_log_level = CMD_LOG_LEVEL_NONE;
    return errno;
  }
  g_log_fp = fp;

  // set global log level
  if (log_level >= 0 && log_level < CMD_LOG_LEVEL_SIZE) {
    g_log_level = log_level;
  } else {
    g_log_level = CMD_LOG_LEVEL_INFO;
  }
  is_initialized = true;

  return 0;
}

int cmd_stop_logging() {
  if (g_log_fp == NULL) {
    g_log_level = CMD_LOG_LEVEL_NONE;
    return 0;
  }
  int rc = fclose(g_log_fp);
  g_log_fp = NULL;
  g_log_level = CMD_LOG_LEVEL_NONE;
  return rc;
}

static void print_time(FILE *out) {
  struct timespec ts;
  if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
    char time[16];
    strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
    sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
    fprintf(out, "%s - CMD - ", time);
  } else {
    fprintf(out, "!!:!!:!!.!!! - ");
  }
}

void cmd_fprintf(const int level, const bool prepend_date, FILE *const out, const char *const format, ...) {
  if (level < g_log_level) {
    return;
  }
  if (out == NULL) {
    return;
  }
  if (prepend_date) {
    print_time(out);
  }
  // print the log line
  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fflush(out);
}

void cmd_print_hex(const int level, FILE *const out, const void *data, size_t size) {
  if (level < g_log_level) {
    return;
  }
  if (out == NULL || data == NULL) {
    return;
  }
  for (size_t i = 0; i < size; i++) {
    fprintf(out, "%02x ", ((const unsigned char *)data)[i]);
    if (i % 16 == 15) {
      fprintf(out, "\n");
    }
  }
  fprintf(out, "\n");
}

void cmd_print_stack() {
#ifdef CMD_VERBOSE
  if (g_log_fp == NULL) {
    return;
  }

  const int maxStackFrames = 64;
  HANDLE process = GetCurrentProcess();
  DWORD pid = GetCurrentProcessId();
  DWORD tid = GetCurrentThreadId();
  CMD_DEBUG("Stack trace begin for PID %d TID %d...\n", pid, tid);

  void *stack[maxStackFrames];
  WORD frames = CaptureStackBackTrace(0, maxStackFrames, stack, NULL);

  // skip the first frame (this function)
  for (WORD i = 1; i < frames; ++i) {
    DWORD64 address = (DWORD64)stack[i];
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];

    if (i >= 2 && address == (DWORD64)stack[i - 1]) {
      fprintf(g_log_fp, "\t[%02d] (repeated frame) @ %p\n", i, (PVOID)address);
    }

    // get module name
    char module[MAX_SYM_NAME];
    HMODULE hModule = NULL;
    lstrcpy(module, "");
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                      (LPCTSTR)address, &hModule);
    if (hModule != NULL) {
      GetModuleFileName(hModule, module, MAX_SYM_NAME);
    } else {
      lstrcpy(module, "unknown module");
    }

    // get symbol name
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacementSym = 0;
    BOOL symbolFound = SymFromAddr(process, address, &displacementSym, pSymbol);
    if (!symbolFound) {
      fprintf(g_log_fp, "\t[%02d] SymFromAddr64 returned error for %s!%p: error 0x%lx\n", i, module, (PVOID)address,
              GetLastError());
      continue;
    }
    DWORD64 offset = address - pSymbol->Address;
    fprintf(g_log_fp, "\t[%02d] at %s!%s+0x%llx @ %p, in ", i, module, pSymbol->Name, offset, (PVOID)address);

    // get line info
    IMAGEHLP_LINE64 line;
    DWORD displacementLine = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    BOOL lineFound = SymGetLineFromAddr64(process, address, &displacementLine, &line);
    if (lineFound) {
      fprintf(g_log_fp, "%s:%lu\n", line.FileName, line.LineNumber);
    } else {
      fprintf(g_log_fp, "unknown line\n");
    }
  }
  CMD_DEBUG("Stack trace end.\n");
#else
  CMD_WARN("Stack trace is disabled in non-debug mode.\n");
#endif
}
