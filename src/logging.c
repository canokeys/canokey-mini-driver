#include "logging.h"

#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// clang-format off
#include <Windows.h>
#include <DbgHelp.h>
#include <fcntl.h>
#include <io.h>
#include <synchapi.h>
// clang-format on

const char *g_log_level_name[CMD_LOG_LEVEL_SIZE] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "NONE",
};

static atomic_int g_log_level = CMD_LOG_LEVEL_NONE;
static atomic_bool g_unsafe_log_apdu = false;
static FILE *g_log_fp = NULL;
static SRWLOCK g_log_lock = SRWLOCK_INIT;
static bool g_logging_initialized = false;

static int ascii_tolower(int ch) {
  if (ch >= 'A' && ch <= 'Z') {
    return ch - 'A' + 'a';
  }
  return ch;
}

static bool ascii_equals_ignore_case(const char *lhs, const char *rhs) {
  if (lhs == NULL || rhs == NULL) {
    return false;
  }

  while (*lhs != '\0' && *rhs != '\0') {
    if (ascii_tolower((unsigned char)*lhs) != ascii_tolower((unsigned char)*rhs)) {
      return false;
    }
    lhs++;
    rhs++;
  }

  return *lhs == '\0' && *rhs == '\0';
}

static bool parse_log_level(const char *value, int *level) {
  if (value == NULL || level == NULL) {
    return false;
  }

  char *end = NULL;
  long numeric = strtol(value, &end, 10);
  if (end != value && *end == '\0' && numeric >= 0 && numeric < CMD_LOG_LEVEL_SIZE) {
    *level = (int)numeric;
    return true;
  }

  for (int i = 0; i < CMD_LOG_LEVEL_SIZE; i++) {
    if (ascii_equals_ignore_case(value, g_log_level_name[i])) {
      *level = i;
      return true;
    }
  }

  return false;
}

static bool parse_bool(const char *value, bool *result) {
  if (value == NULL || result == NULL) {
    return false;
  }

  if (ascii_equals_ignore_case(value, "1") || ascii_equals_ignore_case(value, "true") ||
      ascii_equals_ignore_case(value, "yes") || ascii_equals_ignore_case(value, "on")) {
    *result = true;
    return true;
  }

  if (ascii_equals_ignore_case(value, "0") || ascii_equals_ignore_case(value, "false") ||
      ascii_equals_ignore_case(value, "no") || ascii_equals_ignore_case(value, "off")) {
    *result = false;
    return true;
  }

  return false;
}

CMD_LOG_CONFIG cmd_logging_config_from_env(void) {
  CMD_LOG_CONFIG config = {
      .level = CMD_LOG_LEVEL_WARN,
      .unsafe_log_apdu = false,
  };

  int level = CMD_LOG_LEVEL_NONE;
  const char *level_env = getenv("CNK_LOG_LEVEL");
  if (parse_log_level(level_env, &level)) {
    config.level = level;
  }

  bool unsafe_log_apdu = false;
  const char *unsafe_log_apdu_env = getenv("CNK_UNSAFE_LOG_APDU");
  if (parse_bool(unsafe_log_apdu_env, &unsafe_log_apdu)) {
    config.unsafe_log_apdu = unsafe_log_apdu;
  }

  return config;
}

int cmd_init_logging(const char *log_file, CMD_LOG_CONFIG config) {
  AcquireSRWLockExclusive(&g_log_lock);
  if (g_logging_initialized) {
    atomic_store(&g_log_level, config.level);
    atomic_store(&g_unsafe_log_apdu, config.unsafe_log_apdu);
    ReleaseSRWLockExclusive(&g_log_lock);
    return 0;
  }

  if (config.level >= 0 && config.level < CMD_LOG_LEVEL_SIZE) {
    atomic_store(&g_log_level, config.level);
  } else {
    atomic_store(&g_log_level, CMD_LOG_LEVEL_WARN);
  }
  atomic_store(&g_unsafe_log_apdu, config.unsafe_log_apdu);

  if (atomic_load(&g_log_level) == CMD_LOG_LEVEL_NONE || log_file == NULL) {
    g_logging_initialized = true;
    ReleaseSRWLockExclusive(&g_log_lock);
    return 0;
  }

  HANDLE hFile = CreateFile(log_file, FILE_APPEND_DATA | FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    atomic_store(&g_log_level, CMD_LOG_LEVEL_NONE);
    ReleaseSRWLockExclusive(&g_log_lock);
    return (int)GetLastError();
  }

  int log_fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_APPEND | _O_BINARY);
  if (log_fd == -1) {
    CloseHandle(hFile);
    atomic_store(&g_log_level, CMD_LOG_LEVEL_NONE);
    ReleaseSRWLockExclusive(&g_log_lock);
    return EINVAL;
  }

  FILE *fp = _fdopen(log_fd, "a");
  if (fp == NULL) {
    _close(log_fd);
    atomic_store(&g_log_level, CMD_LOG_LEVEL_NONE);
    ReleaseSRWLockExclusive(&g_log_lock);
    return errno;
  }

  g_log_fp = fp;
  g_logging_initialized = true;
  ReleaseSRWLockExclusive(&g_log_lock);
  return 0;
}

int cmd_stop_logging() {
  AcquireSRWLockExclusive(&g_log_lock);
  FILE *fp = g_log_fp;
  g_log_fp = NULL;
  g_logging_initialized = false;
  atomic_store(&g_log_level, CMD_LOG_LEVEL_NONE);
  atomic_store(&g_unsafe_log_apdu, false);
  ReleaseSRWLockExclusive(&g_log_lock);

  if (fp == NULL) {
    return 0;
  }
  return fclose(fp);
}

FILE *cmd_get_log_file(void) {
  AcquireSRWLockShared(&g_log_lock);
  FILE *fp = g_log_fp;
  ReleaseSRWLockShared(&g_log_lock);
  return fp;
}

bool cmd_should_log(const int level) {
  return level >= atomic_load(&g_log_level);
}

bool cmd_unsafe_log_apdu_enabled(void) {
  return atomic_load(&g_unsafe_log_apdu);
}

static void print_time(FILE *out) {
  struct timespec ts;
  if (timespec_get(&ts, TIME_UTC) == TIME_UTC) {
    char time[16];
    strftime(time, sizeof(time), "%H:%M:%S", localtime(&ts.tv_sec));
    sprintf(time + 8, ".%03ld", ts.tv_nsec / 1000000);
    fprintf(out, "%s - CMD - ", time);
  } else {
    fprintf(out, "!!:!!:!!.!!! - CMD - ");
  }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"

void cmd_printlogf(const int level, const char *const function, const char *const file, const int line,
                   const char *const format, ...) {
  if (!cmd_should_log(level)) {
    return;
  }

  AcquireSRWLockExclusive(&g_log_lock);
  FILE *out = g_log_fp;
  if (out == NULL) {
    ReleaseSRWLockExclusive(&g_log_lock);
    return;
  }

  print_time(out);
  fprintf(out, "%-20s(%-20s:L%03d)[%-5s]: ", function, file, line, g_log_level_name[level]);

  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fprintf(out, "\n");
  fflush(out);
  ReleaseSRWLockExclusive(&g_log_lock);
}

#pragma clang diagnostic pop

void cmd_print_hex(const int level, const void *data, size_t size) {
  if (!cmd_should_log(level) || !cmd_unsafe_log_apdu_enabled() || data == NULL) {
    return;
  }

  AcquireSRWLockExclusive(&g_log_lock);
  FILE *out = g_log_fp;
  if (out == NULL) {
    ReleaseSRWLockExclusive(&g_log_lock);
    return;
  }

  for (size_t i = 0; i < size; i++) {
    fprintf(out, "%02x ", ((const unsigned char *)data)[i]);
    if (i % 16 == 15) {
      fprintf(out, "\n");
    }
  }
  fprintf(out, "\n");
  fflush(out);
  ReleaseSRWLockExclusive(&g_log_lock);
}

#ifdef CMD_VERBOSE
static void print_stack_line(const char *format, ...) {
  AcquireSRWLockExclusive(&g_log_lock);
  FILE *out = g_log_fp;
  if (out == NULL) {
    ReleaseSRWLockExclusive(&g_log_lock);
    return;
  }

  va_list args;
  va_start(args, format);
  vfprintf(out, format, args);
  va_end(args);
  fflush(out);
  ReleaseSRWLockExclusive(&g_log_lock);
}
#endif

void cmd_print_stack() {
#ifdef CMD_VERBOSE
  if (!cmd_should_log(CMD_LOG_LEVEL_DEBUG)) {
    return;
  }

  const int maxStackFrames = 64;
  HANDLE process = GetCurrentProcess();
  DWORD pid = GetCurrentProcessId();
  DWORD tid = GetCurrentThreadId();
  CMD_DEBUG("Stack trace begin for PID %d TID %d...", pid, tid);

  void *stack[maxStackFrames];
  WORD frames = CaptureStackBackTrace(0, maxStackFrames, stack, NULL);

  for (WORD i = 1; i < frames; ++i) {
    DWORD64 address = (DWORD64)stack[i];
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];

    if (i >= 2 && address == (DWORD64)stack[i - 1]) {
      print_stack_line("\t[%02d] (repeated frame) @ %p\n", i, (PVOID)address);
    }

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

    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacementSym = 0;
    BOOL symbolFound = SymFromAddr(process, address, &displacementSym, pSymbol);
    if (!symbolFound) {
      print_stack_line("\t[%02d] SymFromAddr64 returned error for %s!%p: error 0x%lx\n", i, module, (PVOID)address,
                       GetLastError());
      continue;
    }
    DWORD64 offset = address - pSymbol->Address;

    IMAGEHLP_LINE64 line;
    DWORD displacementLine = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    BOOL lineFound = SymGetLineFromAddr64(process, address, &displacementLine, &line);
    if (lineFound) {
      print_stack_line("\t[%02d] at %s!%s+0x%llx @ %p, in %s:%lu\n", i, module, pSymbol->Name, offset,
                       (PVOID)address, line.FileName, line.LineNumber);
    } else {
      print_stack_line("\t[%02d] at %s!%s+0x%llx @ %p, in unknown line\n", i, module, pSymbol->Name, offset,
                       (PVOID)address);
    }
  }
  CMD_DEBUG("Stack trace end.");
#else
  return;
#endif
}
