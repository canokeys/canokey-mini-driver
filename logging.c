#include "logging.h"

#include <stdarg.h>
#include <fcntl.h>
#include <io.h>
#include <assert.h>
#include <Windows.h>

const char* g_log_level_name[CMD_LOG_LEVEL_SIZE] = {
	"TRACE",
	"DEBUG",
	"INFO",
	"WARN",
	"ERROR",
	"FATAL",
	"NONE",
};

// default values
int g_log_level = CMD_LOG_LEVEL_NONE;

int cmd_init_logging(const char* log_file, const int log_level) {
  static bool is_initialized = false;
  static int log_fd;

  if (is_initialized || log_file == NULL) {
    return 0;
  }

  // create log file in shared mode
  HANDLE hFile = CreateFile(
    log_file,
    FILE_APPEND_DATA | FILE_GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  // convert file handle to fd
  assert(hFile != INVALID_HANDLE_VALUE);
  log_fd = _open_osfhandle((intptr_t)hFile, _O_CREAT | _O_APPEND | _O_BINARY);
  assert(log_fd != -1);

  // redirect stderr to log file
  FILE* old_stderr;
  // stderr might be already closed - open it first
  assert(freopen_s(&old_stderr, "NUL", "w", stderr) == 0);
  assert(_dup2(log_fd, _fileno(stderr)) != -1);
  assert(_close(log_fd) == 0);

  // set global log level
	if (log_level >= 0 && log_level < CMD_LOG_LEVEL_SIZE) {
		g_log_level = log_level;
	}
	else {
		g_log_level = CMD_LOG_LEVEL_INFO;
	}
  is_initialized = true;

  return 0;
}

int cmd_stop_logging() {
  fclose(stderr);
}

void cmd_fprintf(const int level, FILE* const out, const char* const format, ...) {
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
