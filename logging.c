#include "logging.h"
#include <stdarg.h>

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
FILE* g_log_file = NULL;
int g_log_level = CMD_LOG_LEVEL_NONE;

int cmd_init_logging(const char* log_file, const int log_level) {
	if (log_file != NULL) {
		if (g_log_file != NULL) {
			fclose(g_log_file);
			g_log_file = NULL;
		}
		int res = fopen_s(&g_log_file, log_file, "a+");
		if (res != 0) {
			return res;
		}
		fflush(g_log_file);
		if (log_level >= 0 && log_level < CMD_LOG_LEVEL_SIZE) {
			g_log_level = log_level;
		}
		else {
			g_log_level = CMD_LOG_LEVEL_INFO;
		}
	}
	return 0;
}

void cmd_fprintf(const int level, FILE* const out, const char* const format, ...) {
	if (level < g_log_level) {
		return;
	}
	va_list args;
	va_start(args, format);
	vfprintf(out, format, args);
	va_end(args);
	fflush(out);
}
