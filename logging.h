#pragma once
#ifndef __LOGGING__H__
#define __LOGGING__H__

#include <stdio.h>

#include "third-party/dbg.h"

enum CMD_LOG_LEVEL {
	CMD_LOG_LEVEL_TRACE = 0,
	CMD_LOG_LEVEL_DEBUG,
	CMD_LOG_LEVEL_INFO,
	CMD_LOG_LEVEL_WARNING,
	CMD_LOG_LEVEL_ERROR,
	CMD_LOG_LEVEL_FATAL,
	CMD_LOG_LEVEL_NONE,
	CMD_LOG_LEVEL_SIZE,
};

extern const char* g_log_level_name[CMD_LOG_LEVEL_SIZE];

extern FILE* g_log_file;
extern int g_log_level;

extern int cmd_init_logging(const char* log_file, const int log_level);
extern int cmd_stop_logging();
extern void cmd_fprintf(const int level, FILE* const out, const char* format, ...);

#define CMD_PRINTLOGF(level, format, ...) cmd_fprintf(level, stderr, "%-20s(%-20s:%03d)[%-5s]: " format, __FUNCTION__, __FILE__, __LINE__, g_log_level_name[level], ##__VA_ARGS__);
#define CMD_TRACE(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CMD_DEBUG(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CMD_INFO(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CMD_WARN(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define CMD_ERROR(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CMD_FATAL(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)


#ifdef CMD_VERBOSE
#define FUNC_TRACE(CALL) dbg(CALL)
#define CMD_RETURN(ARG, REASON) CMD_DEBUG("Returning value %s = %d with reason \"%s\"\n", #ARG, (ARG), REASON); return (ARG);
#else
#define FUNC_TRACE(CALL) CALL
#define CMD_RETURN(ARG, ...) return (ARG);
#endif // CMD_VERBOSE

#define CMD_RET_OK CMD_RETURN(SCARD_S_SUCCESS, "success");
#define CMD_RET_UNIMPL CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "should be supported (not implemented now)");

#endif // __LOGGING__H__
