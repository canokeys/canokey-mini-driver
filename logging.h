#pragma once
#ifndef __LOGGING__H__
#define __LOGGING__H__

#include <stdio.h>

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
extern void cmd_fprintf(const int level, FILE* const out, const char* format, ...);

#define CMD_PRINTF(level, format, ...) cmd_fprintf(level, g_log_file, "%16s(%16s:%3d)[%5s]" format, __FUNCTION__, __FILE__, __LINE__, g_log_level_name[level], ##__VA_ARGS__);
#define CMD_TRACE(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CMD_DEBUG(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CMD_INFO(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CMD_WARN(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define CMD_ERROR(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CMD_FATAL(format, ...) CMD_PRINTF(CMD_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)

#endif // __LOGGING__H__