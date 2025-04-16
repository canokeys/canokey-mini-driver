#pragma once
#ifndef __LOGGING__H__
#define __LOGGING__H__

#include <stdbool.h>
#include <stdio.h>

#include "external/dbg.h"

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

extern const char *g_log_level_name[CMD_LOG_LEVEL_SIZE];

extern FILE *g_log_file;
extern int g_log_level;

extern int cmd_init_logging(const char *log_file, const int log_level);
extern int cmd_stop_logging();
extern void cmd_fprintf(const int level, const bool prepend_date, FILE *const out, const char *const format, ...);
extern void cmd_print_stack();

#define CMD_PRINTLOGF(level, format, ...)                                                                              \
  cmd_fprintf(level, true, stderr, "%-20s(%-20s:L%03d)[%-5s]: ", __FUNCTION__, __FILE__, __LINE__,                     \
              g_log_level_name[level]);                                                                                \
  cmd_fprintf(level, false, stderr, format "\n", ##__VA_ARGS__);
#define CMD_TRACE(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CMD_DEBUG(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CMD_INFO(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CMD_WARN(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define CMD_ERROR(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CMD_FATAL(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)

#ifdef CMD_VERBOSE
#define FUNC_TRACE(CALL) dbg(CALL)
#define CMD_RETURN_IMPL(ARG, NAME, REASON)                                                                             \
  do {                                                                                                                 \
    CMD_DEBUG("Returning %s = %d: \"%s\"", NAME, (ARG), REASON);                                                       \
    return (ARG);                                                                                                      \
  } while (0)
#define CMD_LOG_FUNC(name, ...) CNK_DEBUG("Called: ", __VA_ARGS__)
#else
#define FUNC_TRACE(CALL) (CALL)
#define CMD_RETURN_IMPL(ARG, ...) return (ARG);
#define CMD_LOG_FUNC(name, ...)
#endif // CMD_VERBOSE

#define CMD_RETURN(ARG, REASON) CMD_RETURN_IMPL(ARG, #ARG, REASON)
#define CMD_RET_OK CMD_RETURN(SCARD_S_SUCCESS, "success");
#define CMD_RET_UNIMPL CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "should be supported (not implemented now)");

#define CMD_ENSURE_NONNULL(PTR, ERR)                                                                                   \
  do {                                                                                                                 \
    typeof((PTR)) _ptr = (PTR);                                                                                        \
    if (_ptr == NULL) {                                                                                                \
      CMD_RETURN_IMPL(ERR, #ERR, #PTR " is NULL");                                                                     \
    }                                                                                                                  \
    __builtin_assume(_ptr != NULL);                                                                                    \
  } while (0)
#define CMD_NONNULL_PARAM(PTR) CMD_ENSURE_NONNULL(PTR, SCARD_E_INVALID_PARAMETER)

#define CMD_UNUSED(...)                                                                                                \
  do {                                                                                                                 \
    ((void)(__VA_ARGS__))                                                                                              \
  } while (0)

#endif // __LOGGING__H__
