#pragma once
#ifndef __LOGGING__H__
#define __LOGGING__H__

#include <stdbool.h>
#include <stdio.h>

#include "../external/dbg.h"

enum CMD_LOG_LEVEL {
  CMD_LOG_LEVEL_TRACE = 0,
  CMD_LOG_LEVEL_DEBUG,
  CMD_LOG_LEVEL_INFO,
  CMD_LOG_LEVEL_WARN,
  CMD_LOG_LEVEL_ERROR,
  CMD_LOG_LEVEL_FATAL,
  CMD_LOG_LEVEL_NONE,
  CMD_LOG_LEVEL_SIZE,
};

typedef struct {
  int level;
  bool unsafe_log_apdu;
} CMD_LOG_CONFIG;

extern const char *g_log_level_name[CMD_LOG_LEVEL_SIZE];

extern bool cmd_parse_log_level(const char *value, int *level);
extern bool cmd_parse_bool(const char *value, bool *result);
extern int cmd_init_logging(const char *log_file, CMD_LOG_CONFIG config);
extern int cmd_stop_logging();
extern FILE *cmd_get_log_file(void);
extern bool cmd_should_log(const int level);
extern bool cmd_unsafe_log_apdu_enabled(void);
extern void cmd_printlogf(const int level, const char *function, const char *file, const int line, const char *format,
                          ...);
extern void cmd_print_hex(const int level, const void *data, size_t size);
extern void cmd_print_stack();

#define CMD_PRINTLOGF(level, format, ...)                                                                              \
  do {                                                                                                                 \
    if (__builtin_expect(!cmd_should_log((level)), true)) {                                                            \
      break;                                                                                                           \
    }                                                                                                                  \
    cmd_printlogf((level), __FUNCTION__, __FILE__, __LINE__, format, ##__VA_ARGS__);                                   \
  } while (0)
#define CMD_TRACE(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_TRACE, format, ##__VA_ARGS__)
#define CMD_DEBUG(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)
#define CMD_INFO(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define CMD_WARN(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_WARN, format, ##__VA_ARGS__)
#define CMD_ERROR(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define CMD_FATAL(format, ...) CMD_PRINTLOGF(CMD_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)
#define CMD_PRINT_HEX(data, size) cmd_print_hex(CMD_LOG_LEVEL_DEBUG, (data), (size));

#ifdef CMD_VERBOSE
#define FUNC_TRACE(CALL) dbg(CALL)
#define CMD_RETURN_IMPL(ARG, NAME, REASON)                                                                             \
  do {                                                                                                                 \
    CMD_DEBUG("Returning %s = %d: \"%s\"", NAME, (ARG), REASON);                                                       \
    return (ARG);                                                                                                      \
  } while (0)
#define CMD_LOG_FUNC(...) CMD_DEBUG("Called: " __VA_ARGS__)
#else
#define FUNC_TRACE(CALL) (CALL)
#define CMD_RETURN_IMPL(ARG, ...) return (ARG);
#define CMD_LOG_FUNC(...)
#endif // CMD_VERBOSE

#define CMD_RETURN(ARG, REASON) CMD_RETURN_IMPL(ARG, #ARG, REASON)

#define CMD_RET_OK CMD_RETURN(SCARD_S_SUCCESS, "success")

#define CMD_RET_UNIMPL CMD_RETURN(SCARD_E_UNSUPPORTED_FEATURE, "should be supported (not implemented now)")

#define CMD_ENSURE_NONNULL(PTR, ERR)                                                                                   \
  do {                                                                                                                 \
    __typeof__((PTR)) _ptr = (PTR);                                                                                    \
    if (_ptr == NULL) {                                                                                                \
      CMD_RETURN_IMPL(ERR, #ERR, #PTR " is NULL");                                                                     \
    }                                                                                                                  \
    __builtin_assume(_ptr != NULL);                                                                                    \
  } while (0)

#define CMD_ENSURE_VALID_HANDLE(PTR, ERR)                                                                              \
  do {                                                                                                                 \
    __typeof__((PTR)) _ptr = (PTR);                                                                                    \
    if (_ptr == 0) {                                                                                                   \
      CMD_RETURN_IMPL(ERR, #ERR, #PTR " is NULL");                                                                     \
    }                                                                                                                  \
  } while (0)

#define CMD_NONNULL_PARAM(PTR) CMD_ENSURE_NONNULL(PTR, SCARD_E_INVALID_PARAMETER)

#define CMD_CHECK_DW_FLAGS                                                                                             \
  do {                                                                                                                 \
    if (dwFlags != 0) {                                                                                                \
      CMD_RETURN(SCARD_E_INVALID_PARAMETER, "dwFlags is not zero");                                                    \
    }                                                                                                                  \
  } while (0)

#define CMD_UNUSED(...)                                                                                                \
  do {                                                                                                                 \
    ((void)(__VA_ARGS__))                                                                                              \
  } while (0)

#define CMD_GET_CTX(PCARD, CTX)                                                                                        \
  CMD_CONTEXT_PTR CTX = (CMD_CONTEXT_PTR)(PCARD)->pvVendorSpecific;                                                    \
  CMD_NONNULL_PARAM(CTX)

#endif // __LOGGING__H__
