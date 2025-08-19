#ifndef XRPC_DEBUG_H
#define XRPC_DEBUG_H
#include <stdio.h>

#ifdef DEBUG
#define XRPC_DEBUG_PRINT(fmt, ...)                                             \
  do {                                                                         \
    fprintf(stderr, "[XRPC-DEBUG] " fmt "\n", ##__VA_ARGS__);                  \
  } while (0);
#else
#define XRPC_DEBUG_PRINT(fmt, ...)                                             \
  do {                                                                         \
  } while (0)
#endif

#ifdef DEBUG
#define XRPC_PRINT_ERR_AND_RETURN(fmt, retcode, ...)                           \
  do {                                                                         \
    fprintf(stderr, "[XRPC-DEBUG] " fmt "\n", ##__VA_ARGS__);                  \
    return retcode;                                                            \
  } while (0)
#else
#define XRPC_PRINT_ERR_AND_RETURN(fmt, ...)                                    \
  do {                                                                         \
  } while (0)
#endif

/*
 * Print errno description and return given error code.
 * Usage:
 *    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("bind", XRPC_ERR_BIND);
 */
#ifdef DEBUG
#include <errno.h>
#include <string.h>
#define XRPC_PRINT_SYSCALL_ERR_AND_RETURN(syscall_name, retcode)               \
  do {                                                                         \
    fprintf(stderr, "[XRPC-DEBUG] %s failed: %s (errno=%d)\n", syscall_name,   \
            strerror(errno), errno);                                           \
    return (retcode);                                                          \
  } while (0)
#else
#define XRPC_PRINT_SYSCALL_ERR_AND_RETURN(syscall_name, retcode)               \
  do {                                                                         \
    return (retcode);                                                          \
  } while (0)
#endif

#endif // XRPC_DEBUG_H
