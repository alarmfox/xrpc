#ifndef __XRPC_DEBUG_H
#define __XRPC_DEBUG_H
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
#define _print_err_and_return(fmt, retcode, ...)                               \
  do {                                                                         \
    fprintf(stderr, "[XRPC-DEBUG] " fmt "\n", ##__VA_ARGS__);                  \
    return retcode;                                                            \
  } while (0)
#else
#define _print_err_and_return(fmt, ...)                                        \
  do {                                                                         \
  } while (0)
#endif

/*
 * Print errno description and return given error code.
 * Usage:
 *    _print_syscall_err_and_return("bind", XRPC_ERR_BIND);
 */
#ifdef DEBUG
#include <errno.h>
#include <string.h>
#define _print_syscall_err_and_return(syscall_name, retcode)                   \
  do {                                                                         \
    fprintf(stderr, "[XRPC-DEBUG] %s failed: %s (errno=%d)\n", syscall_name,   \
            strerror(errno), errno);                                           \
    return (retcode);                                                          \
  } while (0)
#else
#define _print_syscall_err_and_return(syscall_name, retcode)                   \
  do {                                                                         \
    return (retcode);                                                          \
  } while (0)
#endif

/*
 * Print mbedtls-specific error and return given error code.
 * Requires: mbedtls_strerror to be available.
 */
#ifdef DEBUG
#include "mbedtls/error.h"
#define _print_mbedtls_err_and_return(func_name, mbedtls_ret, retcode)         \
  do {                                                                         \
    char _mbed_err_buf[128];                                                   \
    mbedtls_strerror(mbedtls_ret, _mbed_err_buf, sizeof(_mbed_err_buf));       \
    fprintf(stderr, "[XRPC-DEBUG] %s failed: %s (ret=%d)\n", func_name,        \
            _mbed_err_buf, mbedtls_ret);                                       \
    return (retcode);                                                          \
  } while (0)
#else
#define _print_mbedtls_err_and_return(func_name, mbedtls_ret, retcode)         \
  do {                                                                         \
    return (retcode);                                                          \
  } while (0)
#endif

#endif // __XRPC_DEBUG_H
