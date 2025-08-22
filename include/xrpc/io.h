#ifndef XRPC_IO_H
#define XRPC_IO_H

#include <stddef.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/pool.h"

/*
 * The `xrpc_io` abstraction provides methods to handle I/O dispatching,
 * multiplexing, scheduling at a per connection level.
 */
struct xrpc_io_system;
struct xrpc_io_system_config;

enum xrpc_io_type {
  XRPC_IO_READ,
  XRPC_IO_WRITE,
};

struct xrpc_io_operation {
  enum xrpc_io_type type;
  struct xrpc_connection *conn;
  void *buf;
  size_t len;
  size_t transferred_bytes;

  void (*on_complete)(struct xrpc_io_operation *op);
  int status;
  void *ctx; // this should be the context data of the request
};

/*
 * I/O operations API
 */
struct xrpc_io_system_ops {

  /*
   * @brief Creates a new I/O system management instance.
   *
   * @params[in,out] xio  Pointer to the `xrpc_io` instance allocated if
   * successful.
   * @params[in] cfg      Pointer to valid configuration
   */
  int (*init)(struct xrpc_io_system **xio,
              const struct xrpc_io_system_config *args);

  /*
   * @brief Creates a new I/O system management instance.
   *
   * @params[in,out] xio  Pointer to the `xrpc_io` instance allocated if
   * successful.
   * @params[in] cfg      Pointer to valid configuration
   */
  int (*schedule_operation)(struct xrpc_io_system *xio,
                            struct xrpc_io_operation *op);

  /*
   * @brief Polls for events.
   *
   * @params[in,out] xio  Pointer to the `xrpc_io`instance allocated if
   * successful.
   */
  int (*poll)(struct xrpc_io_system *xio);

  /*
   * @brief Releases the allocated resources

   * @param[in] t  Pointer to the transport instance
   */
  void (*free)(struct xrpc_io_system *xio);
};

struct xrpc_io_system {
  const struct xrpc_io_system_ops *ops;
  struct xrpc_pool *op_pool;
  void *data; // implementation specific data
};

/*
 * Utilities to create and destory operations struct using the internal pool.
 * Users must use these functions to get the I/O system work properly.
 */
/*
 * @brief Creates a new operation reusing a pre allocated memory space
 *
 * @param[in] io  The I/O system instance
 * @param[out] op The operation allocated
 *
 * @return XRPC_SUCCESS on success
 * @return XRPC_INTERNAL_ERR_ALLOC when the allocation fails
 * @return XRPC_INTERNAL_POOL_EMPTY when the pool is empty
 */
static inline int xrpc_io_operation_new(struct xrpc_io_system *io,
                                        struct xrpc_io_operation **op) {

  if (!io || !op) return XRPC_INTERNAL_ERR_POOL_INVALID_ARG;

  return xrpc_pool_get(io->op_pool, (void **)op);
}

/*
 * @brief Release the operation resources
 *
 * @param[in] io The I/O system instance
 * @param[in] op The operation to be freed
 *
 * @return XRPC_SUCCESS on success
 * @return XRPC_INTERNAL_POOL_FULL when the pool is full
 */
static inline int xrpc_io_operation_free(struct xrpc_io_system *io,
                                         struct xrpc_io_operation *op) {

  if (!io || !op) return XRPC_INTERNAL_ERR_POOL_INVALID_ARG;

  memset(op, 0, sizeof(struct xrpc_io_operation));

  return xrpc_pool_put(io->op_pool, op);
}

extern const struct xrpc_io_system_ops xrpc_blocking_ops;
#endif // ! XRPC_IO_H
