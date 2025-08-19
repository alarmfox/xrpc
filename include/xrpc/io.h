#ifndef XRPC_IO_H
#define XRPC_IO_H

#include <stddef.h>

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
  void *data; // implementation specific data
};

extern const struct xrpc_io_system_ops xrpc_blocking_ops;
#endif // ! XRPC_IO_H
