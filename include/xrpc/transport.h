#ifndef XRPC_TRANSPORT_H
#define XRPC_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The `xrpc_transport` abstraction provides method to manage low level
 * connections.
 */

// Forward declarations
struct xrpc_transport;
struct xrpc_connection;
struct xrpc_transport_config;

/*
 * Transport API. This is meant to be used directly by the server
 */
struct xrpc_transport_ops {
  /*
   * @brief Creates a new transport instance.
   *
   * This function creates a transport for the specific implementation. `args`
   * must point to a valid configuration. The `transport` is ready to accept
   * connections.
   *
   * @param[in,out] t  Pointer to the transport instance allocated, if
   * successful
   * @param[in] args   Pointer to a valid args struct
   *
   */
  int (*init)(struct xrpc_transport **t,
              const struct xrpc_transport_config *args);

  /*
   * @brief Closes the listening process (no more requests are accepted) and
   frees resources.

   * @param[in] t  Pointer to the transport instance
   */
  void (*free)(struct xrpc_transport *t);

  /*
   * @brief Accept a new client connection if available.
   *
   * This function checks for an incoming connection. All configuration in the
   * init apply If a new client is waiting, it accepts the connection and stores
   * its state inside the xrpc_connection.
   *
   * This call may block depending on the transport implementation and socket
   * mode.
   *
   * @param[in] t      Pointer to the transport instance.
   * @param[in,out] c  Pointer to the new allocated connection.
   *
   * @retval  0  A new client was successfully accepted.
   * @retval -1  No new client available or an error occurred.
   */
  int (*accept)(struct xrpc_transport *t, struct xrpc_connection **c);

  /*
   * @brief Closes the connection.
   *
   * This is implemented in the transport API because it allows connection
   * pooling
   *
   * @param[in] t  Pointer to the transport instance.
   * @param[in] c  Pointer to the connection to close.
   */
  void (*close)(struct xrpc_transport *t, struct xrpc_connection *c);
};

/*
 * Connection operations. It is meant to be used by the I/O systems.
 */
struct xrpc_connection_ops {
  /**
   * @brief Receives a len bytes from the connection.
   *
   * Attempts to read `len` bytes from the `conn` into *buf writing in
   * `*bytes_read` the number of bytes read.
   *
   * @param[in,out] conn    Pointer to the connection instance.
   * @param[out] buf        Pointer to buffer to store received bytes.
   * @param[in]  len        Number of bytes to read.
   * @param[out] bytes_read Number of bytes read
   *
   * @retval  0  Request successfully received.
   * @retval -1  An error occurred (including client disconnection).
   */
  int (*recv)(struct xrpc_connection *conn, void *buf, size_t len,
              size_t *bytes_read);

  /**
   * @brief Send a buf of `len` bytes on the connection.
   *
   * Attempts to write `len` bytes to the connection from `buf` writing in
   * `bytes_written` the number of bytes written.
   *
   * @param[in,out] t           Pointer to the connection instance.
   * @param[in]  buf            Pointer to buffer containing data to send.
   * @param[in]  len            Number of bytes to send.
   * @param[out] bytes_written  Number of bytes read
   *
   * @retval  0  Response successfully sent.
   * @retval -1  An error occurred while sending.
   */
  int (*send)(struct xrpc_connection *conn, const void *buf, size_t len,
              size_t *bytes_written);
};

struct xrpc_connection {
  const struct xrpc_connection_ops *ops;
  int ref_count;   // number of contexts that uses this connection
  bool is_closed;  // connection is closed
  bool is_closing; // connection marked for closing. Cannot be assigned to
                   // contexts
  uint64_t id;     // unique connection ID. Useful for connection pooling
  void *data;
};

struct xrpc_transport {
  const struct xrpc_transport_ops *ops;
  void *data; // transport specific data
};

/*
 * Exporting VTables abstracting different transport implementation
 *
 */
extern const struct xrpc_transport_ops xrpc_transport_tcp_ops;

/*
 * Utilities to help managing the connection lifecycle
 */

static inline bool connection_is_valid(struct xrpc_connection *c) {
  if (!c) return false;
  if (c->is_closed || c->is_closing) return false;
  return true;
}

static inline void connection_mark_for_close(struct xrpc_connection *c) {
  if (!c) return;
  c->is_closing = true;
}

static inline void connection_ref(struct xrpc_transport *t,
                                  struct xrpc_connection *c) {
  (void)t;
  if (!c) return;

  c->ref_count++;
}

static inline void connection_unref(struct xrpc_transport *t,
                                    struct xrpc_connection *c) {
  if (!c || !t) return;

  c->ref_count--;

  // if the ref_count <= 0 and the conn is closing close safely the underlying
  // connection
  if (c->ref_count <= 0 && c->is_closing) {
    if (t->ops->close) t->ops->close(t, c);
    c->is_closed = true;
  }
}

#endif // !XRPC_TRANSPORT_H
