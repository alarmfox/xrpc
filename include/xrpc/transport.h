#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <stddef.h>

// Forward declarations
struct xrpc_transport;
struct xrpc_connection;
struct xrpc_server_config;

/*
 * VTable approach to support different transports at runtime.
 */
struct xrpc_transport_ops {
  /*
   * @brief Creates a new transport instance
   *
   * This function creates a transport for the specific implementation. `args`
   * must point to a valid configuration. See `include/xrpc/config.h`
   *
   * @param[in,out] t  Pointer to the transport instance allocated, if
   * successful
   * @param[in] args   Pointer to a valid args struct
   *
   */
  int (*init)(struct xrpc_transport **t, const struct xrpc_server_config *args);

  /*
   * @brief Closes the server (no more requests are accepted) and frees
   resources.

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
  int (*accept_connection)(struct xrpc_transport *t,
                           struct xrpc_connection **c);
  /*
   * @brief Release the client
   *
   * Frees the current client. Must be called after every connection
   *
   * @param[in,out] c  Pointer to the connection to close. This is freed during
   * this call.
   */
  void (*close_connection)(struct xrpc_connection *c);

  /**
   * @brief Receive a request from the connected client.
   *
   * Reads a complete `struct request` from the currently connected client.
   * This function blocks until the full request is received or an error occurs.
   *
   * @param[in,out] conn   Pointer to the connection instance.
   * @param[out] buf    Pointer to buffer to store received bytes.
   * @param[in]  len    Number of bytes to read.
   *
   * @retval  0  Request successfully received.
   * @retval -1  An error occurred (including client disconnection).
   */
  int (*recv)(struct xrpc_connection *conn, void *buf, size_t len);

  /**
   * @brief Send a response to the connected client.
   *
   * Writes a complete `struct response` to the currently connected client.
   * The function will marshal the response into network byte order before
   * sending.
   *
   * @param[in,out] t  Pointer to the connection instance.
   * @param[in]  buf   Pointer to buffer containing data to send.
   * @param[in]  len   Number of bytes to send.
   *
   * @retval  0  Response successfully sent.
   * @retval -1  An error occurred while sending.
   */
  int (*send)(struct xrpc_connection *conn, const void *buf, size_t len);
};

struct xrpc_transport {
  const struct xrpc_transport_ops *ops;
  void *data; // transport specific data
};

extern const struct xrpc_transport_ops xrpc_transport_unix_ops;
extern const struct xrpc_transport_ops xrpc_transport_tcp_ops;
extern const struct xrpc_transport_ops xrpc_transport_tls_ops;

#endif // !__TRANSPORT_H
