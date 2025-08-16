#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <stddef.h>

// Forward declarations
struct xrpc_transport;

/*
 * VTable approach to support different transports at runtime.
 */
struct xrpc_transport_ops {
  /**
   * @brief Accept a new client connection if available.
   *
   * This function checks for an incoming connection on the listening socket.
   * If a new client is waiting, it accepts the connection and stores its state
   * inside the transport object.
   *
   * This call may block depending on the transport implementation and socket
   * mode.
   *
   * @param[in,out] t  Pointer to the transport instance.
   *
   * @retval  0  A new client was successfully accepted.
   * @retval -1  No new client available or an error occurred.
   */
  int (*poll_client)(struct xrpc_transport *t);
  /*
   * @brief Release the client
   *
   * Frees the current client. Must be called after every connection
   *
   * @param[in,out] t  Pointer to the transport instance.
   */
  void (*release_client)(struct xrpc_transport *t);

  /**
   * @brief Receive a request from the connected client.
   *
   * Reads a complete `struct request` from the currently connected client.
   * This function blocks until the full request is received or an error occurs.
   *
   * @param[in,out] t   Pointer to the transport instance.
   * @param[out] buf    Pointer to buffer to store received bytes.
   * @param[in]  len    Number of bytes to read.
   *
   * @retval  0  Request successfully received.
   * @retval -1  An error occurred (including client disconnection).
   */
  int (*recv)(struct xrpc_transport *t, void *buf, size_t len);

  /**
   * @brief Send a response to the connected client.
   *
   * Writes a complete `struct response` to the currently connected client.
   * The function will marshal the response into network byte order before
   * sending.
   *
   * @param[in,out] t  Pointer to the transport instance.
   * @param[in]  buf   Pointer to buffer containing data to send.
   * @param[in]  len   Number of bytes to send.
   *
   * @retval  0  Response successfully sent.
   * @retval -1  An error occurred while sending.
   */
  int (*send)(struct xrpc_transport *t, const void *buf, size_t len);
};

struct xrpc_server_unix_config;
struct xrpc_server_tcp_config;
struct xrpc_server_tls_config;

struct xrpc_transport {
  const struct xrpc_transport_ops *ops;
  void *data; // transport specific data
};

/*
 * Internal transport server API
 */
int xrpc_transport_server_init_unix(struct xrpc_transport **t,
                                    const struct xrpc_server_unix_config *args);
int xrpc_transport_server_init_tcp(struct xrpc_transport **t,
                                   const struct xrpc_server_tcp_config *args);
int xrpc_transport_server_init_tls(struct xrpc_transport **t,
                                   const struct xrpc_server_tls_config *args);

static inline int xrpc_transport_server_poll_client(struct xrpc_transport *t) {
  return t->ops->poll_client(t);
}

static inline void
xrpc_transport_server_release_client(struct xrpc_transport *t) {
  return t->ops->release_client(t);
}

static inline int xrpc_transport_server_send(struct xrpc_transport *t,
                                             const void *data, size_t s) {
  return t->ops->send(t, data, s);
}

static inline int xrpc_transport_server_recv(struct xrpc_transport *t,
                                             void *data, size_t s) {
  return t->ops->recv(t, data, s);
}

#endif // !__TRANSPORT_H
