#ifndef XRPC_CONFIG_H
#define XRPC_CONFIG_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "xrpc/error.h"

/*
 * ==================================================================
 * Server configuration system
 * ==================================================================
 */

/*
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_transport_tcp_config {
  struct sockaddr_in addr;

  // TCP-specific options
  bool nodelay;            // TCP_NODELAY (disable Nagle)
  bool reuseaddr;          // SO_REUSEADDR
  bool reuseport;          // SO_REUSEPORT
  bool keepalive;          // SO_KEEPALIVE
  int keepalive_idle;      // TCP_KEEPIDLE (seconds)
  int keepalive_interval;  // TCP_KEEPINTVL (seconds)
  int keepalive_probes;    // TCP_KEEPCNT
  int send_timeout_ms;     // SO_SNDTIMEO
  int recv_timeout_ms;     // SO_RCVTIMEO
  uint32_t listen_backlog; // listen() backlog

  // Buffer size
  int send_buffer_size; // SO_SNDBUF
  int recv_buffer_size; // SO_RCVBUF

  // Non blocking mode
  bool nonblocking; // Set O_NONBLOCK

  int accept_timeout_ms; // Puts a timeout (using `select()`) on the socket sot
                         // that even if when blocking, we are allowed to run an
                         // event loop. Set `0` to disable non blocking. This
                         // parameter is ignored if `nonblocking = true`

  int connection_pool_size; // size of the connection pool to preallocate
                            // connection memory
};

enum xrpc_transport_type {
  XRPC_TRANSPORT_TCP,
};

enum xrpc_io_system_type {
  XRPC_IO_SYSTEM_BLOCKING,
};

struct xrpc_transport_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_transport_tcp_config tcp;
  } config;
};

struct xrpc_io_system_config {
  enum xrpc_io_system_type type;
  union {
  } config;
  size_t max_concurrent_operations;
};

struct xrpc_server_config {
  struct xrpc_transport_config transport;
  struct xrpc_io_system_config io;

  size_t max_concurrent_requests;
};

/*
 * @brief Build a TCP server configuration
 *
 *
 * @param[in] address Address to bind and listen on as a string.
 * @param[in] port    Port to bind and listen on
 * @param[out] config Pointer to the configuration to poulate
 *
 * @return XRPC_SUCCESS on success
 * @return XRPC_API_ERR_INVALID_ARGS if address or config are not valid
 */
static inline int
xrpc_tcpv4_server_build_default_config(const char *address, uint16_t port,
                                       struct xrpc_server_config *config) {

  if (!config || !address) return XRPC_API_ERR_INVALID_ARGS;

  int ret;
  struct xrpc_transport_tcp_config tcp_config = {0};

  config->transport.type = XRPC_TRANSPORT_TCP;

  ret = inet_pton(AF_INET, address, &tcp_config.addr.sin_addr);

  if (ret == 0) return XRPC_API_ERR_INVALID_ARGS;

  // create default TCP configuration
  tcp_config.nodelay = true;
  tcp_config.reuseaddr = false;
  tcp_config.reuseport = false;

  // keepalive
  tcp_config.keepalive = true;
  tcp_config.keepalive_idle = 60;
  tcp_config.keepalive_interval = 5;
  tcp_config.keepalive_probes = 3;

  // send and receive timeouts and buffer size
  tcp_config.send_timeout_ms = -1;
  tcp_config.recv_timeout_ms = -1;
  tcp_config.send_buffer_size = -1;
  tcp_config.recv_buffer_size = -1;

  tcp_config.nonblocking = true;
  tcp_config.accept_timeout_ms = 10;

  tcp_config.listen_backlog = 128;

  tcp_config.addr.sin_family = AF_INET;
  tcp_config.addr.sin_port = htons(port);

  // copy all the created config into the result
  memcpy(&config->transport.config.tcp, &tcp_config,
         sizeof(struct xrpc_transport_tcp_config));

  return XRPC_SUCCESS;
}

/*
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_client_connection_tcp_config {
  struct sockaddr_in addr;

  // TCP-specific options
  bool nodelay;           // TCP_NODELAY (disable Nagle)
  bool keepalive;         // SO_KEEPALIVE
  int keepalive_idle;     // TCP_KEEPIDLE (seconds)
  int keepalive_interval; // TCP_KEEPINTVL (seconds)
  int keepalive_probes;   // TCP_KEEPCNT
  int send_timeout_ms;    // SO_SNDTIMEO
  int recv_timeout_ms;    // SO_RCVTIMEO
  int connect_timeout_ms; // Timeout for the connect function

  // Buffer size
  int send_buffer_size; // SO_SNDBUF
  int recv_buffer_size; // SO_RCVBUF

  // Non blocking mode
  bool nonblocking; // Set O_NONBLOCK
};

struct xrpc_client_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_client_connection_tcp_config tcp;
  } transport_config;
};

/*
 * @brief Build a TCP client configuration with default values.
 *
 *
 * @param[in,out] config  The pointer to the configuration that will be
 * populated
 *
 * @return XRPC_SUCCESS on success
 * @return XRPC_API_ERR_INVALID_ARGS if config is NULL;
 */
static inline void
xrpc_tcpv4_client_build_default_config(struct xrpc_client_config *config) {

  if (!config) return;

  struct xrpc_client_connection_tcp_config tcp_config = {0};

  config->type = XRPC_TRANSPORT_TCP;

  tcp_config.nodelay = true;
  tcp_config.keepalive = true;
  tcp_config.keepalive_idle = 60;
  tcp_config.keepalive_interval = 5;
  tcp_config.keepalive_probes = 3;
  tcp_config.send_timeout_ms = -1;
  tcp_config.recv_timeout_ms = -1;
  tcp_config.send_buffer_size = -1;
  tcp_config.recv_buffer_size = -1;

  tcp_config.nonblocking = false;
  tcp_config.connect_timeout_ms = 0;

  memcpy(&config->transport_config.tcp, &tcp_config,
         sizeof(struct xrpc_client_connection_tcp_config));
}
#endif // !XRPC_CONFIG_H
