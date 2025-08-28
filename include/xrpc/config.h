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
/* Default configuration values */
#define XRPC_DEFAULT_LISTEN_BACKLOG 128
#define XRPC_DEFAULT_CONNECTION_POOL_SIZE 128
#define XRPC_DEFAULT_MAX_CONCURRENT_OPS 1024
#define XRPC_DEFAULT_MAX_CONCURRENT_REQS 1024
#define XRPC_DEFAULT_KEEPALIVE_IDLE 60
#define XRPC_DEFAULT_KEEPALIVE_INTERVAL 5
#define XRPC_DEFAULT_KEEPALIVE_PROBES 3
#define XRPC_DEFAULT_ACCEPT_TIMEOUT_MS 10
#define XRPC_DEFAULT_CONNECT_TIMEOUT_MS 5000

/* Special timeout values */
/*
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_transport_tcp_config {
  struct sockaddr_in addr; /* Server address and port */

  /* TCP socket options */
  bool nodelay;   /* TCP_NODELAY (disable Nagle algorithm) */
  bool reuseaddr; /* SO_REUSEADDR (reuse local address) */
  bool reuseport; /* SO_REUSEPORT (load balance across processes) */
  bool keepalive; /* SO_KEEPALIVE (enable TCP keepalive) */

  /* TCP keepalive parameters */
  int keepalive_idle_sec;     /* TCP_KEEPIDLE (idle time before probes) */
  int keepalive_interval_sec; /* TCP_KEEPINTVL (interval between probes) */
  int keepalive_probes;       /* TCP_KEEPCNT (number of probes) */

  /* Timeout configuration (in milliseconds, -1 = infinite, 0 = disabled) */
  int send_timeout_ms;   /* SO_SNDTIMEO (send operation timeout) */
  int recv_timeout_ms;   /* SO_RCVTIMEO (receive operation timeout) */
  int accept_timeout_ms; /* Accept operation timeout for event loop */

  /* Buffer sizes (-1 = system default) */
  int send_buffer_size; /* SO_SNDBUF (send buffer size) */
  int recv_buffer_size; /* SO_RCVBUF (receive buffer size) */

  /* Connection management */
  uint32_t listen_backlog; /* listen() backlog queue size */
  bool nonblocking;        /* Set O_NONBLOCK flag */
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
  size_t connection_pool_size;
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
                                       struct xrpc_transport_config *config) {

  if (!config || !address || port == 0) return XRPC_API_ERR_INVALID_ARGS;

  /* Initialize the entire structure to zero */
  memset(config, 0, sizeof(struct xrpc_server_config));

  int ret;
  struct xrpc_transport_tcp_config tcp_config = {0};
  /* Configure transport layer */
  config->type = XRPC_TRANSPORT_TCP;
  config->connection_pool_size = XRPC_DEFAULT_CONNECTION_POOL_SIZE;

  ret = inet_pton(AF_INET, address, &tcp_config.addr.sin_addr);

  if (ret == 0) return XRPC_API_ERR_INVALID_ARGS;

  /* Set up socket address */
  tcp_config.addr.sin_family = AF_INET;
  tcp_config.addr.sin_port = htons(port);

  /* Configure TCP socket options with production defaults */
  tcp_config.nodelay = true;    /* Disable Nagle for low latency */
  tcp_config.reuseaddr = true;  /* Allow rapid server restart */
  tcp_config.reuseport = false; /* Single process by default */
  tcp_config.keepalive = true;  /* Enable connection monitoring */

  /* Configure keepalive parameters */
  tcp_config.keepalive_idle_sec = XRPC_DEFAULT_KEEPALIVE_IDLE;
  tcp_config.keepalive_interval_sec = XRPC_DEFAULT_KEEPALIVE_INTERVAL;
  tcp_config.keepalive_probes = XRPC_DEFAULT_KEEPALIVE_PROBES;

  /* Configure timeouts */
  tcp_config.send_timeout_ms = 0;
  tcp_config.recv_timeout_ms = 0;
  tcp_config.accept_timeout_ms = 0;

  /* Configure buffer sizes (use system defaults) */
  tcp_config.send_buffer_size = -1;
  tcp_config.recv_buffer_size = -1;

  /* Configure connection management */
  tcp_config.listen_backlog = XRPC_DEFAULT_LISTEN_BACKLOG;
  tcp_config.nonblocking = true; /* Enable non-blocking I/O */

  memcpy(&config->config.tcp, &tcp_config,
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
