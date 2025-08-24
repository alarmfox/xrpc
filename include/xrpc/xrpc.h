#ifndef XRPC_H
#define XRPC_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/un.h>

#include "xrpc/protocol.h"

/*
 * ==================================================================
 * Server configuration system
 * ==================================================================
 */

/**
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
  struct xrpc_transport_config *tcfg;
  struct xrpc_io_system_config *iocfg;

  size_t max_concurrent_requests;
};

/*
 * ==================================================================
 * Server API
 * ==================================================================
 */

// Forward definitions
struct xrpc_server;

/**
 * @brief RPC handler function signature.
 *
 * @param req  Pointer to the incoming request data.
 * @return 0 on success, nonzero on error.
 */
typedef int (*xrpc_handler_fn)(const struct xrpc_request *req,
                               struct xrpc_response *res);

/**
 * @brief Creates and initializes an xrpc server including the underlying
 * transport.
 *
 * @param[out] srv       Pointer to allocated server instance.
 * @param[in]  cfg       Pointer to a valid xrpc_server_config
 *
 * @return 0 on success, -1 on error.
 */
int xrpc_server_create(struct xrpc_server **srv,
                       const struct xrpc_server_config *cfg);

// Register handler flags
enum xrpc_handler_register_flags {
  // Allows user to overwrite an existing handler without giving errors.
  XRPC_RF_OVERWRITE = 1 << 0,
};

/**
 * @brief Register an RPC handler for a given method name.
 *
 * @param srv       Server instance.
 * @param method    Identifier of the operation
 * @param handler   Function pointer to call when method is invoked.
 * @return 0 on success, -1 on error.
 */
int xrpc_server_register(struct xrpc_server *srv, const size_t op,
                         xrpc_handler_fn handler, const int flags);

/**
 * @brief Poll the server for new clients and requests, dispatch handlers, send
 * responses.
 *
 * This call processes one iteration of the server loop: it accepts new clients
 * if available, reads incoming requests, queues them, executes handlers,
 * and sends responses.
 *
 * @param srv         Server instance.
 * @return 0 on success, -1 on fatal error.
 */
int xrpc_server_run(struct xrpc_server *srv);

/**
 * @brief Flags the server to stop if running
 *
 * TODO: make user to choice between a graceful shutdown or to force
 *
 * @param srv         Server instance.
 * @return 0 on success, -1 on fatal error.
 */
void xrpc_server_stop(struct xrpc_server *srv);

/**
 * @brief Release server resources.
 *
 * @param srv  Server instance to free.
 */
void xrpc_server_free(struct xrpc_server *srv);

/*
 * ==================================================================
 * Client API
 * ==================================================================
 * These are the core functions to be used by the client.
 */

struct xrpc_client;

enum xrpc_client_status {
  XRPC_CLIENT_CONNECTED,
  XRPC_CLIENT_DISCONNECTED,
  XRPC_CLIENT_ERROR,
};
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
  int connect_timeout_ms;

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
  } config;
};

/*
 * @brief Creates a client but not does not connect to anything.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @return 0 on success, -1 on error.
 */
int xrpc_client_init(struct xrpc_client **cli);

/*
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to the client instance.
 * @param[in]  cfg  Pointer to client configuration
 * @return 0 on success, -1 on error.
 */
int xrpc_client_connect(struct xrpc_client *cli,
                        const struct xrpc_client_config *cfg);

/*
 * @brief Connect to an XRPC server.
 *
 * @param[in] cli  The client instance.
 * @return 0 on success, -1 on error.
 */
int xrpc_client_disconnect(struct xrpc_client *cli);

/*
 * @brief Perform a synchronous RPC call.
 *
 * @param[in] cli           Client instance.
 * @param[in] op            Operation ID
 * @param[in] request_data  Pointer to request payload (can be NULL)
 * @param[in] request_size  Size of request payload
 * @param[out] response     Pointer to allocated response (caller must free)
 * @return XRPC_SUCCESS on success, error code on failure.
 */
int xrpc_client_call_sync(struct xrpc_client *cli, uint32_t op,
                          const void *request_data, size_t request_size,
                          struct xrpc_response **response);

/*
 * @brief Close client and free resources.
 *
 * @param[in] cli Client instance
 */
void xrpc_client_free(struct xrpc_client *cli);

/*
 * @brief Get the current client status
 *
 * @param[in] cli Client instance
 */
enum xrpc_client_status xrpc_client_status_get(const struct xrpc_client *cli);

/*
 * @brief Check if a client is connected
 *
 * @param[in] cli Client instance
 * @param[out] true if the server is connected, false otherwise
 */
bool xrpc_client_is_connected(const struct xrpc_client *cli);

/*
 * @brief Return the server name
 *
 * @param[in] cli Client instance
 * @param[out] Server name if connected. "" otherwise.
 */
const char *xrpc_client_get_server_name(const struct xrpc_client *cli);

/*
 * ==================================================================
 * Configuration utils
 * ==================================================================
 */
#define XRPC_TCP_SERVER_DEFAULT_CONFIG(addr_, port_)                           \
  {                                                                            \
    .type = XRPC_TRANSPORT_TCP, .config.tcp = {                                \
      .addr =                                                                  \
          {                                                                    \
              .sin_family = AF_INET,                                           \
              .sin_port = htons(port_),                                        \
              .sin_addr.s_addr = htonl(addr_),                                 \
          },                                                                   \
      .nodelay = true,                                                         \
      .reuseaddr = false,                                                      \
      .reuseport = false,                                                      \
      .keepalive = true,                                                       \
      .keepalive_idle = 60,                                                    \
      .keepalive_interval = 5,                                                 \
      .keepalive_probes = 3,                                                   \
      .send_timeout_ms = -1,                                                   \
      .recv_timeout_ms = -1,                                                   \
      .listen_backlog = 128,                                                   \
      .send_buffer_size = -1,                                                  \
      .recv_buffer_size = -1,                                                  \
      .nonblocking = true,                                                     \
      .accept_timeout_ms = 0,                                                  \
      .connection_pool_size = 10,                                              \
    }                                                                          \
  }

#define XRPC_TCP_CLIENT_DEFAULT_CONFIG(addr_, port_)                           \
  {                                                                            \
    .type = XRPC_TRANSPORT_TCP, .config.tcp = {                                \
      .addr =                                                                  \
          {                                                                    \
              .sin_family = AF_INET,                                           \
              .sin_port = htons(port_),                                        \
              .sin_addr.s_addr = htonl(addr_),                                 \
          },                                                                   \
      .nodelay = true,                                                         \
      .keepalive = true,                                                       \
      .keepalive_idle = 60,                                                    \
      .keepalive_interval = 5,                                                 \
      .keepalive_probes = 3,                                                   \
      .send_timeout_ms = -1,                                                   \
      .recv_timeout_ms = -1,                                                   \
      .send_buffer_size = -1,                                                  \
      .recv_buffer_size = -1,                                                  \
      .nonblocking = true,                                                     \
      .connect_timeout_ms = 0,                                                 \
    }                                                                          \
  }
#endif // XRPC_H
