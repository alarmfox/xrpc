#ifndef XRPC_H
#define XRPC_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/un.h>

struct xrpc_transport;
/**
 * @brief RPC request header
 *
 * Before sending the requests, the client will send the header containng the
 * selected operation and the size of the request.
 */
struct __attribute__((packed)) xrpc_request_header {
  uint32_t op;    /* Operation ID */
  uint32_t sz;    /* Size of the payload */
  uint64_t reqid; /* Request identifier */
};

// Response status flags
enum xrpc_response_status {
  XRPC_RESPONSE_SUCCESS = 1 << 0,
  XRPC_RESPONSE_INTERNAL_ERROR = 1 << 1,
  XRPC_RESPONSE_UNSUPPORTED_HANDLER = 1 << 2,
  XRPC_RESPONSE_INVALID_PARAMS = 1 << 3,
};
/**
 * @brief RPC response header
 *
 * Before sending the response, the server will send the header containng the
 * selected operation and the size of the request and a byte status.
 */
struct __attribute__((packed)) xrpc_response_header {
  uint32_t op;    /* Operation ID*/
  uint32_t sz;    /* Size of the payload */
  uint64_t reqid; /* Request identifier */
  uint8_t status; /* Status byte */
};

/**
 * @brief An incoming RPC request.
 *
 * The server provides a pointer to the request data. The handler is assumed to
 * not modify the request. It contains a prefixed struct xrpc_request_header.
 *
 * */
struct __attribute__((packed)) xrpc_request {
  struct xrpc_request_header *hdr; /* Header of the request */
  const void *data;                /**< Pointer to request payload */
};

/**
 * @brief An outgoint RPC response.
 *
 * The server provides a pointer to the request data and a buffer for the
 * handler to write its response. The handler is responsible for filling in the
 * data (up to hdr->sz) and updating the hdr->sz with the actual bytes
 * number of response.
 */
struct __attribute__((packed)) xrpc_response {
  struct xrpc_response_header *hdr; /* Header of the request */
  void *data;                       /**< Buffer for writing response data */
};

/*
 * ==================================================================
 * Server configuration system
 * ==================================================================
 */

/*
 * @brief Unix transport configuration struct.
 *
 * Unix transport configuration struct. Contains sockaddr_un which contains the
 * path for the socket.
 *
 */
struct xrpc_transport_unix_config {
  struct sockaddr_un addr;
};

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

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_transport_tls_config {
  const char *address;
  const char *port;
  const char *crt_path;
  const char *key_path;
};

enum xrpc_transport_type {
  XRPC_TRANSPORT_UNIX,
  XRPC_TRANSPORT_TCP,
  XRPC_TRANSPORT_TLS,
};

enum xrpc_io_system_type {
  XRPC_IO_SYSTEM_BLOCKING,
};

struct xrpc_transport_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_transport_unix_config unix;
    struct xrpc_transport_tcp_config tcp;
    struct xrpc_transport_tls_config tls;
  } config;
};

struct xrpc_io_system_config {
  enum xrpc_io_system_type type;
  union {
  } config;
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
 * @brief Free server resources.
 *
 * Frees ring buffers, closes connections, and releases the transport.
 *
 * @param srv  Server instance to free.
 */
void xrpc_server_free(struct xrpc_server *srv);

/*
 * ==================================================================
 * Client configuration system
 * ==================================================================
 */

/*
 * ==================================================================
 * Client API
 * ==================================================================
 */
struct xrpc_client;

/**
 * @brief Unix transport configuration struct.
 *
 * Unix transport configuration struct. Contains sockaddr_un which contains the
 * path for the socket.
 *
 */
struct xrpc_client_unix_config {
  struct sockaddr_un addr;
};

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_client_tcp_config {
  struct sockaddr_in addr;
};

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_client_tls_config {
  const char *address;
  const char *port;
  const char *crt_path;
  const char *key_path;
};

struct xrpc_client_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_client_unix_config unix;
    struct xrpc_client_tcp_config tcp;
    struct xrpc_client_tls_config tls;
  } config;
};

/*
 * Init unix client
 */
int xrpc_transport_client_init(struct xrpc_transport **t,
                               const struct xrpc_client_config *c);

/**
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @param[in]  t    Initialized transport instance (connected to server).
 * @return 0 on success, -1 on error.
 */
int xrpc_client_init(struct xrpc_client **cli, struct xrpc_transport *t);

/**
 * @brief Perform a synchronous RPC call.
 *
 * @param cli   Client instance.
 * @param rq    Pointer to request (hdr + data must be filled).
 * @param rs    Pointer to response (hdr + data buffer must be allocated).
 * @return 0 on success, -1 on error.
 */
int xrpc_call(struct xrpc_client *cli, const struct xrpc_request *rq,
              struct xrpc_response *rs);

/**
 * @brief Close client and free resources.
 */
void xrpc_client_free(struct xrpc_client *cli);

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

#define XRPC_UNIX_SERVER_DEFAULT_CONFIG(path_)                                 \
  {                                                                            \
    .type = XRPC_TRANSPORT_UNIX,                                               \
    .config.unix = {                                                           \
        .addr = {.sun_family = AF_UNIX, .sun_path = path_},                    \
    },                                                                         \
  }
#endif // XRPC_H
