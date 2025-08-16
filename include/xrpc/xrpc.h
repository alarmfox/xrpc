#ifndef __XRPC_H
#define __XRPC_H

#include <netinet/in.h>
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
struct xrpc_server_unix_config {
  struct sockaddr_un addr;
};

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_server_tcp_config {
  struct sockaddr_in addr;
};

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_server_tls_config {
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

struct xrpc_server_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_server_unix_config unix;
    struct xrpc_server_tcp_config tcp;
    struct xrpc_server_tls_config tls;
  } config;
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

int xrpc_transport_server_init(struct xrpc_transport **t,
                               const struct xrpc_server_config *c);
// void xrpc_transport_server_free(struct xrpc_transport *t);

/**
 * @brief Create and initialize an xrpc server.
 *
 * @param[out] srv       Pointer to allocated server instance.
 * @param[in]  t         Transport instance (already initialized via
 * xrpc_transport_server_init()).
 * @return 0 on success, -1 on error.
 */
int xrpc_server_create(struct xrpc_server **srv, struct xrpc_transport *t);

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
 * @brief Shut down and free server resources.
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
    .type = XRPC_TRANSPORT_TCP,                                                \
    .config.tcp = {                                                            \
        .addr =                                                                \
            {                                                                  \
                .sin_family = AF_INET,                                         \
                .sin_port = htons(port_),                                      \
                .sin_addr.s_addr = htonl(addr_),                               \
            },                                                                 \
    },                                                                         \
  }

#define XRPC_UNIX_SERVER_DEFAULT_CONFIG(path_)                                 \
  {                                                                            \
    .type = XRPC_TRANSPORT_UNIX,                                               \
    .config.unix = {                                                           \
        .addr = {.sun_family = AF_UNIX, .sun_path = path_},                    \
    },                                                                         \
  }
#endif // __XRPC_H
