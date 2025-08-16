#ifndef __XRPC_H
#define __XRPC_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>

// Opaque definitions
struct xrpc_server;
struct xrpc_client;
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
enum XRPC_RESPONSE_STATUS {
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
 * Server API

 * For now to me sounds good to propose different connection creation/teardown
 * instead of relying on some sort of enumeration/type of backend stuff.
 *
 */

/**
 * @brief RPC handler function signature.
 *
 * @param req  Pointer to the incoming request data.
 * @return 0 on success, nonzero on error.
 */
typedef int (*xrpc_handler_fn)(const struct xrpc_request *req,
                               struct xrpc_response *res);

/**
 * @brief Unix transport configuration struct.
 *
 * Unix transport configuration struct. Contains sockaddr_un which contains the
 * path for the socket.
 *
 */
struct xrpc_unix_server_config {
  struct sockaddr_un addr;
};

/*
 * Init and destroy unix server
 */
int xrpc_transport_server_init_unix(struct xrpc_transport **t,
                                    const struct xrpc_unix_server_config *c);
void xrpc_transport_server_free_unix(struct xrpc_transport *t);

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_tcp_server_config {
  struct sockaddr_in addr;
};
/*
 * Init and destroy TCP server
 */
int xrpc_transport_server_init_tcp(struct xrpc_transport **t,
                                   const struct xrpc_tcp_server_config *c);
void xrpc_transport_server_free_tcp(struct xrpc_transport *t);

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_tls_server_config {
  const char *address;
  const char *port;
  const char *crt_path;
  const char *key_path;
};

/*
 * Init and destroy TLS server
 */
int xrpc_transport_server_init_tls(struct xrpc_transport **t,
                                   const struct xrpc_tls_server_config *c);
void xrpc_transport_server_free_tls(struct xrpc_transport *t);
/**
 * @brief Create and initialize an xrpc server.
 *
 * @param[out] srv       Pointer to allocated server instance.
 * @param[in]  t         Transport instance (already initialized via
 * transport_init()).
 * @return 0 on success, -1 on error.
 */
int xrpc_server_create(struct xrpc_server **srv, struct xrpc_transport *t);

// Register handler flags
enum XRPC_HANDLER_REGISTER_FLAGS {
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
 * Client API

 * For now to me sounds good to propose different connection creation/teardown
 * instead of relying on some sort of enumeration/type of backend stuff.
 *
 */

/**
 * @brief Unix transport configuration struct.
 *
 * Unix transport configuration struct. Contains sockaddr_un which contains the
 * path for the socket.
 *
 */
struct xrpc_unix_client_config {
  struct sockaddr_un addr;
};

/*
 * Init and destroy unix client
 */
int xrpc_transport_client_init_unix(struct xrpc_transport **t,
                                    const struct xrpc_unix_client_config *c);
void xrpc_transport_client_free_unix(struct xrpc_transport *t);

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_tcp_client_config {
  struct sockaddr_in addr;
};
/*
 * Init and destroy TCP client
 */
int xrpc_transport_client_init_tcp(struct xrpc_transport **t,
                                   const struct xrpc_tcp_client_config *c);
void xrpc_transport_client_free_tcp(struct xrpc_transport *t);

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_tls_client_config {
  const char *address;
  const char *port;
  const char *crt_path;
  const char *key_path;
};

/*
 * Init and destroy TLS client
 */
int xrpc_transport_client_init_tls(struct xrpc_transport **t,
                                   const struct xrpc_tls_client_config *c);
void xrpc_transport_client_free_tls(struct xrpc_transport *t);

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
void xrpc_client_close(struct xrpc_client *cli);

#endif // __XRPC_H
