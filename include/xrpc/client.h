#ifndef XRPC_CLIENT_H
#define XRPC_CLIENT_H

#include <netinet/in.h>

#include "xrpc/xrpc.h"

/*
 * ==================================================================
 * Client API
 * ==================================================================
 * These are the core functions to be used by the client.
 */
struct xrpc_client;

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_client_tcp_config {
  struct sockaddr_in addr;
};

struct xrpc_client_config {
  enum xrpc_transport_type type;
  union {
    struct xrpc_client_tcp_config tcp;
  } config;
};

/*
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @param[in]  cfg  Pointer to client configuration
 * @return 0 on success, -1 on error.
 */
int xrpc_client_init(struct xrpc_client **cli,
                     const struct xrpc_client_config *cfg);

/*
 * @brief Perform a synchronous RPC call.
 *
 * @param[in] cli   Client instance.
 * @param[in] rq    Pointer to request
 * @param[ou] rs    Pointer to response
 * @return 0 on success, -1 on error.
 */
int xrpc_client_call_sync(struct xrpc_client *cli,
                          const struct xrpc_request *rq,
                          struct xrpc_response **rs);

/*
 * @brief Close client and free resources.
 *
 * @param[in] cli Client instance
 */
void xrpc_client_free(struct xrpc_client *cli);

#endif // !XRPC_CLIENT_H
