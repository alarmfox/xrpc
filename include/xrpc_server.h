#ifndef __XRPC_SERVER_H
#define __XRPC_SERVER_H

#include <stddef.h>

#include "transport.h"
#include "xrpc_common.h"

/* Forward declarations */
struct xrpc_server;

// Register handler flags
enum XRPC_HANDLER_REGISTER_FLAGS {
  XRPC_RF_OVERWRITE = 1 << 0,
};

/**
 * @brief RPC handler function signature.
 *
 * @param req  Pointer to the incoming request data.
 * @return 0 on success, nonzero on error.
 */
typedef int (*xrpc_handler_fn)(const struct xrpc_request *req,
                               struct xrpc_response *res);

/**
 * @brief Create and initialize an xrpc server.
 *
 * @param[out] srv       Pointer to allocated server instance.
 * @param[in]  t         Transport instance (already initialized via
 * transport_init()).
 * @param[in]  max_reqs  Maximum number of in-flight requests (ring buffer
 * size).
 * @return 0 on success, -1 on error.
 */
int xrpc_server_create(struct xrpc_server **srv, struct transport *t,
                       size_t max_reqs);

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
int xrpc_server_poll(struct xrpc_server *srv);

/**
 * @brief Shut down and free server resources.
 *
 * Frees ring buffers, closes connections, and releases the transport.
 *
 * @param srv  Server instance to free.
 */
void xrpc_server_free(struct xrpc_server *srv);

#endif /* __XRPC_SERVER_H */
