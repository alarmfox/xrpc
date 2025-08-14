#ifndef __XRPC_CLIENT_H
#define __XRPC_CLIENT_H

#include "transport.h"
#include "xrpc_common.h"

struct xrpc_client;

/**
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @param[in]  t    Initialized transport instance (connected to server).
 * @return 0 on success, -1 on error.
 */
int xrpc_client_init(struct xrpc_client **cli, struct transport *t);

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

#endif // !__XRPC_CLIENT_H
