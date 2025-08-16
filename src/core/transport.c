#include "xrpc/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

static const struct xrpc_transport_ops *transport_ops_map[] = {
    [XRPC_TRANSPORT_UNIX] = &xrpc_transport_unix_ops,
    [XRPC_TRANSPORT_TCP] = &xrpc_transport_tcp_ops,
    [XRPC_TRANSPORT_TLS] = &xrpc_transport_tls_ops,
};

int xrpc_transport_server_init(struct xrpc_transport **t,
                               const struct xrpc_server_config *conf) {
  // sanity check
  if (!t || !conf) return XRPC_API_ERR_INVALID_ARGS;
  if ((size_t)conf->type >=
      sizeof(transport_ops_map) / sizeof(transport_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  const struct xrpc_transport_ops *ops = transport_ops_map[conf->type];

  if (!ops) return XRPC_API_ERR_INVALID_TRANSPORT;

  return ops->init(t, (const void *)conf);
}
