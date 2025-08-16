#include "internal/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

int xrpc_transport_server_init(struct xrpc_transport **t,
                               const struct xrpc_server_config *c) {
  int ret = XRPC_SUCCESS;

  switch (c->type) {
  case XRPC_TRANSPORT_UNIX:
    xrpc_transport_server_init_unix(t, &c->config.unix);
    break;
  case XRPC_TRANSPORT_TCP:
    xrpc_transport_server_init_tcp(t, &c->config.tcp);
    break;
  case XRPC_TRANSPORT_TLS:
    xrpc_transport_server_init_tls(t, &c->config.tls);
    break;
  default:
    ret = XRPC_API_INVALID_TRANSPORT;
  }

  return ret;
}
