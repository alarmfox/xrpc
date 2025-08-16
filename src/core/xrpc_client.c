#include <stdlib.h>

#include "internal/debug.h"
#include "internal/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

struct xrpc_client {
  struct xrpc_transport *t;
};

int xrpc_client_init(struct xrpc_client **cli, struct xrpc_transport *t) {
  struct xrpc_client *c = malloc(sizeof(struct xrpc_client));

  if (!c) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  c->t = t;

  *cli = c;

  return XRPC_SUCCESS;
}

int xrpc_call(struct xrpc_client *cli, const struct xrpc_request *rq,
              struct xrpc_response *rs) {
  int ret = XRPC_SUCCESS;

  // send header
  ret = transport_send(cli->t, (const void *)rq->hdr,
                       sizeof(struct xrpc_request_header));

  if (ret != XRPC_SUCCESS) goto exit;

  // send payload
  ret = transport_send(cli->t, (const void *)rq->data, rq->hdr->sz);

  if (ret != XRPC_SUCCESS) goto exit;

  // read response header
  ret = transport_recv(cli->t, (void *)rs->hdr,
                       sizeof(struct xrpc_response_header));
  if (ret != XRPC_SUCCESS) goto exit;

  // read response body
  ret = transport_recv(cli->t, (void *)rs->data, rs->hdr->sz);
  if (ret != XRPC_SUCCESS) goto exit;

exit:
  return ret;
}

void xrpc_client_close(struct xrpc_client *cli) {
  if (!cli) return;
  free(cli);
}
