#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "error.h"
#include "xrpc_server.h"

#define MAX_HANDLERS 256
#define RESP_BUF_SIZE 4096

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct transport *t;
  size_t max_reqs;
};

int xrpc_server_create(struct xrpc_server **srv, struct transport *t,
                       size_t max_reqs) {

  if (!t)
    _print_err_and_return("transport is NULL", XRPC_API_INVALID_TRANSPORT);

  struct xrpc_server *s = malloc(sizeof(struct xrpc_server));

  if (!s)
    _print_err_and_return("cannot create xrpc_server", XRPC_API_ERR_ALLOC);

  s->t = t;
  s->max_reqs = max_reqs;

  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }

  *srv = s;
  return XRPC_SUCCESS;
}

int xrpc_server_register(struct xrpc_server *srv, const size_t op,
                         xrpc_handler_fn handler, const int flags) {

  if (op >= MAX_HANDLERS)
    _print_err_and_return("cannot register handler with op (out of range): %lu",
                          XRPC_API_ERR_BAD_OPID, op);

  xrpc_handler_fn fn = srv->handlers[op];

  if (fn && !(flags & XRPC_RF_OVERWRITE))
    _print_err_and_return("handler already registered at op=%lu",
                          XRPC_API_HANDLER_ALREADY_REGISTERED, op);

  srv->handlers[op] = handler;
  return XRPC_SUCCESS;
}

int xrpc_server_poll(struct xrpc_server *srv) {
  int ret = XRPC_SUCCESS;
  struct xrpc_request_header rq_hdr;
  struct xrpc_response_header rs_hdr;
  struct xrpc_request request;
  struct xrpc_response response;
  xrpc_handler_fn fn = NULL;
  unsigned char resp_buf[RESP_BUF_SIZE];

  request.hdr = &rq_hdr;
  response.hdr = &rs_hdr;

new_client:
  if (ret = transport_poll_client(srv->t), ret != XRPC_SUCCESS) return ret;

  while (1) {
    // reset the values
    memset(request.hdr, 0, sizeof(struct xrpc_request_header));
    memset(response.hdr, 0, sizeof(struct xrpc_response_header));
    memset(resp_buf, 0, sizeof(resp_buf));

    // read the header
    ret = transport_recv(srv->t, (void *)request.hdr,
                         sizeof(struct xrpc_request_header));

    if (ret != XRPC_SUCCESS) goto exit;

    // allocate hdr.sz for the payload
    request.data = malloc(request.hdr->sz);

    if (!request.data) {
      ret = XRPC_API_ERR_ALLOC;
      goto exit;
    }

    // read the request payload
    ret = transport_recv(srv->t, (void *)request.data, request.hdr->sz);
    if (ret != XRPC_SUCCESS) goto exit;

    // init response header
    response.hdr->status = XRPC_RESPONSE_SUCCESS;
    response.hdr->reqid = request.hdr->reqid;
    response.hdr->op = request.hdr->op;
    response.hdr->sz = RESP_BUF_SIZE;

    // init response body with a scratch buffer
    response.data = resp_buf;

    if (request.hdr->op >= MAX_HANDLERS) {
      response.hdr->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      goto send_response;
    }

    fn = srv->handlers[request.hdr->op];

    if (!fn) {
      response.hdr->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      goto send_response;
    }

    if (fn(&request, &response) != 0)
      response.hdr->status = XRPC_RESPONSE_INTERNAL_ERROR;

  send_response:

    // send header
    ret = transport_send(srv->t, (const void *)response.hdr,
                         sizeof(struct xrpc_response_header));

    // send result
    if ((response.hdr->status & ~XRPC_RESPONSE_SUCCESS) == 0) {
      ret =
          transport_send(srv->t, (const void *)response.data, response.hdr->sz);
      if (ret != XRPC_SUCCESS) goto exit;
    }

    if (request.data) {
      free((void *)request.data);
      response.data = NULL;
    }
  }

exit:
  transport_release_client(srv->t);

  if (ret == XRPC_TRANSPORT_ERR_READ_CONN_CLOSED) goto new_client;

  return ret;
}

void xrpc_server_free(struct xrpc_server *srv) {
  if (!srv) return;
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    srv->handlers[i] = 0;
  }
  free(srv);
}
