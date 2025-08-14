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

  struct xrpc_server *s = malloc(sizeof(struct xrpc_server));

  if (!s)
    _print_err_and_return("cannot create xrpc_server", XRPC_API_ERR_ALLOC);

  s->t = t;
  s->max_reqs = max_reqs;

  for (int i = 0; i < MAX_HANDLERS; ++i) {
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
  ;

  srv->handlers[op] = handler;
  return XRPC_SUCCESS;
}

int xrpc_server_poll(struct xrpc_server *srv) {
  int ret = XRPC_SUCCESS;
  void *payload = NULL;
new_client:
  if (ret = transport_poll_client(srv->t), ret != XRPC_SUCCESS) return ret;

  while (1) {
    struct xrpc_request_header req_hdr;
    struct xrpc_response_header res_hdr;
    struct xrpc_request request;
    xrpc_handler_fn fn = NULL;
    unsigned char resp_buf[RESP_BUF_SIZE];
    size_t resp_len = sizeof(resp_buf);

    memset(&req_hdr, 0, sizeof(struct xrpc_request_header));
    memset(&res_hdr, 0, sizeof(struct xrpc_response_header));
    memset(resp_buf, 0, sizeof(resp_buf));

    // read the header
    ret = transport_recv(srv->t, (void *)&req_hdr,
                         sizeof(struct xrpc_request_header));

    if (ret != XRPC_SUCCESS) goto exit;

    payload = malloc(req_hdr.sz);

    if (!payload) {
      ret = XRPC_API_ERR_ALLOC;
      goto exit;
    }

    // read the request
    ret = transport_recv(srv->t, payload, req_hdr.sz);
    if (ret != XRPC_SUCCESS) goto exit;

    // populate request field
    request.data = payload;
    request.len = req_hdr.sz;
    request.resp_buf = resp_buf;
    request.resp_len = &resp_len;

    // init response header
    res_hdr.status = XRPC_RESPONSE_SUCCESS;
    res_hdr.reqid = req_hdr.reqid;
    res_hdr.op = res_hdr.op;

    if (req_hdr.op >= MAX_HANDLERS) {
      res_hdr.status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      goto send_response;
    }

    fn = srv->handlers[req_hdr.op];

    if (!fn) {
      res_hdr.status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      goto send_response;
    }

    if (fn(&request) != 0) res_hdr.status = XRPC_RESPONSE_INTERNAL_ERROR;

  send_response:
    if (*request.resp_len > 0) { res_hdr.sz = *request.resp_len; }

    // send header
    ret = transport_send(srv->t, (const void *)&res_hdr,
                         sizeof(struct xrpc_response_header));

    if (ret != XRPC_SUCCESS) goto exit;

    // send result
    if ((res_hdr.status & ~XRPC_RESPONSE_SUCCESS) == 0) {
      ret = transport_send(srv->t, (const void *)request.resp_buf,
                           *request.resp_len);
      if (ret != XRPC_SUCCESS) goto exit;
    }

    if (payload) {
      free(payload);
      payload = NULL;
    }
  }

exit:
  if (payload) free(payload);
  transport_release_client(srv->t);

  if (ret == XRPC_TRANSPORT_ERR_READ_CONN_CLOSED) goto new_client;

  return ret;
}
void xrpc_server_free(struct xrpc_server *srv) {
  if (!srv) return;
  for (int i = 0; i < MAX_HANDLERS; ++i) {
    srv->handlers[i] = 0;
  }
  free(srv);
}
