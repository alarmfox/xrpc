#include <stdlib.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_HANDLERS 256
#define MAX_REQUEST_SIZE (1024 * 1024 * 4) // 4M
#define RESPONSE_BUF_SIZE (1024 * 4)       // 4K

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct xrpc_transport *t;
};

int xrpc_server_create(struct xrpc_server **srv, struct xrpc_transport *t) {

  if (!t)
    _print_err_and_return("transport is NULL", XRPC_API_ERR_INVALID_TRANSPORT);

  struct xrpc_server *s = malloc(sizeof(struct xrpc_server));

  if (!s)
    _print_err_and_return("cannot create xrpc_server", XRPC_API_ERR_ALLOC);

  s->t = t;

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
                          XRPC_API_ERR_HANDLER_ALREADY_REGISTERED, op);

  srv->handlers[op] = handler;
  return XRPC_SUCCESS;
}

int xrpc_server_run(struct xrpc_server *srv) {
  int ret = XRPC_SUCCESS;

  uint8_t request_buffer[MAX_REQUEST_SIZE];
  uint8_t response_buffer[RESPONSE_BUF_SIZE];
  struct xrpc_connection *conn = NULL;

  while (1) {
    if (ret = srv->t->ops->accept_connection(srv->t, &conn),
        ret != XRPC_SUCCESS)
      continue;
    while (1) {
      struct xrpc_request request = {0};
      struct xrpc_response response = {0};
      struct xrpc_request_header rq_hdr = {0};
      struct xrpc_response_header rs_hdr = {0};

      // read the header
      ret = srv->t->ops->recv(conn, (void *)&rq_hdr,
                              sizeof(struct xrpc_request_header));

      if (ret != XRPC_SUCCESS) break;

      request.hdr = &rq_hdr;
      response.hdr = &rs_hdr;

      // prevent a DoS. A malicious client could make a very big request
      if (request.hdr->sz > MAX_REQUEST_SIZE) {
        response.hdr->status = XRPC_RESPONSE_INVALID_PARAMS;
        response.hdr->sz = 0;
        response.hdr->reqid = request.hdr->reqid;
        goto send_response;
      }

      // read the request payload if any
      if (request.hdr->sz > 0) {

        ret = srv->t->ops->recv(conn, (void *)request_buffer, request.hdr->sz);
        if (ret != XRPC_SUCCESS) break;

        request.data = request_buffer;
      }

      // init response header
      response.hdr->status = XRPC_RESPONSE_SUCCESS;
      response.hdr->reqid = request.hdr->reqid;
      response.hdr->op = request.hdr->op;
      response.hdr->sz = RESPONSE_BUF_SIZE;

      // init response body with a scratch buffer
      response.data = response_buffer;

      if (request.hdr->op < MAX_HANDLERS && srv->handlers[request.hdr->op]) {
        if (srv->handlers[request.hdr->op](&request, &response) !=
            XRPC_SUCCESS) {

          response.hdr->status = XRPC_RESPONSE_INTERNAL_ERROR;
        }
      } else {
        response.hdr->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
        response.hdr->sz = 0;
      }

    send_response:

      // send header
      ret = srv->t->ops->send(conn, (const void *)response.hdr,
                              sizeof(struct xrpc_response_header));

      // send result
      if (response.hdr->sz > 0) {
        if (srv->t->ops->send(conn, (const void *)response.data,
                              response.hdr->sz) != XRPC_SUCCESS)
          break;
      }
    }
    srv->t->ops->close_connection(conn);
  }

  return ret;
}

void xrpc_server_free(struct xrpc_server *srv) {
  if (!srv) return;
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    srv->handlers[i] = 0;
  }
  free(srv);
}
