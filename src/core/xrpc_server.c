#include <stdlib.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_HANDLERS 128
#define MAX_REQUEST_SIZE (1024 * 1024 * 4) // 4M

/*
 * Macro to ease up the error handling of the request.
 * The error basically means sending an error state in the response error and
 * mark the request as error.
 */
#define send_error(ctx_, err_)                                                 \
  do {                                                                         \
    ctx_->response_header->status = err_;                                      \
    ctx_->response_header->sz = 0;                                             \
    ctx_->response_header->reqid = rctx->request_header->reqid;                \
    goto send;                                                                 \
  } while (0)

static bool running = false;

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct xrpc_transport *transport;
};

struct xrpc_request_context {
  struct xrpc_transport_connection *tconn;

  enum {
    XRPC_PROTO_READING_HEADER,
    XRPC_PROTO_READING_BODY,
    XRPC_PROTO_PROCESSING,
    XRPC_PROTO_ERROR,
    XRPC_PROTO_WRITING_HEADER,
    XRPC_PROTO_WRITING_BODY,
  } state;

  struct xrpc_request_header *request_header;
  uint8_t *request_data;

  struct xrpc_response_header *response_header;
  uint8_t *response_data;
};

static int
handle_all_requests_on_connection(struct xrpc_server *srv,
                                  struct xrpc_transport_connection *tconn);

// This map stores different transports. For now this is onyl for supported
// transport of this library. In future, a "register" method could be provided.
static const struct xrpc_transport_ops *transport_ops_map[] = {
    [XRPC_TRANSPORT_UNIX] = &xrpc_transport_unix_ops,
    [XRPC_TRANSPORT_TCP] = &xrpc_transport_tcp_ops,
    [XRPC_TRANSPORT_TLS] = &xrpc_transport_tls_ops,
};

int xrpc_server_create(struct xrpc_server **srv,
                       const struct xrpc_server_config *cfg) {

  int ret = XRPC_SUCCESS;
  struct xrpc_server *s = NULL;
  struct xrpc_transport *t = NULL;

  if (!cfg) _print_err_and_return("config is NULL", XRPC_API_ERR_INVALID_ARGS);

  s = malloc(sizeof(struct xrpc_server));
  if (!s) _print_err_and_return("malloc", XRPC_API_ERR_ALLOC);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->type >=
      sizeof(transport_ops_map) / sizeof(transport_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the transport_ops table from the transport_ops_map and init the
  // transport
  const struct xrpc_transport_ops *ops = transport_ops_map[cfg->type];

  if (ret = ops->init(&t, cfg), ret != XRPC_SUCCESS)
    _print_err_and_return("cannot create transport", ret);

  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }

  s->transport = t;
  *srv = s;
  return ret;
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

  struct xrpc_transport_connection *tconn = NULL;
  running = true;

  while (running) {
    if (ret = srv->transport->ops->accept_connection(srv->transport, &tconn),
        ret != XRPC_SUCCESS)
      continue;

    XRPC_DEBUG_PRINT("received connection");

    if (ret = handle_all_requests_on_connection(srv, tconn),
        ret != XRPC_SUCCESS) {
      XRPC_DEBUG_PRINT("error during connection: %d", ret);
    }

    srv->transport->ops->close_connection(tconn);
    free(tconn);
    tconn = NULL;
  }

  return ret;
}

void xrpc_server_free(struct xrpc_server *srv) {
  if (!srv) return;
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    srv->handlers[i] = 0;
  }
  if (srv->transport && srv->transport->ops->free) {
    srv->transport->ops->free(srv->transport);
    free(srv->transport);
    srv->transport = NULL;
  }
}

static int
handle_all_requests_on_connection(struct xrpc_server *srv,
                                  struct xrpc_transport_connection *tconn) {

  int ret;
  struct xrpc_request request;
  struct xrpc_response response;
  bool stop = false;

  struct xrpc_request_context *rctx =
      malloc(sizeof(struct xrpc_request_context));

  if (!rctx) return XRPC_API_ERR_ALLOC;

  rctx->tconn = tconn;
  rctx->request_header = malloc(sizeof(struct xrpc_request_header));
  rctx->response_header = malloc(sizeof(struct xrpc_response_header));
  rctx->state = XRPC_PROTO_READING_HEADER;
  rctx->response_data = NULL;

  if (!rctx->request_header || !rctx->response_header)
    return XRPC_API_ERR_ALLOC;

  while (!stop && running) {
    // read the header
    ret = srv->transport->ops->recv(rctx->tconn, (void *)rctx->request_header,
                                    sizeof(struct xrpc_request_header));

    if (ret != XRPC_SUCCESS) {
      stop = true;
      goto free;
    }

    rctx->state = XRPC_PROTO_READING_BODY;
    // prevent a DoS. A malicious client could make a very big request
    if (rctx->request_header->sz > MAX_REQUEST_SIZE)
      send_error(rctx, XRPC_RESPONSE_INVALID_PARAMS);

    // read the request payload if any
    if (rctx->request_header->sz > 0) {
      rctx->request_data = malloc(rctx->request_header->sz);
      if (!rctx->request_data) send_error(rctx, XRPC_RESPONSE_INTERNAL_ERROR);

      ret = srv->transport->ops->recv(tconn, (void *)rctx->request_data,
                                      rctx->request_header->sz);
      if (ret != XRPC_SUCCESS) {
        stop = true;
        goto free;
      }
    }

    rctx->state = XRPC_PROTO_PROCESSING;

    // init response header
    rctx->response_header->status = XRPC_RESPONSE_SUCCESS;
    rctx->response_header->reqid = rctx->request_header->reqid;
    rctx->response_header->op = rctx->request_header->op;

    if (rctx->request_header->op < MAX_HANDLERS &&
        srv->handlers[rctx->request_header->op]) {

      request.hdr = rctx->request_header,
      request.data = (const void *)rctx->request_data,

      response.hdr = rctx->response_header;
      response.data = NULL;

      if (srv->handlers[rctx->request_header->op](&request, &response) !=
          XRPC_SUCCESS) {
        rctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
      }
      rctx->response_data = response.data;
    } else {
      rctx->response_header->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      rctx->response_header->sz = 0;
    }

  send:
    rctx->state = XRPC_PROTO_WRITING_HEADER;
    // send header
    ret = srv->transport->ops->send(tconn, (const void *)rctx->response_header,
                                    sizeof(struct xrpc_response_header));

    rctx->state = XRPC_PROTO_WRITING_BODY;
    // send result
    if (rctx->response_header->sz > 0) {
      if (srv->transport->ops->send(tconn, (const void *)rctx->response_data,
                                    rctx->response_header->sz) != XRPC_SUCCESS)
        stop = true;
    }

  free:
    if (rctx->request_data) {
      free(rctx->request_data);
      rctx->request_data = NULL;
    }
    if (rctx->response_data) {
      free(rctx->response_data);
      rctx->response_data = NULL;
    }
  }
  free(rctx);
  rctx = NULL;
  return XRPC_SUCCESS;
}
