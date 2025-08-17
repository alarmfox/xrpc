#include <stdlib.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_HANDLERS 64
#define MAX_REQUEST_SIZE (1024 * 1024 * 4) // 4M

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct xrpc_transport *transport;
  struct xrpc_io_system *ios;
};

struct xrpc_request_context {
  struct xrpc_server *srv;
  struct xrpc_connection *conn;

  struct xrpc_request_header *request_header;
  uint8_t *request_data;

  struct xrpc_response_header *response_header;
  uint8_t *response_data;
};

static int handle_all_requests_on_connection(struct xrpc_server *srv,
                                             struct xrpc_connection *tconn);
static void header_read_complete(struct xrpc_io_system *io,
                                 struct xrpc_io_operation *op);

static void body_read_complete(struct xrpc_io_system *io,
                               struct xrpc_io_operation *op);
static void response_write_complete(struct xrpc_io_system *io,
                                    struct xrpc_io_operation *op);
// This map stores different transports. For now this is only for supported
// transport of this library. In future, a "register" method could be provided.
static const struct xrpc_transport_ops *transport_ops_map[] = {
    [XRPC_TRANSPORT_TCP] = &xrpc_transport_tcp_ops,
};

// This map stores io systems . For now this is only for supported
// io systems of this library. In future, a "register" method could be provided.
static const struct xrpc_io_system_ops *io_ops_map[] = {
    [XRPC_IO_SYSTEM_BLOCKING] = &xrpc_blocking_ops,
};

int xrpc_server_create(struct xrpc_server **srv,
                       const struct xrpc_server_config *cfg) {

  int ret = XRPC_SUCCESS;
  struct xrpc_server *s = NULL;
  struct xrpc_transport *t = NULL;
  struct xrpc_io_system *ios = NULL;

  if (!cfg)
    XRPC_PRINT_ERR_AND_RETURN("config is NULL", XRPC_API_ERR_INVALID_ARGS);

  s = malloc(sizeof(struct xrpc_server));
  if (!s) XRPC_PRINT_ERR_AND_RETURN("malloc", XRPC_API_ERR_ALLOC);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->tcfg->type >=
      sizeof(transport_ops_map) / sizeof(transport_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the transport_ops table from the transport_ops_map and init the
  // transport
  const struct xrpc_transport_ops *tops = transport_ops_map[cfg->tcfg->type];

  if (ret = tops->init(&t, cfg->tcfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create transport", ret);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->iocfg->type >= sizeof(io_ops_map) / sizeof(io_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the `io_system_ops` table from the ios_map and init the
  // I/O system.
  const struct xrpc_io_system_ops *ops = io_ops_map[cfg->iocfg->type];

  if (ret = ops->init(&ios, cfg->iocfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create I/O system", ret);

  // Zero init the handlers
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }

  s->transport = t;
  s->ios = ios;
  *srv = s;
  return ret;
}

int xrpc_server_register(struct xrpc_server *srv, const size_t op,
                         xrpc_handler_fn handler, const int flags) {

  if (op >= MAX_HANDLERS)
    XRPC_PRINT_ERR_AND_RETURN(
        "cannot register handler with op (out of range): %lu",
        XRPC_API_ERR_BAD_OPID, op);

  xrpc_handler_fn fn = srv->handlers[op];

  if (fn && !(flags & XRPC_RF_OVERWRITE))
    XRPC_PRINT_ERR_AND_RETURN("handler already registered at op=%lu",
                              XRPC_API_ERR_HANDLER_ALREADY_REGISTERED, op);

  srv->handlers[op] = handler;
  return XRPC_SUCCESS;
}

int xrpc_server_run(struct xrpc_server *srv) {
  int ret = XRPC_SUCCESS;

  struct xrpc_connection *tconn = NULL;

  while (1) {
    if (ret = srv->transport->ops->accept(srv->transport, &tconn),
        ret != XRPC_SUCCESS)
      continue;

    XRPC_DEBUG_PRINT("received connection");

    if (ret = handle_all_requests_on_connection(srv, tconn),
        ret != XRPC_SUCCESS) {
      XRPC_DEBUG_PRINT("error during connection: %d", ret);
    }

    srv->transport->ops->close(srv->transport, tconn);
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

static int handle_all_requests_on_connection(struct xrpc_server *srv,
                                             struct xrpc_connection *conn) {

  bool running = true;

  struct xrpc_request_context *ctx =
      malloc(sizeof(struct xrpc_request_context));

  if (!ctx) return XRPC_API_ERR_ALLOC;

  ctx->request_header = malloc(sizeof(struct xrpc_request_header));
  ctx->response_header = malloc(sizeof(struct xrpc_response_header));
  ctx->response_data = NULL;

  if (!ctx->request_header || !ctx->response_header) return XRPC_API_ERR_ALLOC;

  while (running) {
    struct xrpc_io_operation *op = malloc(sizeof(struct xrpc_io_operation));
    op->type = XRPC_IO_READ;
    op->conn = conn;
    op->ctx = ctx;
    op->buf = ctx->request_header;
    op->len = sizeof(struct xrpc_request_header);
    op->on_complete = header_read_complete;

    srv->ios->ops->schedule_operation(srv->ios, op);

    free(op);
  }
  free(ctx);
  ctx = NULL;
  return XRPC_SUCCESS;
}

static void header_read_complete(struct xrpc_io_system *io,
                                 struct xrpc_io_operation *op) {

  struct xrpc_request_context *ctx = (struct xrpc_request_context *)op->ctx;

  // prevent a DoS. A malicious client could make a very big request
  if (ctx->request_header->sz > MAX_REQUEST_SIZE) {
    op->type = XRPC_IO_WRITE;
    op->len = sizeof(struct xrpc_response_header);
    op->buf = ctx->response_header;
    op->on_complete = 0;

    ctx->response_header->status = XRPC_API_ERR_INVALID_ARGS;
    io->ops->schedule_operation(io, op);
    return;
  }

  // read the request payload if any
  if (ctx->request_header->sz > 0) {
    ctx->request_data = malloc(ctx->request_header->sz);
    // TODO: send error
    if (!ctx->request_data) {

      op->type = XRPC_IO_WRITE;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
      op->on_complete = 0;

      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
      io->ops->schedule_operation(io, op);
      return;
    }

    op->buf = ctx->request_data;
    op->len = ctx->request_header->sz;
    op->on_complete = body_read_complete;
    io->ops->schedule_operation(io, op);
    return;
  }
  body_read_complete(io, op);
}

static void body_read_complete(struct xrpc_io_system *io,
                               struct xrpc_io_operation *op) {

  (void)io;
  struct xrpc_request_context *ctx = (struct xrpc_request_context *)op->ctx;
  struct xrpc_request request;
  struct xrpc_response response;

  if (ctx->request_header->op < MAX_HANDLERS &&
      ctx->srv->handlers[ctx->request_header->op]) {

    request.hdr = ctx->request_header,
    request.data = (const void *)ctx->request_data,

    response.hdr = ctx->response_header;
    response.data = NULL;

    if (ctx->srv->handlers[ctx->request_header->op](&request, &response) !=
        XRPC_SUCCESS) {
      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
    }

    ctx->response_data = response.data;
  } else {
    ctx->response_header->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
    ctx->response_header->sz = 0;
  }

  op->type = XRPC_IO_WRITE;
  op->buf = ctx->response_header;
  op->len = sizeof(struct xrpc_response_header) + ctx->response_header->sz;
  op->on_complete = response_write_complete;
}

static void response_write_complete(struct xrpc_io_system *io,
                                    struct xrpc_io_operation *op) {

  (void)io;
  struct xrpc_request_context *ctx = (struct xrpc_request_context *)op->ctx;

  if (ctx->request_data) {
    free(ctx->request_data);
    ctx->request_data = NULL;
  }
  if (ctx->response_data) {
    free(ctx->response_data);
    ctx->response_data = NULL;
  }

  free(op);
  op = NULL;
}
