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
  struct xrpc_io_system *io;
};

struct xrpc_request_context {
  enum state {
    XRPC_REQ_STATE_READ_HEADER,
    XRPC_REQ_STATE_READ_BODY,
    XRPC_REQ_STATE_WRITE,
    XRPC_REQ_STATE_PROCESS,
    XRPC_REQ_STATE_COMPLETED,
  } state;

  struct xrpc_server *srv;
  struct xrpc_connection *conn;

  struct xrpc_request_header *request_header;
  uint8_t *request_data;

  struct xrpc_response_header *response_header;
  uint8_t *response_data;
};

// Utils functions to manage xrpc_request_context lifecycle
static struct xrpc_request_context *
create_request_context(struct xrpc_server *srv, struct xrpc_connection *conn);
static void free_context(struct xrpc_request_context *ctx);
static void advance_request_state_machine(struct xrpc_request_context *ctx);
static void process(struct xrpc_request_context *ctx);
static void io_request_completed(struct xrpc_io_operation *op, int status);

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
  s->io = ios;
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
  struct xrpc_connection *conn = NULL;
  struct xrpc_request_context *ctx = NULL;

  while (1) {
    if (ret = srv->transport->ops->accept(srv->transport, &conn),
        ret != XRPC_SUCCESS)
      continue;

    XRPC_DEBUG_PRINT("received connection");
    ctx = create_request_context(srv, conn);

    if (!ctx) goto release_conn;

    advance_request_state_machine(ctx);

    srv->io->ops->poll(srv->io);

  release_conn:
    srv->transport->ops->close(srv->transport, conn);
    free(conn);
    conn = NULL;
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
  if (srv->io && srv->io->ops->free) {
    srv->io->ops->free(srv->io);
    free(srv->io);
    srv->io = NULL;
  }
}

static struct xrpc_request_context *
create_request_context(struct xrpc_server *srv, struct xrpc_connection *conn) {
  struct xrpc_request_context *ctx =
      malloc(sizeof(struct xrpc_request_context));
  if (!ctx) return NULL;

  ctx->request_header = malloc(sizeof(struct xrpc_request_header));
  ctx->response_header = malloc(sizeof(struct xrpc_response_header));
  ctx->response_data = NULL;
  ctx->srv = srv;
  ctx->conn = conn;
  ctx->state = XRPC_REQ_STATE_READ_HEADER;

  if (!ctx->request_header || !ctx->response_header) return NULL;
  return ctx;
}

static void free_context(struct xrpc_request_context *ctx) {
  if (!ctx) return;
  if (ctx->request_header) free(ctx->request_header);
  if (ctx->response_header) free(ctx->response_header);
  if (ctx->request_data) free(ctx->request_data);
  if (ctx->response_data) free(ctx->response_data);

  free(ctx);
}

// Schedule an I/O operation based on the current request state
static void advance_request_state_machine(struct xrpc_request_context *ctx) {

  struct xrpc_io_operation *op = NULL;
  switch (ctx->state) {
  case XRPC_REQ_STATE_READ_HEADER:
    op = malloc(sizeof(struct xrpc_io_operation));
    op->type = XRPC_IO_READ;
    op->conn = ctx->conn;
    op->ctx = ctx;
    op->buf = ctx->request_header;
    op->len = sizeof(struct xrpc_request_header);
    op->on_complete = io_request_completed;

    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
  case XRPC_REQ_STATE_READ_BODY:
    op = malloc(sizeof(struct xrpc_io_operation));
    ctx->request_data = malloc(ctx->request_header->sz);
    if (!ctx->request_data) {
      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;

      op->type = XRPC_IO_WRITE;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
      op->on_complete = io_request_completed;
    } else {
      op->type = XRPC_IO_READ;
      op->len = ctx->request_header->sz;
      op->buf = ctx->request_data;
      op->on_complete = io_request_completed;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
    // process the request and schedule the write operation for the response
  case XRPC_REQ_STATE_PROCESS:
    process(ctx);
    break;

  case XRPC_REQ_STATE_WRITE: {
    op = malloc(sizeof(struct xrpc_io_operation));

    // Create single buffer for header + data
    size_t total_len =
        sizeof(struct xrpc_response_header) + ctx->response_header->sz;
    uint8_t *write_buffer = malloc(total_len);

    if (!write_buffer) {
      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
      ctx->response_header->sz = 0;
      op->type = XRPC_IO_WRITE;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
      op->on_complete = io_request_completed;
    } else {
      // Copy header first
      memcpy(write_buffer, ctx->response_header,
             sizeof(struct xrpc_response_header));

      // Copy data if any
      if (ctx->response_header->sz > 0 && ctx->response_data) {
        memcpy(write_buffer + sizeof(struct xrpc_response_header),
               ctx->response_data, ctx->response_header->sz);
      }
      // Schedule single write operation
      op->type = XRPC_IO_WRITE;
      op->buf = write_buffer;
      op->len = total_len;
      op->on_complete = io_request_completed;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
  case XRPC_REQ_STATE_COMPLETED:
    free_context(ctx);
    break;
  }
  }
}
static void io_request_completed(struct xrpc_io_operation *op, int status) {
  (void)status;
  struct xrpc_request_context *ctx = (struct xrpc_request_context *)op->ctx;

  switch (ctx->state) {
    // on header complete schedule body read if any otherwise process the
    // request.
  case XRPC_REQ_STATE_READ_HEADER:
    ctx->response_header->status = XRPC_RESPONSE_SUCCESS;
    ctx->response_header->reqid = ctx->request_header->reqid;
    ctx->response_header->op = ctx->request_header->op;
    // prevent a DoS. A malicious client could make a very big request
    if (ctx->request_header->sz > MAX_REQUEST_SIZE) {
      ctx->state = XRPC_REQ_STATE_WRITE;
      ctx->response_header->status = XRPC_API_ERR_INVALID_ARGS;
      ctx->response_header->sz = 0;
    } else if (ctx->request_header->sz == 0)
      ctx->state = XRPC_REQ_STATE_PROCESS;
    else
      ctx->state = XRPC_REQ_STATE_READ_BODY;
    break;
    // on body read schedule the process
  case XRPC_REQ_STATE_READ_BODY:

    if (ctx->request_header->op < MAX_HANDLERS &&
        ctx->srv->handlers[ctx->request_header->op]) {
      ctx->state = XRPC_REQ_STATE_PROCESS;
    } else {
      ctx->response_header->status = XRPC_RESPONSE_UNSUPPORTED_HANDLER;
      ctx->response_header->sz = 0;
      ctx->state = XRPC_REQ_STATE_WRITE;
    }
    break;
  case XRPC_REQ_STATE_PROCESS:
    ctx->state = XRPC_REQ_STATE_WRITE;
    break;
  case XRPC_REQ_STATE_WRITE:
    ctx->state = XRPC_REQ_STATE_COMPLETED;
    break;
  case XRPC_REQ_STATE_COMPLETED:
    break;
  }

  if (op) {
    free(op);
    op = NULL;
  }

  advance_request_state_machine(ctx);
}

static void process(struct xrpc_request_context *ctx) {
  struct xrpc_request req = {.hdr = ctx->request_header,
                             .data = (const void *)ctx->request_data};
  struct xrpc_response res = {.hdr = ctx->response_header, .data = NULL};

  if (ctx->srv->handlers[ctx->request_header->op](&req, &res) != XRPC_SUCCESS) {
    ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
  } else {
    ctx->response_data = res.data;
  }
}
