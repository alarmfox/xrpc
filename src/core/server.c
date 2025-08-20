#include <stdlib.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/ringbuf.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_HANDLERS 64
#define MAX_REQUEST_SIZE (1024 * 1024 * 4) // 4M

struct xrpc_request_context {
  enum state {
    XRPC_REQ_STATE_READ_HEADER,
    XRPC_REQ_STATE_READ_BODY,
    XRPC_REQ_STATE_WRITE,
    XRPC_REQ_STATE_PROCESS,
    XRPC_REQ_STATE_COMPLETED,
  } state;

  int last_error;
  struct xrpc_server *srv;
  struct xrpc_connection *conn;

  struct xrpc_request_header *request_header;
  uint8_t *request_data;

  struct xrpc_response_header *response_header;
  uint8_t *response_data;
};

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct xrpc_transport *transport;
  struct xrpc_io_system *io;

  struct xrpc_ringbuf *active_contexts;
};

// Utils functions to manage xrpc_request_context lifecycle
static int create_request_context(struct xrpc_server *srv,
                                  struct xrpc_connection *conn,
                                  struct xrpc_request_context **ctx);
static void free_request_context(struct xrpc_request_context *ctx);
static void advance_request_state_machine(struct xrpc_request_context *ctx);
static void process(struct xrpc_request_context *ctx);
static void io_request_completed(struct xrpc_io_operation *op);

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
  struct xrpc_ringbuf *rb = NULL;

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

  // init the ringbuf
  if (ret = xrpc_ringbuf_init(&rb, 100), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create request context queue", ret);

  s->transport = t;
  s->io = ios;
  s->active_contexts = rb;
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
        ret == XRPC_SUCCESS) {

      ret = create_request_context(srv, conn, &ctx);
      if (ret != XRPC_SUCCESS) {
        XRPC_DEBUG_PRINT("failed to create request context");
        srv->transport->ops->close(srv->transport, conn);
        continue;
      }

      XRPC_DEBUG_PRINT("created context for connection %lu", conn->id);
      xrpc_ringbuf_push(srv->active_contexts, ctx);
    }

    srv->io->ops->poll(srv->io);

    // snapshot the context so that we can consume at most `n` contexts. This
    // helps because we can append new contexts in the loop an they will be
    // processed in the next iteration.
    size_t n = xrpc_ringbuf_count(srv->active_contexts);

    while ((n--) > 0 && xrpc_ringbuf_pop(srv->active_contexts, (void *)&ctx) ==
                            XRPC_SUCCESS) {
      // if the underlying connection is no longer valid. Put the request for
      // completion and free the resource completed body reading, we are ready
      if (!connection_is_valid(ctx->conn) ||
          ctx->state == XRPC_REQ_STATE_COMPLETED) {
        free_request_context(ctx);
        ctx = NULL;
        continue;
      }
      // to read another request while processing. This could be more helpful if
      // we add a worker thread.
      if (ctx->state == XRPC_REQ_STATE_PROCESS) {
        process(ctx);
        ctx->state = XRPC_REQ_STATE_WRITE;

        /*
         * Start to read another request.
         * Limit the scope of the new _ctx variable
         */
        {
          struct xrpc_request_context *_ctx = NULL;
          ret = create_request_context(srv, ctx->conn, &_ctx);
          if (ret == XRPC_SUCCESS)
            xrpc_ringbuf_push(srv->active_contexts, _ctx);
        }
      }
      advance_request_state_machine(ctx);
    }
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
    srv->transport = NULL;
  }
  if (srv->io && srv->io->ops->free) {
    srv->io->ops->free(srv->io);
    srv->io = NULL;
  }

  free(srv);
}

static int create_request_context(struct xrpc_server *srv,
                                  struct xrpc_connection *conn,
                                  struct xrpc_request_context **ctx) {
  // don't create context for closing connection, closed or invalid connections
  if (!conn || !connection_is_valid(conn)) return XRPC_API_ERR_INVALID_CONN;

  struct xrpc_request_context *_ctx =
      malloc(sizeof(struct xrpc_request_context));

  if (!_ctx) return XRPC_API_ERR_ALLOC;

  _ctx->last_error = XRPC_SUCCESS;
  _ctx->request_header = malloc(sizeof(struct xrpc_request_header));
  _ctx->response_header = malloc(sizeof(struct xrpc_response_header));
  _ctx->request_data = NULL;
  _ctx->response_data = NULL;
  _ctx->srv = srv;
  _ctx->conn = conn;
  _ctx->state = XRPC_REQ_STATE_READ_HEADER;

  if (!_ctx->request_header || !_ctx->response_header)
    return XRPC_API_ERR_ALLOC;

  // increment refernce count to the connection
  connection_ref(srv->transport, conn);

  *ctx = _ctx;

  return XRPC_SUCCESS;
}

static void free_request_context(struct xrpc_request_context *ctx) {
  if (!ctx) return;

  if (ctx->request_header) free(ctx->request_header);
  if (ctx->response_header) free(ctx->response_header);
  if (ctx->request_data) free(ctx->request_data);
  if (ctx->response_data) free(ctx->response_data);

  if (ctx->conn) connection_unref(ctx->srv->transport, ctx->conn);

  ctx->request_header = NULL;
  ctx->response_header = NULL;
  ctx->request_data = NULL;
  ctx->response_data = NULL;
  ctx->conn = NULL;

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

      op->conn = ctx->conn;
      op->ctx = ctx;
      op->type = XRPC_IO_WRITE;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
      op->on_complete = io_request_completed;
    } else {
      op->conn = ctx->conn;
      op->ctx = ctx;
      op->type = XRPC_IO_READ;
      op->len = ctx->request_header->sz;
      op->buf = ctx->request_data;
      op->on_complete = io_request_completed;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
    // process the request and schedule the write operation for the response
  case XRPC_REQ_STATE_PROCESS:
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
      op->ctx = ctx;
      op->type = XRPC_IO_WRITE;
      op->conn = ctx->conn;
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
      op->ctx = ctx;
      op->buf = write_buffer;
      op->conn = ctx->conn;
      op->len = total_len;
      op->on_complete = io_request_completed;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
  case XRPC_REQ_STATE_COMPLETED:
    break;
  }
  }
}
static void io_request_completed(struct xrpc_io_operation *op) {
  struct xrpc_request_context *ctx = (struct xrpc_request_context *)op->ctx;
  /*
   * If transport there are errors, mark the connection for close, free
   * resources and skips to request completed which will trigger the cleanup
   */
  if (op->status == XRPC_TRANSPORT_ERR_CONN_CLOSED ||
      op->status == XRPC_TRANSPORT_ERR_READ ||
      op->status == XRPC_TRANSPORT_ERR_WRITE) {

    if (op->status != XRPC_TRANSPORT_ERR_CONN_CLOSED)
      XRPC_DEBUG_PRINT("Transport error: %d", op->status);

    /* Clean up write buffer if needed */
    if (op->buf && ctx->state == XRPC_REQ_STATE_WRITE) free(op->buf);
    op->buf = NULL;

    ctx->state = XRPC_REQ_STATE_COMPLETED;
    ctx->last_error = op->status;
    connection_mark_for_close(ctx->conn);

    free(op);
    op = NULL;

    /* Enqueue once for cleanup - server loop will free it */
    xrpc_ringbuf_push(ctx->srv->active_contexts, ctx);
    return;
  }

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
    if (op->buf) free(op->buf);
    break;
  }

  if (op) {
    free(op);
    op = NULL;
  }

  // the main loop will advance the schedule
  xrpc_ringbuf_push(ctx->srv->active_contexts, ctx);
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
