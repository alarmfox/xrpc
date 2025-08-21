#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark.h"
#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/pool.h"
#include "xrpc/ringbuf.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_HANDLERS 64
#define MAX_REQUEST_SIZE (1024 * 1024) // 1M

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
  struct xrpc_response_header *response_header;

  uint8_t *response_data;
  uint8_t *request_data;
};

struct xrpc_server {
  xrpc_handler_fn handlers[MAX_HANDLERS];
  struct xrpc_transport *transport;
  struct xrpc_io_system *io;
  struct xrpc_pool *request_context_pool;
  struct xrpc_ringbuf *active_contexts;
  int running;
};

// Utils functions to manage xrpc_request_context lifecycle
static int create_request_context(struct xrpc_server *srv,
                                  struct xrpc_connection *conn,
                                  struct xrpc_request_context **ctx);
static void free_request_context(struct xrpc_server *s,
                                 struct xrpc_request_context *ctx);
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
  size_t context_size;

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

  if (ret = tops->init(&s->transport, cfg->tcfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create transport", ret);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->iocfg->type >= sizeof(io_ops_map) / sizeof(io_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the `io_system_ops` table from the ios_map and init the
  // I/O system.
  const struct xrpc_io_system_ops *ops = io_ops_map[cfg->iocfg->type];

  if (ret = ops->init(&s->io, cfg->iocfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create I/O system", ret);

  // Zero init the handlers
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }

  // init the ringbuf
  if (ret =
          xrpc_ringbuf_init(&s->active_contexts, cfg->max_concurrent_requests),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create request context queue", ret);

  /*
   * Init the context_pool with total size = struct size + MAX_REQUEST_SIZE +
   * headers size In this way we can save 3 allocations: 1 for the request body
   * and 2 for the headers. The context layout is:
   *
   * +-----------------+---------------+----------------+----------------+
   * | request_context |request_header |response_header |request_body   |
   * +-----------------+---------------+----------------+----------------+
   *
   */
  context_size = sizeof(struct xrpc_request_context) +
                 sizeof(struct xrpc_request_header) +
                 sizeof(struct xrpc_response_header) + MAX_REQUEST_SIZE;

  if (ret = xrpc_pool_init(&s->request_context_pool,
                           cfg->max_concurrent_requests, context_size),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create request context queue", ret);

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

  // mark the server as running
  __atomic_store_n(&srv->running, 1, __ATOMIC_SEQ_CST);

  while (__atomic_load_n(&srv->running, __ATOMIC_RELAXED)) {
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
        free_request_context(srv, ctx);
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

/**
 * @brief Flags the server to stop if running
 *
 * TODO: make user to choice between a graceful shutdown or to force
 *
 * @param srv         Server instance.
 */
void xrpc_server_stop(struct xrpc_server *srv) {
  __atomic_store_n(&srv->running, 0, __ATOMIC_SEQ_CST);
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

  if (xrpc_pool_get(srv->request_context_pool, (void **)ctx) != XRPC_SUCCESS)
    return XRPC_INTERNAL_ERR_ALLOC;

  if (!ctx) return XRPC_API_ERR_ALLOC;

  (*ctx)->last_error = XRPC_SUCCESS;
  (*ctx)->request_header = (struct xrpc_request_header *)(*ctx) +
                           sizeof(struct xrpc_request_context);
  (*ctx)->response_header = (struct xrpc_response_header *)(*ctx) +
                            sizeof(struct xrpc_request_context) +
                            sizeof(struct xrpc_request_header);
  (*ctx)->request_data =
      (uint8_t *)(*ctx) + sizeof(struct xrpc_request_context) +
      sizeof(struct xrpc_request_header) + sizeof(struct xrpc_response_header);

  (*ctx)->response_data = NULL;
  (*ctx)->srv = srv;
  (*ctx)->conn = conn;
  (*ctx)->state = XRPC_REQ_STATE_READ_HEADER;

  // increment refernce count to the connection
  connection_ref(srv->transport, conn);

  return XRPC_SUCCESS;
}

static void free_request_context(struct xrpc_server *srv,
                                 struct xrpc_request_context *ctx) {
  if (!ctx) return;
  size_t context_size = sizeof(struct xrpc_request_context) +
                        sizeof(struct xrpc_request_header) +
                        sizeof(struct xrpc_response_header) + MAX_REQUEST_SIZE;

  if (ctx->response_data) free(ctx->response_data);

  if (ctx->conn) connection_unref(ctx->srv->transport, ctx->conn);

  memset(ctx, 0, context_size);

  assert(xrpc_pool_put(srv->request_context_pool, ctx) == XRPC_SUCCESS);
}

// Schedule an I/O operation based on the current request state
static void advance_request_state_machine(struct xrpc_request_context *ctx) {

  struct xrpc_io_operation *op = NULL;
  int ret;
  // try to get a new operation
  if (ret = xrpc_io_operation_new(ctx->srv->io, &op), ret != XRPC_SUCCESS) {

    ctx->state = XRPC_REQ_STATE_COMPLETED;
    ctx->last_error = ret;
    xrpc_ringbuf_push(ctx->srv->active_contexts, ctx);
    return;
  }

  // common setup for the operation
  op->conn = ctx->conn;
  op->ctx = ctx;
  op->on_complete = io_request_completed;

  switch (ctx->state) {
  case XRPC_REQ_STATE_READ_HEADER:
    op->type = XRPC_IO_READ;
    op->buf = ctx->request_header;
    op->len = sizeof(struct xrpc_request_header);

    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
  case XRPC_REQ_STATE_READ_BODY:
    // ctx->request_data = malloc(ctx->request_header->sz);
    if (!ctx->request_data) {
      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;

      op->type = XRPC_IO_WRITE;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
    } else {
      op->type = XRPC_IO_READ;
      op->len = ctx->request_header->sz;
      op->buf = ctx->request_data;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
    // process the request and schedule the write operation for the response
  case XRPC_REQ_STATE_PROCESS:
    break;

  case XRPC_REQ_STATE_WRITE: {

    // Create single buffer for header + data
    size_t total_len =
        sizeof(struct xrpc_response_header) + ctx->response_header->sz;
    uint8_t *write_buffer = malloc(total_len);

    op->type = XRPC_IO_WRITE;

    if (!write_buffer) {
      ctx->response_header->status = XRPC_RESPONSE_INTERNAL_ERROR;
      ctx->response_header->sz = 0;
      op->len = sizeof(struct xrpc_response_header);
      op->buf = ctx->response_header;
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
      op->conn = ctx->conn;
      op->len = total_len;
      op->buf = write_buffer;
    }
    ctx->srv->io->ops->schedule_operation(ctx->srv->io, op);
    break;
  case XRPC_REQ_STATE_COMPLETED:
    if (op->status == XRPC_SUCCESS)
      XRPC_BENCH_REQ_CLOSE_SUCC(op->conn->id, ctx->request_header->reqid);
    else
      XRPC_BENCH_REQ_CLOSE_ERR(op->conn->id, ctx->request_header->reqid);

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

    assert(xrpc_io_operation_free(ctx->srv->io, op) == XRPC_SUCCESS);
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
    // trace
    XRPC_BENCH_REQ_START(op->conn->id, ctx->request_header->reqid);
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
    if (op->buf) {
      free(op->buf);
      op->buf = NULL;
    }
    ctx->state = XRPC_REQ_STATE_COMPLETED;
    break;
  case XRPC_REQ_STATE_COMPLETED:
    break;
  }

  if (op) {
    assert(xrpc_io_operation_free(ctx->srv->io, op) == XRPC_SUCCESS);
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
