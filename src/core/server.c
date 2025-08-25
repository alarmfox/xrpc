#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark.h"
#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/pool.h"
#include "xrpc/protocol.h"
#include "xrpc/ringbuf.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define MAX_INFLIGHT_FRAMES 64
#define MAX_HANDLERS 64

/*
 * Connection context manages a single client connection. On a single connection
 * the client can negotiate a batch and start sending frame (operation
 * requests).
 */
struct xrpc_connection_context {
  enum xrpc_connection_context_state {
    XRPC_CONN_STATE_READ_HEADER,
    XRPC_CONN_STATE_IN_BATCH,
    XRPC_CONN_STATE_WRITE_HEADER,
    XRPC_CONN_STATE_COMPLETED,
  } state;

  int last_error;
  // Things needed from the server
  struct xrpc_transport *transport;
  struct xrpc_io_system *io;
  struct xrpc_connection *conn;

  // Borrowed references
  struct xrpc_pool *frame_context_pool;
  struct xrpc_ringbuf *conn_context_rb;

  uint16_t *next_batch_id;

  /* pointers to request/response headers */
  struct xrpc_request_header *rq_hdr;
  struct xrpc_response_header *rs_hdr;

  /* Pointers to raw data coming from the net (network-byte order)*/
  uint8_t rq_hdr_raw[8];
  uint8_t rs_hdr_raw[8];

  // counters for state management
  size_t transferred_bytes;
  uint16_t frames_completed;
  uint16_t frames_remaining;
  uint16_t frames_inflight;
};

/*
 * @brief Request frame context.
 * The metadata are a pointer to the `xrpc_connection`,
 */
struct xrpc_frame_context {
  enum xrpc_frame_context_state {
    XRPC_FRAME_STATE_READ_HEADER,
    XRPC_FRAME_STATE_PROCESS,
    XRPC_FRAME_STATE_WRITE_HEADER,
    XRPC_FRAME_STATE_COMPLETED,
  } state;

  int last_error;
  struct xrpc_connection_context *conn_ctx;

  // Frame headers
  struct xrpc_request_frame_header *rq_hdr;
  struct xrpc_response_frame_header *rs_hdr;

  /* Pointers to raw data coming from the net (network-byte order)*/
  uint8_t rq_hdr_raw[8];
  uint8_t rs_hdr_raw[8];

  // Frame data buffers
  uint8_t *req_frame_data;
  uint8_t *resp_frame_data;
  size_t req_data_size;
  size_t resp_data_size;
};

/*
 * @brief The server implementing the protocol.
 *
 * It contains a pool of connections which is used for client connections. Each
 * client produces request frame which are sent to the `request_frame_rb` to be
 * processed. The `response_frame_rb` contains requests to be sent.
 */
struct xrpc_server {
  // Handlers
  xrpc_handler_fn handlers[MAX_HANDLERS];
  // Transport and I/O system
  struct xrpc_transport *transport;
  struct xrpc_io_system *io;

  struct xrpc_pool *conn_context_pool;
  struct xrpc_pool *frame_context_pool;
  struct xrpc_ringbuf *conn_context_rb;

  uint16_t next_batch_id;
  int running;
};

// Utils functions to manage xrpc_request_context lifecycle
static int xrpc_conn_context_create(struct xrpc_server *srv,
                                    struct xrpc_connection *conn,
                                    struct xrpc_connection_context **out_ctx);
static void xrpc_conn_context_free(struct xrpc_server *s,
                                   struct xrpc_connection_context *ctx);
static int xrpc_frame_context_create(struct xrpc_connection_context *conn_ctx,
                                     struct xrpc_frame_context **out_ctx);
static void xrpc_frame_context_free(struct xrpc_connection_context *conn_ctx,
                                    struct xrpc_frame_context *fctx);

static void
xrpc_conn_context_schedule_next_operation(struct xrpc_connection_context *ctx);
static void xrpc_frame_process(struct xrpc_frame_context *ctx);
static void xrpc_io_conn_completed(struct xrpc_io_operation *op);
static void xrpc_io_frame_completed(struct xrpc_io_operation *op);
static void xrpc_handle_request_header(struct xrpc_connection_context *ctx);

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

int xrpc_server_create(struct xrpc_server **out_srv,
                       const struct xrpc_server_config *cfg) {

  int ret = XRPC_SUCCESS;
  struct xrpc_server *srv = NULL;
  size_t conn_context_size, frame_context_size;

  if (!cfg)
    XRPC_PRINT_ERR_AND_RETURN("config is NULL", XRPC_API_ERR_INVALID_ARGS);

  srv = malloc(sizeof(struct xrpc_server));
  if (!srv) XRPC_PRINT_ERR_AND_RETURN("malloc", XRPC_API_ERR_ALLOC);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->tcfg->type >=
      sizeof(transport_ops_map) / sizeof(transport_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the transport_ops table from the transport_ops_map and init the
  // transport
  const struct xrpc_transport_ops *tops = transport_ops_map[cfg->tcfg->type];

  if (ret = tops->init(&srv->transport, cfg->tcfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create transport", ret);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)cfg->iocfg->type >= sizeof(io_ops_map) / sizeof(io_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the `io_system_ops` table from the ios_map and init the
  // I/O system.
  const struct xrpc_io_system_ops *ops = io_ops_map[cfg->iocfg->type];

  if (ret = ops->init(&srv->io, cfg->iocfg), ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create I/O system", ret);

  // Zero init the handlers
  for (size_t i = 0; i < MAX_HANDLERS; ++i) {
    srv->handlers[i] = NULL;
  }

  // init the ringbuf
  if (ret = xrpc_ringbuf_init(&srv->conn_context_rb,
                              cfg->max_concurrent_requests),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create request context queue", ret);

  /*
   * Init the context_pool with total size = struct size + MAX_REQUEST_SIZE +
   * headers size In this way we can save 3 allocations: 1 for the request body
   * and 2 for the headers. The context layout is:
   *
   * +-----------------+---------------+---------------+
   * | request_context |request_header |response_header|
   * +-----------------+---------------+---------------+
   *
   */
  conn_context_size = sizeof(struct xrpc_connection_context) +
                      sizeof(struct xrpc_request_header) +
                      sizeof(struct xrpc_response_header);

  if (ret = xrpc_pool_init(&srv->conn_context_pool,
                           cfg->max_concurrent_requests, conn_context_size),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create connection context pool", ret);

  frame_context_size = sizeof(struct xrpc_frame_context) +
                       sizeof(struct xrpc_request_frame_header) +
                       sizeof(struct xrpc_response_frame_header);

  if (ret = xrpc_pool_init(&srv->frame_context_pool,
                           cfg->max_concurrent_requests * MAX_INFLIGHT_FRAMES,
                           frame_context_size),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create framw context pool ", ret);

  __atomic_store_n(&srv->next_batch_id, 0, __ATOMIC_SEQ_CST);
  *out_srv = srv;
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
  struct xrpc_connection_context *ctx = NULL;

  // mark the server as running
  __atomic_store_n(&srv->running, 1, __ATOMIC_SEQ_CST);

  /*
   * Main loop.
   * - accept new connections
   * - poll for events
   * - process enqueued connections
   */
  while (__atomic_load_n(&srv->running, __ATOMIC_RELAXED)) {

    if (ret = srv->transport->ops->accept(srv->transport, &conn),
        ret == XRPC_SUCCESS) {

      if (ret = xrpc_conn_context_create(srv, conn, &ctx),
          ret == XRPC_SUCCESS) {
        XRPC_DEBUG_PRINT("created context for connection %lu", conn->id);
        xrpc_ringbuf_push(srv->conn_context_rb, ctx);
      } else {
        XRPC_DEBUG_PRINT("failed to create request context");
        srv->transport->ops->close(srv->transport, conn);
      }
    }

    srv->io->ops->poll(srv->io);

    // snapshot the context so that we can consume at most `n` contexts. This
    // helps because we can append new contexts in the loop an they will be
    // processed in the next iteration.
    size_t n = xrpc_ringbuf_count(srv->conn_context_rb);

    while ((n--) > 0 && xrpc_ringbuf_pop(srv->conn_context_rb, (void *)&ctx) ==
                            XRPC_SUCCESS) {
      // if the underlying connection is no longer valid. Put the request for
      // completion and free the resource completed body reading, we are ready
      if (!connection_is_valid(ctx->conn) ||
          ctx->state == XRPC_CONN_STATE_COMPLETED ||
          ctx->last_error != XRPC_SUCCESS) {
        xrpc_conn_context_free(srv, ctx);
        ctx = NULL;
        continue;
      }
      // step the state machine for the current connection context
      xrpc_conn_context_schedule_next_operation(ctx);

      // if the connection has not completed put it back in the queue
      if (ctx->state != XRPC_CONN_STATE_COMPLETED)
        xrpc_ringbuf_push(srv->conn_context_rb, ctx);

      // if the underlying connection is no longer valid. Put the request for
      // completion and free the resource completed body reading, we are ready
      if (!connection_is_valid(ctx->conn) ||
          ctx->state == XRPC_CONN_STATE_COMPLETED ||
          ctx->last_error != XRPC_SUCCESS) {
        xrpc_conn_context_free(srv, ctx);
        ctx = NULL;
      }
    }
  }

  return ret;
}

static int xrpc_conn_context_create(struct xrpc_server *srv,
                                    struct xrpc_connection *conn,
                                    struct xrpc_connection_context **out_ctx) {
  *out_ctx = NULL;

  if (!srv || !conn || !connection_is_valid(conn) || !out_ctx)
    return XRPC_INTERNAL_ERR_INVALID_CONN;

  struct xrpc_connection_context *ctx = NULL;
  int ret;

  if (ret = xrpc_pool_get(srv->conn_context_pool, (void **)&ctx),
      ret != XRPC_SUCCESS)
    return ret;

  ctx->conn = conn;
  ctx->frames_completed = 0;
  ctx->frames_inflight = 0;
  ctx->frames_remaining = 0;
  ctx->io = srv->io;
  ctx->transport = srv->transport;
  ctx->frame_context_pool = srv->frame_context_pool;
  ctx->conn_context_rb = srv->conn_context_rb;
  ctx->next_batch_id = &srv->next_batch_id;

  ctx->last_error = XRPC_SUCCESS;
  ctx->state = XRPC_CONN_STATE_READ_HEADER;

  // setup pointers to headers
  uint8_t *base = (uint8_t *)ctx + sizeof(struct xrpc_connection_context);

  ctx->rq_hdr = (struct xrpc_request_header *)base;
  base += sizeof(struct xrpc_request_header);

  ctx->rs_hdr = (struct xrpc_response_header *)base;

  if (ret = connection_ref(srv->transport, conn), ret != XRPC_SUCCESS) {
    assert(xrpc_pool_put(srv->conn_context_pool, ctx) == XRPC_SUCCESS);
    return ret;
  }

  *out_ctx = ctx;

  return XRPC_SUCCESS;
}

static void xrpc_conn_context_free(struct xrpc_server *srv,
                                   struct xrpc_connection_context *ctx) {
  if (!srv || !ctx) return;
  if (ctx->conn) connection_unref(ctx->transport, ctx->conn);
  assert(xrpc_pool_put(srv->conn_context_pool, ctx) == XRPC_SUCCESS);
}

static int xrpc_frame_context_create(struct xrpc_connection_context *conn_ctx,
                                     struct xrpc_frame_context **out_fctx) {

  if (!conn_ctx || !out_fctx) return XRPC_INTERNAL_ERR_INVALID_CONN;

  *out_fctx = NULL;
  struct xrpc_frame_context *fctx = NULL;
  assert(xrpc_pool_get(conn_ctx->frame_context_pool, (void **)&fctx) ==
         XRPC_SUCCESS);

  fctx->conn_ctx = conn_ctx;
  fctx->state = XRPC_FRAME_STATE_READ_HEADER;

  // setup pointers to headers
  uint8_t *base = (uint8_t *)fctx + sizeof(struct xrpc_connection_context);

  fctx->rq_hdr = (struct xrpc_request_frame_header *)base;
  base += sizeof(struct xrpc_request_frame_header);

  fctx->rs_hdr = (struct xrpc_response_frame_header *)base;

  fctx->last_error = XRPC_SUCCESS;
  fctx->req_data_size = 0;
  fctx->resp_data_size = 0;

  *out_fctx = fctx;
  return XRPC_SUCCESS;
}

static void xrpc_frame_context_free(struct xrpc_connection_context *conn_ctx,
                                    struct xrpc_frame_context *fctx) {
  if (!conn_ctx || !fctx) return;
  assert(xrpc_pool_put(conn_ctx->frame_context_pool, fctx) == XRPC_SUCCESS);
}

// Schedule an I/O operation based on the current request state. This function
// does not push to the queue, it modifies the context and lets the caller do it
// if needed
static void
xrpc_conn_context_schedule_next_operation(struct xrpc_connection_context *ctx) {
  struct xrpc_io_operation *op = NULL;
  int ret;

  // try to get a new operation
  if (ret = xrpc_io_operation_new(ctx->io, &op), ret != XRPC_SUCCESS) {
    ctx->state = XRPC_CONN_STATE_COMPLETED;
    ctx->last_error = ret;
    return;
  }

  // common setup for the operation
  op->conn = ctx->conn;
  op->ctx = ctx;

  switch (ctx->state) {
  case XRPC_CONN_STATE_READ_HEADER:
    op->type = XRPC_IO_READ;
    op->buf = ctx->rq_hdr_raw;
    op->len = sizeof(struct xrpc_request_header);
    op->on_complete = xrpc_io_conn_completed;

    ctx->io->ops->schedule_operation(ctx->io, op);
    break;
    // in batch. Continue reading frames
  case XRPC_CONN_STATE_IN_BATCH:
    // limit the number of frame in flight
    if (__atomic_load_n(&ctx->frames_inflight, __ATOMIC_RELAXED) >
            MAX_INFLIGHT_FRAMES ||
        __atomic_load_n(&ctx->frames_remaining, __ATOMIC_ACQUIRE) == 0)
      return;
    {
      struct xrpc_frame_context *fctx = NULL;
      int ret;
      if (ret = xrpc_frame_context_create(ctx, &fctx), ret != XRPC_SUCCESS) {
        // fatal error
        ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
        ctx->last_error = ret;
        ctx->rs_hdr->status = XRPC_API_ERR_ALLOC;
        return;
      }
      // schedule the operation
      op->type = XRPC_IO_READ;
      op->conn = ctx->conn;
      op->buf = fctx->rq_hdr_raw;
      op->len = sizeof(struct xrpc_request_frame_header);
      op->transferred_bytes = 0;
      op->on_complete = xrpc_io_frame_completed;
      op->ctx = fctx; // frame-level ctx

      __atomic_add_fetch(&ctx->frames_inflight, 1, __ATOMIC_RELAXED);
      ctx->io->ops->schedule_operation(ctx->io, op);
    }

    break;
  case XRPC_CONN_STATE_WRITE_HEADER:
    // serialize the response
    xrpc_response_header_to_net(ctx->rs_hdr, ctx->rs_hdr_raw);

    op->type = XRPC_IO_WRITE;
    op->buf = ctx->rs_hdr_raw;
    op->len = sizeof(struct xrpc_response_header);
    op->on_complete = xrpc_io_conn_completed;
    ctx->io->ops->schedule_operation(ctx->io, op);

  case XRPC_CONN_STATE_COMPLETED:
    // TODO: report for benchmark.
    break;
  }
}

static void xrpc_frame_process(struct xrpc_frame_context *ctx) { (void)ctx; }

/*
 * @brief Release server resources
 *
 * @param[in] srv  The server instance.
 */
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

  if (srv->conn_context_rb) {
    xrpc_ringbuf_free(srv->conn_context_rb);
    srv->conn_context_rb = NULL;
  }

  if (srv->conn_context_pool) {
    xrpc_pool_free(srv->conn_context_pool);
    srv->conn_context_pool = NULL;
  }

  if (srv->frame_context_pool) {
    xrpc_pool_free(srv->frame_context_pool);
    srv->frame_context_pool = NULL;
  }

  free(srv);
}

/*
 * @brief Flags the server to stop if running
 *
 * TODO: make user to choice between a graceful shutdown or to force
 *
 * @param srv         Server instance.
 */
void xrpc_server_stop(struct xrpc_server *srv) {
  __atomic_store_n(&srv->running, 0, __ATOMIC_SEQ_CST);
}

static void xrpc_io_conn_completed(struct xrpc_io_operation *op) {
  if (!op) return;
  struct xrpc_connection_context *ctx = op->ctx;

  // If the operation has not been completed, schedule again
  if (op->transferred_bytes < op->len &&
      op->status == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
    op->len -= op->transferred_bytes;
    op->buf += op->transferred_bytes;
    op->transferred_bytes = 0;
    ctx->io->ops->schedule_operation(ctx->io, op);
    return;
  }

  // An error occurred, handle the error
  if (op->status != XRPC_SUCCESS) {
    if (op->status == XRPC_TRANSPORT_ERR_CONN_CLOSED)
      connection_mark_for_close(ctx->conn);
    else
      XRPC_DEBUG_PRINT("Transport error: %d", op->status);

    ctx->state = XRPC_CONN_STATE_COMPLETED;
    ctx->last_error = op->status;

    assert(xrpc_io_operation_free(ctx->io, op) == XRPC_SUCCESS);
    op = NULL;

    /* Enqueue once for cleanup - server loop will free it */
    xrpc_ringbuf_push(ctx->conn_context_rb, ctx);
    return;
  }

  // Handle the completion of the operation. Prepare the next schedule and
  // advance the state.
  switch (ctx->state) {
  case XRPC_CONN_STATE_READ_HEADER:
    xrpc_handle_request_header(ctx);
    break;
  case XRPC_CONN_STATE_WRITE_HEADER:
    ctx->state = XRPC_CONN_STATE_COMPLETED;
    break;
  case XRPC_CONN_STATE_IN_BATCH:
    break;
  case XRPC_CONN_STATE_COMPLETED:
    break;
  }

  if (op) {
    assert(xrpc_io_operation_free(ctx->io, op) == XRPC_SUCCESS);
    op = NULL;
  }
}

static void xrpc_io_frame_completed(struct xrpc_io_operation *op) {
  if (!op) return;
  struct xrpc_frame_context *fctx = (struct xrpc_frame_context *)op->ctx;
  struct xrpc_connection_context *conn_ctx = fctx->conn_ctx;

  // If the operation has not been completed, schedule again
  if (op->transferred_bytes < op->len &&
      op->status == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
    op->len -= op->transferred_bytes;
    op->buf += op->transferred_bytes;
    op->transferred_bytes = 0;
    fctx->conn_ctx->io->ops->schedule_operation(fctx->conn_ctx->io, op);
    return;
  }

  if (op->status != XRPC_SUCCESS) {
    // network error: drop this frame, release slot and fctx
    __atomic_sub_fetch(&conn_ctx->frames_inflight, 1, __ATOMIC_RELAXED);
    xrpc_io_operation_free(conn_ctx->io, op);
    xrpc_pool_put(conn_ctx->frame_context_pool, fctx);
    return;
  }

  switch (fctx->state) {
  case XRPC_FRAME_STATE_READ_HEADER:
    // we read 8 bytes into fctx->req_hdr_raw -- parse to host-order hdr
    xrpc_request_frame_header_from_net(fctx->rq_hdr_raw, fctx->rq_hdr);

    // compute payload size
    size_t payload_len = xrpc_calculate_frame_data_size(fctx->rq_hdr);
    if (payload_len == 0) {
      // network error: drop this frame, release slot and fctx
      __atomic_sub_fetch(&conn_ctx->frames_inflight, 1, __ATOMIC_RELAXED);
      xrpc_io_operation_free(conn_ctx->io, op);
      xrpc_pool_put(conn_ctx->frame_context_pool, fctx);
    }
    break;
  case XRPC_FRAME_STATE_PROCESS:
    // payload fully read into fctx->req_frame_data
    fctx->req_data_size = op->transferred_bytes;

    // free the operation (we'll schedule new ops for other needs)
    xrpc_io_operation_free(conn_ctx->io, op);

    // Immediately try to schedule the next frame header read so we overlap
    // reading next header with worker processing. This uses conn->state
    // IN_BATCH and will create a new frame ctx.
    xrpc_conn_context_schedule_next_operation(
        conn_ctx); // non-blocking; will early-return if limit reached

    xrpc_frame_process(fctx);
    break;
  case XRPC_FRAME_STATE_WRITE_HEADER:
    break;
  case XRPC_FRAME_STATE_COMPLETED:
    __atomic_sub_fetch(&conn_ctx->frames_inflight, 1, __ATOMIC_RELAXED);
    xrpc_io_operation_free(conn_ctx->io, op);
    xrpc_pool_put(conn_ctx->frame_context_pool, fctx);
    break;
  }
}

/*
 * Handle a new request header. Understand what the user want and do it
 */
static void xrpc_handle_request_header(struct xrpc_connection_context *ctx) {
  struct xrpc_request_header *hdr = ctx->rq_hdr;

  // deserialize the request
  xrpc_request_header_from_net(ctx->rq_hdr_raw, hdr);

  uint8_t proto_version = XRPC_REQ_GET_VER(*hdr);
  enum xrpc_request_type msg_type = XRPC_REQ_GET_TYPE(*hdr);

  // if protocol mismatch return an error
  if (proto_version != XRPC_PROTO_VERSION) {
    ctx->rs_hdr->status = XRPC_PROTO_ERR_VERSION_MISMATCH;
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    return;
  }

  switch (msg_type) {
  case XRPC_REQUEST_BATCH_INIT: {
    uint16_t batch_id =
        __atomic_fetch_add(ctx->next_batch_id, 1, __ATOMIC_RELAXED);
    ctx->rs_hdr->batch_id = batch_id;
    ctx->rs_hdr->payload_size = 0;
    ctx->rs_hdr->status = XRPC_RESP_STATUS_ACK;
  } break;
  case XRPC_REQUEST_SERVER_INFO:
    ctx->rs_hdr->status = XRPC_RESP_STATUS_ACK;
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    ctx->rs_hdr->payload_size = 0;
    break;
  case XRPC_REQUEST_SERVER_PING:
    ctx->rs_hdr->status = XRPC_RESP_STATUS_ACK;
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    ctx->rs_hdr->payload_size = 0;
    break;
  case XRPC_REQUEST_BATCH_START:
    ctx->state = XRPC_CONN_STATE_IN_BATCH;
    ctx->last_error = XRPC_SUCCESS;
    ctx->rs_hdr->payload_size = 0;
    ctx->frames_completed = 0;
    ctx->frames_inflight = 0;
    ctx->frames_remaining = hdr->batch_size;
    break;
  }
}
