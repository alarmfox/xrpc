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

/* Configuration constants */
#define MAX_INFLIGHT_FRAMES 64
#define MAX_INFLIGHT_BATCH 64
#define MAX_HANDLERS 64
#define MAX_PAYLOAD_ALLOWED (16 * 1024 * 1024) /* 16 MiB */
#define SMALL_BUF_SIZE 256
#define DIRECT_PROCESSING

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
  // Reference to the server and the client connection
  struct xrpc_server *server;
  struct xrpc_connection *conn;

  /* pointers to request/response headers */
  struct xrpc_request_header *request_header;
  struct xrpc_response_header *response_header;

  /* Pointers to raw data coming from the net (network-byte order)*/
  uint8_t request_header_raw[sizeof(struct xrpc_request_header)];
  uint8_t response_header_raw[sizeof(struct xrpc_response_header)];

  // counters for state management
  size_t transferred_bytes;
  uint16_t frames_remaining;
  uint16_t frames_inflight;
  uint16_t frames_requested;
};

/*
 * @brief Request frame context.
 * The metadata are a pointer to the `xrpc_connection`,
 */
struct xrpc_frame_context {
  enum xrpc_frame_context_state {
    XRPC_FRAME_STATE_READ_HEADER,
    XRPC_FRAME_STATE_READ_BODY,
    XRPC_FRAME_STATE_PROCESS,
    XRPC_FRAME_STATE_WRITE_HEADER,
    XRPC_FRAME_STATE_WRITE_BODY,
    XRPC_FRAME_STATE_COMPLETED,
  } state;

  int last_error;
  struct xrpc_connection_context *conn_ctx;

  // Frame headers
  struct xrpc_request_frame_header *request_header;
  struct xrpc_response_frame_header *response_header;

  /* Pointers to raw data coming from the net (network-byte order)*/
  uint8_t request_header_raw[12];
  uint8_t response_header_raw[12];

  // Frame data buffers. These will be populated with host byte order
  uint8_t *request_data;
  uint8_t *response_data;
  size_t request_size;
  size_t response_size;

  // small buffer to handle small request
  uint8_t small_buf[SMALL_BUF_SIZE];
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

  struct xrpc_pool *connection_context_pool;
  struct xrpc_pool *frame_context_pool;
  struct xrpc_ringbuf *connection_context_rb;

  // TODO: move this to an external worker pool
  struct xrpc_ringbuf *frame_processing_rb;

  uint16_t next_batch_id;
  int running;
};

// Utils functions to manage xrpc_request_context lifecycle
static int connection_context_create(struct xrpc_server *srv,
                                     struct xrpc_connection *conn,
                                     struct xrpc_connection_context **out_ctx);
static void connection_context_free(struct xrpc_connection_context *ctx);
static int frame_context_create(struct xrpc_connection_context *conn_ctx,
                                struct xrpc_frame_context **out_ctx);
static void frame_context_free(struct xrpc_frame_context *fctx);

static void handle_request_header(struct xrpc_connection_context *ctx);

static void
connection_context_schedule_next_operation(struct xrpc_connection_context *ctx);
static void
frame_context_schedule_next_operation(struct xrpc_frame_context *ctx);

static void io_connection_completed(struct xrpc_io_operation *op);
static void io_frame_completed(struct xrpc_io_operation *op);

// Processing frame utilties
static void schedule_frame_for_processing(struct xrpc_frame_context *ctx);
static void frame_process_request(struct xrpc_frame_context *fctx);

// This map stores different transports. For now this is only for supported
// transport of this library. In future, a "register" method could be
// provided.
static const struct xrpc_transport_ops *transport_ops_map[] = {
    [XRPC_TRANSPORT_TCP] = &xrpc_transport_tcp_ops,
};

// This map stores io systems . For now this is only for supported
// io systems of this library. In future, a "register" method could be
// provided.
static const struct xrpc_io_system_ops *io_ops_map[] = {
    [XRPC_IO_SYSTEM_BLOCKING] = &xrpc_blocking_ops,
};

int xrpc_server_init(struct xrpc_server **out_server,
                     const struct xrpc_server_config *config) {

  int ret = XRPC_SUCCESS;
  struct xrpc_server *server = NULL;
  size_t conn_context_size, frame_context_size;

  if (!config || !out_server)
    XRPC_PRINT_ERR_AND_RETURN("invalid arguments", XRPC_API_ERR_INVALID_ARGS);

  server = malloc(sizeof(struct xrpc_server));

  if (!server) XRPC_PRINT_ERR_AND_RETURN("malloc", XRPC_API_ERR_ALLOC);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)config->transport.type >=
      sizeof(transport_ops_map) / sizeof(transport_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the transport_ops table from the transport_ops_map and init the
  // transport
  const struct xrpc_transport_ops *tops =
      transport_ops_map[config->transport.type];

  ret = tops->init(&server->transport, &config->transport);
  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create transport", ret);

  // Check if the transport is present in the transport_ops_map
  if ((size_t)config->io.type >= sizeof(io_ops_map) / sizeof(io_ops_map[0]))
    return XRPC_API_ERR_INVALID_TRANSPORT;

  // Find the `io_system_ops` table from the ios_map and init the
  // I/O system.
  const struct xrpc_io_system_ops *ops = io_ops_map[config->io.type];

  ret = ops->init(&server->io, &config->io);
  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create I/O system", ret);

  // Zero init the handlers
  memset(server->handlers, 0, sizeof(server->handlers));

  // init the ringbuf for connection context
  ret = xrpc_ringbuf_init(&server->connection_context_rb,
                          config->max_concurrent_requests);

  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create connection request context queue",
                              ret);

  // init the ringbuf for processing frame
  ret = xrpc_ringbuf_init(&server->frame_processing_rb, MAX_INFLIGHT_FRAMES);

  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create frame processing queue", ret);

  /*
   * Init the connection_context_pool
   * [connection_context_pool][requesst header][response header]
   */
  conn_context_size = sizeof(struct xrpc_connection_context) +
                      sizeof(struct xrpc_request_header) +
                      sizeof(struct xrpc_response_header);

  ret = xrpc_pool_init(&server->connection_context_pool,
                       config->max_concurrent_requests, conn_context_size);
  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create connection context pool", ret);

  /*
   * Init frame context pool
   * [frame_context][requesst header][response header]
   */
  frame_context_size = sizeof(struct xrpc_frame_context) +
                       sizeof(struct xrpc_request_frame_header) +
                       sizeof(struct xrpc_response_frame_header);
  ret = xrpc_pool_init(&server->frame_context_pool,
                       config->max_concurrent_requests * MAX_INFLIGHT_FRAMES,
                       frame_context_size);
  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create framw context pool ", ret);

  __atomic_store_n(&server->next_batch_id, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n(&server->running, 0, __ATOMIC_SEQ_CST);

  *out_server = server;
  return ret;
}

int xrpc_server_register(struct xrpc_server *server, size_t operation_id,
                         xrpc_handler_fn handler, int flags) {
  if (!server || !handler) {
    XRPC_PRINT_ERR_AND_RETURN("Invalid arguments", XRPC_API_ERR_INVALID_ARGS);
  }

  if (operation_id >= MAX_HANDLERS) {
    XRPC_PRINT_ERR_AND_RETURN("Operation ID out of range: %lu",
                              XRPC_PROTO_ERR_INVALID_OP, operation_id);
  }

  if (server->handlers[operation_id] && !(flags & XRPC_RF_OVERWRITE)) {
    XRPC_PRINT_ERR_AND_RETURN("Handler already registered at operation=%lu",
                              XRPC_API_ERR_HANDLER_ALREADY_REGISTERED,
                              operation_id);
  }

  server->handlers[operation_id] = handler;
  return XRPC_SUCCESS;
}

int xrpc_server_run(struct xrpc_server *server) {
  int ret = XRPC_SUCCESS;
  struct xrpc_connection *conn = NULL;
  struct xrpc_connection_context *ctx = NULL;

  // mark the server as running
  __atomic_store_n(&server->running, 1, __ATOMIC_SEQ_CST);

  /*
   * Main loop.
   * - accept new connections
   * - poll for events
   * - process enqueued connections
   */
  while (__atomic_load_n(&server->running, __ATOMIC_RELAXED)) {
    /* Accept new connections */
    ret = server->transport->ops->accept(server->transport, &conn);
    if (ret == XRPC_SUCCESS) {
      ret = connection_context_create(server, conn, &ctx);
      if (ret == XRPC_SUCCESS) {
        XRPC_DEBUG_PRINT("created context for connection %lu", conn->id);
        xrpc_ringbuf_push(server->connection_context_rb, ctx);
      } else {
        XRPC_DEBUG_PRINT("failed to create request context");
        server->transport->ops->close(server->transport, conn);
      }
    }

    server->io->ops->poll(server->io);

    // snapshot the context so that we can consume at most `n` contexts. This
    // helps because we can append new contexts in the loop an they will be
    // processed in the next iteration.
    size_t contexts_count = xrpc_ringbuf_count(server->connection_context_rb);

    while ((contexts_count--) > 0 &&
           xrpc_ringbuf_pop(server->connection_context_rb, (void **)&ctx) ==
               XRPC_SUCCESS) {

      // if the underlying connection is no longer valid. Put the request for
      // completion and free the resources
      if (!connection_is_valid(ctx->conn) || ctx->last_error != XRPC_SUCCESS) {
        connection_context_free(ctx);
        ctx = NULL;
        continue;
      }

      // step the state machine for the current connection context
      connection_context_schedule_next_operation(ctx);

      // put the context in the queue if it's not been freed
      if (ctx->state != XRPC_CONN_STATE_COMPLETED)
        xrpc_ringbuf_push(server->connection_context_rb, ctx);
      else {
        connection_context_free(ctx);
        ctx = NULL;
      }
    }

    /* Process frames ready */
    struct xrpc_frame_context *fctx = NULL;
    size_t frame_count = xrpc_ringbuf_count(server->frame_processing_rb);

    while (frame_count-- > 0 &&
           xrpc_ringbuf_pop(server->frame_processing_rb, (void **)&fctx) ==
               XRPC_SUCCESS) {

      // schedule next frame operation
      frame_context_schedule_next_operation(fctx);

      // put the context in the queue if it's not been freed
      if (fctx->state != XRPC_FRAME_STATE_COMPLETED)
        xrpc_ringbuf_push(server->frame_processing_rb, fctx);
      else {
        frame_context_free(fctx);
        fctx = NULL;
      }
    }
  }

  return ret;
}

/*
 * @brief Checks if the server is running
 *
 * @param[in] The server instance
 *
 * @return True if the server is running
 * @return False otherwise
 */
bool xrpc_server_running(const struct xrpc_server *srv) {
  if (!srv) return false;
  return __atomic_load_n(&srv->running, __ATOMIC_RELAXED);
}

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

  if (srv->connection_context_rb) {
    xrpc_ringbuf_free(srv->connection_context_rb);
    srv->connection_context_rb = NULL;
  }

  if (srv->connection_context_pool) {
    xrpc_pool_free(srv->connection_context_pool);
    srv->connection_context_pool = NULL;
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
  if (srv) __atomic_store_n(&srv->running, 0, __ATOMIC_SEQ_CST);
}

/*
 * Context management utils
 */
static int connection_context_create(struct xrpc_server *srv,
                                     struct xrpc_connection *conn,
                                     struct xrpc_connection_context **out_ctx) {

  if (!srv || !conn || !connection_is_valid(conn) || !out_ctx)
    return XRPC_INTERNAL_ERR_INVALID_CONN;

  *out_ctx = NULL;
  struct xrpc_connection_context *ctx = NULL;
  int ret;

  ret = xrpc_pool_get(srv->connection_context_pool, (void **)&ctx);

  if (ret != XRPC_SUCCESS) return ret;

  ctx->conn = conn;
  ctx->server = srv;
  ctx->last_error = XRPC_SUCCESS;
  ctx->state = XRPC_CONN_STATE_READ_HEADER;

  // setup pointers to headers
  uint8_t *base = (uint8_t *)ctx + sizeof(struct xrpc_connection_context);

  ctx->request_header = (struct xrpc_request_header *)base;
  base += sizeof(struct xrpc_request_header);

  ctx->response_header = (struct xrpc_response_header *)base;

  ret = connection_ref(srv->transport, conn);
  if (ret != XRPC_SUCCESS) {
    assert(xrpc_pool_put(srv->connection_context_pool, ctx) == XRPC_SUCCESS);
    return ret;
  }

  *out_ctx = ctx;

  return XRPC_SUCCESS;
}

static void connection_context_free(struct xrpc_connection_context *ctx) {
  if (!ctx || !ctx->conn) return;

  // Check if there are still frames in flight
  uint16_t inflight = __atomic_load_n(&ctx->frames_inflight, __ATOMIC_ACQUIRE);

  if (inflight > 0) {
    // Don't free yet - transition to draining state
    return;
  }

  if (ctx->conn) connection_unref(ctx->server->transport, ctx->conn);

  assert(xrpc_pool_put(ctx->server->connection_context_pool, ctx) ==
         XRPC_SUCCESS);
}

static int frame_context_create(struct xrpc_connection_context *conn_ctx,
                                struct xrpc_frame_context **out_fctx) {

  if (!conn_ctx || !out_fctx) return XRPC_INTERNAL_ERR_INVALID_CONN;

  *out_fctx = NULL;
  struct xrpc_frame_context *fctx = NULL;
  assert(xrpc_pool_get(conn_ctx->server->frame_context_pool, (void **)&fctx) ==
         XRPC_SUCCESS);

  fctx->conn_ctx = conn_ctx;
  fctx->state = XRPC_FRAME_STATE_READ_HEADER;

  // setup pointers to headers
  uint8_t *base = (uint8_t *)fctx + sizeof(struct xrpc_frame_context);

  fctx->request_header = (struct xrpc_request_frame_header *)base;
  base += sizeof(struct xrpc_request_frame_header);

  fctx->response_header = (struct xrpc_response_frame_header *)base;

  fctx->last_error = XRPC_SUCCESS;
  fctx->request_size = 0;
  fctx->response_size = 0;

  __atomic_add_fetch(&fctx->conn_ctx->frames_inflight, 1, __ATOMIC_RELAXED);

  *out_fctx = fctx;

  return XRPC_SUCCESS;
}

static void frame_context_free(struct xrpc_frame_context *fctx) {
  if (!fctx) return;

  /* Free allocated data if not using small buffer */
  if (fctx->request_data && fctx->request_data != fctx->small_buf)
    free(fctx->request_data);

  if (fctx->response_data && fctx->response_data != fctx->small_buf)
    free(fctx->response_data);

  // Atomically decrement both inflight and remaining counters
  __atomic_sub_fetch(&fctx->conn_ctx->frames_inflight, 1, __ATOMIC_RELEASE);
  __atomic_sub_fetch(&fctx->conn_ctx->frames_remaining, 1, __ATOMIC_RELEASE);

  assert(xrpc_pool_put(fctx->conn_ctx->server->frame_context_pool, fctx) ==
         XRPC_SUCCESS);
}

/* I/O completion callbacks */

// Schedule an I/O operation based on the current request state. This function
// does not push to the queue, it modifies the context and lets the caller do
// it if needed
static void connection_context_schedule_next_operation(
    struct xrpc_connection_context *ctx) {

  if (!ctx) return;

  struct xrpc_io_operation *op = NULL;
  int ret;

  // try to get a new operation
  ret = xrpc_io_operation_new(ctx->server->io, &op);
  if (ret != XRPC_SUCCESS) {
    ctx->state = XRPC_CONN_STATE_COMPLETED;
    ctx->last_error = ret;
    return;
  }

  // common setup for the operation
  op->conn = ctx->conn;
  op->ctx = ctx;
  op->on_complete = io_connection_completed;

  switch (ctx->state) {
  case XRPC_CONN_STATE_READ_HEADER:
    op->type = XRPC_IO_READ;
    op->buf = ctx->request_header_raw;
    op->len = sizeof(struct xrpc_request_header);
    ctx->server->io->ops->schedule_operation(ctx->server->io, op);
    break;

    // in batch. Continue reading frames
  case XRPC_CONN_STATE_IN_BATCH: {
    /* Check if we should schedule more frame   reads */
    /* Load current counters atomically */
    uint16_t remaining =
        __atomic_load_n(&ctx->frames_remaining, __ATOMIC_ACQUIRE);
    uint16_t inflight =
        __atomic_load_n(&ctx->frames_inflight, __ATOMIC_ACQUIRE);
    uint16_t requested =
        __atomic_load_n(&ctx->frames_requested, __ATOMIC_ACQUIRE);

    /*
     * Schedule new frame read if:
     * 1. We haven't hit the inflight limit
     * 2. There are still frames remaining to read
     * 3. We have available inflight slots (remaining > 0)
     */
    if (inflight > MAX_INFLIGHT_FRAMES) {
      xrpc_io_operation_free(ctx->server->io, op);
      op = NULL;
      return;
    }

    if (requested >= remaining || remaining == 0) {
      // All frames have been requested or batch is complete
      // Check if all frames are done processing
      if (inflight == 0) {
        // All frames completed, send response header with status
        ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
      }
      if (op) xrpc_io_operation_free(ctx->server->io, op);
      return;
    }

    struct xrpc_frame_context *fctx = NULL;
    int ret;

    ret = frame_context_create(ctx, &fctx);

    if (ret != XRPC_SUCCESS) {
      // fatal error
      ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
      ctx->last_error = ret;
      ctx->response_header->status = XRPC_API_ERR_ALLOC;
      xrpc_io_operation_free(ctx->server->io, op);
      op = NULL;
      return;
    }
    // Atomically increment the requested counter
    __atomic_add_fetch(&ctx->frames_requested, 1, __ATOMIC_RELEASE);
    xrpc_ringbuf_push(ctx->server->frame_processing_rb, fctx);
    break;
  }

  case XRPC_CONN_STATE_WRITE_HEADER:
    xrpc_response_header_to_net(ctx->response_header, ctx->response_header_raw);
    op->type = XRPC_IO_WRITE;
    op->buf = ctx->response_header_raw;
    op->len = sizeof(struct xrpc_response_header);
    op->on_complete = io_connection_completed;
    ctx->server->io->ops->schedule_operation(ctx->server->io, op);
    break;

  case XRPC_CONN_STATE_COMPLETED:
    // TODO: report for benchmark.
    xrpc_io_operation_free(ctx->server->io, op);
    op = NULL;
    break;
  }
}

static void
frame_context_schedule_next_operation(struct xrpc_frame_context *fctx) {

  if (!fctx) return;

  struct xrpc_io_operation *op = NULL;
  struct xrpc_server *server = fctx->conn_ctx->server;
  struct xrpc_connection *conn = fctx->conn_ctx->conn;
  size_t transferred;
  int ret;

  // try to get a new operation
  ret = xrpc_io_operation_new(server->io, &op);
  if (ret != XRPC_SUCCESS) {
    fctx->state = XRPC_FRAME_STATE_COMPLETED;
    fctx->last_error = ret;
    return;
  }

  // common setup for the operation
  op->conn = conn;
  op->ctx = fctx;
  op->on_complete = io_frame_completed;
  op->transferred_bytes = 0;

  switch (fctx->state) {
  case XRPC_FRAME_STATE_READ_HEADER:
    // schedule the operation
    op->type = XRPC_IO_READ;
    op->buf = fctx->request_header_raw;
    op->len = sizeof(struct xrpc_request_frame_header);

    server->io->ops->schedule_operation(server->io, op);
    break;
  case XRPC_FRAME_STATE_READ_BODY: {
    uint8_t *raw_buffer = NULL;

    // avoid mallocs for small size and use a stack allocated buffer
    if (fctx->request_size < SMALL_BUF_SIZE) {
      raw_buffer = fctx->small_buf;
    } else {
      raw_buffer = malloc(fctx->request_size);
      assert(raw_buffer != NULL);
    }
    op->type = XRPC_IO_READ;
    op->buf = raw_buffer;
    op->len = fctx->request_size;
    server->io->ops->schedule_operation(server->io, op);
    break;
  }
  case XRPC_FRAME_STATE_PROCESS:
    schedule_frame_for_processing(fctx);
    break;
  case XRPC_FRAME_STATE_WRITE_HEADER:
    xrpc_response_frame_header_to_net(fctx->response_header,
                                      fctx->response_header_raw);
    op->type = XRPC_IO_WRITE;
    op->buf = fctx->response_header_raw;
    op->len = sizeof(struct xrpc_response_frame_header);
    server->io->ops->schedule_operation(server->io, op);
    break;
  case XRPC_FRAME_STATE_WRITE_BODY: {
    uint8_t *raw_buffer = NULL;

    // Attempt to avoid the malloc:
    // TODO: maybe use a pool
    // - use the stack buffer
    // - reuse the request buffer
    // - fallback to malloc
    if (fctx->response_size < SMALL_BUF_SIZE)
      raw_buffer = fctx->small_buf;
    else if (fctx->response_size < fctx->request_size)
      raw_buffer = fctx->request_data;
    else {
      raw_buffer = malloc(fctx->response_size);
      assert(raw_buffer != NULL);
    }

    enum xrpc_dtype_base dtyb =
        xrpc_res_fr_get_dtypb_from_opinfo(fctx->response_header->opinfo);
    enum xrpc_dtype_category dtyc =
        xrpc_res_fr_get_dtypc_from_opinfo(fctx->response_header->opinfo);
    uint16_t size_params = fctx->response_header->size_params;

    ret = xrpc_vector_to_net(dtyb, dtyc, size_params, fctx->response_data,
                             raw_buffer, fctx->response_size, &transferred);

    assert(ret == XRPC_SUCCESS);

    op->type = XRPC_IO_WRITE;
    op->buf = raw_buffer;
    op->len = fctx->response_size;
    server->io->ops->schedule_operation(server->io, op);
    break;
  }
  case XRPC_FRAME_STATE_COMPLETED:
    xrpc_io_operation_free(server->io, op);
    op = NULL;
    break;
  }
}

static void io_connection_completed(struct xrpc_io_operation *op) {
  if (!op) return;
  struct xrpc_connection_context *ctx = op->ctx;

  // If the operation has not been completed, schedule again
  if (op->transferred_bytes < op->len &&
      op->status == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
    op->len -= op->transferred_bytes;
    op->buf += op->transferred_bytes;
    op->transferred_bytes = 0;
    ctx->server->io->ops->schedule_operation(ctx->server->io, op);
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

    assert(xrpc_io_operation_free(ctx->server->io, op) == XRPC_SUCCESS);
    op = NULL;

    /* Enqueue once for cleanup - server loop will free it */
    // xrpc_ringbuf_push(ctx->server->connection_context_rb, ctx);
    return;
  }

  // Handle the completion of the operation. Prepare the next schedule and
  // advance the state.
  switch (ctx->state) {
  case XRPC_CONN_STATE_READ_HEADER:
    handle_request_header(ctx);
    break;
  case XRPC_CONN_STATE_WRITE_HEADER:
    ctx->state = XRPC_CONN_STATE_READ_HEADER;
    break;
  default:
    break;
  }

  if (op) {
    assert(xrpc_io_operation_free(ctx->server->io, op) == XRPC_SUCCESS);
    op = NULL;
  }
}

static void io_frame_completed(struct xrpc_io_operation *op) {
  if (!op) return;

  struct xrpc_frame_context *fctx = op->ctx;
  struct xrpc_server *server = fctx->conn_ctx->server;

  // If the operation has not been completed, schedule again
  if (op->transferred_bytes < op->len &&
      op->status == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
    op->len -= op->transferred_bytes;
    op->buf += op->transferred_bytes;
    op->transferred_bytes = 0;
    server->io->ops->schedule_operation(server->io, op);
    return;
  }

  if (op->status != XRPC_SUCCESS) {
    // network error: drop this frame, release slot and fctx
    xrpc_io_operation_free(server->io, op);
    frame_context_free(fctx);
    return;
  }

  switch (fctx->state) {
  case XRPC_FRAME_STATE_READ_HEADER:
    // we read 8 bytes into fctx->req_hdr_raw -- parse to host-order hdr
    xrpc_request_frame_header_from_net(fctx->request_header_raw,
                                       fctx->request_header);

    // compute payload size
    size_t payload_len = xrpc_calculate_req_fr_data_size(fctx->request_header);
    if (payload_len == 0) {
      // network error: drop this frame, release slot and fctx
      xrpc_io_operation_free(server->io, op);
      op = NULL;
      frame_context_free(fctx);
    } else if (payload_len > MAX_PAYLOAD_ALLOWED) {
      // TODO: return error
      return;
    }

    fctx->request_size = payload_len;

    fctx->state = XRPC_FRAME_STATE_READ_BODY;
    xrpc_io_operation_free(server->io, op);
    break;
  case XRPC_FRAME_STATE_READ_BODY: {
    // payload fully read into fctx->req_frame_data
    // IN_BATCH and will create a new frame ctx.
    // connection_context_schedule_next_operation(
    //     conn_ctx); // non-blocking; will early-return if limit reached
    // TODO: understand the type of payload and deserialize it before processing
    uint8_t buf[SMALL_BUF_SIZE] = {0};
    size_t transferred = 0;
    int ret;
    fctx->request_size = op->transferred_bytes;

    /*
     * To avoid a malloc we create a temporary buffer copy the raw data in it
     * and assign the struct small buf to request_data
     */
    if (fctx->request_size < SMALL_BUF_SIZE) {
      memcpy(buf, op->buf, fctx->request_size);
      fctx->request_data = fctx->small_buf;
      op->buf = buf;
    } else {
      fctx->request_data = malloc(fctx->request_size);
      assert(fctx->request_data != NULL);
    }

    enum xrpc_dtype_base dtyb =
        xrpc_req_fr_get_dtypb_from_opinfo(fctx->request_header->opinfo);
    enum xrpc_dtype_category dtyc =
        xrpc_req_fr_get_dtypc_from_opinfo(fctx->request_header->opinfo);
    uint16_t size_params = fctx->request_header->size_params;

    ret = xrpc_vector_from_net(dtyb, dtyc, size_params, op->buf,
                               fctx->request_size, fctx->request_data,
                               &transferred);

    assert(ret == XRPC_SUCCESS);

    fctx->state = XRPC_FRAME_STATE_PROCESS;
    break;
  }
  case XRPC_FRAME_STATE_WRITE_HEADER: {
    if (fctx->response_size > 0)
      fctx->state = XRPC_FRAME_STATE_WRITE_BODY;
    else
      fctx->state = XRPC_FRAME_STATE_COMPLETED;
    break;
  }
  case XRPC_FRAME_STATE_WRITE_BODY: {
    fctx->state = XRPC_FRAME_STATE_COMPLETED;
    break;
  }
  default:
    break;
  }
  if (op) xrpc_io_operation_free(server->io, op);
}

/*
 * Utilities
 */

/*
 * Handle a new request header. Understand what the user want and do it
 */
static void handle_request_header(struct xrpc_connection_context *ctx) {
  struct xrpc_request_header *hdr = ctx->request_header;

  // deserialize the request
  xrpc_request_header_from_net(ctx->request_header_raw, hdr);

  uint8_t proto_version = xrpc_req_get_ver_from_preamble(hdr->preamble);
  enum xrpc_request_type msg_type =
      xrpc_req_get_type_from_preamble(hdr->preamble);

  // if protocol mismatch return an error
  if (proto_version != XRPC_PROTO_VERSION) {
    ctx->response_header->status = XRPC_PROTO_ERR_VERSION_MISMATCH;
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    return;
  }

  switch (msg_type) {
  case XRPC_REQUEST_BATCH_INIT: {
    uint16_t batch_id =
        __atomic_fetch_add(&ctx->server->next_batch_id, 1, __ATOMIC_RELAXED);
    ctx->response_header->batch_id = batch_id;
    ctx->response_header->payload_size = 0;
    xrpc_res_set_type(&ctx->response_header->preamble, XRPC_RESP_TYPE_ACK);
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
  } break;
  case XRPC_REQUEST_SERVER_INFO:
    xrpc_res_set_type(&ctx->response_header->preamble, XRPC_RESP_TYPE_ACK);
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    ctx->response_header->payload_size = 0;
    break;
  case XRPC_REQUEST_SERVER_PING:
    xrpc_res_set_type(&ctx->response_header->preamble, XRPC_RESP_TYPE_ACK);
    ctx->state = XRPC_CONN_STATE_WRITE_HEADER;
    ctx->last_error = XRPC_SUCCESS;
    ctx->response_header->payload_size = 0;
    break;
  case XRPC_REQUEST_BATCH_START:
    ctx->state = XRPC_CONN_STATE_IN_BATCH;
    ctx->last_error = XRPC_SUCCESS;
    ctx->response_header->payload_size = 0;
    ctx->frames_inflight = 0;

    ctx->response_header->status = ctx->request_header->batch_size;
    ctx->response_header->batch_id = ctx->request_header->batch_id;
    xrpc_res_set_type(&ctx->response_header->preamble,
                      XRPC_RESP_TYPE_BATCH_REPORT);

    xrpc_res_set_version(&ctx->response_header->preamble, XRPC_PROTO_VERSION);
    // Initialize atomic counters for batch processing
    __atomic_store_n(&ctx->frames_inflight, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&ctx->frames_remaining, hdr->batch_size, __ATOMIC_RELEASE);
    __atomic_store_n(&ctx->frames_requested, 0, __ATOMIC_RELEASE);
    break;
  }
  // increment the sequence number
  ctx->response_header->sequence_number =
      ctx->request_header->sequence_number + 1;
}

static void schedule_frame_for_processing(struct xrpc_frame_context *fctx) {
/* Option 1: Direct processing (blocking - simple but not scalable) */
#ifdef DIRECT_PROCESSING
  frame_process_request(fctx);

  /* Transition to write response state */
  fctx->response_header->batch_id = fctx->request_header->batch_id;
  fctx->response_header->frame_id = fctx->request_header->frame_id;
  fctx->state = XRPC_FRAME_STATE_WRITE_HEADER;
  return;
#endif

/* Option 2: Thread pool processing  */
#ifdef THREAD_POOL_PROCESSING
  xrpc_connection_context_t *conn_ctx = fctx->connection_ctx;
  struct xrpc_server *server =
      container_of(conn_ctx->transport, struct xrpc_server, transport);

  if (server->thread_pool) {
    thread_pool_submit_job(server->thread_pool, frame_process_request, fctx);
    return;
  }
#endif

/* Option 3: Work queue processing (for single-threaded async processing) */
#ifdef WORK_QUEUE_PROCESSING
  xrpc_connection_context_t *conn_ctx = fctx->connection_ctx;

  if (conn_ctx->work_queue) {
    work_queue_enqueue(conn_ctx->work_queue, fctx);
    return;
  }
#endif
}

static void frame_process_request(struct xrpc_frame_context *fctx) {
  if (!fctx || !fctx->conn_ctx) return;

  struct xrpc_connection_context *conn_ctx = fctx->conn_ctx;
  struct xrpc_request_frame_header *req_header = fctx->request_header;

  /* Extract operation ID and find handler */
  uint8_t operation_id = xrpc_req_fr_get_opcode_from_opinfo(req_header->opinfo);

  struct xrpc_server *server = conn_ctx->server;

  if (operation_id >= MAX_HANDLERS || !server->handlers[operation_id]) {
    /* No handler found - prepare error response */
    xrpc_res_fr_set_status(&fctx->response_header->opinfo,
                           XRPC_FR_RESPONSE_INVALID_OP);
    fctx->response_data = NULL;
    fctx->response_size = 0;
    fctx->last_error = XRPC_PROTO_ERR_INVALID_OP;
  } else {
    /* Call the registered handler */
    int ret;
    // allocate memory for response data
    fctx->response_data = malloc(8);
    xrpc_handler_fn handler = server->handlers[operation_id];
    struct xrpc_request_frame req = {.header = fctx->request_header,
                                     .data = fctx->request_data};

    struct xrpc_response_frame res = {.header = fctx->response_header,
                                      .data = fctx->response_data};
    /* Execute handler */
    ret = handler(&req, &res);

    assert(ret == XRPC_SUCCESS);

    xrpc_res_fr_set_status(&fctx->response_header->opinfo,
                           XRPC_FR_RESPONSE_SUCCESS);
    xrpc_res_fr_set_dtypb(&fctx->response_header->opinfo, XRPC_BASE_UINT64);
    xrpc_res_fr_set_dtypc(&fctx->response_header->opinfo,
                          XRPC_DTYPE_CAT_VECTOR);

    xrpc_res_fr_set_scale(&fctx->response_header->opinfo, 0);
    fctx->response_size = 8;
    fctx->last_error = XRPC_SUCCESS;
    fctx->response_header->size_params = 1;
  }
}
