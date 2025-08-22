#include <stdlib.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/pool.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

const struct xrpc_io_system_ops xrpc_blocking_ops;

static int xrpc_io_blocking_init(struct xrpc_io_system **xio,
                                 const struct xrpc_io_system_config *args) {

  int ret;
  struct xrpc_io_system *io = malloc(sizeof(struct xrpc_io_system));

  if (!io) return XRPC_INTERNAL_ERR_ALLOC;

  ret = xrpc_pool_init(&io->op_pool, args->max_concurrent_operations,
                       sizeof(struct xrpc_io_operation));

  if (ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("cannot create operations pool", ret);

  io->ops = &xrpc_blocking_ops;
  io->data = NULL;

  *xio = io;
  return XRPC_SUCCESS;
}

static int xrpc_io_blocking_schedule_operation(struct xrpc_io_system *xio,
                                               struct xrpc_io_operation *op) {

  (void)xio;
  int ret = XRPC_SUCCESS;
  size_t n = 0;

  switch (op->type) {
  case XRPC_IO_READ:
    while (op->transferred_bytes < op->len) {
      ret = op->conn->ops->recv(op->conn, op->buf + op->transferred_bytes,
                                op->len - op->transferred_bytes, &n);
      if (ret != XRPC_SUCCESS) break;
      op->transferred_bytes += n;
    }
    break;
  case XRPC_IO_WRITE: {
    while (op->transferred_bytes < op->len) {
      ret = op->conn->ops->send(op->conn, op->buf + op->transferred_bytes,
                                op->len - op->transferred_bytes, &n);
      if (ret != XRPC_SUCCESS) break;
      op->transferred_bytes += n;
    }
    break;
  }
  }

  op->status = ret;
  if (op->on_complete) op->on_complete(op);

  return XRPC_SUCCESS;
}

static int xrpc_io_blocking_poll(struct xrpc_io_system *xio) {
  (void)xio;
  return XRPC_SUCCESS;
}

static void xrpc_io_blocking_free(struct xrpc_io_system *xio) {
  if (!xio) return;
  if (xio->op_pool) {
    xrpc_pool_free(xio->op_pool);
    xio->op_pool = NULL;
  }
  free(xio);
}

const struct xrpc_io_system_ops xrpc_blocking_ops = {
    .init = xrpc_io_blocking_init,
    .schedule_operation = xrpc_io_blocking_schedule_operation,
    .poll = xrpc_io_blocking_poll,
    .free = xrpc_io_blocking_free,
};
