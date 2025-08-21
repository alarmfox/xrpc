#include <stdlib.h>

#include "xrpc/error.h"
#include "xrpc/io.h"
#include "xrpc/transport.h"

const struct xrpc_io_system_ops xrpc_blocking_ops;

static int xrpc_io_blocking_init(struct xrpc_io_system **xio,
                                 const struct xrpc_io_system_config *args) {
  (void)args;
  struct xrpc_io_system *io = malloc(sizeof(struct xrpc_io_system));

  io->ops = &xrpc_blocking_ops;
  io->data = NULL;

  *xio = io;
  return XRPC_SUCCESS;
}

static int xprc_io_blocking_schedule_operation(struct xrpc_io_system *xio,
                                               struct xrpc_io_operation *op) {

  (void)xio;
  int ret = XRPC_SUCCESS;
  size_t transferred_bytes = 0, n = 0;

  switch (op->type) {
  case XRPC_IO_READ:
    while (transferred_bytes < op->len) {
      ret = op->conn->ops->recv(op->conn, op->buf + transferred_bytes,
                                op->len - transferred_bytes, &n);
      if (ret != XRPC_SUCCESS) break;
      transferred_bytes += n;
    }
    break;
  case XRPC_IO_WRITE: {
    while (transferred_bytes < op->len) {
      ret = op->conn->ops->send(op->conn, op->buf + transferred_bytes,
                                op->len - transferred_bytes, &n);
      if (ret != XRPC_SUCCESS) break;
      transferred_bytes += n;
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
  if (xio) free(xio);
}

const struct xrpc_io_system_ops xrpc_blocking_ops = {
    .init = xrpc_io_blocking_init,
    .schedule_operation = xprc_io_blocking_schedule_operation,
    .poll = xrpc_io_blocking_poll,
    .free = xrpc_io_blocking_free,
};
