#include <stdlib.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/ringbuf.h"

int xrpc_ringbuf_init(struct xrpc_ringbuf **rb, const size_t capacity) {
  struct xrpc_ringbuf *_rb = malloc(sizeof(struct xrpc_ringbuf));

  if (!_rb) return XRPC_INTERNAL_ERR_ALLOC;

  _rb->capacity = capacity;
  _rb->head = 0;
  _rb->tail = 0;

  _rb->items = malloc(sizeof(void *) * capacity);
  if (!_rb->items) return XRPC_INTERNAL_ERR_ALLOC;

  memset(_rb->items, 0, sizeof(void *) * capacity);

  *rb = _rb;

  return XRPC_SUCCESS;
}

void xrpc_ringbuf_free(struct xrpc_ringbuf *rb) {
  if (!rb) return;
  if (rb->items) free(rb->items);
  rb->items = NULL;
  free(rb);
}

int xrpc_ringbuf_enqueue(struct xrpc_ringbuf *rb, void *item) {
  size_t pos = (1 + rb->tail) % rb->capacity;
  if (pos == rb->head) return XRPC_INTERNAL_ERR_QUEUE_FULL;

  rb->items[rb->tail] = item;
  rb->tail = pos;

  return XRPC_SUCCESS;
}

int xrpc_ringbuf_dequeue(struct xrpc_ringbuf *rb, void **item) {

  if (rb->head == rb->tail) return XRPC_INTERNAL_ERR_QUEUE_EMPTY;
  *item = rb->items[rb->head];
  rb->items[rb->head] = NULL;
  rb->head = (rb->head + 1) % rb->capacity;

  return XRPC_SUCCESS;
}
