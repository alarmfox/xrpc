#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/ringbuf.h"

/*
 * @brief Initializes a new instance of the ringbuf of capacity `capacity`.
 *
 * @param[out] rb       A new pointer to the ringbuf instance
 * @param[in] capacity  Capacity of the array
 *
 * @return XRPC_SUCCESS on success.
 * @return XRPC_INTERNAL_ERR_ALLOC if cannot allocate
 * memory
 * @return XRPC_INTENAL_ERR_RINGBUF_INVALID_ARG if capacity is zero.
 */
int xrpc_ringbuf_init(struct xrpc_ringbuf **out_rb, const size_t capacity) {

  if (capacity == 0) return XRPC_INTERNAL_ERR_RINGBUF_INVALID_ARG;

  struct xrpc_ringbuf *rb =
      aligned_alloc(CACHE_LINE_SIZE, sizeof(struct xrpc_ringbuf));

  if (!rb) return XRPC_INTERNAL_ERR_ALLOC;

  rb->capacity = capacity + 1;
  rb->head = 0;
  rb->tail = 0;

  // align the allocation. The size of void * should already be memory aligned
  size_t rounded = (sizeof(void *) * rb->capacity + CACHE_LINE_SIZE - 1) &
                   ~(CACHE_LINE_SIZE - 1);

  rb->items = aligned_alloc(CACHE_LINE_SIZE, rounded);
  if (!rb->items) {
    free(rb);
    return XRPC_INTERNAL_ERR_ALLOC;
  }

  memset(rb->items, 0, sizeof(void *) * rb->capacity);

  *out_rb = rb;

  return XRPC_SUCCESS;
}

/*
 * @brief Frees ringbuf resources
 *
 * @param[in] rb        The ringbuf instance
 */
void xrpc_ringbuf_free(struct xrpc_ringbuf *rb) {
  if (!rb) return;
  if (rb->items) free(rb->items);
  rb->items = NULL;
  free(rb);
}

/*
 * @brief Push a new element to the queue.
 *
 * @param[in] rb        The ringbuf instance
 * @param[in] item      A pointer to the element
 *
 * @return XRPC_SUCCESS on success or XRPC_INTERNAL_ERR_RINGBUF_FULL if the
 * queue is full
 */
int xrpc_ringbuf_push(struct xrpc_ringbuf *rb, void *item) {
  if ((rb->tail + 1) % rb->capacity == rb->head)
    return XRPC_INTERNAL_ERR_RINGBUF_FULL;

  rb->items[rb->tail] = item;
  rb->tail = (rb->tail + 1) % rb->capacity;

  return XRPC_SUCCESS;
}

/*
 * @brief Gets the first available element in a FIFO policy.
 *
 * @param[in] rb        The ringbuf instance
 * @param[in] item      A pointer to the element
 *
 * @return XRPC_SUCCESS on success or XRPC_INTERNAL_ERR_RINGBUF_EMPTY if the
 * queue is empty
 */
int xrpc_ringbuf_pop(struct xrpc_ringbuf *rb, void **item) {

  if (rb->head == rb->tail) return XRPC_INTERNAL_ERR_RINGBUF_EMPTY;

  *item = rb->items[rb->head];
  rb->items[rb->head] = NULL;
  rb->head = (rb->head + 1) % rb->capacity;

  return XRPC_SUCCESS;
}
