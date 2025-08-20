#ifndef XRPC_RINGBUF_H
#define XRPC_RINGBUF_H

#include <stddef.h>

/*
 * Ring buffer data structure. It manages pointers of data with a FIFO policy.
 */
struct xrpc_ringbuf {
  void **items;
  size_t capacity;
  size_t head;
  size_t tail;
};

/*
 * @brief Initializes a new instance of the ringbuf of capacity `capacity`.
 *
 * @param[out] rb       A new pointer to the ringbuf instance
 * @param[in] capacity  Capacity of the array
 */
int xrpc_ringbuf_init(struct xrpc_ringbuf **rb, const size_t capacity);

/*
 * @brief Frees ringbuf resources
 *
 * @param[in] rb        The ringbuf instance
 */
void xrpc_ringbuf_free(struct xrpc_ringbuf *rb);

/*
 * @brief Push a new element to the queue.
 *
 * @param[in] rb        The ringbuf instance
 * @param[in] item      A pointer to the element
 *
 * @return XRPC_SUCCESS on success or XRPC_INTERNAL_ERR_QUEUE_FULL if the queue
 * is full
 */
int xrpc_ringbuf_push(struct xrpc_ringbuf *rb, void *item);

/*
 * @brief Gets the first available element in a FIFO policy.
 *
 * @param[in] rb        The ringbuf instance
 * @param[in] item      A pointer to the element
 *
 * @return XRPC_SUCCESS on success or XRPC_INTERNAL_ERR_QUEUE_EMPTY if the queue
 * is empty
 */
int xrpc_ringbuf_pop(struct xrpc_ringbuf *rb, void **item);

/*
 * @brief Gets the current number of element enqueued.
 *
 * @param[in] rb        The ringbuf instance
 *
 * @return: number of elements in the queue
 *
 */
static inline size_t xrpc_ringbuf_count(const struct xrpc_ringbuf *rb) {
  return rb->tail >= rb->head ? rb->tail - rb->head
                              : rb->capacity - rb->head + rb->tail;
}
#endif // !XRPC_RINGBUF_H
