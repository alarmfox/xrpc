#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/pool.h"

#define XRPC_POOL_ELEM_USED 0x0
#define XRPC_POOL_ELEM_FREE 0x1

/*
 * Elements foramtting:
 * U: used bit
 * F: free bit
 * R: reserved bit
 *
 *  RRRRRRUF
 * +--------+----------------------------------------+
 * |Meta    |  Element                               |
 * +--------+----------------------------------------+
 */

/*
 * @brief Create a new pool.
 *
 * @param[out] p      The pool instance to create.
 * @parm[in] max_len  Max length of the pool (specified as number of
 * elements).
 * @param[in] elem_size Size of one element (specified as number of bytes).
 *
 * @return XRPC_SUCCESS on succes and XRPC_API_ERR_ALLOC if there are errors
 * during allocations.
 */
int xrpc_pool_init(struct xrpc_pool **p, const size_t max_len,
                   const size_t elem_size) {

  struct xrpc_pool *_p = malloc(sizeof(struct xrpc_pool));
  uint8_t *tmp = NULL, *curr = NULL, header = 0;

  if (!p) return XRPC_API_ERR_ALLOC;

  // element size is increment by 1 byte to store the meta information.
  // TODO: make this aligned.
  _p->elem_size = elem_size;
  _p->capacity = max_len;
  // pre allocate
  // TODO: evaluate lazy allocation
  _p->items = malloc(elem_size * (max_len + 1));

  if (!_p->items) return XRPC_API_ERR_ALLOC;

  // zero out the pool
  memset(_p->items, 0, elem_size * (max_len + 1));

  // init all items as free
  tmp = (uint8_t *)_p->items + 1;
  for (size_t i = 0; i < max_len; ++i) {
    curr = 1 + tmp + elem_size * i;
    header = *(curr - 1);
    header ^= header | (1 << XRPC_POOL_ELEM_FREE);
    *(curr - 1) = header;
  }

  *p = _p;

  return XRPC_SUCCESS;
}

/*
 * @brief Retrieves the first available element.
 *
 * This function reuses existing elements previously created by the pool. If
 * none is free, it attempts to create a new instance with malloc.
 *
 * The main strategy is to add a byte meta information to the actual item and
 * strip it off to the user
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element retrieved
 *
 * @return XRPC_SUCCESS if no errors. XRPC_API_ERR_ALLOC if the resource cannot
 * be allocated or the pool exceeds the max_len.
 */
int xrpc_pool_get(struct xrpc_pool *p, void **elem) {
  uint8_t header = 0, *tmp = p->items + 1, *curr = NULL;
  void *ret = NULL;

  // attempt to find a free slot
  for (size_t i = 0; i < p->capacity; ++i) {
    // treat the void* array as bytes.
    curr = (1 + tmp + p->elem_size * i);
    header = *(curr - 1);

    // if the slot is free mark it as used
    if (header & (1 << XRPC_POOL_ELEM_FREE)) {
      header ^= header | (1 << XRPC_POOL_ELEM_USED);
      *(curr - 1) = header;

      ret = curr;
      break;
    }
  }

  if (ret == NULL) return XRPC_API_ERR_ALLOC;

  *elem = ret;
  return XRPC_SUCCESS;
}

/*
 * @brief Gives back the element to the pool.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element to store.
 */
void xrpc_pool_put(struct xrpc_pool *p, const void *elem) {
  uint8_t header = 0, *tmp = p->items + 1, *curr = NULL;
  for (size_t i = 0; i < p->capacity; ++i) {
    curr = (1 + tmp + p->elem_size * i);
    header = *(curr - 1);

    if (curr == elem && (header & (1 << XRPC_POOL_ELEM_USED))) {
      // if the slot is used mark it as free
      header ^= header | (1 << XRPC_POOL_ELEM_FREE);
      *(curr - 1) = header;
      break;
    }
  }
}

/*
 * @brief Free pool resources.
 *
 * @param[out] p      The pool instance to create.
 */
void xrpc_pool_free(struct xrpc_pool *p) {
  if (p) free(p->items);
}
