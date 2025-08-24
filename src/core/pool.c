#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/pool.h"

/*
 * @brief Create a new pool.
 *
 * @param[out] p      The pool instance to create.
 * @parm[in] max_len  Max length of the pool (number o elements).
 * @param[in] elem_size Size of one element (number of bytes).
 *
 * @return XRPC_SUCCESS on succes
 * @return XRPC_INTERNAL_ERR_ALLOC if there are errors during allocations.
 * @return XRPC_INTERNAL_ERR_POOL_INVALID_ARG if max len is zero or elem_size is
 * zero
 */
int xrpc_pool_init(struct xrpc_pool **out_pool, const size_t max_len,
                   const size_t elem_size) {

  if (max_len == 0 || elem_size == 0 || !out_pool)
    return XRPC_INTERNAL_ERR_POOL_INVALID_ARG;

  struct xrpc_pool *pool = NULL;
  uint8_t *tmp = NULL;

  pool = malloc(sizeof(struct xrpc_pool));
  if (!pool) return XRPC_INTERNAL_ERR_ALLOC;

  pool->elem_size = align_size(CACHE_LINE_SIZE, elem_size);
  pool->capacity = max_len;
  pool->items = aligned_alloc(CACHE_LINE_SIZE, pool->elem_size * max_len);

  if (!pool->items) return XRPC_INTERNAL_ERR_ALLOC;

  // zero out the pool
  memset(pool->items, 0, pool->elem_size * max_len);

  // init the free list
  pool->free_list = malloc(max_len * sizeof(void *));

  if (!pool->free_list) return XRPC_INTERNAL_ERR_ALLOC;

  memset(pool->free_list, 0, max_len * sizeof(void *));

  // load all address in the free list since everything is free at the beginning
  tmp = (uint8_t *)pool->items;
  for (size_t i = 0; i < pool->capacity; ++i) {
    pool->free_list[i] = (void *)tmp;
    tmp += pool->elem_size;
  }

  // initialize the free count as atomic variable
  __atomic_store_n(&pool->free_count, pool->capacity, __ATOMIC_SEQ_CST);

  *out_pool = pool;

  return XRPC_SUCCESS;
}

/*
 * @brief Retrieves the first available element.
 *
 * This is operation is performed in O(1) since it is just peaking the free_list
 * with a stack policy.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element retrieved
 *
 * @return XRPC_SUCCESS if no errors.
 * @return XRPC_INTERNAL_ERR_POOL_FULL if no available elements
 */
int xrpc_pool_get(struct xrpc_pool *p, void **elem) {
  size_t current = __atomic_load_n(&p->free_count, __ATOMIC_RELAXED);

  // try to decrement the counter atomically
  while (current > 0) {
    // if successfull return the target pointer
    if (__atomic_compare_exchange_n(&p->free_count, &current, current - 1, true,
                                    __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
      *elem = p->free_list[current - 1];
      return XRPC_SUCCESS;
    }
  }

  return XRPC_INTERNAL_ERR_POOL_EMPTY;
}

/*
 * @brief Gives back the element to the pool.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element to store.

 * @return XRPC_SUCCESS on success
 * @return XRPC_INTERNAL_ERR_POOL_INVALID_ARG when elem is not part of the pool
 */
int xrpc_pool_put(struct xrpc_pool *p, const void *elem) {
  // Check first if element belongs to the pool.
  const uint8_t *start = (const uint8_t *)p->items;
  const uint8_t *end = (const uint8_t *)p->items + p->capacity * p->elem_size;
  const uint8_t *elem_ptr = (const uint8_t *)elem;
  size_t current_free;

  // the element does not belong to the pool
  if (elem_ptr < start || elem_ptr >= end)
    return XRPC_INTERNAL_ERR_POOL_INVALID_ARG;

  // address must be one of element
  if ((elem_ptr - start) % p->elem_size != 0)
    return XRPC_INTERNAL_ERR_POOL_INVALID_ARG;

  current_free = __atomic_load_n(&p->free_count, __ATOMIC_SEQ_CST);

  // try to increment the top of the stack to find a place where to store the
  // address
  while (current_free < p->capacity) {
    if (__atomic_compare_exchange_n(&p->free_count, &current_free,
                                    current_free + 1, true, __ATOMIC_RELAXED,
                                    __ATOMIC_RELAXED)) {

      p->free_list[current_free] = (void *)elem;
      return XRPC_SUCCESS;
    }
  }

  return XRPC_INTERNAL_ERR_POOL_FULL;
}

/*
 * @brief Free pool resources.
 *
 * @param[out] p      The pool instance to create.
 */
void xrpc_pool_free(struct xrpc_pool *p) {
  if (!p) return;

  if (p->items) {
    free(p->items);
    p->items = NULL;
  }

  if (p->free_list) {
    free(p->free_list);
    p->free_list = NULL;
  }
  free(p);
}
