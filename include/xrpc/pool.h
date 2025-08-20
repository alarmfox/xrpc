#ifndef XRPC_POOL_H
#define XRPC_POOL_H

#include <stdatomic.h>
#include <stddef.h>

// Number of bytes of the cache line.
// TODO: change this based on CPU architecture.
#define CACHE_LINE_SIZE 64

/*
 * Pool to be used to avoid excessive malloc operations. This should be used to
 * allocate same size elements. Performance ideas:
 *
 * - Aligned with cache line size
 * - O(1) allocation/free operations
 * - Atomic operation for thread safety
 */
struct xrpc_pool {
  size_t elem_size; // size of a single element (as bytes including aligment)
  size_t capacity;  // max number of elmentsn (as elements count)
  _Atomic size_t free_count; // current available element in the free_list
  void *items;               // pointer to the start of memory region
  void **free_list;          // pointer to a stack which contains free pointers
} __attribute__((aligned(CACHE_LINE_SIZE)));

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
int xrpc_pool_init(struct xrpc_pool **p, const size_t max_len,
                   const size_t elem_size);

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
int xrpc_pool_get(struct xrpc_pool *p, void **elem);

/*
 * @brief Gives back the element to the pool.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element to store.

 * @return XRPC_SUCCESS on success
 * @return XRPC_INTERNAL_ERR_POOL_INVALID_ARG when elem is not part of the pool
 */
int xrpc_pool_put(struct xrpc_pool *p, const void *elem);

/*
 * @brief Free pool resources.
 *
 * @param[out] p      The pool instance to create.
 */
void xrpc_pool_free(struct xrpc_pool *p);

/*
 * Utilities for the pool
 */
static inline size_t align_size(const size_t alignement, const size_t size) {
  return (size + alignement - 1) & ~(alignement - 1);
}
static inline size_t xrpc_pool_count(struct xrpc_pool *p) {
  return atomic_load(&p->free_count);
}

#endif // !XRPC_POOL_H
