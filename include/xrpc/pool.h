#ifndef XRPC_POOL_H
#define XRPC_POOL_H

#include <stddef.h>

/*
 * Pool to be used to avoid excessive malloc operations.
 * Since this can be used for more same size but different use cases the user
 * specifies the size for each element allocation.
 *
 */

struct xrpc_pool {
  void *items;
  size_t elem_size;
  size_t capacity;
};

/*
 * @brief Create a new pool.
 *
 * @param[out] p      The pool instance to create.
 * @parm[in] max_len  Max length of the pool (specified as number of elements).
 * @param[in] elem_size Size of one element (specified as number of bytes).
 *
 * @return XRPC_SUCCESS on succes and XRPC_API_ERR_ALLOC if there are errors
 * during allocations.
 */
int xrpc_pool_init(struct xrpc_pool **p, const size_t max_len,
                   const size_t elem_size);

/*
 * @brief Retrieves the first available element.
 *
 * This function reuses existing elements previously created by the pool. If
 * none is free, it attempts to create a new instance with malloc.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element retrieved
 *
 * @return XRPC_SUCCESS if no errors. XRPC_API_ERR_ALLOC if the resource cannot
 * be allocated or the pool exceeds the max_len.
 */
int xrpc_pool_get(struct xrpc_pool *p, void **elem);

/*
 * @brief Gives back the element to the pool.
 *
 * If there is space the element is stored to avoid free/malloc. Otherwise it's
 * free.
 *
 * @param[in] p     The pool instance.
 * @param[out] elem A pointer to the element to store.
 */
void xrpc_pool_put(struct xrpc_pool *p, const void *elem);

/*
 * @brief Free pool resources.
 *
 * @param[out] p      The pool instance to create.
 */
void xrpc_pool_free(struct xrpc_pool *p);

#endif // !XRPC_POOL_H
