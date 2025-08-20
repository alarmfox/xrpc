#include "xrpc/error.h"
#include "xrpc/pool.h"

#include "test.h"

// Test basic pool creation and destruction
static int test_pool_init_free() {
  TEST_CASE("pool_init_free");

  struct xrpc_pool *pool = NULL;
  int ret = xrpc_pool_init(&pool, 10, 64);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");
  TEST_ASSERT_NOT_NULL(pool, "Pool should not be NULL after init");

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Test getting elements from pool
static int test_pool_get_basic() {
  TEST_CASE("pool_get_basic");

  struct xrpc_pool *pool = NULL;
  void *elem1, *elem2;

  int ret = xrpc_pool_init(&pool, 5, 32);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");

  // Get first element
  ret = xrpc_pool_get(pool, &elem1);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First pool_get should succeed");
  TEST_ASSERT_NOT_NULL(elem1, "First element should not be NULL");

  // Get second element
  ret = xrpc_pool_get(pool, &elem2);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second pool_get should succeed");
  TEST_ASSERT_NOT_NULL(elem2, "Second element should not be NULL");

  // Elements should be different
  TEST_ASSERT(elem1 != elem2, "Pool elements should be different");

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Test pool exhaustion
static int test_pool_exhaustion() {
  TEST_CASE("pool_exhaustion");

  struct xrpc_pool *pool = NULL;
  void *elements[3];

  // Create small pool
  int ret = xrpc_pool_init(&pool, 2, 16);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");

  // Fill the pool
  ret = xrpc_pool_get(pool, &elements[0]);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First get should succeed");

  ret = xrpc_pool_get(pool, &elements[1]);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second get should succeed");

  // Pool should be exhausted
  ret = xrpc_pool_get(pool, &elements[2]);
  TEST_ASSERT_EQ(XRPC_API_ERR_ALLOC, ret,
                 "Third get should fail (pool exhausted)");

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Test the critical reuse functionality - THIS WILL EXPOSE THE BUG
static int test_pool_reuse() {
  TEST_CASE("pool_reuse");

  struct xrpc_pool *pool = NULL;
  void *elem1, *elem2, *elem3;

  // Create pool with capacity 2
  int ret = xrpc_pool_init(&pool, 2, 64);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");

  // Get two elements (should work)
  ret = xrpc_pool_get(pool, &elem1);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First get should succeed");

  ret = xrpc_pool_get(pool, &elem2);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second get should succeed");

  // Try to get third (should fail - pool full)
  ret = xrpc_pool_get(pool, &elem3);
  TEST_ASSERT_EQ(XRPC_API_ERR_ALLOC, ret, "Third get should fail (pool full)");

  // Put one back
  xrpc_pool_put(pool, elem1);

  // Should be able to get it again - THIS WILL FAIL with current buggy code
  ret = xrpc_pool_get(pool, &elem3);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Get after put should succeed");
  TEST_ASSERT_NOT_NULL(elem3, "Element after reuse should not be NULL");

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Test multiple put/get cycles
static int test_pool_multiple_reuse() {
  TEST_CASE("pool_multiple_reuse");

  struct xrpc_pool *pool = NULL;
  void *elem;

  int ret = xrpc_pool_init(&pool, 1, 32);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");

  // Multiple cycles of get/put
  for (int i = 0; i < 5; i++) {
    ret = xrpc_pool_get(pool, &elem);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Get in cycle should succeed");

    // Write to element to ensure it's valid memory
    memset(elem, 0xAA, 32);

    xrpc_pool_put(pool, elem);
  }

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Test invalid parameters
static int test_pool_invalid_params() {
  TEST_CASE("pool_invalid_params");

  struct xrpc_pool *pool = NULL;
  void *elem;

  // Test NULL pool pointer
  int ret = xrpc_pool_init(NULL, 10, 32);
  TEST_ASSERT_EQ(XRPC_API_ERR_ALLOC, ret, "Init with NULL should fail");

  // Test zero capacity (edge case)
  ret = xrpc_pool_init(&pool, 0, 32);
  // This might succeed or fail depending on implementation
  if (ret == XRPC_SUCCESS) {
    // If it succeeds, getting should immediately fail
    ret = xrpc_pool_get(pool, &elem);
    TEST_ASSERT_EQ(XRPC_API_ERR_ALLOC, ret,
                   "Get from zero-capacity pool should fail");
    xrpc_pool_free(pool);
  }

  TEST_SUCCESS();
}

// Test putting back wrong element
static int test_pool_invalid_put() {
  TEST_CASE("pool_invalid_put");

  struct xrpc_pool *pool = NULL;
  void *elem, *fake_elem;
  char buffer[64];

  int ret = xrpc_pool_init(&pool, 2, 32);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pool init should succeed");

  ret = xrpc_pool_get(pool, &elem);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Get should succeed");

  fake_elem = buffer; // This is not from the pool

  // Put back wrong element - should not crash, but might not work correctly
  xrpc_pool_put(pool, fake_elem);

  // Pool should still work normally
  xrpc_pool_put(pool, elem); // Put back real element

  ret = xrpc_pool_get(pool, &elem);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Get after invalid put should still work");

  xrpc_pool_free(pool);

  TEST_SUCCESS();
}

// Main test runner for pool tests
int main() {
  TEST_SUITE("Pool Tests");

  RUN_TEST(test_pool_init_free);
  RUN_TEST(test_pool_get_basic);
  RUN_TEST(test_pool_exhaustion);
  RUN_TEST(test_pool_reuse);
  RUN_TEST(test_pool_multiple_reuse);
  RUN_TEST(test_pool_invalid_params);
  RUN_TEST(test_pool_invalid_put);

  TEST_REPORT();
  return 0;
}
