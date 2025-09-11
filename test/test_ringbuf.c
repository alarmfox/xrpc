#include "xrpc/error.h"
#include "xrpc/ringbuf.h"

#include "test.h"

static int test_ringbuf_init_free() {
  TEST_CASE("ringbuf_init_free");

  struct xrpc_ringbuf *rb = NULL;
  int ret;

  ret = xrpc_ringbuf_init(&rb, 10);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Ringbuf init should succed");
  TEST_ASSERT_NOT_NULL(rb, "Ringbuf should not be NULL after init");

  xrpc_ringbuf_free(rb);

  TEST_SUCCESS();
}

static int test_ringbuf_basic_usage() {
  TEST_CASE("ringbuf_basic_usage");

  struct xrpc_ringbuf *rb = NULL;
  int ret;
  int elem1 = 5, elem2 = 7;
  int *res = NULL;

  ret = xrpc_ringbuf_init(&rb, 5);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Ringbuf init should succed");
  TEST_ASSERT_NOT_NULL(rb, "Ringbuf should not be NULL after init");

  ret = xrpc_ringbuf_push(rb, &elem1);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First push should succed");

  ret = xrpc_ringbuf_push(rb, &elem2);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second push should succed");

  ret = xrpc_ringbuf_pop(rb, (void *)&res);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First pop should succed");
  TEST_ASSERT_EQ(*res, elem1,
                 "First pop should return the first inserted element");

  ret = xrpc_ringbuf_pop(rb, (void *)&res);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second pop should succed");
  TEST_ASSERT_EQ(*res, elem2,
                 "Second pop should return the first inserted element");

  xrpc_ringbuf_free(rb);

  TEST_SUCCESS();
}

static int test_ringbuf_count() {
  TEST_CASE("ringbuf_count");

  struct xrpc_ringbuf *rb = NULL;
  int ret;
  int elems[] = {0, 1, 2};
  int *res = NULL;
  size_t count;

  ret = xrpc_ringbuf_init(&rb, 3);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Ringbuf init should succed");
  TEST_ASSERT_NOT_NULL(rb, "Ringbuf should not be NULL after init");

  // Fill the ringbuf
  for (size_t i = 0; i < 3; ++i) {
    ret = xrpc_ringbuf_push(rb, &elems[i]);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Push should succed");

    count = xrpc_ringbuf_count(rb);
    TEST_ASSERT_EQ(i + 1, count,
                   "count should be incremented according to elements");
  }

  // Drain the ringbuf
  for (size_t i = 0; i < 3; ++i) {
    ret = xrpc_ringbuf_pop(rb, (void *)&res);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pop should succed");

    TEST_ASSERT_EQ(elems[i], *res, "Pop should return elemets in FIFO policy");

    count = xrpc_ringbuf_count(rb);
    TEST_ASSERT_EQ(3 - i - 1, count,
                   "count should be decremented according to elements");
  }

  xrpc_ringbuf_free(rb);
  TEST_SUCCESS();
}

static int test_ringbuf_full() {
  TEST_CASE("ringbuf_full");

  struct xrpc_ringbuf *rb = NULL;
  int ret;
  int elems[] = {0, 1, 2};
  int *res = NULL;

  ret = xrpc_ringbuf_init(&rb, 2);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Ringbuf init should succed");
  TEST_ASSERT_NOT_NULL(rb, "Ringbuf should not be NULL after init");

  // Fill the ringbuf
  ret = xrpc_ringbuf_push(rb, &elems[0]);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "First push should succed");

  ret = xrpc_ringbuf_push(rb, &elems[1]);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Second push should succed");

  ret = xrpc_ringbuf_push(rb, &elems[2]);
  TEST_ASSERT_EQ(XRPC_INTERNAL_ERR_RINGBUF_FULL, ret,
                 "Third push should fail (ringbuf full)");

  // remove the first two pushed elements
  for (int i = 0; i < 2; ++i) {

    ret = xrpc_ringbuf_pop(rb, (void *)&res);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Pop should succed");
    TEST_ASSERT_EQ(*res, elems[i],
                   "Pop should return elements with FIFO policy");
  }

  xrpc_ringbuf_free(rb);

  TEST_SUCCESS();
}

static int test_ringbuf_empty() {
  TEST_CASE("ringbuf_empty");

  struct xrpc_ringbuf *rb = NULL;
  int ret;
  int *res = NULL;

  ret = xrpc_ringbuf_init(&rb, 2);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Ringbuf init should succed");
  TEST_ASSERT_NOT_NULL(rb, "Ringbuf should not be NULL after init");

  ret = xrpc_ringbuf_pop(rb, (void *)&res);
  TEST_ASSERT_EQ(XRPC_INTERNAL_ERR_RINGBUF_EMPTY, ret,
                 "Pop should fail on an empty ringbuf");

  xrpc_ringbuf_free(rb);

  TEST_SUCCESS();
}

static int test_ringbuf_zero_cap() {
  TEST_CASE("ringbuf_zero_cap");

  struct xrpc_ringbuf *rb = NULL;
  int ret;

  ret = xrpc_ringbuf_init(&rb, 0);
  TEST_ASSERT_EQ(XRPC_INTERNAL_ERR_RINGBUF_INVALID_ARG, ret,
                 "Ringbuf init should fail with zero capacity");

  xrpc_ringbuf_free(rb);

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Ringbuf Tests");

  RUN_TEST(test_ringbuf_init_free);
  RUN_TEST(test_ringbuf_basic_usage);
  RUN_TEST(test_ringbuf_count);
  RUN_TEST(test_ringbuf_full);
  RUN_TEST(test_ringbuf_empty);
  RUN_TEST(test_ringbuf_zero_cap);

  TEST_REPORT();

  return 0;
}
