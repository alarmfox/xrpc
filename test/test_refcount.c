#include "xrpc/transport.h"

#include "test.h"

int dummy_recv(struct xrpc_connection *conn, void *buf, size_t len,
               size_t *bytes_read) {
  (void)conn;
  (void)buf;
  (void)len;
  (void)bytes_read;

  return XRPC_SUCCESS;
}

int dummy_send(struct xrpc_connection *conn, const void *buf, size_t len,
               size_t *bytes_written) {

  (void)conn;
  (void)buf;
  (void)len;
  (void)bytes_written;

  return XRPC_SUCCESS;
}

static const struct xrpc_connection_ops conn_ops = {
    .recv = dummy_recv,
    .send = dummy_send,
};

static int test_conn_refcount_single_thread() {
  TEST_CASE("conn_refcount_single_thread");

  struct xrpc_connection conn = {.ops = &conn_ops,
                                 .ref_count = 0,
                                 .data = NULL,
                                 .id = 0,
                                 .is_closed = false,
                                 .is_closing = false};

  struct xrpc_transport t = {0};
  int ret;

  TEST_ASSERT(connection_is_valid(&conn),
              "connection should be valid after created");

  ret = connection_ref(&t, &conn);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "reference should not give errors");
  TEST_ASSERT_EQ(__atomic_load_n(&conn.ref_count, __ATOMIC_ACQUIRE), 1,
                 "reference should be 1 after first reference");
  connection_unref(&t, &conn);

  TEST_ASSERT_EQ(__atomic_load_n(&conn.ref_count, __ATOMIC_ACQUIRE), 0,
                 "reference should be 0 after dereference");

  connection_unref(&t, &conn);

  TEST_ASSERT_EQ(__atomic_load_n(&conn.ref_count, __ATOMIC_ACQUIRE), 0,
                 "reference should never be negative");

  connection_mark_for_close(&conn);
  TEST_ASSERT_EQ(__atomic_load_n(&conn.is_closing, __ATOMIC_ACQUIRE), true,
                 "after marked for closing the is_closing must be true");

  ret = connection_ref(&t, &conn);
  TEST_ASSERT_EQ(
      XRPC_INTERNAL_ERR_INVALID_CONN, ret,
      "after marked for closing connection cannot be referenced anymore");

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Connection reference counting Tests");

  RUN_TEST(test_conn_refcount_single_thread);

  TEST_REPORT();

  return 0;
}
