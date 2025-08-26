#include "xrpc/error.h"
#include "xrpc/protocol.h"

#include "test.h"

static int test_serder_request_frame_array(void) {
  TEST_CASE("serder_request_frame_array");

  // array to serialize
  uint16_t arr[] = {1, 2, 3};
  uint8_t buf[64];
  uint16_t recv_vector[64];
  struct xrpc_request_frame_header fhdr = {0};
  size_t transferred = 0;
  int ret;

  xrpc_req_fr_set_dtypc(&fhdr.opinfo, XRPC_DTYPE_CAT_VECTOR);
  xrpc_req_fr_set_dtypb(&fhdr.opinfo, XRPC_BASE_UINT16);
  xrpc_req_fr_set_scale(&fhdr.opinfo, 0);
  xrpc_req_fr_set_opcode(&fhdr.opinfo, 43);

  // assert that parameters are set correctly
  TEST_ASSERT_EQ(XRPC_DTYPE_CAT_VECTOR,
                 xrpc_req_fr_get_dtypc_from_opinfo(fhdr.opinfo),
                 "category type should be vector");

  TEST_ASSERT_EQ(XRPC_BASE_UINT16,
                 xrpc_req_fr_get_dtypb_from_opinfo(fhdr.opinfo),
                 "base type should be uint16");

  TEST_ASSERT_EQ(0, xrpc_req_fr_get_scale_from_opinfo(fhdr.opinfo),
                 "scale should be 0");
  TEST_ASSERT_EQ(43, xrpc_req_fr_get_opcode_from_opinfo(fhdr.opinfo),
                 "op code should be 99");

  fhdr.size_params = sizeof(arr) / sizeof(arr[0]);
  fhdr.batch_id = 69;
  fhdr.frame_id = 420;

  xrpc_request_frame_header_to_net(&fhdr, buf);
  ret = xrpc_vector_to_net(&fhdr, (const void *)arr, buf + sizeof(fhdr),
                           sizeof(buf) - sizeof(fhdr), &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "serialize should succeed");
  TEST_ASSERT_EQ(
      sizeof(arr), transferred,
      "bytes written should be equal to the size of the array in bytes");

  // simulate the receive (deserialize header and data)
  memset(&fhdr, 0, sizeof(struct xrpc_request_frame_header));
  xrpc_request_frame_header_from_net(buf, &fhdr);

  // check if header is correct
  TEST_ASSERT_EQ(3, fhdr.size_params, "Size params must be 3");
  TEST_ASSERT_EQ(69, fhdr.batch_id, "Batch ID must be 69");
  TEST_ASSERT_EQ(420, fhdr.frame_id, "Frame ID must be 420");

  // assert that parameters are set correctly
  TEST_ASSERT_EQ(XRPC_DTYPE_CAT_VECTOR,
                 xrpc_req_fr_get_dtypc_from_opinfo(fhdr.opinfo),
                 "category type should be vector");

  TEST_ASSERT_EQ(XRPC_BASE_UINT16,
                 xrpc_req_fr_get_dtypb_from_opinfo(fhdr.opinfo),
                 "base type should be uint16");

  TEST_ASSERT_EQ(0, xrpc_req_fr_get_scale_from_opinfo(fhdr.opinfo),
                 "scale should be 0");
  TEST_ASSERT_EQ(43, xrpc_req_fr_get_opcode_from_opinfo(fhdr.opinfo),
                 "op code should be 99");

  ret = xrpc_vector_from_net(&fhdr, buf + sizeof(fhdr),
                             sizeof(buf) - sizeof(fhdr), recv_vector,
                             &transferred);

  for (size_t i = 0; i < fhdr.size_params; ++i) {
    TEST_ASSERT_EQ(recv_vector[i], arr[i], "Vector element must match");
  }
  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Protocol structure test");

  RUN_TEST(test_serder_request_frame_array);

  TEST_REPORT();

  return 0;
}
