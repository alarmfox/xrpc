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
  ret = xrpc_vector_to_net(XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR,
                           fhdr.size_params, (const void *)arr,
                           buf + sizeof(fhdr), sizeof(buf) - sizeof(fhdr),
                           &transferred);

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

  ret = xrpc_vector_from_net(XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR,
                             fhdr.size_params, buf + sizeof(fhdr),
                             sizeof(buf) - sizeof(fhdr), recv_vector,
                             &transferred);

  for (size_t i = 0; i < fhdr.size_params; ++i) {
    TEST_ASSERT_EQ(recv_vector[i], arr[i], "Vector element must match");
  }
  TEST_SUCCESS();
}

/* New test: uint8_t vector */
static int test_serder_request_frame_uint8_array(void) {
  TEST_CASE("serder_request_frame_uint8_array");

  uint8_t arr[] = {10, 20, 30, 40};
  uint8_t buf[128];
  uint8_t recv_vector[64];
  struct xrpc_request_frame_header fhdr = {0};
  size_t transferred = 0;
  int ret;

  xrpc_req_fr_set_dtypc(&fhdr.opinfo, XRPC_DTYPE_CAT_VECTOR);
  xrpc_req_fr_set_dtypb(&fhdr.opinfo, XRPC_BASE_UINT8);
  xrpc_req_fr_set_scale(&fhdr.opinfo, 0);
  xrpc_req_fr_set_opcode(&fhdr.opinfo, 7);

  fhdr.size_params = sizeof(arr) / sizeof(arr[0]);
  fhdr.batch_id = 7;
  fhdr.frame_id = 8;

  xrpc_request_frame_header_to_net(&fhdr, buf);
  ret = xrpc_vector_to_net(XRPC_BASE_UINT8, XRPC_DTYPE_CAT_VECTOR,
                           fhdr.size_params, (const void *)arr,
                           buf + sizeof(fhdr), sizeof(buf) - sizeof(fhdr),
                           &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "serialize should succeed");
  TEST_ASSERT_EQ(sizeof(arr), transferred,
                 "bytes written must equal element bytes");

  memset(&fhdr, 0, sizeof fhdr);
  xrpc_request_frame_header_from_net(buf, &fhdr);

  ret = xrpc_vector_from_net(XRPC_BASE_UINT8, XRPC_DTYPE_CAT_VECTOR,
                             fhdr.size_params, buf + sizeof(fhdr),
                             sizeof(buf) - sizeof(fhdr), recv_vector,
                             &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "deserialize should succeed");
  TEST_ASSERT_EQ(sizeof(arr), transferred,
                 "bytes read should equal original size");

  for (size_t i = 0; i < fhdr.size_params; ++i) {
    TEST_ASSERT_EQ(recv_vector[i], arr[i], "uint8 vector element must match");
  }

  TEST_SUCCESS();
}

/* New test: uint32_t vector */
static int test_serder_request_frame_uint32_array(void) {
  TEST_CASE("serder_request_frame_uint32_array");

  uint32_t arr[] = {100000u, 200000u};
  uint8_t buf[256];
  uint32_t recv_vector[64];
  struct xrpc_request_frame_header fhdr = {0};
  size_t transferred = 0;
  int ret;

  xrpc_req_fr_set_dtypc(&fhdr.opinfo, XRPC_DTYPE_CAT_VECTOR);
  xrpc_req_fr_set_dtypb(&fhdr.opinfo, XRPC_BASE_UINT32);
  xrpc_req_fr_set_scale(&fhdr.opinfo, 0);
  xrpc_req_fr_set_opcode(&fhdr.opinfo, 11);

  fhdr.size_params = sizeof(arr) / sizeof(arr[0]);
  fhdr.batch_id = 13;
  fhdr.frame_id = 14;

  xrpc_request_frame_header_to_net(&fhdr, buf);
  ret = xrpc_vector_to_net(XRPC_BASE_UINT32, XRPC_DTYPE_CAT_VECTOR,
                           fhdr.size_params, (const void *)arr,
                           buf + sizeof(fhdr), sizeof(buf) - sizeof(fhdr),
                           &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "serialize should succeed");
  TEST_ASSERT_EQ(sizeof(arr), transferred,
                 "bytes written must equal element bytes");

  memset(&fhdr, 0, sizeof fhdr);
  xrpc_request_frame_header_from_net(buf, &fhdr);

  ret = xrpc_vector_from_net(XRPC_BASE_UINT32, XRPC_DTYPE_CAT_VECTOR,
                             fhdr.size_params, buf + sizeof(fhdr),
                             sizeof(buf) - sizeof(fhdr), recv_vector,
                             &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "deserialize should succeed");
  TEST_ASSERT_EQ(sizeof(arr), transferred,
                 "bytes read should equal original size");

  for (size_t i = 0; i < fhdr.size_params; ++i) {
    TEST_ASSERT_EQ(recv_vector[i], arr[i], "uint32 vector element must match");
  }

  TEST_SUCCESS();
}

/* New test: empty vector */
static int test_serder_request_frame_empty_vector(void) {
  TEST_CASE("serder_request_frame_empty_vector");

  uint8_t buf[64];
  struct xrpc_request_frame_header fhdr = {0};
  size_t transferred = 0;
  int ret;

  xrpc_req_fr_set_dtypc(&fhdr.opinfo, XRPC_DTYPE_CAT_VECTOR);
  xrpc_req_fr_set_dtypb(&fhdr.opinfo, XRPC_BASE_UINT8);
  xrpc_req_fr_set_scale(&fhdr.opinfo, 0);
  xrpc_req_fr_set_opcode(&fhdr.opinfo, 1);

  fhdr.size_params = 0; /* empty */
  fhdr.batch_id = 1;
  fhdr.frame_id = 2;

  xrpc_request_frame_header_to_net(&fhdr, buf);
  /* zero-length, but we still pass a valid buffer pointer */
  ret = xrpc_vector_to_net(XRPC_BASE_UINT8, XRPC_DTYPE_CAT_VECTOR, 0,
                           (const void *)NULL, buf + sizeof(fhdr),
                           sizeof(buf) - sizeof(fhdr), &transferred);

  /* Expect success and zero bytes transferred */
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret,
                 "serialize of zero-length vector should succeed");
  TEST_ASSERT_EQ(0u, transferred, "zero-length vector should write zero bytes");

  memset(&fhdr, 0, sizeof fhdr);
  xrpc_request_frame_header_from_net(buf, &fhdr);

  ret = xrpc_vector_from_net(XRPC_BASE_UINT8, XRPC_DTYPE_CAT_VECTOR, 0,
                             buf + sizeof(fhdr), sizeof(buf) - sizeof(fhdr),
                             NULL, &transferred);

  TEST_ASSERT_EQ(XRPC_SUCCESS, ret,
                 "deserialize of zero-length vector should succeed");
  TEST_ASSERT_EQ(0u, transferred, "zero-length vector should read zero bytes");

  TEST_SUCCESS();
}

/* New test: response frame header ser/de and opinfo getters/setters */
static int test_serder_response_frame_header(void) {
  TEST_CASE("serder_response_frame_header");

  struct xrpc_response_frame_header rhdr = {0};
  uint8_t buf[16];

  /* set response opinfo fields */
  xrpc_res_fr_set_dtypc(&rhdr.opinfo, XRPC_RES_FR_DTYPC_MASK & 1);
  xrpc_res_fr_set_dtypb(&rhdr.opinfo, XRPC_BASE_UINT16);
  xrpc_res_fr_set_scale(&rhdr.opinfo, 2);
  xrpc_res_fr_set_status(&rhdr.opinfo, 12);

  rhdr.size_params = 5;
  rhdr.batch_id = 1234;
  rhdr.frame_id = 5678;

  /* quick assertions using getters */
  TEST_ASSERT_EQ((int)XRPC_BASE_UINT16,
                 (int)xrpc_res_fr_get_dtypb_from_opinfo(rhdr.opinfo),
                 "res opinfo dtb should be UINT16");
  TEST_ASSERT_EQ(2, (int)xrpc_res_fr_get_scale_from_opinfo(rhdr.opinfo),
                 "res opinfo scale should be 2");
  TEST_ASSERT_EQ(12, (int)xrpc_res_fr_get_status_from_opinfo(rhdr.opinfo),
                 "res opinfo status should be 12");

  xrpc_response_frame_header_to_net(&rhdr, buf);

  memset(&rhdr, 0, sizeof rhdr);
  xrpc_response_frame_header_from_net(buf, &rhdr);

  TEST_ASSERT_EQ(5, rhdr.size_params, "size params must survive round-trip");
  TEST_ASSERT_EQ(1234u, rhdr.batch_id, "batch id must survive round-trip");
  TEST_ASSERT_EQ(5678u, rhdr.frame_id, "frame id must survive round-trip");

  TEST_ASSERT_EQ((int)XRPC_BASE_UINT16,
                 (int)xrpc_res_fr_get_dtypb_from_opinfo(rhdr.opinfo),
                 "res opinfo dtb should be UINT16 after round-trip");
  TEST_ASSERT_EQ(2, (int)xrpc_res_fr_get_scale_from_opinfo(rhdr.opinfo),
                 "res opinfo scale should be 2 after round-trip");
  TEST_ASSERT_EQ(12, (int)xrpc_res_fr_get_status_from_opinfo(rhdr.opinfo),
                 "res opinfo status should be 12 after round-trip");

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Protocol structure test");

  RUN_TEST(test_serder_request_frame_array);
  RUN_TEST(test_serder_request_frame_uint8_array);
  RUN_TEST(test_serder_request_frame_uint32_array);
  RUN_TEST(test_serder_request_frame_empty_vector);
  RUN_TEST(test_serder_response_frame_header);

  TEST_REPORT();

  return 0;
}
