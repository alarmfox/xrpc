#include "xrpc/protocol.h"
#include "xrpc/error.h"
#include "xrpc/protocol_utils.h"

void xrpc_request_header_to_net(const struct xrpc_request_header *r,
                                uint8_t buf[8]) {

  uint32_t w1 = xrpc_req_word1_pack(r->preamble, r->resp_mode, r->batch_id);
  uint32_t w2 = xrpc_req_word2_pack(r->batch_size, r->reserved);

  /* convert to network byte order */
  w1 = htonl(w1);
  w2 = htonl(w2);

  /* copy to buffer */
  memcpy(buf, &w1, 4);
  memcpy(buf + 4, &w2, 4);
}

void xrpc_request_header_from_net(const uint8_t buf[8],
                                  struct xrpc_request_header *r) {
  uint32_t w1, w2;

  /* copy the 32-bit words first then ntohl */
  memcpy(&w1, buf, 4);
  memcpy(&w2, buf + 4, 4);

  w1 = ntohl(w1);
  w2 = ntohl(w2);

  /* extract fields using macros  */
  r->preamble = xrpc_req_word1_preamble(w1);
  r->resp_mode = xrpc_req_word1_respmode(w1);
  r->batch_id = xrpc_req_word1_batchid(w1);

  r->batch_size = xrpc_req_word2_batchsize(w2);
  r->reserved = xrpc_req_word2_reserved(w2);
}

void xrpc_response_header_to_net(const struct xrpc_response_header *r,
                                 uint8_t buf[8]) {

  uint32_t w1 = xrpc_res_word1_pack(r->preamble, r->batch_id);
  uint32_t w2 = xrpc_res_word2_pack(r->status, r->payload_size);

  /* convert to network byte order */
  w1 = htonl(w1);
  w2 = htonl(w2);

  /* copy to buffer */
  memcpy(buf, &w1, 4);
  memcpy(buf + 4, &w2, 4);
}

void xrpc_response_header_from_net(const uint8_t buf[8],
                                   struct xrpc_response_header *r) {
  uint32_t w1, w2;

  /* copy the 32-bit words first then ntohl */
  memcpy(&w1, buf, 4);
  memcpy(&w2, buf + 4, 4);

  w1 = ntohl(w1);
  w2 = ntohl(w2);

  /* extract fields using macros  */
  r->preamble = xrpc_res_word1_preamble(w1);
  r->batch_id = xrpc_res_word1_batchid(w1);

  r->status = xrpc_res_word2_status(w2);
  r->payload_size = xrpc_res_word2_payload_size(w2);
}

void xrpc_request_frame_header_to_net(const struct xrpc_request_frame_header *r,
                                      uint8_t buf[8]) {
  uint32_t w1, w2;

  w1 = xrpc_req_fr_word1_pack(r->opinfo, r->size_params);
  w2 = xrpc_req_fr_word2_pack(r->batch_id, r->frame_id);

  w1 = htonl(w1);
  w2 = htonl(w2);

  memcpy(buf, &w1, 4);
  memcpy(buf + 4, &w2, 4);
}

void xrpc_request_frame_header_from_net(const uint8_t buf[8],
                                        struct xrpc_request_frame_header *r) {
  uint32_t w1, w2;
  memcpy(&w1, buf, 4);
  memcpy(&w2, buf + 4, 4);

  w1 = ntohl(w1);
  w2 = ntohl(w2);

  r->opinfo = xrpc_req_fr_word1_opinfo(w1);
  r->size_params = xrpc_req_fr_word1_size_params(w1);
  r->batch_id = xrpc_req_fr_word2_batch_id(w2);
  r->frame_id = xrpc_req_fr_word2_frame_id(w2);
}

void xrpc_response_frame_header_to_net(
    const struct xrpc_response_frame_header *r, uint8_t buf[8]) {
  uint32_t w1, w2;

  w1 = xrpc_res_fr_word1_pack(r->opinfo, r->size_params);
  w2 = xrpc_res_fr_word2_pack(r->batch_id, r->frame_id);

  w1 = htonl(w1);
  w2 = htonl(w2);

  memcpy(buf, &w1, 4);
  memcpy(buf + 4, &w2, 4);
}

void xrpc_response_frame_header_from_net(const uint8_t buf[8],
                                         struct xrpc_response_frame_header *r) {
  uint32_t w1, w2;
  memcpy(&w1, buf, 4);
  memcpy(&w2, buf + 4, 4);

  w1 = ntohl(w1);
  w2 = ntohl(w2);

  r->opinfo = xrpc_res_fr_word1_opinfo(w1);
  r->size_params = xrpc_res_fr_word1_size_params(w1);
  r->batch_id = xrpc_res_fr_word2_batch_id(w2);
  r->frame_id = xrpc_res_fr_word2_frame_id(w2);
}

/* Serialize a vector on the network (network-order) */
int xrpc_vector_to_net(const struct xrpc_request_frame_header *r,
                       const void *data, uint8_t *buf, size_t len,
                       size_t *written) {
  // sanity check
  if (!r || !data || !buf || len == 0 || !written)
    return XRPC_PROTO_ERR_SERIALIZATION_INVALID_ARGS;

  enum xrpc_dtype_base dtyb = xrpc_req_fr_get_dtypb_from_opinfo(r->opinfo);
  enum xrpc_dtype_category dtyc = xrpc_req_fr_get_dtypc_from_opinfo(r->opinfo);

  // the data category must be array
  if (dtyc != XRPC_DTYPE_CAT_VECTOR) return XRPC_PROTO_ERR_INVALID_DTYPE;

  // ignore scale for now
  size_t elem_size = xrpc_dtypb_size(dtyb);
  size_t total_size = elem_size * r->size_params;

  if (len < total_size) return XRPC_PROTO_ERR_SERIALIZATION_INVALID_ARGS;

  switch (dtyb) {
  // now swapping needed on single byte elements
  case XRPC_BASE_INT8:
  case XRPC_BASE_UINT8:
    memcpy(buf, data, total_size);
    break;
  case XRPC_BASE_INT16:
  case XRPC_BASE_UINT16: {
    uint16_t t;
    for (size_t i = 0; i < r->size_params; ++i) {
      memcpy(&t, (const uint8_t *)data + i * 2, 2);
      t = htons(t);
      memcpy(buf + i * 2, &t, 2);
    }
    break;
  }
  case XRPC_BASE_UINT32:
  case XRPC_BASE_INT32:
  case XRPC_BASE_FLOAT32:
  case XRPC_BASE_DOUBLE32: {
    for (size_t i = 0; i < r->size_params; ++i) {
      uint32_t v;
      memcpy(&v, (const uint8_t *)data + i * 4, 4);
      v = htonl(v);
      memcpy(buf + i * 4, &v, 4);
    }
    break;
  }
  case XRPC_BASE_UINT64:
  case XRPC_BASE_INT64:
  case XRPC_BASE_FLOAT64:
  case XRPC_BASE_DOUBLE64: {
    for (size_t i = 0; i < r->size_params; ++i) {
      uint64_t v;
      memcpy(&v, (const uint8_t *)data + i * 8, 8);
      v = xrpc_hton64(v);
      memcpy(buf + i * 8, &v, 8);
    }
    break;
  }
  }
  *written = total_size;

  return XRPC_SUCCESS;
}

/* Deerialize a vector from the network (host-order) */
int xrpc_vector_from_net(const struct xrpc_request_frame_header *r,
                         const uint8_t *buf, size_t len, void *data,
                         size_t *read) {

  // sanity check
  if (!r || !data || !buf || len == 0 || !read)
    return XRPC_PROTO_ERR_SERIALIZATION_INVALID_ARGS;

  enum xrpc_dtype_base dtyb = xrpc_req_fr_get_dtypb_from_opinfo(r->opinfo);
  enum xrpc_dtype_category dtyc = xrpc_req_fr_get_dtypc_from_opinfo(r->opinfo);

  // the data category must be array
  if (dtyc != XRPC_DTYPE_CAT_VECTOR) return XRPC_PROTO_ERR_INVALID_DTYPE;

  // ignore scale for now
  size_t elem_size = xrpc_dtypb_size(dtyb);
  size_t total_size = elem_size * r->size_params;

  if (len < total_size) return XRPC_PROTO_ERR_SERIALIZATION_INVALID_ARGS;

  switch (dtyb) {
  // now swapping needed on single byte elements
  case XRPC_BASE_INT8:
  case XRPC_BASE_UINT8:
    memcpy(data, buf, total_size);
    break;
  case XRPC_BASE_INT16:
  case XRPC_BASE_UINT16: {
    uint16_t t;
    for (size_t i = 0; i < r->size_params; ++i) {
      memcpy(&t, buf + i * 2, 2);
      t = ntohs(t);
      memcpy((uint8_t *)data + i * 2, &t, 2);
    }
    break;
  }
  case XRPC_BASE_UINT32:
  case XRPC_BASE_INT32:
  case XRPC_BASE_FLOAT32:
  case XRPC_BASE_DOUBLE32: {
    for (size_t i = 0; i < r->size_params; ++i) {
      uint32_t t;
      memcpy(&t, buf + i * 4, 4);
      t = htonl(t);
      memcpy((uint8_t *)data + i * 4, &t, 4);
    }
    break;
  }
  case XRPC_BASE_UINT64:
  case XRPC_BASE_INT64:
  case XRPC_BASE_FLOAT64:
  case XRPC_BASE_DOUBLE64: {
    for (size_t i = 0; i < r->size_params; ++i) {
      uint64_t t;
      memcpy(&t, buf + i * 8, 8);
      t = xrpc_hton64(t);
      memcpy((uint8_t *)data + i * 8, &t, 8);
    }
    break;
  }
  }
  *read = total_size;
  return XRPC_SUCCESS;
}
