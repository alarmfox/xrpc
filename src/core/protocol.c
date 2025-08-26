#include "xrpc/protocol.h"
#include "xrpc/error.h"

/* Serialize a vector on the network (network-order) */
int xrpc_vector_to_net(const struct xrpc_request_frame_header *r,
                       const void *data, uint8_t *buf, size_t len,
                       size_t *written) {
  // sanity check
  if (!r || !data || !buf || len == 0 || !written)
    return XRPC_PROTO_ERR_SERIALIZATION_INVALID_ARGS;

  enum xrpc_dtype_base dtyb = XRPC_REQ_FR_DTYPB(r->opinfo);
  enum xrpc_dtype_category dtyc = XRPC_REQ_FR_DTYPC(r->opinfo);

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

  enum xrpc_dtype_base dtyb = XRPC_REQ_FR_DTYPB(r->opinfo);
  enum xrpc_dtype_category dtyc = XRPC_REQ_FR_DTYPC(r->opinfo);

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
