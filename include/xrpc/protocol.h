#ifndef XRPC_PROTOCOL_H
#define XRPC_PROTOCOL_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "xrpc/error.h"

#define XRPC_PROTO_VERSION 0x0

/* dtype */
enum xrpc_dtype {
  XRPC_DTYPE_UINT8 = 1,
  XRPC_DTYPE_INT32 = 2,
  XRPC_DTYPE_INT64 = 3,
  XRPC_DTYPE_FLOAT32 = 4,
  XRPC_DTYPE_FLOAT64 = 5,
};

/* category values (choose numbers to match your spec) */
enum {
  XRPC_DTYPE_CAT_SCALAR = 1,
  XRPC_DTYPE_CAT_ARRAY = 2,
  XRPC_DTYPE_CAT_TENSOR = 3,
  XRPC_DTYPE_CAT_MATRIX = 4,
};

/* element base types (same as your earlier enum xrpc_dtype) */
enum {
  XRPC_BASE_UINT8 = 1,
  XRPC_BASE_INT32 = 2,
  XRPC_BASE_INT64 = 3,
  XRPC_BASE_FLOAT32 = 4,
  XRPC_BASE_FLOAT64 = 5,
};
/**
 * @brief RPC request header
 *
 * Before sending the requests, the client will send the header containing the
 * selected operation and the size of the request.
 *
 *  4bit 4bit   8 bit          16 bit
 * +----+----+----+-----+----+----+----+-----+
 * |VER |TYPE|   DTYPE  |     BATCH SIZE     | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |    OPERATION ID    |    PAYLOAD SIZE    | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |               REQUEST ID                | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 *
 */
struct xrpc_request_header {
  uint8_t proto_version; /* Protocol Version */
  uint8_t msg_type;      /* Message type */
  uint8_t data_type;     /* Data type of the numbers */
  uint16_t batch_size;   /* Batch size */
  uint16_t operation_id; /* Operation ID */
  uint16_t payload_size; /* Size of the payload */
  uint32_t request_id;   /* Request identifier */
};

// Response status flags
enum xrpc_response_status {
  XRPC_RESPONSE_SUCCESS = 1 << 0,
  XRPC_RESPONSE_INTERNAL_ERROR = 1 << 1,
  XRPC_RESPONSE_UNSUPPORTED_HANDLER = 1 << 2,
  XRPC_RESPONSE_INVALID_PARAMS = 1 << 3,
};
/*
 * @brief RPC response header
 *
 *  4bit 4bit   8 bit          16 bit
 * +----+----+----+-----+----+----+----+-----+
 * |VER |RSV |  DTYPE   |    OPERATION ID    | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |      STATUS        |    PAYLOAD SIZE    | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |               REQUEST ID                | (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 *
 */
struct xrpc_response_header {
  uint8_t proto_version; /* Protocol Version */
  uint8_t data_type;     /* Data type of the numbers */
  uint16_t operation_id; /* Operation ID */
  uint16_t status;       /* Status ID */
  uint16_t payload_size; /* Size of the payload */
  uint64_t request_id;   /* Request identifier */
};

/*
 * @brief An incoming RPC request.
 *
 * The server provides a pointer to the request data. The handler is assumed to
 * not modify the request. It contains a prefixed struct xrpc_request_header.
 *
 */
struct xrpc_request {
  struct xrpc_request_header *hdr; /* Header of the request */
  const uint8_t *payload;          /* Pointer to request payload */
};

/**
 * @brief An outgoing RPC response.
 *
 * The server provides a pointer to the request data and a buffer for the
 * handler to write its response. The handler is responsible for filling in the
 * data (up to hdr->sz) and updating the hdr->sz with the actual bytes
 * number of response.
 */
struct xrpc_response {
  struct xrpc_response_header *hdr; /* Header of the request */
  uint8_t *payload;                 /* Buffer for writing response data */
};

/* Helper macros */
#define XRPC_REQUEST_MSG_SIZE(payload_len)                                     \
  (sizeof(struct xrpc_request_header) + (size_t)(payload_len))
#define XRPC_RESPONSE_MSG_SIZE(payload_len)                                    \
  (sizeof(struct xrpc_response_header) + (size_t)(payload_len))

/* Endianness helpers (simple portable 64-bit swap) */
static inline uint64_t xrpc_bswap64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(x);
#else
  // clang-format off
  return ((x & 0xffULL) << 56) |
         ((x & 0xff00ULL) << 40) |
         ((x & 0xff0000ULL) << 24) |
         ((x & 0xff000000ULL) << 8) |
         ((x & 0xff00000000ULL) >> 8) |
         ((x & 0xff0000000000ULL) >> 24) |
         ((x & 0xff000000000000ULL) >> 40) |
         ((x & 0xff00000000000000ULL) >> 56);
#endif
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define xrpc_hton64(x) xrpc_bswap64(x)
# define xrpc_ntoh64(x) xrpc_bswap64(x)
#else
# define xrpc_hton64(x) (x)
# define xrpc_ntoh64(x) (x)
#endif


static inline int xrpc_serialize_request(const struct xrpc_request *r, uint8_t *buf, size_t len) {
  if(len < sizeof(struct xrpc_request_header) + r->hdr->payload_size) return XRPC_API_ERR_SERIALIZATION;

  // serialize the header

  // concatenate proto_version and msg_type
  uint8_t msg_ver = ((r->hdr->proto_version & 0xF) <<  4) | (r->hdr->msg_type & 0xF);

  uint16_t batch_size = htons(r->hdr->batch_size);
  uint16_t operation_id = htons(r->hdr->operation_id);
  uint16_t payload_size= htons(r->hdr->payload_size);
  uint32_t request_id= htonl(r->hdr->request_id);

  // serialize first word
  buf[0]= msg_ver;
  buf[1] = r->hdr->data_type;
  memcpy(buf + 2, &batch_size, 2);

  // serialize the second word
  memcpy(buf + 4, &operation_id, 2);
  memcpy(buf + 6, &payload_size, 2);

  // serialize the third word
  memcpy(buf + 8, &request_id, 4);


  // Serialize

  return XRPC_SUCCESS;
}

#endif // !XRPC_PROTOCOL_H
