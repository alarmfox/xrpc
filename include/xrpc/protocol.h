#ifndef XRPC_PROTOCOL_H
#define XRPC_PROTOCOL_H

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>

#include "xrpc/protocol_utils.h"

/*
 * Usage: the client negotiate a batch identifier with the server. A batch is a
 * sequence of operations that the server performs without renegoatiating basic
 * paramters. For example, parameters could be security related.
 *
 * All data is exchanged through the network using the NETWORK ENDIANESS.
 *
 */
#define XRPC_PROTO_VERSION 0x0

enum xrpc_request_type {
  XRPC_REQUEST_BATCH_START = 1,
  XRPC_REQUEST_SERVER_INFO = 2,
  XRPC_REQUEST_SERVER_PING = 3,
  XRPC_REQUEST_BATCH_INIT = 4
};

// clang-format off
/*
 * @brief RPC request header
 *
 * The protocol supports `batching`. A batch is a sequence of operations that
 * the client requests to the server exchanging one header and sending bulk data
 * receiving response asyncrously. After a request header there will be
 * `batch_size` frames. Each frame will have a prefixed size header.
 *
 * * VER (4 bit): protocol version number
 * * TYPE (4 bit): message type can be one of `xrpc_message_type`
 * * RESP MODE (8 bit): indicates how the server should behaves. Reserved for
 * future use. The idea is to use this field to specify how the server should
 * behave if a request fails (ignore, abort all the batch, ecc)
 * * BATCH ID (16 bit): identifier of the batch
 * * BATCH SIZE (16 bit): number of operation to be performed
 * * RESERVED (16 bit): must be zero
 *
 *  4bit 4bit   8 bit          16 bit
 * +----+----+----+----+----+----+----+----+
 * |VER |TYPE|RESP MODE|      BATCH ID     | (32 bit)
 * +----+----+----+----+----+----+----+----+
 * +----+----+----+----+----+----+----+----+
 * |     BATCH SIZE    |      RESERVED     | (32 bit)
 * +----+----+----+----+----+----+----+----+
 *
 */
struct xrpc_request_header {
  uint8_t preamble;    /* Protocol version and message type*/
  uint8_t resp_mode;   /* Response mode */
  uint16_t batch_id;   /* Batch identifier */
  uint16_t batch_size; /* Batch size */
  uint16_t reserved;   /* Reserved. Must be 0*/
};

/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_request_header) == 8,
              "Request header must be exactly 8 bytes");

/* category values */
enum xrpc_dtype_category {
  XRPC_DTYPE_CAT_VECTOR = 0,
  XRPC_DTYPE_CAT_MATRIX = 1,
  XRPC_DTYPE_CAT_TENSOR = 2,
};

/* element base types */
enum xrpc_dtype_base {
  XRPC_BASE_UINT8 = 1,
  XRPC_BASE_UINT16,
  XRPC_BASE_UINT32,
  XRPC_BASE_UINT64,
  XRPC_BASE_INT8,
  XRPC_BASE_INT16,
  XRPC_BASE_INT32,
  XRPC_BASE_INT64,
  XRPC_BASE_FLOAT32,
  XRPC_BASE_FLOAT64,
  XRPC_BASE_DOUBLE32,
  XRPC_BASE_DOUBLE64,
};
// clang-format off
/*
 * @brief XRPC frame request header
 *
 * A frame header describes an operation that the server should do along with
 * its input data. This frame depends on the `dtype` field of the original
 * request.
 * * OPCODE (6 bit): id of the function to be invoked;
 * * SCALE (4 bit): number to scale the matrix/vector dimension;
 * * DTYPB (4 bit): data type base. One of `xrpc_dtype_base`
 * * DC (2 bit): data type category. One of `xrpc_dtype_category`
 * * SIZE PARAMS (14 bit):
 *     - DC = XRPC_DTYPE_CAT_SCALAR: it must be 1;
 *     - DC = XRPC_DTYPE_CAT_VECTOR: represents the size of the
 * array;
 *     - DC = XRPC_DTYPE_CAT_MATRIX: left 8 bits represent rows and right 8
 * bits represent cols
 *
 *   6 bit 4bit  6 bit         16 bit
 * +----+----+----+-----+----+----+----+-----+
 * |OPCOD|SCALE|DTYPB|DC|     SIZE PARAMS    |  (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |      BATCH_ID      |      FRAME ID      |  (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |               FRAME DATA                | (2 * sizeof(DTYPB) ^ scale)
 * +----+----+----+-----+----+----+----+-----+
 */
struct xrpc_request_frame_header {
  uint16_t opinfo;      /* Operation ID, scale, data type base and data type category */
  uint16_t size_params; /*  Dimension of the params based on dtype */
  uint16_t batch_id;    /*  Batch ID */
  uint16_t frame_id;    /*  Frame identifier */
};

/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_request_frame_header) == 8,
              "Frame header must be exactly 8 bytes");

enum xrpc_response_type {
  XRPC_RESP_STATUS_BATCH_INIT = 1,
  XRPC_RESP_STATUS_BATCH_REPORT = 2,
  XRPC_RESP_STATUS_ACK = 3,
};

/*
 * @brief RPC response header
 *
 * Reports the status of the specified `batch_id`.
 * * VER (4 bit): version of the protocol;
 * * TYPE (4 bit): type of message for the response `xrpc_response_type`;
 * * RSV (8 bit): reserved must be kept to zero
 * * BATCH ID(16 bit): ID of the batch
 * * STATUS (16 bit): ID of the batch
 * * PAYLOAD SIZE (16 bit): size of the payload for report and metrics. (TBD)
 *
 *
 *  4bit 4 bit  8 bit          16 bit
 * +----+----+----+----+----+----+----+----+
 * |VER | TYP|   RSV   |      BATCH ID     | (32 bit)
 * +----+----+----+----+----+----+----+----+
 * +----+----+----+----+----+----+----+----+
 * |       STATUS      |    PAYLOAD SIZE   | (32 bit)
 * +----+----+----+----+----+----+----+----+
 *
 */
struct xrpc_response_header {
  uint16_t preamble; /* Protocol Version most significant 4 bit and message type
                        4 bit*/
  uint16_t batch_id; /* Operation ID */
  uint16_t status;   /* Status ID */
  uint16_t payload_size; /* Size of the payload */
};

/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_response_header) == 8,
              "Response header must be exactly 8 bytes");

// Operation status flags
enum xrpc_fr_resp_status {
  XRPC_FR_RESPONSE_SUCCESS = 0,
  XRPC_FR_RESPONSE_INTERNAL_ERROR = 1,
  XRPC_FR_RESPONSE_INVALID_OP = 2,
  XRPC_FR_RESPONSE_INVALID_PARAMS = 3,
};

/*
 * @brief XRPC frame response header
 *
 * A frame response header describes the result of an operation in a specific
 * batch.
 * * STATU (6 bit): indicates the status of the response
 * * SCALE (4 bit): number to scale the matrix/vector dimension;
 * * DTYPB (4 bit): data type base. One of `xrpc_dtype_base`
 * * DC (2 bit): data type category. One of `xrpc_dtype_category`
 * * SIZE PARAMS (14 bit):
 *     - DC = XRPC_DTYPE_CAT_SCALAR: it must be 1;
 *     - DC = XRPC_DTYPE_CAT_VECTOR: represents the size of the
 * array;
 *     - DC = XRPC_DTYPE_CAT_MATRIX: left 8 bits represent rows and right 8
 * bits represent cols
 *
 *  6 bit 4bit  6 bit         16 bit
 * +----+----+----+-----+----+----+----+-----+
 * |STATU|SCALE|DTYPB|DC|     SIZE PARAMS    |  (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |      BATCH_ID      |      FRAME ID      |  (32 bit)
 * +----+----+----+-----+----+----+----+-----+
 * +----+----+----+-----+----+----+----+-----+
 * |               FRAME DATA                | (2 * sizeof(DTYPB) ^ scale * <size_params>)
 * +----+----+----+-----+----+----+----+-----+
 */
struct xrpc_response_frame_header {
  uint16_t  opinfo; /* Operation ID, scale, data type base and data type category*/
  uint16_t size_params; /*  Dimension of the params based on dtype */
  uint16_t batch_id;    /*  Batch ID */
  uint16_t frame_id;    /*  Frame identifier */
};

static inline size_t xrpc_dtypb_size(enum xrpc_dtype_base dtyb) {
  switch(dtyb) {
    case XRPC_BASE_UINT8:
    case XRPC_BASE_INT8:
      return 1;
    case XRPC_BASE_INT16:
    case XRPC_BASE_UINT16:
      return 2;
    case XRPC_BASE_UINT32:
    case XRPC_BASE_INT32:
    case XRPC_BASE_FLOAT32:
    case XRPC_BASE_DOUBLE32:
      return 4;
    case XRPC_BASE_UINT64:
    case XRPC_BASE_INT64:
    case XRPC_BASE_FLOAT64:
    case XRPC_BASE_DOUBLE64:
      return 8;
    default:
      return 0;
  }
}

/* Endianness helpers (simple portable 64-bit swap) */
static inline uint64_t xrpc_bswap64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(x);
#else
  return ((x & 0xffULL) << 56) | ((x & 0xff00ULL) << 40) |
         ((x & 0xff0000ULL) << 24) | ((x & 0xff000000ULL) << 8) |
         ((x & 0xff00000000ULL) >> 8) | ((x & 0xff0000000000ULL) >> 24) |
         ((x & 0xff000000000000ULL) >> 40) |
         ((x & 0xff00000000000000ULL) >> 56);
#endif
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define xrpc_hton64(x) xrpc_bswap64(x)
#define xrpc_ntoh64(x) xrpc_bswap64(x)
#else
#define xrpc_hton64(x) (x)
#define xrpc_ntoh64(x) (x)
#endif

// Batch processing utilities
static inline size_t
xrpc_calculate_frame_data_size(const struct xrpc_request_frame_header *hdr) {

  enum xrpc_dtype_base dtypb = xrpc_req_fr_get_dtypb_from_opinfo(hdr->opinfo);
  enum xrpc_dtype_category dtypc = xrpc_req_fr_get_dtypc_from_opinfo(hdr->opinfo);
  uint8_t scale = xrpc_req_fr_get_scale_from_opinfo(hdr->opinfo);

  size_t base_size = xrpc_dtypb_size(dtypb);
  if (base_size == 0) return 0;

  size_t scaled_size = base_size;
  for (uint8_t i = 0; i < scale; i++) {
    scaled_size *= 2; // Each scale doubles the size
  }

  switch (dtypc) {
  case XRPC_DTYPE_CAT_VECTOR:
    return scaled_size * hdr->size_params;

  case XRPC_DTYPE_CAT_MATRIX: {
    // size_params encodes rows in upper 8 bits, cols in lower 8 bits
    uint8_t rows = (hdr->size_params >> 8) & 0xFF;
    uint8_t cols = hdr->size_params & 0xFF;
    return scaled_size * rows * cols;
  }

  case XRPC_DTYPE_CAT_TENSOR:
    // For tensor, size_params represents total number of elements
    return scaled_size * hdr->size_params;

  default:
    return 0;
  }
}

// clang-format on
/*
 * Utilities  to serialize and deserialize struct to and from the network.
 */
void xrpc_request_header_to_net(const struct xrpc_request_header *r,
                                uint8_t buf[8]);

void xrpc_request_header_from_net(const uint8_t buf[8],
                                  struct xrpc_request_header *r);
void xrpc_response_header_to_net(const struct xrpc_response_header *r,
                                 uint8_t buf[8]);

void xrpc_response_header_from_net(const uint8_t buf[8],
                                   struct xrpc_response_header *r);

void xrpc_request_frame_header_to_net(const struct xrpc_request_frame_header *r,
                                      uint8_t buf[8]);

void xrpc_request_frame_header_from_net(const uint8_t buf[8],
                                        struct xrpc_request_frame_header *r);

void xrpc_response_frame_header_to_net(
    const struct xrpc_response_frame_header *r, uint8_t buf[8]);

void xrpc_response_frame_header_from_net(const uint8_t buf[8],
                                         struct xrpc_response_frame_header *r);

int xrpc_vector_to_net(const struct xrpc_request_frame_header *r,
                       const void *data, uint8_t *buf, size_t len,
                       size_t *written);
int xrpc_vector_from_net(const struct xrpc_request_frame_header *r,
                         const uint8_t *buf, size_t buflen, void *data,
                         size_t *read);

#endif //! XRPC_PROTOCOL_H
