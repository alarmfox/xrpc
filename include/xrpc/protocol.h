#ifndef XRPC_PROTOCOL_H
#define XRPC_PROTOCOL_H

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "xrpc/error.h"

// clang-format off
/*
 * NOTE: although the protocol specifies batch, it just implemented one
 * operation for now. So the server implementation always assumes batch_size
 * = 1.
 */
#define XRPC_PROTO_VERSION 0x0

enum xrpc_message_type {
  XRPC_MSG_TYPE_REQ = 1,
  XRPC_MSG_TYPE_INFO = 2,
  XRPC_MSG_TYPE_PING = 3,
};

/*
 * @brief RPC request header
 *
 * Before sending the requests, the client will send the header containing the
 * selected operation and the size of the request. The protocol supports
 * `batching`. A batch is a sequence of operations that the client
 * requests to the server exchanging one header and sending bulk data receiving
 * response asyncrously. After a request header there will be `batch_size`
 * frames. Each frame will have a prefixed size header.
 *
 * * VER (4 bit): protocol version number
 * * TYPE (4 bit): message type can be one of `xrpc_message_type`
 * * RESP MODE (8 bit): indicates how the server should behaves. Reserved for
 * future use. The idea is to use this field to specify how the server should
 * behave if a request fails (ignore, abort all the batch, ecc)
 * * BATCH SIZE (16 bit): number of operation to be performed
 * * BATCH ID (16 bit): identifier of the batch
 * * RESERVED (16 bit): must be zero
 *
 *  4bit 4bit   8 bit          16 bit
 * +----+----+----+----+----+----+----+----+
 * |VER |TYPE|RESP MODE|     BATCH SIZE    | (32 bit)
 * +----+----+----+----+----+----+----+----+
 * +----+----+----+----+----+----+----+----+
 * |      BATCH ID     |      RESERVED     | (32 bit)
 * +----+----+----+----+----+----+----+----+
 *
 */
struct xrpc_request_header {
  uint8_t preamble;      /* Protocol version and message type*/
  uint8_t resp_mode;     /* Response mode */
  uint16_t batch_size;   /* Batch size */
  uint16_t batch_id;     /* Batch identifier */
  uint16_t reserved;     /* Reserved. Must be 0*/
};

/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_request_header) == 8, 
              "Request header must be exactly 8 bytes");

/* category values */
enum xrpc_dtype_category {
  XRPC_DTYPE_CAT_ARRAY = 0,
  XRPC_DTYPE_CAT_MATRIX = 1,
  XRPC_DTYPE_CAT_TENSOR = 2,
};

/* element base types */
enum xrpc_dtype_base {
  XRPC_BASE_UINT8 = 0,
  XRPC_BASE_INT32 = 1,
  XRPC_BASE_INT64 = 2,
  XRPC_BASE_FLOAT32 = 3,
  XRPC_BASE_FLOAT64 = 4,
};

/*
 * @brief XRPC frame header
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
 * |               FRAME DATA                | (NARG * sizeof(DTYPB) * <params_size> ^ scale)
 * +----+----+----+-----+----+----+----+-----+
 */
struct xrpc_frame_header {
  uint8_t opinfo;        /* Operation ID, scale, data type base and data type category*/
  uint16_t size_params; /*  Dimension of the params based on dtype */
  uint16_t batch_id ;   /*  Batch ID */
  uint16_t frame_id;    /*  Frame identifier */
};
/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_frame_header) == 8, 
              "Frame header must be exactly 8 bytes");

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
 * Reports the status of the specified `batch_id`.
 *
 *  4bit     12 bit          16 bit
 * +----+----+----+----+----+----+----+----+
 * |VER |      RSV     |      BATCH ID     | (32 bit)
 * +----+----+----+----+----+----+----+----+
 * +----+----+----+----+----+----+----+----+
 * |       STATUS      |    PAYLOAD SIZE   | (32 bit)
 * +----+----+----+----+----+----+----+----+
 *
 */
struct xrpc_response_header {
  uint16_t preamble;     /* Protocol Version */
  uint16_t batch_id;     /* Operation ID */
  uint16_t status;       /* Status ID */
  uint16_t payload_size; /* Size of the payload */
};
/* Compile-time check that the struct is the expected size */
static_assert(sizeof(struct xrpc_response_header) == 8, 
              "Response header must be exactly 8 bytes");

/* Endianness helpers (simple portable 64-bit swap) */
static inline uint64_t xrpc_bswap64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(x);
#else
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
