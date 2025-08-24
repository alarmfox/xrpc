#ifndef XRPC_PROTOCOL_H
#define XRPC_PROTOCOL_H

#include <arpa/inet.h>
#include <stdint.h>

// Response status flags
enum xrpc_response_status {
  XRPC_RESPONSE_SUCCESS = 1 << 0,
  XRPC_RESPONSE_INTERNAL_ERROR = 1 << 1,
  XRPC_RESPONSE_UNSUPPORTED_HANDLER = 1 << 2,
  XRPC_RESPONSE_INVALID_PARAMS = 1 << 3,
};

/**
 * @brief RPC request header
 *
 * Before sending the requests, the client will send the header containng the
 * selected operation and the size of the request.
 *
 */
struct __attribute__((packed)) xrpc_request_header {
  uint32_t operation_id; /* Operation ID */
  uint32_t payload_size; /* Size of the payload */
  uint64_t request_id;   /* Request identifier */
};

/*
 * @brief RPC response header
 *
 * Before sending the response, the server will send the header containng the
 * selected operation and the size of the request and a byte status.
 */
struct __attribute__((packed)) xrpc_response_header {
  uint32_t operation_id; /* Operation ID*/
  uint32_t payload_size; /* Size of the payload */
  uint64_t request_id;   /* Request identifier */
  uint8_t status;        /* Status byte */
};

/**
 * @brief An incoming RPC request.
 *
 * The server provides a pointer to the request data. The handler is assumed to
 * not modify the request. It contains a prefixed struct xrpc_request_header.
 *
 * */
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
struct __attribute__((packed)) xrpc_response {
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

/* Convenience inline helpers to convert header fields to/from network order */
static inline void xrpc_request_header_to_net(struct xrpc_request_header *h) {
  h->operation_id = htonl(h->operation_id);
  h->payload_size = htonl(h->payload_size);
  h->request_id = xrpc_hton64(h->request_id);
}
static inline void xrpc_request_header_from_net(struct xrpc_request_header *h) {
  h->operation_id = ntohl(h->operation_id);
  h->payload_size = ntohl(h->payload_size);
  h->request_id = xrpc_ntoh64(h->request_id);
}

static inline void xrpc_response_header_to_net(struct xrpc_response_header *h) {
  h->operation_id = htonl(h->operation_id);
  h->payload_size = htonl(h->payload_size);
  h->request_id = xrpc_hton64(h->request_id);
  h->status = htonl(h->status);
}
static inline void xrpc_response_header_from_net(struct xrpc_response_header *h) {
  h->operation_id = ntohl(h->operation_id);
  h->payload_size = ntohl(h->payload_size);
  h->request_id = xrpc_ntoh64(h->request_id);
  h->status = ntohl(h->status);
}
#endif // !XRPC_PROTOCOL_H
