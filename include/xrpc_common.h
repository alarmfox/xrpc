#ifndef __XRPC_COMMON_H
#define __XRPC_COMMON_H

#include <stdint.h>

// Response status flags
enum XRPC_RESPONSE_STATUS {
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
 */
struct __attribute__((packed)) xrpc_request_header {
  uint32_t op;    /* Operation ID */
  uint32_t sz;    /* Size of the payload */
  uint64_t reqid; /* Request identifier */
};

/**
 * @brief RPC response header
 *
 * Before sending the response, the server will send the header containng the
 * selected operation and the size of the request and a byte status.
 */
struct __attribute__((packed)) xrpc_response_header {
  uint32_t op;    /* Operation ID*/
  uint32_t sz;    /* Size of the payload */
  uint64_t reqid; /* Request identifier */
  uint8_t status; /* Status byte */
};

/**
 * @brief An incoming RPC request.
 *
 * The server provides a pointer to the request data. The handler is assumed to
 * not modify the request. It contains a prefixed struct xrpc_request_header.
 *
 * */
struct __attribute__((packed)) xrpc_request {
  struct xrpc_request_header *hdr; /* Header of the request */
  const void *data;                /**< Pointer to request payload */
};

/**
 * @brief An outgoint RPC response.
 *
 * The server provides a pointer to the request data and a buffer for the
 * handler to write its response. The handler is responsible for filling in the
 * data (up to hdr->sz) and updating the hdr->sz with the actual bytes
 * number of response.
 */
struct __attribute__((packed)) xrpc_response {
  struct xrpc_response_header *hdr; /* Header of the request */
  void *data;                       /**< Buffer for writing response data */
};

#endif // !__XRPC_COMMON_H
