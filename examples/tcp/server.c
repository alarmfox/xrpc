#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define OP_SUM 0x0
#define OP_DOT_PROD 0x1

/*
 * For demonstration purposes this sums just 2 uint64_t.
 */
static int sum_handler(const struct xrpc_request *req,
                       struct xrpc_response *res) {
  if (req->hdr->sz != 16) {
    res->hdr->status = XRPC_RESPONSE_INVALID_PARAMS;
    res->hdr->sz = 0;
    return XRPC_SUCCESS;
  }
  uint64_t *p = (uint64_t *)req->data;

  uint64_t op1 = *p++;
  uint64_t op2 = *p;
  uint64_t c = op1 + op2;

  // write the header and populate the result
  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);
  memcpy(res->data, &c, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

/*
 * Performs the dot product between two arrays.
 * Arrays are sent one after the other. The array size must req->hdr->sz / 2
 * For now assume uint64_t arrays. Since req->hdr->sz is bytes, to get the
 * number of elements we need to divide by the sizeof(type)
 */
static int dot_product_handler(const struct xrpc_request *req,
                               struct xrpc_response *res) {

  // We cannot construct 2 arrays from an odd size
  if (req->hdr->sz % (2 * sizeof(uint64_t)) != 0) {
    res->hdr->status = XRPC_RESPONSE_INVALID_PARAMS;
    res->hdr->sz = 0;

    return XRPC_SUCCESS;
  }

  size_t arr_sz = req->hdr->sz / (2 * sizeof(uint64_t));
  uint64_t *p = (uint64_t *)req->data;
  uint64_t prod = 0;

  for (size_t i = 0; i < arr_sz; i++) {
    prod += p[i] * p[i + arr_sz];
  }

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);

  memcpy(res->data, &prod, sizeof(uint64_t));
  res->hdr->sz = sizeof(uint64_t);

  return XRPC_SUCCESS;
}

#include <netinet/in.h>
#include <sys/socket.h>

int main(void) {
  struct xrpc_transport *t = NULL;
  struct xrpc_server *rs = NULL;
  struct xrpc_tcp_server_config args = {0};

  args.addr.sin_family = AF_INET;
  args.addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  args.addr.sin_port = htons(9000);

  if (xrpc_transport_server_init_tcp(&t, &args) != XRPC_SUCCESS) {
    printf("cannot create transport server\n");
    goto exit;
  }

  if (xrpc_server_create(&rs, t) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  if (xrpc_server_register(rs, OP_SUM, sum_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register sum handler\n");
    goto exit;
  }

  if (xrpc_server_register(rs, OP_DOT_PROD, dot_product_handler,
                           XRPC_RF_OVERWRITE) != XRPC_SUCCESS) {
    printf("cannot register dot product handler\n");
    goto exit;
  }

  while (xrpc_server_run(rs) == 0) {}

exit:
  xrpc_server_free(rs);
  xrpc_transport_server_free_tcp(t);

  return 0;
}
