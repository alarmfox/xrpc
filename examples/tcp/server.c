#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define OP_DUMMY 0x0
#define OP_SUM 0x1
#define OP_DOT_PROD 0x2

static int dummy_handler(const struct xrpc_request *req,
                         struct xrpc_response *res) {

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);

  res->data = malloc(sizeof(uint64_t));
  memcpy(res->data, req->data, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

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
  res->data = malloc(res->hdr->sz);

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
  res->data = malloc(res->hdr->sz);

  memcpy(res->data, &prod, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

int main(void) {
  struct xrpc_server *srv = NULL;
  struct xrpc_transport_config tcfg =
      XRPC_TCP_SERVER_DEFAULT_CONFIG(INADDR_LOOPBACK, 9000);
  struct xrpc_io_system_config iocfg = {.type = XRPC_IO_SYSTEM_BLOCKING};
  struct xrpc_server_config cfg = {.tcfg = &tcfg, .iocfg = &iocfg};

  tcfg.config.tcp.nonblocking = false;
  tcfg.config.tcp.accept_timeout_ms = 100;

  if (xrpc_server_create(&srv, &cfg) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_DUMMY, dummy_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register dummy handler\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_SUM, sum_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register sum handler\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_DOT_PROD, dot_product_handler,
                           XRPC_RF_OVERWRITE) != XRPC_SUCCESS) {
    printf("cannot register dot product handler\n");
    goto exit;
  }

  xrpc_server_run(srv);

exit:
  xrpc_server_free(srv);
  srv = NULL;

  return 0;
}
