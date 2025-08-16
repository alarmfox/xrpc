#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define RESP_BUFSIZE 4096

int main(void) {
  struct xrpc_transport *t = NULL;
  struct xrpc_client *cli = NULL;

  struct xrpc_request_header req_hdr = {
      .op = 0, .reqid = 1, .sz = 2 * sizeof(uint64_t)};
  struct xrpc_response_header rsp_hdr = {
      .op = 0, .reqid = 1, .sz = RESP_BUFSIZE};

  uint64_t nums[2] = {6, 7};
  unsigned char *buf[RESP_BUFSIZE];

  struct xrpc_request req = {.hdr = &req_hdr, .data = (const void *)nums};
  struct xrpc_response rsp = {.hdr = &rsp_hdr, .data = (void *)buf};

  struct xrpc_tcp_client_config args = {0};

  args.addr.sin_family = AF_INET;
  args.addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  args.addr.sin_port = htons(9000);

  if (xrpc_transport_client_init_tcp(&t, &args) != XRPC_SUCCESS) {
    printf("cannot create transport client\n");
    goto exit;
  }

  if (xrpc_client_init(&cli, t) != XRPC_SUCCESS) {
    printf("cannot create transport server\n");
    goto exit;
  }

  if (xrpc_call(cli, &req, &rsp) != XRPC_SUCCESS) {
    printf("call error\n");
    goto exit;
  }

  printf("%lu+%lu=%lu\n", nums[0], nums[1], *(uint64_t *)rsp.data);

exit:
  xrpc_transport_client_free_tcp(t);
}
