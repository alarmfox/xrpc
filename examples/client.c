#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "xrpc_client.h"

#ifdef TRANSPORT_UNIX
#define UNIX_SOCKET_PATH "/tmp/xrpc.sock"

#include <sys/socket.h>
#include <sys/un.h>
static struct transport_args {
  struct sockaddr_un sa;
} args = {.sa = {.sun_family = AF_LOCAL, .sun_path = UNIX_SOCKET_PATH}};
#endif /* if TRANSPORT_UNIX */

#ifdef TRANSPORT_TCP
#include <netinet/in.h>
#include <sys/socket.h>

static struct transport_args {
  struct sockaddr_in sa;
} args = {.sa = {
              .sin_family = AF_INET,
              .sin_addr =
                  {
                      .s_addr = INADDR_LOOPBACK,
                  },
              .sin_port = 9000,

          }};

#endif /* if TRANSPORT_TCP */

#ifdef TRANSPORT_TLS
#include <netinet/in.h>
#include <sys/socket.h>

#define CRT_PATH "certs/certificate.crt"
#define KEY_PATH "certs/pkey"

static struct transport_args {
  struct sockaddr_in sa;
  char *crt_path;
  char *key_path;
} args = {
    .sa =
        {
            .sin_family = AF_INET,
            .sin_addr =
                {
                    .s_addr = INADDR_LOOPBACK,
                },
            .sin_port = 9001,

        },
    .crt_path = CRT_PATH,
    .key_path = KEY_PATH,
};

#endif /* if TRANSPORT_TLS */

int main(void) {
  struct transport *t = NULL;
  struct xrpc_client *cli = NULL;
  struct xrpc_request_header req_hdr = {
      .op = 0, .reqid = 1, .sz = 2 * sizeof(uint64_t)};
  uint64_t nums[2] = {6, 7};
  struct xrpc_response rsp;

  struct xrpc_request req = {.hdr = &req_hdr, .data = (const void *)nums};

  if (transport_client_init(&t, (void *)&args) != XRPC_SUCCESS) {
    printf("cannot create transport client\n");
    goto exit;
  }

  if (xrpc_client_connect(&cli, t) != XRPC_SUCCESS) {
    printf("cannot create transport server\n");
    goto exit;
  }

  if (xrpc_call(cli, &req, &rsp) != XRPC_SUCCESS) {
    printf("call error\n");
    goto exit;
  }
  printf("%lu+%lu=%lu\n", nums[0], nums[1], *(uint64_t *)rsp.data);

exit:
  transport_free(t);
}
