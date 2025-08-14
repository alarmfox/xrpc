#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "xrpc_server.h"

#define OP_SUM 0x0

/*
 * For demonstration purposes this sums just 2 uint64_t.
 */
int sum_handler(const struct xrpc_request *r) {
  assert(r->len == 16);
  uint64_t *p = (uint64_t *)r->data;

  uint64_t op1 = *p++;
  uint64_t op2 = *p;
  uint64_t res = op1 + op2;
  unsigned char *b = (unsigned char *)&res;
  unsigned char *resp_buf = (unsigned char *)r->resp_buf;

  for (int i = 0; i < 8; ++i) {
    resp_buf[i] = *b++;
  }

  *r->resp_len = 8;

  return XRPC_SUCCESS;
}

#ifdef TRANSPORT_UNIX
#define UNIX_SOCKET_PATH "/tmp/xrpc.sock"
const char *log_prefix = "rpc_server_unix";

#include <sys/socket.h>
#include <sys/un.h>
static struct transport_args {
  struct sockaddr_un sa;
} args = {.sa = {.sun_family = AF_LOCAL, .sun_path = UNIX_SOCKET_PATH}};
#endif /* if TRANSPORT_UNIX */

#ifdef TRANSPORT_TCP
#include <netinet/in.h>
#include <sys/socket.h>
const char *log_prefix = "rpc_server_tcp";

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

#ifdef TRANSPORT_TCP_TLS
#include <netinet/in.h>
#include <sys/socket.h>

#define CRT_PATH "certs/certificate.crt"
#define KEY_PATH "certs/pkey"

const char *log_prefix = "rpc_server_tcp_tls";

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

#endif /* if TRANSPORT_TCP_TLS */

int main() {
  struct transport *t = NULL;
  struct xrpc_server *rs = NULL;

  if (transport_init(&t, (void *)&args) != XRPC_SUCCESS) {
    printf("cannot create transport server\n");
    goto exit;
  }

  if (xrpc_server_create(&rs, t, 10) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  if (xrpc_server_register(rs, OP_SUM, sum_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register handlers\n");
    goto exit;
  }

  while (xrpc_server_poll(rs) == 0) {}

exit:
  xrpc_server_free(rs);
  rs = NULL;
  transport_free(t);
  t = NULL;

  return 0;
}
