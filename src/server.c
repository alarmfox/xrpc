#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "protocol.h"
#include "transport.h"

#define OP_SUM 0x0

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

#ifdef TRANSPORT_UNIX
#define UNIX_SOCKET_PATH "/tmp/xrpc.sock"
const char *log_prefix = "rpc_server_unix";

#include <sys/un.h>
static struct transport_args {
  struct sockaddr_un sa;
} args = {.sa = {.sun_family = AF_LOCAL, .sun_path = UNIX_SOCKET_PATH}};
#endif /* if TRANSPORT_UNIX */

#ifdef TRANSPORT_TCP
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
  int ret;
  struct transport *t = NULL;
  struct rpc_server *rs = NULL;
  struct request req;
  struct response res;

  rpc_server_init(&rs);
  ret = rpc_server_register_handler(rs, OP_SUM, op_sum, RF_OVERWRITE);

  if (ret < 0) {
    printf("cannot register handler\n");
    goto exit;
  }

  if (transport_init(&t, (void *)&args) != XRPC_SUCCESS) {
    printf("cannot create transport server\n");
    goto exit;
  }

  while (transport_poll_client(t) == 0) {
    while (transport_recv(t, (void *)&req, sizeof(struct request)) ==
           XRPC_SUCCESS) {
      unmarshal_req(&req);
      rpc_server_handle_req(rs, &req, &res);
      marshal_res(&res);
      transport_send(t, (const void *)&res, sizeof(struct response));

      memset(&req, 0, sizeof(struct request));
      memset(&res, 0, sizeof(struct response));
    }

    transport_release_client(t);
  }

exit:
  rpc_server_free(rs);
  rs = NULL;
  transport_free(t);
  t = NULL;

  return 0;
}
