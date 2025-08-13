#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "transport.h"

#define OP_SUM 0x0

#define DEBUG 1

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

#ifdef TRANSPORT_UNIX
#define UNIX_SOCKET_PATH "/tmp/rpc.sock"
const char *log_prefix = "rpc_server_unix";

#include <sys/un.h>
struct transport_args {
  struct sockaddr_un sa;
} args = {.sa = {.sun_family = AF_LOCAL, .sun_path = UNIX_SOCKET_PATH}};
#endif /* if TRANSPORT_UNIX */

#ifdef TRANSPORT_TCP
const char *log_prefix = "rpc_server_tcp";

struct transport_args {
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

struct transport_args {
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
            .sin_port = 9000,

        },
    .crt_path = CRT_PATH,
    .key_path = KEY_PATH,
};

#endif /* if TRANSPORT_TCP_TLS */

int main() {
  int ret;
  struct transport *t = NULL;
  struct rpc_server *rs = NULL;
  struct request *req = malloc(sizeof(struct request));
  struct response *res = malloc(sizeof(struct response));

  if (DEBUG) log_set_minimum_level(LOG_LV_DEBUG);

  log_init(log_prefix);

  rpc_server_init(&rs);
  ret = rpc_server_register_handler(rs, OP_SUM, op_sum, RF_OVERWRITE);

  if (ret < 0) bail("cannot register handler");

  transport_init(&t, (void *)&args);

  log_message(LOG_LV_INFO, "waiting for connections");
  while (transport_recv(t, req) == 0) {
    rpc_server_handle_req(rs, req, res);
    dbg_request((*req), (*res));
    transport_send(t, res);

    memset(req, 0, sizeof(struct request));
    memset(res, 0, sizeof(struct response));
  }

  rpc_server_free(rs);
  transport_free(t);
  free(req);
  free(res);
  log_free();

  return 0;
}
